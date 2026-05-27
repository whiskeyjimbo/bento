//go:build linux

package runner

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/whiskeyjimbo/bento/internal/grants"
	"github.com/whiskeyjimbo/bento/internal/proxy"
	"github.com/whiskeyjimbo/bento/internal/spec"
	"github.com/whiskeyjimbo/bento/internal/sysprobe"
)

// runPlatform orchestrates the Linux sandbox lifecycle: resolve tools, start
// auxiliary resources (proxies, launcher), compile bwrap argv, exec.
func runPlatform(ctx context.Context, m *spec.Manifest, cfg *Config) (int, error) {
	interp, scriptAbs, err := resolveTools(m)
	if err != nil {
		return -1, err
	}
	if err := validateWritePaths(m.Write); err != nil {
		return -1, err
	}

	aux, err := startAuxiliary(m, cfg)
	if err != nil {
		return -1, err
	}
	defer aux.close()

	args, sections := compileBwrapArgs(compileCtx{
		manifest:  m,
		interp:    interp,
		scriptAbs: scriptAbs,
		aux:       aux,
		extraEnv:  cfg.ExtraEnv,
	})
	obs := newFSObserver(cfg, scriptAbs, interp)
	defer obs.close()
	args = obs.injectArgs(args)

	if cfg.Logger != nil && cfg.Verbose {
		cfg.Logger.Printf("[bwrap] argv:\n%s", formatBwrapArgs(args, sections))
	}

	code, err := executeCommand(ctx, m.Limits, args, cfg, obs)
	if cfg.FSObserver != nil {
		cfg.FSObserver(obs.collect(cfg))
	}
	return code, err
}

// formatBwrapArgs pretty-prints the bwrap argv as labeled sections with one
// flag (and its operands) per line. Empty sections are dropped. Flags are
// tokens starting with "--"; "--" alone is the entrypoint separator.
func formatBwrapArgs(args []string, sections []bwrapSection) string {
	var b strings.Builder
	writeRange := func(lo, hi int) {
		var line []string
		flush := func() {
			if len(line) == 0 {
				return
			}
			b.WriteString("    ")
			b.WriteString(strings.Join(line, " "))
			b.WriteByte('\n')
			line = line[:0]
		}
		for _, a := range args[lo:hi] {
			if strings.HasPrefix(a, "--") && len(line) > 0 {
				flush()
			}
			line = append(line, a)
		}
		flush()
	}
	if len(sections) == 0 {
		writeRange(0, len(args))
		return strings.TrimRight(b.String(), "\n")
	}
	for i, s := range sections {
		end := len(args)
		if i+1 < len(sections) {
			end = sections[i+1].start
		}
		if s.start == end {
			continue // empty section
		}
		fmt.Fprintf(&b, "  # %s\n", s.label)
		writeRange(s.start, end)
	}
	return strings.TrimRight(b.String(), "\n")
}

// resolveTools verifies bwrap is installed and resolves the interpreter and script paths.
func resolveTools(m *spec.Manifest) (interp, scriptAbs string, err error) {
	if _, err = exec.LookPath("bwrap"); err != nil {
		return "", "", fmt.Errorf("bwrap not found in PATH: %w", err)
	}
	interp, err = exec.LookPath(m.Interpreter)
	if err != nil {
		return "", "", fmt.Errorf("interpreter %q not found: %w", m.Interpreter, err)
	}
	if real, errSym := filepath.EvalSymlinks(interp); errSym == nil {
		interp = real
	}
	scriptAbs, err = filepath.Abs(m.Script)
	if err != nil {
		return "", "", err
	}
	if _, err = os.Stat(scriptAbs); err != nil {
		return "", "", fmt.Errorf("script: %w", err)
	}
	return interp, scriptAbs, nil
}

// Sandbox-side proxy ports in bridge mode; fixed inside an isolated netns.
const (
	sandboxHTTPProxyPort  = 3128
	sandboxSOCKSProxyPort = 1080
)

// auxiliary holds per-Run resources: proxies, proxychains config, launcher,
// unix sockets, host socats. Cleanups run LIFO via close().
type auxiliary struct {
	networkMode  spec.NetworkMode // resolved (never Auto)
	httpProxy    proxy.ProxyServer
	socks        proxy.ProxyServer
	pchainsCfg   string
	launcherPath string
	passwdPath   string // synthetic /etc/passwd bind source
	groupPath    string // synthetic /etc/group bind source

	// Script-visible endpoints. Landlock: host proxy addrs. Bridge: fixed sandbox ports.
	httpProxyURL string
	socksAddr    string
	allowedPorts string

	// Bridge-mode only.
	unixHTTPSock  string
	unixSocksSock string

	cleanups []func()
}

// onClose registers a LIFO cleanup.
func (a *auxiliary) onClose(f func()) {
	a.cleanups = append(a.cleanups, f)
}

func (a *auxiliary) close() {
	if a == nil {
		return
	}
	for i := len(a.cleanups) - 1; i >= 0; i-- {
		a.cleanups[i]()
	}
}

func startAuxiliary(m *spec.Manifest, cfg *Config) (*auxiliary, error) {
	aux := &auxiliary{networkMode: resolveNetworkMode(cfg.NetworkMode, cfg)}

	// Synthetic /etc/passwd + /etc/group so tools like `whoami`, `id`, and
	// language runtimes that look up the current user (e.g. Python's pwd
	// module) get a real answer instead of "cannot find name for user ID".
	// We don't bind the host's files: that would leak every username on the
	// box. We also can't generate these inside the sandbox (no write to /etc).
	if passwd, group, err := writeSyntheticUserDB(); err == nil {
		aux.passwdPath = passwd
		aux.groupPath = group
		aux.onClose(func() { os.Remove(passwd); os.Remove(group) })
	} else {
		cfg.warn("synthetic /etc/passwd setup failed: %v — whoami / pwd lookups inside the sandbox will fail", err)
	}

	if m.Network != nil {
		proxyOpts := []proxy.Option{proxy.WithLogger(cfg.Logger)}
		if cfg.GrantCallback != nil {
			// Shared cache so HTTP and SOCKS5 don't both prompt for the same host:port.
			cache := grants.NewCache()
			proxyOpts = append(proxyOpts, proxy.WithGrants(cfg.GrantCallback, cache))
		}
		socks, err := proxy.StartSOCKS5(m.Network, proxyOpts...)
		if err != nil {
			return nil, err
		}
		aux.socks = socks
		aux.onClose(func() { socks.Close() })

		http, err := proxy.StartHTTPConnect(m.Network, proxyOpts...)
		if err != nil {
			aux.close()
			return nil, err
		}
		aux.httpProxy = http
		aux.onClose(func() { http.Close() })

		if err := setupNetworkBridges(aux, cfg); err != nil {
			aux.close()
			return nil, err
		}
	}

	// Exec block via launcher (seccomp + Landlock). Extraction failure degrades silently.
	// PreExtractedLauncher (Sandbox warm-pool) skips per-Run extraction and cleanup.
	// allow_exec=true (or the deprecated non-empty exec: list) skips the launcher.
	if !m.AllowExec && len(m.Exec) == 0 {
		if cfg.PreExtractedLauncher != "" {
			aux.launcherPath = cfg.PreExtractedLauncher
		} else if path, err := extractLauncher(); err == nil {
			aux.launcherPath = path
			aux.onClose(func() { os.Remove(path) })
		} else {
			cfg.warn("launcher extract failed: %v — exec block (seccomp+Landlock) disabled", err)
		}
		if aux.launcherPath != "" {
			if abi := sysprobe.LandlockABI(); abi < 4 {
				cfg.warn("Landlock TCP not supported (ABI=%d, need ≥4) — static binaries can bypass the network proxy; upgrade kernel to ≥6.7 to close this gap", abi)
			}
		}
	}
	return aux, nil
}

// executeCommand runs bwrap (optionally wrapped in systemd-run for limits).
// Sets up the fd-3 telemetry pipe if cfg.Telemetry is set.
func executeCommand(ctx context.Context, lim *spec.Limits, bwrapArgs []string, cfg *Config, obs *fsObserver) (int, error) {
	exe, fullArgs := wrapWithLimits(lim, "bwrap", bwrapArgs, cfg)
	exe, fullArgs = obs.wrapExec(exe, fullArgs)
	cmd := exec.CommandContext(ctx, exe, fullArgs...)
	cmd.Stdin = cfg.Stdin
	cmd.Stdout = cfg.Stdout
	// Capture stderr so we can detect bwrap's userns failures (typical when
	// running inside a restricted container) and surface a remediation hint
	// alongside the original message.
	stderrTee := newBwrapStderrTee(cfg.Stderr)
	cmd.Stderr = stderrTee
	defer stderrTee.maybeHintContainer(cfg)

	if cfg.Telemetry != nil {
		r, w, err := os.Pipe()
		if err != nil {
			return -1, fmt.Errorf("telemetry pipe: %w", err)
		}
		defer r.Close()
		cmd.ExtraFiles = []*os.File{w} // becomes fd 3 in the child
		done := make(chan struct{})
		go func() {
			defer close(done)
			io.Copy(cfg.Telemetry, r)
		}()
		// Closing the parent's write end lets io.Copy see EOF when the child exits.
		defer func() {
			w.Close()
			<-done
		}()
	}

	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode(), nil
		}
		return -1, err
	}
	return 0, nil
}

// resolveNetworkMode resolves Auto to Landlock (kernel ABI ≥4) or Bridge otherwise.
func resolveNetworkMode(requested spec.NetworkMode, cfg *Config) spec.NetworkMode {
	if requested != spec.NetworkModeAuto {
		return requested
	}
	if sysprobe.LandlockABI() >= 4 {
		return spec.NetworkModeLandlock
	}
	cfg.warn("Landlock TCP unavailable (kernel <6.7) — auto-selecting NetworkModeBridge")
	return spec.NetworkModeBridge
}

// setupNetworkBridges configures script-visible network endpoints based on aux.networkMode.
func setupNetworkBridges(aux *auxiliary, cfg *Config) error {
	switch aux.networkMode {
	case spec.NetworkModeLandlock:
		return setupLandlockBridge(aux, cfg)
	case spec.NetworkModeBridge:
		return setupSocketBridge(aux, cfg)
	}
	return fmt.Errorf("unresolved network mode %v", aux.networkMode)
}

// setupLandlockBridge: script reaches host proxies directly on loopback.
// Both IPv4 and IPv6 ephemeral ports are allowlisted for dual-stack scripts.
func setupLandlockBridge(aux *auxiliary, cfg *Config) error {
	aux.socksAddr = aux.socks.Addr()
	aux.httpProxyURL = "http://" + aux.httpProxy.Addr()
	aux.allowedPorts = collectPorts(aux.httpProxy.Addrs(), aux.socks.Addrs())
	return setupProxychainsIfAvailable(aux, cfg, aux.socksAddr)
}

// collectPorts returns a comma-separated dedup'd list of ports from addrs.
func collectPorts(addrSets ...[]string) string {
	var ports []string
	seen := map[string]bool{}
	for _, set := range addrSets {
		for _, a := range set {
			_, p, err := net.SplitHostPort(a)
			if err != nil || p == "" || seen[p] {
				continue
			}
			seen[p] = true
			ports = append(ports, p)
		}
	}
	return strings.Join(ports, ",")
}

// setupSocketBridge: --unshare-net with unix-socket bridges to host TCP.
// Script sees fixed inner ports (3128/1080) on loopback.
func setupSocketBridge(aux *auxiliary, cfg *Config) error {
	socat := sysprobe.FindSocat()
	if socat == "" {
		return fmt.Errorf("NetworkModeBridge requires socat; install it (apt install socat) or use NetworkModeLandlock on kernel ≥ 6.7")
	}

	httpSock, err := allocUnixSocket("bento-http")
	if err != nil {
		return fmt.Errorf("alloc http unix socket: %w", err)
	}
	aux.unixHTTPSock = httpSock
	aux.onClose(func() { os.Remove(httpSock) })

	socksSock, err := allocUnixSocket("bento-socks")
	if err != nil {
		return fmt.Errorf("alloc socks unix socket: %w", err)
	}
	aux.unixSocksSock = socksSock
	aux.onClose(func() { os.Remove(socksSock) })

	if err := spawnHostSocat(aux, socat, httpSock, aux.httpProxy.Addr(), cfg); err != nil {
		return fmt.Errorf("host http bridge: %w", err)
	}
	if err := spawnHostSocat(aux, socat, socksSock, aux.socks.Addr(), cfg); err != nil {
		return fmt.Errorf("host socks bridge: %w", err)
	}

	aux.httpProxyURL = fmt.Sprintf("http://127.0.0.1:%d", sandboxHTTPProxyPort)
	aux.socksAddr = fmt.Sprintf("127.0.0.1:%d", sandboxSOCKSProxyPort)
	aux.allowedPorts = fmt.Sprintf("%d,%d", sandboxHTTPProxyPort, sandboxSOCKSProxyPort)
	return setupProxychainsIfAvailable(aux, cfg, aux.socksAddr)
}

func setupProxychainsIfAvailable(aux *auxiliary, cfg *Config, target string) error {
	if sysprobe.FindProxychainsLib() == "" {
		cfg.warn("libproxychains.so not found — non-HTTP traffic from dynamically-linked binaries will bypass the host allowlist; install proxychains4 to close this gap")
		return nil
	}
	cfgPath, err := writeProxychainsConfig(target)
	if err != nil {
		return fmt.Errorf("writing proxychains config: %w", err)
	}
	aux.pchainsCfg = cfgPath
	aux.onClose(func() { os.Remove(cfgPath) })
	return nil
}

// allocUnixSocket reserves a /tmp path for socat to bind a fresh unix socket.
func allocUnixSocket(prefix string) (string, error) {
	f, err := os.CreateTemp("", prefix+"-*.sock")
	if err != nil {
		return "", err
	}
	path := f.Name()
	f.Close()
	os.Remove(path)
	return path, nil
}

// spawnHostSocat runs a host-side UNIX-LISTEN ↔ TCP socat and registers cleanup.
func spawnHostSocat(aux *auxiliary, socat, unixPath, tcpAddr string, cfg *Config) error {
	cmd := exec.Command(socat,
		"UNIX-LISTEN:"+unixPath+",fork,reuseaddr",
		"TCP:"+tcpAddr+",keepalive,keepidle=10,keepintvl=5,keepcnt=3",
	)
	if cfg.Logger != nil {
		cfg.Logger.Printf("[socat-host] %s ↔ %s", unixPath, tcpAddr)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	aux.onClose(func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
	return nil
}

// writeSyntheticUserDB writes minimal /etc/passwd + /etc/group files
// containing a single entry for the calling user (mapped to "sandbox" /
// "sandbox") plus the standard root and nobody rows. Returns the two temp
// paths; caller binds them into the sandbox at /etc/passwd and /etc/group.
func writeSyntheticUserDB() (string, string, error) {
	uid := os.Getuid()
	gid := os.Getgid()
	passwd := fmt.Sprintf("root:x:0:0:root:/root:/bin/sh\nsandbox:x:%d:%d:bento sandbox:/sandbox:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/sh\n", uid, gid)
	group := fmt.Sprintf("root:x:0:\nsandbox:x:%d:\nnobody:x:65534:\n", gid)

	pf, err := os.CreateTemp("", "bento-passwd-*")
	if err != nil {
		return "", "", err
	}
	if _, err := pf.WriteString(passwd); err != nil {
		pf.Close()
		os.Remove(pf.Name())
		return "", "", err
	}
	pf.Close()

	gf, err := os.CreateTemp("", "bento-group-*")
	if err != nil {
		os.Remove(pf.Name())
		return "", "", err
	}
	if _, err := gf.WriteString(group); err != nil {
		gf.Close()
		os.Remove(gf.Name())
		os.Remove(pf.Name())
		return "", "", err
	}
	gf.Close()
	return pf.Name(), gf.Name(), nil
}

func writeProxychainsConfig(socksAddr string) (string, error) {
	host, port, err := net.SplitHostPort(socksAddr)
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp("", "bento-proxychains-*.conf")
	if err != nil {
		return "", err
	}
	defer f.Close()
	fmt.Fprintf(f, `strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
localnet 127.0.0.0/255.0.0.0
[ProxyList]
socks5 %s %s
`, host, port)
	return f.Name(), nil
}

func wrapWithLimits(lim *spec.Limits, bwrapExe string, bwrapArgs []string, cfg *Config) (string, []string) {
	hasManifestLimits := lim != nil && (lim.Memory != "" || lim.CPU != "" || lim.Tasks != 0 || lim.FDs != 0)
	hasTimeoutBackstop := cfg.Timeout > 0
	if !hasManifestLimits && !hasTimeoutBackstop {
		return bwrapExe, bwrapArgs
	}
	if _, err := exec.LookPath("systemd-run"); err != nil {
		if hasManifestLimits {
			cfg.warn("systemd-run not found — resource limits in manifest (memory/cpu/tasks) will NOT be enforced")
		}
		return bwrapExe, bwrapArgs
	}
	wrap := []string{"--user", "--scope", "--quiet", "--collect"}
	if lim != nil {
		if lim.Memory != "" {
			wrap = append(wrap, "-p", "MemoryMax="+lim.Memory, "-p", "MemorySwapMax=0")
		}
		if lim.CPU != "" {
			wrap = append(wrap, "-p", "CPUQuota="+lim.CPU)
		}
		if lim.Tasks > 0 {
			wrap = append(wrap, "-p", fmt.Sprintf("TasksMax=%d", lim.Tasks))
		}
		// LimitNOFILE= not honored by --scope; FD cap is applied launcher-side via setrlimit.
	}
	// RuntimeMaxSec= terminates the scope even if the bento parent crashes.
	if hasTimeoutBackstop {
		wrap = append(wrap, "-p", fmt.Sprintf("RuntimeMaxSec=%d", int64(cfg.Timeout.Seconds())))
	}
	wrap = append(wrap, bwrapExe)
	wrap = append(wrap, bwrapArgs...)
	return "systemd-run", wrap
}
