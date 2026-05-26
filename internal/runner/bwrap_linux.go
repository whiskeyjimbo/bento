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

// runPlatform on Linux. Orchestrates the sandbox lifecycle:
//
//  1. resolveTools verifies bwrap + interpreter + script exist.
//  2. startAuxiliary brings up proxies, writes proxychains config,
//     extracts the launcher.
//  3. compileBwrapArgs turns the manifest + auxiliary state into the
//     bwrap argv.
//  4. executeCommand runs bwrap (optionally wrapped with systemd-run
//     for resource limits) and translates the exit.
//
// Auxiliary resources are torn down via aux.close() on return.
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

	args := compileBwrapArgs(compileCtx{
		manifest:  m,
		interp:    interp,
		scriptAbs: scriptAbs,
		aux:       aux,
		extraEnv:  cfg.ExtraEnv,
	})
	if cfg.Logger != nil {
		cfg.Logger.Printf("[bwrap] %v", args)
	}
	return executeCommand(ctx, m.Limits, args, cfg)
}

// resolveTools verifies bwrap is installed, resolves the manifest's
// interpreter to a real path (following symlinks), and confirms the
// script file exists.
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

// Sandbox-side proxy ports used in bridge mode. Fixed (not ephemeral)
// so the inline shell wrapper can name them without parameterization.
// These are inside-the-namespace ports; they don't collide with host
// ports because the network namespace is fully isolated.
const (
	sandboxHTTPProxyPort  = 3128
	sandboxSOCKSProxyPort = 1080
)

// auxiliary holds the runtime-only resources started for one Run
// invocation: filter proxies, proxychains config, extracted launcher
// binary, unix socket paths and host-side socat processes (bridge
// mode). Each setup step pushes its cleanup onto the stack; close()
// runs them in reverse order. This makes ordering self-correcting:
// callers can't get LIFO wrong by accident.
type auxiliary struct {
	networkMode  spec.NetworkMode // resolved (never Auto)
	httpProxy    *proxy.HTTPConnect
	socks        *proxy.SOCKS5
	pchainsCfg   string // temp path; "" if no network or libproxychains missing
	launcherPath string // temp path; "" if exec is allowed or extract failed

	// What the SCRIPT sees, post-mode-resolution. In landlock mode
	// these are derived from host proxy addrs; in bridge mode they're
	// the fixed sandbox-side ports.
	httpProxyURL string // for HTTP_PROXY env var; "" if no network
	socksAddr    string // for proxychains config; "" if no network
	allowedPorts string // for BENTO_ALLOW_PORTS env var; "" if no network

	// Bridge-mode-only: host-side unix sockets bind-mounted into the
	// sandbox, plus the socat processes connecting them to host TCP.
	unixHTTPSock  string
	unixSocksSock string

	cleanups []func()
}

// onClose registers a cleanup; close() invokes them in reverse order.
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

	if m.Network != nil {
		proxyOpts := []proxy.Option{proxy.WithLogger(cfg.Logger)}
		if cfg.GrantCallback != nil {
			// Shared cache so HTTP CONNECT + SOCKS5 don't both prompt
			// for the same host:port within a Run.
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

	// Exec block via launcher (seccomp + Landlock). When extraction
	// fails we degrade — log it and proceed without the launcher.
	// When PreExtractedLauncher is set (Sandbox warm-pool), reuse
	// the existing binary and skip cleanup (the Sandbox owns it).
	if len(m.Exec) == 0 {
		if cfg.PreExtractedLauncher != "" {
			aux.launcherPath = cfg.PreExtractedLauncher
			// no cleanup — Sandbox.Close() handles removal
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

// executeCommand runs bwrap (optionally wrapped in systemd-run for
// resource limits) with the given argv. When cfg.Telemetry is set, a
// pipe is established so the child sees fd 3 (writable) and the parent
// reads from the other end into cfg.Telemetry concurrently. Translates
// *exec.ExitError to (exitCode, nil); other errors bubble up.
func executeCommand(ctx context.Context, lim *spec.Limits, bwrapArgs []string, cfg *Config) (int, error) {
	exe, fullArgs := wrapWithLimits(lim, "bwrap", bwrapArgs, cfg)
	cmd := exec.CommandContext(ctx, exe, fullArgs...)
	cmd.Stdin = cfg.Stdin
	cmd.Stdout = cfg.Stdout
	cmd.Stderr = cfg.Stderr

	if cfg.Telemetry != nil {
		r, w, err := os.Pipe()
		if err != nil {
			return -1, fmt.Errorf("telemetry pipe: %w", err)
		}
		defer r.Close()
		// ExtraFiles[0] becomes fd 3 in the child.
		cmd.ExtraFiles = []*os.File{w}
		// Parent writes the read end into cfg.Telemetry until EOF.
		done := make(chan struct{})
		go func() {
			defer close(done)
			io.Copy(cfg.Telemetry, r)
		}()
		// Close the write end in the parent so io.Copy sees EOF when
		// the child closes its fd 3 (i.e. when the child exits).
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

// resolveNetworkMode picks the effective mode when the user asks for
// Auto: Landlock if the kernel supports it (ABI ≥ 4), otherwise Bridge.
// Explicit modes pass through unchanged.
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

// setupNetworkBridges configures the script-visible network endpoints
// based on aux.networkMode. After this call:
//
//   - aux.httpProxyURL is set to the URL the script's HTTP_PROXY should
//     point to.
//   - aux.socksAddr is set to the target for the proxychains config.
//   - aux.allowedPorts is set for BENTO_ALLOW_PORTS (Landlock allowlist).
//   - In bridge mode, aux.unixHTTPSock + aux.unixSocksSock are
//     populated and host-side socats are spawned + registered for
//     cleanup.
//   - In all modes, the proxychains config is written if libproxychains
//     is available, and registered for cleanup.
func setupNetworkBridges(aux *auxiliary, cfg *Config) error {
	switch aux.networkMode {
	case spec.NetworkModeLandlock:
		return setupLandlockBridge(aux, cfg)
	case spec.NetworkModeBridge:
		return setupSocketBridge(aux, cfg)
	}
	return fmt.Errorf("unresolved network mode %v", aux.networkMode)
}

// setupLandlockBridge: script reaches host proxies directly on
// loopback. Both IPv4 and IPv6 ephemeral ports are included in the
// Landlock allowlist so dual-stack scripts work without fallback delay.
func setupLandlockBridge(aux *auxiliary, cfg *Config) error {
	aux.socksAddr = aux.socks.Addr()
	aux.httpProxyURL = "http://" + aux.httpProxy.Addr()
	aux.allowedPorts = collectPorts(aux.httpProxy.Addrs(), aux.socks.Addrs())
	return setupProxychainsIfAvailable(aux, cfg, aux.socksAddr)
}

// collectPorts extracts the port from each addr and returns them as
// a comma-separated string suitable for BENTO_ALLOW_PORTS.
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

// setupSocketBridge: --unshare-net plus unix-socket bridges. Script
// sees fixed inner ports (3128/1080) on loopback; bridges relay to
// host proxy TCP ports via /tmp unix sockets.
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

// allocUnixSocket reserves a /tmp path for a unix socket. The socat
// process binds and lives until killed. We just hold the path; socat
// creates the actual socket on bind.
func allocUnixSocket(prefix string) (string, error) {
	f, err := os.CreateTemp("", prefix+"-*.sock")
	if err != nil {
		return "", err
	}
	path := f.Name()
	f.Close()
	// Remove the temp file so socat can bind a fresh socket at the path.
	os.Remove(path)
	return path, nil
}

// spawnHostSocat runs a UNIX-LISTEN ↔ TCP socat on the host side and
// registers cleanup. The socat exits when killed; its stdout/stderr
// go to the logger if one is set.
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
		// LimitNOFILE= not honored by systemd --scope (services only).
		// FD cap is applied launcher-side via setrlimit; see
		// appendFDLimitEnv.
	}
	// RuntimeMaxSec= belt-and-suspenders: even if the bento parent
	// crashes before context.WithTimeout fires SIGKILL, systemd
	// terminates the scope when this expires.
	if hasTimeoutBackstop {
		wrap = append(wrap, "-p", fmt.Sprintf("RuntimeMaxSec=%d", int64(cfg.Timeout.Seconds())))
	}
	wrap = append(wrap, bwrapExe)
	wrap = append(wrap, bwrapArgs...)
	return "systemd-run", wrap
}
