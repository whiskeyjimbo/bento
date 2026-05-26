//go:build darwin

package runner

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/whiskeyjimbo/bento/internal/grants"
	"github.com/whiskeyjimbo/bento/internal/proxy"
	"github.com/whiskeyjimbo/bento/internal/spec"
)

// runPlatform on macOS: sandbox-exec + SBPL profile.
//
// sandbox-exec is deprecated since 10.15 but still ships and works. App
// Sandbox (the supported replacement) requires entitlements + code
// signing, so it's unsuitable for arbitrary script execution.
//
// Structure mirrors the Linux runPlatform: resolveTools → startAuxiliary
// (cleanup stack) → compile profile → executeCommand. Section helpers
// for the SBPL match the appendXxx pattern in bwrap_linux.go.
func runPlatform(ctx context.Context, m *spec.Manifest, cfg *Config) (int, error) {
	interp, scriptAbs, err := resolveDarwinTools(m)
	if err != nil {
		return -1, err
	}
	if err := validateWritePaths(m.Write); err != nil {
		return -1, err
	}

	aux, err := startDarwinAuxiliary(m, cfg)
	if err != nil {
		return -1, err
	}
	defer aux.close()

	profile := compileSBPL(darwinCompileCtx{
		manifest:          m,
		scriptAbs:         scriptAbs,
		socksAddr:         aux.socksAddr,
		interpreterPrefix: darwinInterpreterPrefix(interp),
	})
	if cfg.Logger != nil {
		cfg.Logger.Printf("[sbpl]\n%s", profile)
	}

	if m.Limits != nil && m.Limits.CPU != "" {
		cfg.warn("Limits.CPU not enforceable on macOS (percentage has no setrlimit equivalent); ignored")
	}

	return executeDarwinCommand(ctx, m, interp, scriptAbs, profile, aux, cfg)
}

// resolveDarwinTools verifies sandbox-exec is installed and resolves the
// manifest's interpreter and script paths. Symlinks on the interpreter
// are followed so the SBPL profile authorizes the real binary, not a
// version-shim.
func resolveDarwinTools(m *spec.Manifest) (interp, scriptAbs string, err error) {
	if _, err = exec.LookPath("sandbox-exec"); err != nil {
		return "", "", fmt.Errorf("sandbox-exec not found")
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
	return interp, scriptAbs, nil
}

// darwinInterpreterPrefix returns the install root to authorize via
// SBPL when the interpreter lives outside system paths. Mirror of the
// Linux interpreterPrefix logic. Empty string means the system
// allowances already cover the interpreter.
func darwinInterpreterPrefix(interp string) string {
	real, err := filepath.EvalSymlinks(interp)
	if err != nil {
		return ""
	}
	for _, sys := range []string{"/usr/", "/bin/", "/sbin/", "/System/"} {
		if strings.HasPrefix(real, sys) {
			return ""
		}
	}
	prefix := filepath.Dir(filepath.Dir(real))
	if prefix == "/" || prefix == "" {
		return ""
	}
	return prefix
}

// darwinAuxiliary mirrors the Linux auxiliary struct: the runtime-only
// resources started for one Run invocation, with a LIFO cleanup stack.
// macOS only needs the SOCKS5 proxy today (Seatbelt does its own
// per-host filtering natively; no HTTP CONNECT or proxychains needed).
type darwinAuxiliary struct {
	socks     *proxy.SOCKS5
	socksAddr string // socks.Addr() captured at start; "" if no network
	cleanups  []func()
}

func (a *darwinAuxiliary) onClose(f func()) {
	a.cleanups = append(a.cleanups, f)
}

func (a *darwinAuxiliary) close() {
	if a == nil {
		return
	}
	for i := len(a.cleanups) - 1; i >= 0; i-- {
		a.cleanups[i]()
	}
}

func startDarwinAuxiliary(m *spec.Manifest, cfg *Config) (*darwinAuxiliary, error) {
	aux := &darwinAuxiliary{}
	if m.Network != nil {
		proxyOpts := []proxy.Option{proxy.WithLogger(cfg.Logger)}
		if cfg.GrantCallback != nil {
			cache := grants.NewCache()
			proxyOpts = append(proxyOpts, proxy.WithGrants(cfg.GrantCallback, cache))
		}
		socks, err := proxy.StartSOCKS5(m.Network, proxyOpts...)
		if err != nil {
			return nil, err
		}
		aux.socks = socks
		aux.socksAddr = socks.Addr()
		aux.onClose(func() { socks.Close() })
	}
	return aux, nil
}

// executeDarwinCommand spawns sandbox-exec with the compiled SBPL +
// interpreter argv. When limits.{memory,tasks,fds} are set, wraps in
// /bin/sh -c 'ulimit ...; exec sandbox-exec ...' so the rlimits apply
// to the child tree. CPU% has no setrlimit equivalent; warned above.
//
// Translates *exec.ExitError to (code, nil); other errors bubble up.
func executeDarwinCommand(ctx context.Context, m *spec.Manifest, interp, scriptAbs, profile string, aux *darwinAuxiliary, cfg *Config) (int, error) {
	sandboxArgs := []string{"-p", profile, interp, scriptAbs}
	sandboxArgs = append(sandboxArgs, m.Args...)

	exe, args := wrapWithUlimits(m.Limits, "/usr/bin/sandbox-exec", sandboxArgs)
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Stdin = cfg.Stdin
	cmd.Stdout = cfg.Stdout
	cmd.Stderr = cfg.Stderr
	cmd.Env = buildDarwinEnv(m, aux, cfg)

	if cfg.Telemetry != nil {
		r, w, err := os.Pipe()
		if err != nil {
			return -1, fmt.Errorf("telemetry pipe: %w", err)
		}
		defer r.Close()
		cmd.ExtraFiles = []*os.File{w}
		done := make(chan struct{})
		go func() {
			defer close(done)
			io.Copy(cfg.Telemetry, r)
		}()
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

// wrapWithUlimits wraps the sandbox-exec invocation in /bin/sh -c
// 'ulimit ...; exec ...' so rlimits apply to the child tree.
// Returns (sandboxExe, sandboxArgs) unchanged when no Limits set.
//
// Mapping:
//
//   - Memory ("128M") → ulimit -v in KiB (virtual memory)
//   - Tasks   (32)    → ulimit -u (max user processes; close cousin of TasksMax)
//   - FDs    (256)    → ulimit -n
//   - CPU             → no setrlimit equivalent for "percent of a core"; ignored
func wrapWithUlimits(lim *spec.Limits, exe string, args []string) (string, []string) {
	if lim == nil {
		return exe, args
	}
	var ulimits []string
	if lim.Memory != "" {
		if n, err := spec.ParseBytes(lim.Memory); err == nil && n > 0 {
			ulimits = append(ulimits, fmt.Sprintf("ulimit -v %d", n/1024))
		}
	}
	if lim.Tasks > 0 {
		ulimits = append(ulimits, fmt.Sprintf("ulimit -u %d", lim.Tasks))
	}
	if lim.FDs > 0 {
		ulimits = append(ulimits, fmt.Sprintf("ulimit -n %d", lim.FDs))
	}
	if len(ulimits) == 0 {
		return exe, args
	}
	// Build: 'ulimit -v N; ulimit -u N; exec sandbox-exec ARG1 "ARG2" ...'
	var quoted []string
	for _, a := range args {
		quoted = append(quoted, shellQuote(a))
	}
	script := strings.Join(ulimits, "; ") + "; exec " + exe + " " + strings.Join(quoted, " ")
	return "/bin/sh", []string{"-c", script}
}

// shellQuote single-quotes s for safe shell embedding. Escapes
// internal single-quotes by closing, escaped-quote, reopening.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// buildDarwinEnv assembles the env slice passed to sandbox-exec.
// Structure mirrors Linux's appendBaseEnv + appendUserEnv +
// appendExtraEnv + appendProxyEnv.
func buildDarwinEnv(m *spec.Manifest, aux *darwinAuxiliary, cfg *Config) []string {
	env := []string{
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		"HOME=" + os.Getenv("HOME"),
		"LANG=C.UTF-8",
	}
	for _, name := range m.Env {
		if v, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+v)
		}
	}
	for k, v := range cfg.ExtraEnv {
		env = append(env, k+"="+v)
	}
	if aux.socksAddr != "" {
		u := "socks5h://" + aux.socksAddr
		const noProxy = "localhost,127.0.0.1,::1,.local"
		env = append(env,
			"HTTP_PROXY="+u, "HTTPS_PROXY="+u, "ALL_PROXY="+u,
			"http_proxy="+u, "https_proxy="+u, "all_proxy="+u,
			"NO_PROXY="+noProxy, "no_proxy="+noProxy,
		)
	}
	return env
}
