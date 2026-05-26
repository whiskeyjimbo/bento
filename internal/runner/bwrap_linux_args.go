//go:build linux

package runner

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/whiskeyjimbo/bento/internal/spec"
	"github.com/whiskeyjimbo/bento/internal/sysprobe"
)

// compileCtx bundles everything compileBwrapArgs needs. Passed as a
// single value so the public signature doesn't grow as new inputs
// (timeouts, extra mounts, etc.) are added.
type compileCtx struct {
	manifest  *spec.Manifest
	interp    string
	scriptAbs string
	aux       *auxiliary
	extraEnv  map[string]string
}

// compileBwrapArgs assembles the bwrap argv by composing small section
// helpers. Each helper is purely additive (append-only) and named for
// its responsibility, so the order of sandbox layering is readable
// top-down.
func compileBwrapArgs(c compileCtx) []string {
	args := appendBaseFlags(nil, c.manifest.Limits)
	args = appendSystemMounts(args)
	args = appendInterpreterPrefix(args, c.interp)
	args = appendNetworkNamespace(args, c.manifest, c.aux)
	args = appendUnixSocketBinds(args, c.aux)
	args = appendUserReadPaths(args, c.manifest.Read)
	args = appendUserWritePaths(args, c.manifest.Write)
	args = appendMandatoryDeny(args)
	args = appendMandatoryDenyWrite(args)
	args = appendWorkspaceWriteProtection(args, c.manifest.Write)
	args = appendScriptBinding(args, c.scriptAbs)
	args = appendBaseEnv(args)
	args = appendUserEnv(args, c.manifest.Env)
	args = appendExtraEnv(args, c.extraEnv)
	args = appendFDLimitEnv(args, c.manifest.Limits)
	args = appendProxyEnv(args, c.aux)
	args = appendAllowedPortsEnv(args, c.aux)
	args = appendProxychains(args, c.aux)
	return appendEntrypoint(args, c.interp, c.aux, c.manifest.Args)
}

func appendBaseFlags(args []string, lim *spec.Limits) []string {
	args = append(args,
		"--die-with-parent",
		"--new-session",
		"--unshare-user",
		"--unshare-ipc",
		"--unshare-pid",
		"--unshare-uts",
		"--unshare-cgroup",
		"--proc", "/proc",
		"--dev", "/dev",
	)
	args = appendSizedTmpfs(args, lim, "/tmp")
	args = appendSizedTmpfs(args, lim, spec.SandboxRoot)
	return append(args,
		"--clearenv",
		"--chdir", spec.SandboxRoot,
	)
}

// appendSizedTmpfs emits "--tmpfs PATH" with an optional "--size N"
// prefix when limits.tmpfs is set. Without the cap, an in-sandbox
// script can write to /tmp until it exhausts host memory.
func appendSizedTmpfs(args []string, lim *spec.Limits, path string) []string {
	if lim != nil && lim.Tmpfs != "" {
		if n, err := spec.ParseBytes(lim.Tmpfs); err == nil && n > 0 {
			args = append(args, "--size", fmt.Sprintf("%d", n))
		}
	}
	return append(args, "--tmpfs", path)
}

// systemReadPaths are bind-mounted read-only into every sandbox so the
// interpreter can resolve libraries and find CA bundles.
var systemReadPaths = []string{
	"/usr", "/bin", "/sbin", "/lib", "/lib64",
	"/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d",
	"/etc/resolv.conf",
	"/etc/ssl", "/etc/ca-certificates", "/etc/pki",
}

func appendSystemMounts(args []string) []string {
	for _, p := range systemReadPaths {
		if _, err := os.Stat(p); err == nil {
			args = append(args, "--ro-bind", p, p)
		}
	}
	return args
}

func appendInterpreterPrefix(args []string, interp string) []string {
	if prefix := interpreterPrefix(interp); prefix != "" {
		args = append(args, "--ro-bind", prefix, prefix)
	}
	return args
}

// appendNetworkNamespace decides whether to isolate the network
// namespace. Three cases:
//
//   - No network rules in manifest → --unshare-net (no network at all).
//   - Bridge mode → --unshare-net (host net hidden; only loopback +
//     bridge sockets reach out).
//   - Landlock mode → keep host network (Landlock TCP restricts which
//     ports the script can connect to).
func appendNetworkNamespace(args []string, m *spec.Manifest, aux *auxiliary) []string {
	if m.Network == nil || aux.networkMode == spec.NetworkModeBridge {
		args = append(args, "--unshare-net")
	}
	return args
}

// appendUnixSocketBinds bind-mounts the host-side unix sockets into
// the sandbox (bridge mode only). The sockets carry HTTP CONNECT and
// SOCKS5 traffic between sandbox-side socat listeners and the host
// proxy servers.
func appendUnixSocketBinds(args []string, aux *auxiliary) []string {
	if aux.networkMode != spec.NetworkModeBridge {
		return args
	}
	if aux.unixHTTPSock != "" {
		args = append(args, "--bind", aux.unixHTTPSock, aux.unixHTTPSock)
	}
	if aux.unixSocksSock != "" {
		args = append(args, "--bind", aux.unixSocksSock, aux.unixSocksSock)
	}
	return args
}

func appendUserReadPaths(args []string, read []string) []string {
	for _, r := range read {
		if abs, err := filepath.Abs(r); err == nil {
			args = append(args, "--ro-bind-try", abs, abs)
		}
	}
	return args
}

func appendUserWritePaths(args []string, write []string) []string {
	for _, w := range write {
		if abs, err := filepath.Abs(w); err == nil {
			args = append(args, "--bind-try", abs, abs)
		}
	}
	return args
}

func appendScriptBinding(args []string, scriptAbs string) []string {
	return append(args, "--ro-bind", scriptAbs, spec.SandboxScriptPath)
}

// appendMandatoryDeny shadows the always-block list with /dev/null bind
// mounts. Even if the user's read: list grants access (e.g. read: ["/"]),
// the dangerous files appear empty inside the sandbox.
//
// Skips paths that don't exist on the host. The "block creation of
// non-existent dangerous paths" case (a script writing ~/.ssh/id_rsa
// for the first time) needs a different mechanism — bwrap can't create
// a mount point inside a read-only parent — and is deferred to a
// follow-up bead.
//
// Runs AFTER appendUserReadPaths so the bind takes precedence; bwrap
// applies binds in order and the last one wins for a given destination.
func appendMandatoryDeny(args []string) []string {
	home, _ := os.UserHomeDir()
	if home == "" {
		return args
	}
	return appendShadowedPaths(args, spec.ExpandDangerousPaths(home))
}

// appendMandatoryDenyWrite shadows persistence/RCE targets (shell rc
// files, user git config, etc.). Same mechanism as appendMandatoryDeny
// — bind /dev/null over the path — but sourced from
// DangerousWriteFiles, which is curated for the persistence threat
// model rather than credential exfil.
func appendMandatoryDenyWrite(args []string) []string {
	home, _ := os.UserHomeDir()
	if home == "" {
		return args
	}
	return appendShadowedPaths(args, spec.ExpandDangerousWritePaths(home))
}

// appendWorkspaceWriteProtection shadows the dangerous subpaths inside
// each user-declared write path. Two mechanisms:
//
//   - Directories like .git/hooks are re-bound read-only (--ro-bind
//     PATH PATH) which shields BOTH existing entries (rendered
//     unwriteable) AND unborn files (mkdir/touch attempts hit EROFS).
//     This is what blocks "cp evil .git/hooks/post-checkout".
//   - Individual files like .git/config and .vscode/tasks.json are
//     /dev/null-shadowed if they exist (writes discarded, reads empty).
func appendWorkspaceWriteProtection(args []string, writes []string) []string {
	for _, w := range writes {
		abs, err := filepath.Abs(w)
		if err != nil {
			continue
		}
		protection := spec.WorkspaceWriteProtectionFor(abs)
		for _, dir := range protection.ReadOnlyDirs {
			if info, err := os.Stat(dir); err == nil && info.IsDir() {
				args = append(args, "--ro-bind", dir, dir)
			}
		}
		args = appendShadowedPaths(args, protection.ShadowFiles)
	}
	return args
}

// appendShadowedPaths emits --ro-bind /dev/null PATH for each path
// that exists on the host. Shared between read- and write-protection
// helpers. Skip-on-missing matches the read-protect rationale: bwrap
// can't create a mount point under a read-only bind, and shielding
// "what doesn't exist yet" needs separate /dev/null-on-first-missing
// machinery (out of scope here).
func appendShadowedPaths(args []string, paths []string) []string {
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		args = append(args, "--ro-bind", "/dev/null", p)
	}
	return args
}

func appendBaseEnv(args []string) []string {
	return append(args,
		"--setenv", "PATH", "/usr/bin:/bin:/usr/sbin:/sbin",
		"--setenv", "HOME", spec.SandboxRoot,
		"--setenv", "LANG", "C.UTF-8",
	)
}

func appendUserEnv(args []string, allowlist []string) []string {
	for _, name := range allowlist {
		if v, ok := os.LookupEnv(name); ok {
			args = append(args, "--setenv", name, v)
		}
	}
	return args
}

// appendExtraEnv emits caller-supplied env values (via WithExtraEnv).
// These are sandboxed-script values, separate from the manifest's host
// passthrough list.
func appendExtraEnv(args []string, env map[string]string) []string {
	for k, v := range env {
		args = append(args, "--setenv", k, v)
	}
	return args
}

// appendFDLimitEnv passes limits.fds to the launcher via env. The
// launcher applies it via setrlimit(RLIMIT_NOFILE) before exec'ing
// the interpreter.
func appendFDLimitEnv(args []string, lim *spec.Limits) []string {
	if lim == nil || lim.FDs <= 0 {
		return args
	}
	return append(args, "--setenv", spec.EnvFDLimit, fmt.Sprintf("%d", lim.FDs))
}

// appendProxyEnv emits HTTP_PROXY/HTTPS_PROXY so HTTP-aware tools
// (curl, requests, net/http, …) route through the host-allowlist proxy.
// noProxyHosts excludes loopback addresses from the script's HTTP
// proxy routing. Without this, requests.get("http://localhost:8080")
// from inside the sandbox would round-trip through our proxy before
// failing (no listener exists at that loopback address inside the
// namespace). NO_PROXY syntax varies by client but the values below
// are honored by curl, requests, urllib, and go net/http.
const noProxyHosts = "localhost,127.0.0.1,::1,.local"

func appendProxyEnv(args []string, aux *auxiliary) []string {
	if aux.httpProxyURL == "" {
		return args
	}
	return append(args,
		"--setenv", "HTTP_PROXY", aux.httpProxyURL,
		"--setenv", "HTTPS_PROXY", aux.httpProxyURL,
		"--setenv", "http_proxy", aux.httpProxyURL,
		"--setenv", "https_proxy", aux.httpProxyURL,
		"--setenv", "NO_PROXY", noProxyHosts,
		"--setenv", "no_proxy", noProxyHosts,
	)
}

// appendAllowedPortsEnv emits BENTO_ALLOW_PORTS, which the launcher
// reads to install a Landlock TCP-port allowlist. In bridge mode this
// is redundant with the network namespace (no route to non-bridge
// destinations exists) but kept as defense in depth.
func appendAllowedPortsEnv(args []string, aux *auxiliary) []string {
	if aux.allowedPorts == "" {
		return args
	}
	return append(args, "--setenv", spec.EnvAllowedPorts, aux.allowedPorts)
}

func appendProxychains(args []string, aux *auxiliary) []string {
	if aux.pchainsCfg == "" {
		return args // either no network or libproxychains missing — see startAuxiliary
	}
	lib := sysprobe.FindProxychainsLib() // guaranteed non-empty: startAuxiliary checked
	return append(args,
		"--ro-bind", lib, lib,
		"--ro-bind", aux.pchainsCfg, spec.SandboxProxychainsConfPath,
		"--setenv", "LD_PRELOAD", lib,
		"--setenv", "PROXYCHAINS_CONF_FILE", spec.SandboxProxychainsConfPath,
		"--setenv", "PROXYCHAINS_QUIET_MODE", "1",
	)
}

// appendEntrypoint emits the bwrap "--" separator plus the final argv.
//
// Landlock mode (or no network): bwrap exec's the launcher (or
// interpreter directly), which exec's the script.
//
// Bridge mode: bwrap exec's bash with an inline script that:
//
//  1. Starts inner socat listeners (sandbox-side bridges) in background.
//  2. Installs a trap so the socats die when the script ends.
//  3. exec's the launcher (or interpreter) into the foreground.
//
// User-supplied script args are passed via $@ rather than embedded in
// the inline string, so no shell-quoting of user input is needed.
func appendEntrypoint(args []string, interp string, aux *auxiliary, userArgs []string) []string {
	if aux.networkMode == spec.NetworkModeBridge && (aux.unixHTTPSock != "" || aux.unixSocksSock != "") {
		return appendBridgeEntrypoint(args, interp, aux, userArgs)
	}
	return appendDirectEntrypoint(args, interp, aux, userArgs)
}

func appendDirectEntrypoint(args []string, interp string, aux *auxiliary, userArgs []string) []string {
	if aux.launcherPath != "" {
		args = append(args,
			"--ro-bind", aux.launcherPath, spec.SandboxLauncherPath,
			"--", spec.SandboxLauncherPath, interp, spec.SandboxScriptPath,
		)
	} else {
		args = append(args, "--", interp, spec.SandboxScriptPath)
	}
	return append(args, userArgs...)
}

func appendBridgeEntrypoint(args []string, interp string, aux *auxiliary, userArgs []string) []string {
	// Inner socats: TCP-LISTEN on fixed sandbox ports, UNIX-CONNECT to
	// the bind-mounted host sockets. Start in background, trap on exit
	// so they die with the script.
	innerHTTP := fmt.Sprintf("socat TCP-LISTEN:%d,fork,reuseaddr UNIX-CONNECT:%s >/dev/null 2>&1 &",
		sandboxHTTPProxyPort, aux.unixHTTPSock)
	innerSOCKS := fmt.Sprintf("socat TCP-LISTEN:%d,fork,reuseaddr UNIX-CONNECT:%s >/dev/null 2>&1 &",
		sandboxSOCKSProxyPort, aux.unixSocksSock)

	var execLine string
	if aux.launcherPath != "" {
		execLine = fmt.Sprintf(`exec %s %s %s "$@"`, spec.SandboxLauncherPath, interp, spec.SandboxScriptPath)
	} else {
		execLine = fmt.Sprintf(`exec %s %s "$@"`, interp, spec.SandboxScriptPath)
	}

	script := innerHTTP + "\n" + innerSOCKS + "\n" +
		`trap 'kill %1 %2 2>/dev/null' EXIT` + "\n" +
		`# Brief wait for socats to bind their TCP listeners.` + "\n" +
		`sleep 0.05` + "\n" +
		execLine

	if aux.launcherPath != "" {
		args = append(args, "--ro-bind", aux.launcherPath, spec.SandboxLauncherPath)
	}
	args = append(args, "--", "/bin/bash", "-c", script, "--")
	return append(args, userArgs...)
}

func interpreterPrefix(interp string) string {
	real, err := filepath.EvalSymlinks(interp)
	if err != nil {
		return ""
	}
	for _, sys := range []string{"/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/"} {
		if len(real) >= len(sys) && real[:len(sys)] == sys {
			return ""
		}
	}
	prefix := filepath.Dir(filepath.Dir(real))
	if prefix == "/" || prefix == "" {
		return ""
	}
	return prefix
}
