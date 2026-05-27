//go:build linux

package runner

import (
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/whiskeyjimbo/bento/internal/spec"
	"github.com/whiskeyjimbo/bento/internal/sysprobe"
)

// compileCtx bundles inputs for compileBwrapArgs.
type compileCtx struct {
	manifest  *spec.Manifest
	interp    string
	scriptAbs string
	aux       *auxiliary
	extraEnv  map[string]string
}

// bwrapSection labels a contiguous run of bwrap args for diagnostic display.
type bwrapSection struct {
	label string
	start int // index into the argv where this section begins
}

// compileBwrapArgs assembles the bwrap argv from small append-only helpers,
// ordered to make sandbox layering readable top-down. The second return value
// is a list of section markers used only by formatBwrapArgs for verbose logging.
func compileBwrapArgs(c compileCtx) ([]string, []bwrapSection) {
	var args []string
	var sections []bwrapSection
	mark := func(label string) {
		sections = append(sections, bwrapSection{label, len(args)})
	}

	mark("isolation")
	args = appendBaseFlags(args, c.manifest.Limits)
	mark("system mounts")
	args = appendSystemMounts(args)
	args = appendUserDB(args, c.aux)
	args = appendInterpreterPrefix(args, c.interp)
	mark("network")
	args = appendNetworkNamespace(args, c.manifest, c.aux)
	args = appendUnixSocketBinds(args, c.aux)
	mark("manifest reads")
	args = appendUserReadPaths(args, c.manifest.Read)
	mark("manifest writes")
	args = appendUserWritePaths(args, c.manifest.Write)
	mark("mandatory deny (read)")
	args = appendMandatoryDeny(args)
	mark("mandatory deny (write)")
	args = appendMandatoryDenyWrite(args)
	mark("workspace write protection")
	args = appendWorkspaceWriteProtection(args, c.manifest.Write)
	mark("script binding")
	args = appendScriptBinding(args, c.scriptAbs)
	mark("env")
	args = appendBaseEnv(args)
	args = appendInterpreterSearchEnv(args, c.interp, c.scriptAbs)
	args = appendUserEnv(args, c.manifest.Env)
	args = appendExtraEnv(args, c.extraEnv)
	args = appendFDLimitEnv(args, c.manifest.Limits)
	args = appendProxyEnv(args, c.aux)
	args = appendAllowedPortsEnv(args, c.aux)
	mark("proxychains")
	args = appendProxychains(args, c.aux)
	mark("entrypoint")
	args = appendEntrypoint(args, c.interp, c.scriptAbs, c.aux, c.manifest.Args)
	return args, sections
}

// isELFEntrypoint reports whether this run is an ELF binary executing itself
// (i.e. there is no separate interpreter and script — they are the same file).
// In that mode we pass only the sandbox script path to the launcher so the
// binary sees argv[0]=/sandbox/script with no spurious argv[1] script-path.
func isELFEntrypoint(interp, scriptAbs string) bool {
	if interp == "" || scriptAbs == "" {
		return false
	}
	if interp == scriptAbs {
		return true
	}
	ri, err := filepath.EvalSymlinks(interp)
	if err != nil {
		return false
	}
	rs, err := filepath.EvalSymlinks(scriptAbs)
	if err != nil {
		return false
	}
	return ri == rs
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

// appendSizedTmpfs emits --tmpfs PATH with --size when limits.tmpfs is set,
// to prevent a script from filling host memory via /tmp.
func appendSizedTmpfs(args []string, lim *spec.Limits, path string) []string {
	if lim != nil && lim.Tmpfs != "" {
		if n, err := spec.ParseBytes(lim.Tmpfs); err == nil && n > 0 {
			args = append(args, "--size", fmt.Sprintf("%d", n))
		}
	}
	return append(args, "--tmpfs", path)
}

// systemReadPaths are bind-mounted read-only so the interpreter resolves libs and CA bundles.
// /etc/alternatives is bound so Debian/Ubuntu's "alternatives" symlink chain
// (`/usr/bin/awk -> /etc/alternatives/awk -> /usr/bin/gawk`) resolves inside
// the sandbox. Without it, awk/editor/pager/java and many other common tools
// fail with a generic "command not found" that gives no clue why.
var systemReadPaths = []string{
	"/usr", "/bin", "/sbin", "/lib", "/lib64",
	"/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d",
	"/etc/resolv.conf",
	"/etc/ssl", "/etc/ca-certificates", "/etc/pki",
	"/etc/alternatives",
}

// appendUserDB binds synthetic /etc/passwd and /etc/group from temp files
// startAuxiliary prepared. Without these, `whoami` and similar pwd lookups
// report "cannot find name for user ID" inside the sandbox.
func appendUserDB(args []string, aux *auxiliary) []string {
	if aux == nil {
		return args
	}
	if aux.passwdPath != "" {
		args = append(args, "--ro-bind", aux.passwdPath, "/etc/passwd")
	}
	if aux.groupPath != "" {
		args = append(args, "--ro-bind", aux.groupPath, "/etc/group")
	}
	return args
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
	for _, p := range interpreterPrefixes(interp) {
		args = append(args, "--ro-bind", p, p)
	}
	return args
}

// appendNetworkNamespace adds --unshare-net for no-network and bridge modes;
// Landlock mode keeps host net (Landlock TCP restricts ports instead).
func appendNetworkNamespace(args []string, m *spec.Manifest, aux *auxiliary) []string {
	if m.Network == nil || aux.networkMode == spec.NetworkModeBridge {
		args = append(args, "--unshare-net")
	}
	return args
}

// appendUnixSocketBinds bind-mounts host-side unix sockets into the sandbox (bridge mode only).
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

// appendMandatoryDeny shadows always-block paths with /dev/null binds.
// Must run AFTER appendUserReadPaths so the bind takes precedence (last bind wins).
// Skips non-existent paths (bwrap can't create mount points under a ro parent).
func appendMandatoryDeny(args []string) []string {
	home, _ := os.UserHomeDir()
	if home == "" {
		return args
	}
	return appendShadowedPaths(args, spec.ExpandDangerousPaths(home))
}

// appendMandatoryDenyWrite shadows persistence/RCE targets (shell rc files, etc.)
// from the DangerousWriteFiles list.
func appendMandatoryDenyWrite(args []string) []string {
	home, _ := os.UserHomeDir()
	if home == "" {
		return args
	}
	return appendShadowedPaths(args, spec.ExpandDangerousWritePaths(home))
}

// appendWorkspaceWriteProtection shadows dangerous subpaths inside each declared
// write path: directories re-bound ro (EROFS on writes), files /dev/null-shadowed.
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

// appendShadowedPaths emits --ro-bind /dev/null PATH for each existing path.
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
	args = append(args,
		"--setenv", "PATH", "/usr/bin:/bin:/usr/sbin:/sbin",
		"--setenv", "HOME", spec.SandboxRoot,
		"--setenv", "LANG", "C.UTF-8",
	)
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		args = append(args, "--setenv", "BENTO_HOST_HOME", home)
	}
	return args
}

// appendInterpreterSearchEnv sets language-specific module search paths so that
// `from utils import x` (Python) and `require('./utils')` (Node) can find sibling
// files next to the script. The script is bind-mounted at /sandbox/script — a
// single file — so the interpreter's default "look beside the script" search
// finds only itself. We point the interpreter at the script's host directory
// instead; that directory is bind-mounted at its host path whenever it appears
// in the manifest's read list (zero-config always includes it).
//
// BENTO_SCRIPT_DIR is also set unconditionally to the script's host directory.
// Shell scripts have no PYTHONPATH/NODE_PATH analogue, and inside the sandbox
// `$0` resolves to /sandbox/script — so `source "$(dirname "$0")/lib.sh"`
// (idiomatic bash) silently fails. BENTO_SCRIPT_DIR gives shell scripts a
// reliable way to reference siblings: `source "$BENTO_SCRIPT_DIR/lib.sh"`.
func appendInterpreterSearchEnv(args []string, interp, scriptAbs string) []string {
	if scriptAbs == "" {
		return args
	}
	dir := filepath.Dir(scriptAbs)
	if dir == "" || dir == "/" {
		return args
	}
	args = append(args, "--setenv", "BENTO_SCRIPT_DIR", dir)
	base := filepath.Base(interp)
	switch {
	case strings.HasPrefix(base, "python"):
		args = append(args, "--setenv", "PYTHONPATH", dir)
	case base == "node":
		args = append(args, "--setenv", "NODE_PATH", dir)
	}
	return args
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
func appendExtraEnv(args []string, env map[string]string) []string {
	for k, v := range env {
		args = append(args, "--setenv", k, v)
	}
	return args
}

// appendFDLimitEnv passes limits.fds via env; launcher applies setrlimit before exec.
func appendFDLimitEnv(args []string, lim *spec.Limits) []string {
	if lim == nil || lim.FDs <= 0 {
		return args
	}
	return append(args, "--setenv", spec.EnvFDLimit, fmt.Sprintf("%d", lim.FDs))
}

// noProxyHosts excludes loopback from proxy routing so in-sandbox localhost
// requests don't pointlessly round-trip through the host proxy.
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

// appendAllowedPortsEnv emits BENTO_ALLOW_PORTS for the launcher's Landlock
// TCP allowlist. Redundant in bridge mode but kept as defense in depth.
func appendAllowedPortsEnv(args []string, aux *auxiliary) []string {
	if aux.allowedPorts == "" {
		return args
	}
	return append(args, "--setenv", spec.EnvAllowedPorts, aux.allowedPorts)
}

func appendProxychains(args []string, aux *auxiliary) []string {
	if aux.pchainsCfg == "" {
		return args
	}
	lib := sysprobe.FindProxychainsLib()
	return append(args,
		"--ro-bind", lib, lib,
		"--ro-bind", aux.pchainsCfg, spec.SandboxProxychainsConfPath,
		"--setenv", "LD_PRELOAD", lib,
		"--setenv", "PROXYCHAINS_CONF_FILE", spec.SandboxProxychainsConfPath,
		"--setenv", "PROXYCHAINS_QUIET_MODE", "1",
	)
}

// appendEntrypoint emits the bwrap "--" separator plus the final argv.
// Bridge mode wraps in bash to start sandbox-side socats before exec'ing the
// launcher; user args go via $@ to avoid shell-quoting.
func appendEntrypoint(args []string, interp, scriptAbs string, aux *auxiliary, userArgs []string) []string {
	if aux.networkMode == spec.NetworkModeBridge && (aux.unixHTTPSock != "" || aux.unixSocksSock != "") {
		return appendBridgeEntrypoint(args, interp, scriptAbs, aux, userArgs)
	}
	return appendDirectEntrypoint(args, interp, scriptAbs, aux, userArgs)
}

func appendDirectEntrypoint(args []string, interp, scriptAbs string, aux *auxiliary, userArgs []string) []string {
	elf := isELFEntrypoint(interp, scriptAbs)
	if aux.launcherPath != "" {
		args = append(args, "--ro-bind", aux.launcherPath, spec.SandboxLauncherPath, "--")
		if elf {
			args = append(args, spec.SandboxLauncherPath, spec.SandboxScriptPath)
		} else {
			args = append(args, spec.SandboxLauncherPath, interp, spec.SandboxScriptPath)
		}
	} else {
		args = append(args, "--")
		if elf {
			args = append(args, spec.SandboxScriptPath)
		} else {
			args = append(args, interp, spec.SandboxScriptPath)
		}
	}
	return append(args, userArgs...)
}

func appendBridgeEntrypoint(args []string, interp, scriptAbs string, aux *auxiliary, userArgs []string) []string {
	// Inner socats bridge fixed sandbox TCP ports → bind-mounted host unix sockets.
	innerHTTP := fmt.Sprintf("socat TCP-LISTEN:%d,fork,reuseaddr UNIX-CONNECT:%s >/dev/null 2>&1 &",
		sandboxHTTPProxyPort, aux.unixHTTPSock)
	innerSOCKS := fmt.Sprintf("socat TCP-LISTEN:%d,fork,reuseaddr UNIX-CONNECT:%s >/dev/null 2>&1 &",
		sandboxSOCKSProxyPort, aux.unixSocksSock)

	elf := isELFEntrypoint(interp, scriptAbs)
	var execLine string
	switch {
	case aux.launcherPath != "" && elf:
		execLine = fmt.Sprintf(`exec %s %s "$@"`, spec.SandboxLauncherPath, spec.SandboxScriptPath)
	case aux.launcherPath != "":
		execLine = fmt.Sprintf(`exec %s %s %s "$@"`, spec.SandboxLauncherPath, interp, spec.SandboxScriptPath)
	case elf:
		execLine = fmt.Sprintf(`exec %s "$@"`, spec.SandboxScriptPath)
	default:
		execLine = fmt.Sprintf(`exec %s %s "$@"`, interp, spec.SandboxScriptPath)
	}

	script := innerHTTP + "\n" + innerSOCKS + "\n" +
		`trap 'kill %1 %2 2>/dev/null' EXIT` + "\n" +
		`sleep 0.05` + "\n" + // brief wait for socats to bind
		execLine

	if aux.launcherPath != "" {
		args = append(args, "--ro-bind", aux.launcherPath, spec.SandboxLauncherPath)
	}
	args = append(args, "--", "/bin/bash", "-c", script, "--")
	return append(args, userArgs...)
}

// interpreterPrefix returns the primary install-root prefix for an interpreter
// outside of system paths (mise/asdf/pyenv/homebrew). Empty for system paths.
// For Nix-store interpreters use interpreterPrefixes instead — Nix binaries
// reference other store paths via RPATH, and binding only the binary's own
// store path leaves the dynamic linker unable to resolve its dependencies.
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

// interpreterPrefixes returns every host path that should be bind-mounted
// so the interpreter and its dynamic-link dependencies resolve inside the
// sandbox. For Nix-managed interpreters this is the full store closure;
// for mise/asdf/pyenv/homebrew it's the install root. System paths return
// nil (covered by systemReadPaths).
func interpreterPrefixes(interp string) []string {
	real, err := filepath.EvalSymlinks(interp)
	if err != nil {
		return nil
	}
	if strings.HasPrefix(real, "/nix/store/") {
		return nixStoreClosure(real)
	}
	if p := interpreterPrefix(interp); p != "" {
		return []string{p}
	}
	return nil
}

// nixStoreClosure returns every /nix/store path the binary transitively
// depends on, including itself. Uses `nix-store --query --requisites` when
// available; falls back to recursively reading the binary's PT_INTERP and
// RPATH/RUNPATH/DT_NEEDED entries.
func nixStoreClosure(path string) []string {
	if out, err := exec.Command("nix-store", "--query", "--requisites", path).Output(); err == nil {
		seen := map[string]bool{}
		var roots []string
		for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || seen[line] {
				continue
			}
			seen[line] = true
			roots = append(roots, line)
		}
		if len(roots) > 0 {
			return roots
		}
	}
	return nixClosureFromElf(path)
}

// nixClosureFromElf walks PT_INTERP / DT_NEEDED / DT_RPATH / DT_RUNPATH
// transitively and collects every /nix/store/<hash>-<name> root referenced.
func nixClosureFromElf(start string) []string {
	seen := map[string]bool{}
	var queue []string
	var roots []string
	addRoot := func(p string) {
		if !strings.HasPrefix(p, "/nix/store/") {
			return
		}
		rest := strings.TrimPrefix(p, "/nix/store/")
		idx := strings.IndexByte(rest, '/')
		if idx >= 0 {
			rest = rest[:idx]
		}
		root := "/nix/store/" + rest
		if !seen[root] {
			seen[root] = true
			roots = append(roots, root)
		}
	}
	queue = append(queue, start)
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		addRoot(cur)
		interp, needed, rpaths := readElfDeps(cur)
		if interp != "" {
			addRoot(interp)
			queue = append(queue, interp)
		}
		for _, n := range needed {
			for _, rp := range rpaths {
				cand := filepath.Join(rp, n)
				if _, err := os.Stat(cand); err == nil {
					addRoot(cand)
					queue = append(queue, cand)
					break
				}
			}
		}
	}
	return roots
}

// readElfDeps extracts PT_INTERP, DT_NEEDED names, and DT_RPATH/RUNPATH
// search dirs from an ELF file. Best-effort: returns zero values on any
// parse error.
func readElfDeps(path string) (interp string, needed []string, rpaths []string) {
	f, err := elf.Open(path)
	if err != nil {
		return "", nil, nil
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			buf := make([]byte, p.Filesz)
			if _, err := p.ReadAt(buf, 0); err == nil {
				interp = strings.TrimRight(string(buf), "\x00")
			}
			break
		}
	}
	if libs, err := f.ImportedLibraries(); err == nil {
		needed = libs
	}
	if rps, err := f.DynString(elf.DT_RUNPATH); err == nil && len(rps) > 0 {
		for _, rp := range rps {
			rpaths = append(rpaths, strings.Split(rp, ":")...)
		}
	}
	if rps, err := f.DynString(elf.DT_RPATH); err == nil && len(rps) > 0 {
		for _, rp := range rps {
			rpaths = append(rpaths, strings.Split(rp, ":")...)
		}
	}
	return interp, needed, rpaths
}
