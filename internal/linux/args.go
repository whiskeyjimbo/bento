package linux

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/whiskeyjimbo/bento-v2/internal/denylist"
	"github.com/whiskeyjimbo/bento-v2/internal/enforce"
	"github.com/whiskeyjimbo/bento-v2/internal/policy"
)

// systemReadPaths are mounted read-only in every sandbox so an interpreter can
// find its runtime and its CA bundle. They carry no user data.
var systemReadPaths = []string{
	"/usr", "/bin", "/sbin", "/lib", "/lib64",
	"/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d",
	"/etc/ssl", "/etc/ca-certificates", "/etc/pki", "/etc/alternatives",
}

// sandbox carries the host facts the argv compiler needs. Keeping them in a
// struct rather than reading the environment inside compile() is what makes the
// compiler a pure function, so every security-critical decision it makes is
// testable without launching anything.
type sandbox struct {
	// home is the host's home directory, which anchors the deny-list.
	home string
	// emptyFile is a real, empty, read-only file on the host. Binding it over a
	// path shields that path even when the path does not exist yet: bwrap creates
	// the mount point and the target becomes an unwritable empty file.
	emptyFile string
	// entrypoint and interpreter are absolute, symlink-resolved host paths.
	// interpreter is empty when the entrypoint is its own interpreter.
	entrypoint  string
	interpreter string
	// proxySocket is the host path of the egress proxy's unix socket, set only
	// when the policy declares network rules. When set, the sandbox is funneled
	// through the proxy: the bento binary is re-exec'd inside as the forwarder.
	proxySocket string
	// bentoPath is the host path of the running bento binary, bound into the
	// sandbox to serve as the forwarder. Set only alongside proxySocket.
	bentoPath string
	// exists reports whether a host path exists. Injected so tests can compile
	// argv against a hypothetical filesystem.
	exists func(string) bool
}

// Fixed in-sandbox paths for the egress bridge. The sandbox filesystem is ours,
// so these are constant.
const (
	sandboxBentoPath   = "/bento"
	sandboxProxySocket = "/proxy.sock"
)

// compile builds the bwrap argv for a policy.
//
// Order is load-bearing: bwrap applies mounts in argv order and the last one
// wins, so the mandatory deny-list must come after the policy's own grants.
// Otherwise a grant of $HOME would re-expose ~/.ssh.
func compile(p *policy.Policy, proc enforce.Process, sb sandbox) ([]string, error) {
	if sb.entrypoint == "" {
		return nil, fmt.Errorf("linux: no entrypoint")
	}
	args := baseFlags()
	args = append(args, systemMounts(sb)...)

	// The network namespace is always unshared: it is the egress fence. With no
	// rules that is the whole story (no route out at all). With rules, the only
	// reachable peer is the loopback forwarder the re-exec'd bento sets up, which
	// bridges to the host-side allowlist proxy — the sandbox still has no route to
	// the outside, so nothing bypasses the proxy.
	args = append(args, "--unshare-net")

	reads, writes, err := resolveGrants(p)
	if err != nil {
		return nil, err
	}
	if err := checkNotShielded(sb.home, append(append([]string{}, reads...), writes...)); err != nil {
		return nil, err
	}
	for _, path := range reads {
		args = append(args, "--ro-bind-try", path, path)
	}
	for _, path := range writes {
		args = append(args, "--bind-try", path, path)
	}

	// The deny-list goes after the grants so it always wins.
	args = append(args, denyArgs(sb, append(append([]string{}, reads...), writes...), writes)...)

	// The entrypoint is bound read-only last so a write grant covering its
	// directory cannot leave the script itself writable mid-run.
	args = append(args, "--ro-bind", sb.entrypoint, sb.entrypoint)

	// When egress is allowed, bind the bento binary (the forwarder) and the proxy
	// socket into the sandbox.
	if sb.proxySocket != "" {
		args = append(args, "--ro-bind", sb.bentoPath, sandboxBentoPath)
		args = append(args, "--bind", sb.proxySocket, sandboxProxySocket)
	}

	args = append(args, envArgs(proc)...)
	args = append(args, "--chdir", filepath.Dir(sb.entrypoint), "--")

	// With egress, the entrypoint is the forwarder, which runs the real command
	// with the proxy environment set; without it, the command runs directly.
	if sb.proxySocket != "" {
		args = append(args, sandboxBentoPath, "__forward", sandboxProxySocket, "--")
	}
	args = append(args, command(p, sb)...)
	return args, nil
}

func baseFlags() []string {
	return []string{
		"--die-with-parent", "--new-session",
		"--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-uts", "--unshare-cgroup",
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
	}
}

// nixStore holds Nix-provided packages, each in its own immutable directory.
const nixStore = "/nix/store"

func systemMounts(sb sandbox) []string {
	var args []string
	for _, p := range systemReadPaths {
		if sb.exists(p) {
			args = append(args, "--ro-bind", p, p)
		}
	}

	// A Nix interpreter's shared libraries are themselves separate store paths,
	// so binding only its own prefix leaves it unable to load. Bind the whole
	// store instead: it is immutable and world-readable package content, so it
	// carries no user data to protect.
	if strings.HasPrefix(sb.interpreter, nixStore+"/") && sb.exists(nixStore) {
		return append(args, "--ro-bind", nixStore, nixStore)
	}

	// Otherwise the interpreter may still live outside the system paths (pyenv,
	// mise). Bind its install prefix so its stdlib and shared objects resolve.
	if prefix := interpreterPrefix(sb.interpreter); prefix != "" && sb.exists(prefix) {
		args = append(args, "--ro-bind", prefix, prefix)
	}
	return args
}

// interpreterPrefix returns the install root of an interpreter that lives
// outside the system paths (e.g. ~/.pyenv/versions/3.12/bin/python3 →
// ~/.pyenv/versions/3.12), so its stdlib comes along. System interpreters are
// already covered by systemReadPaths and return "".
func interpreterPrefix(interp string) string {
	if interp == "" {
		return ""
	}
	for _, sys := range []string{"/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/"} {
		if strings.HasPrefix(interp, sys) {
			return ""
		}
	}
	// .../bin/python3 → ...
	dir := filepath.Dir(interp)
	if filepath.Base(dir) == "bin" {
		return filepath.Dir(dir)
	}
	return dir
}

// denyArgs shields every deny-list rule that a grant could otherwise expose.
//
// A rule whose path no grant reaches is skipped: it is already invisible under
// deny-by-default, and binding over it would force bwrap to create a mount point
// it has no parent for.
func denyArgs(sb sandbox, grants, writes []string) []string {
	rules := denylist.Home(sb.home)
	for _, w := range writes {
		rules = append(rules, denylist.Workspace(w)...)
	}

	var args []string
	for _, r := range rules {
		if !reachable(r.Path, grants) {
			continue
		}
		args = append(args, shield(r, sb)...)
	}
	return args
}

// shield returns the bwrap arguments that enforce one deny rule.
//
// Both branches cover paths that do not exist yet, which is what closes the
// "plant a new credential file or shell profile under a broad write grant" hole:
// bwrap creates the mount point, and the shield — not the host — receives the
// write.
func shield(r denylist.Rule, sb sandbox) []string {
	switch {
	case r.Deny == denylist.DenyAll && r.Dir:
		// An empty tmpfs hides existing contents and absorbs any new file.
		return []string{"--tmpfs", r.Path}
	case r.Deny == denylist.DenyAll:
		// An empty read-only file: contents unreadable, writes rejected.
		return []string{"--ro-bind", sb.emptyFile, r.Path}
	case r.Dir:
		// DenyWrite on a directory. Rebinding it read-only keeps existing contents
		// readable while rejecting new files (a planted git hook). If it does not
		// exist, a tmpfs both keeps it empty and absorbs writes.
		if sb.exists(r.Path) {
			return []string{"--ro-bind", r.Path, r.Path}
		}
		return []string{"--tmpfs", r.Path}
	default:
		// DenyWrite on a file. Rebinding the real file read-only keeps it readable
		// — git must still read ~/.gitconfig — while rejecting writes. Shadowing it
		// with /dev/null, as v1 did, would have blinded those legitimate reads.
		if sb.exists(r.Path) {
			return []string{"--ro-bind", r.Path, r.Path}
		}
		return []string{"--ro-bind", sb.emptyFile, r.Path}
	}
}

// checkNotShielded rejects a grant that falls inside a fully-shielded location
// (a DenyAll deny-list directory such as ~/.ssh). Such a grant cannot be honored
// — the shield wins — so silently dropping it would leave the user believing a
// path is available when it is not. A grant that *contains* a shielded path is
// fine and common (write: ~ with ~/.ssh shielded inside it); only a grant at or
// below a shield is the mistake.
func checkNotShielded(home string, grants []string) error {
	rules := denylist.Home(home)
	for _, g := range grants {
		for _, r := range rules {
			if r.Deny != denylist.DenyAll {
				continue
			}
			if g == r.Path || under(g, r.Path) {
				return fmt.Errorf("linux: grant %q is inside the always-shielded path %q and cannot be honored; remove it", g, r.Path)
			}
		}
	}
	return nil
}

// reachable reports whether a grant could expose path — either because a grant
// contains it, or because it contains a grant.
func reachable(path string, grants []string) bool {
	for _, g := range grants {
		if path == g || under(path, g) || under(g, path) {
			return true
		}
	}
	return false
}

// under reports whether child is inside parent.
func under(child, parent string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// resolveGrants makes every granted path absolute and symlink-free.
//
// Resolving is the defense against a symlinked grant: if `write: /tmp/out` points
// at ~/.ssh, we bind the real target, and the deny-list — which runs after and
// also works on real paths — still shields it. Binding the unresolved path would
// have let the symlink redirect the mount.
func resolveGrants(p *policy.Policy) (reads, writes []string, err error) {
	if reads, err = resolveAll(p.Read); err != nil {
		return nil, nil, err
	}
	if writes, err = resolveAll(p.Write); err != nil {
		return nil, nil, err
	}
	return reads, writes, nil
}

func resolveAll(paths []string) ([]string, error) {
	out := make([]string, 0, len(paths))
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		r, err := resolve(p)
		if err != nil {
			return nil, err
		}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out, nil
}

// resolve returns an absolute, symlink-resolved path. A path that does not exist
// yet (a write target) is resolved as far as it does exist, so the parts that
// could be a symlink are still followed.
func resolve(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("linux: %q: %w", path, err)
	}
	rest := ""
	for cur := abs; ; {
		real, err := filepath.EvalSymlinks(cur)
		if err == nil {
			return filepath.Join(real, rest), nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs, nil
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// envArgs clears the inherited environment and sets only what the policy allowed
// through, plus the minimum an interpreter needs to run.
func envArgs(proc enforce.Process) []string {
	args := []string{"--clearenv"}
	names := make([]string, 0, len(proc.Env))
	for k := range proc.Env {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		args = append(args, "--setenv", k, proc.Env[k])
	}
	if _, ok := proc.Env["PATH"]; !ok {
		args = append(args, "--setenv", "PATH", "/usr/bin:/bin")
	}
	if _, ok := proc.Env["HOME"]; !ok {
		// The sandbox's HOME is the tmpfs, never the host's: a script that writes
		// dotfiles must not reach the real home directory.
		args = append(args, "--setenv", "HOME", "/tmp")
	}
	return args
}

func command(p *policy.Policy, sb sandbox) []string {
	var cmd []string
	if sb.interpreter != "" {
		cmd = append(cmd, sb.interpreter)
	}
	cmd = append(cmd, sb.entrypoint)
	return append(cmd, p.Args...)
}

// hostExists is the real filesystem probe used outside tests.
func hostExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
