package linux

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"

	"github.com/whiskeyjimbo/bento-v2/enforce"
	"github.com/whiskeyjimbo/bento-v2/internal/denylist"
	"github.com/whiskeyjimbo/bento-v2/internal/launcher"
	"github.com/whiskeyjimbo/bento-v2/internal/seccomp"
	"github.com/whiskeyjimbo/bento-v2/policy"
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
	// extraDeny are caller-supplied shields applied on top of the built-in deny-list
	// (a supervising embedder shielding its own state during a profiling trial; see
	// ProfileOptions.DenyPaths). Empty for an ordinary run. Every place that reads
	// the run's shields goes through alwaysShields, so these reach all of them.
	extraDeny []denylist.Rule
	// emptyFile is a real, empty, read-only file on the host. Binding it over a
	// path shields that path even when the path does not exist yet: bwrap creates
	// the mount point and the target becomes an unwritable empty file.
	emptyFile string
	// entrypoint and interpreter are absolute, symlink-resolved host paths.
	// interpreter is empty when the entrypoint is its own interpreter.
	entrypoint  string
	interpreter string
	// proxySocket is the host path of the egress proxy's unix socket, set when the
	// policy declares network rules or a supervising gate is present. When set, the
	// sandbox is funneled through the proxy: the bento binary is re-exec'd inside as
	// the forwarder.
	proxySocket string
	// bentoPath is the host path of the running bento binary, bound into the
	// sandbox to serve as the forwarder or the exec-block launcher. Set whenever the
	// launcher runs: alongside proxySocket, and also for exec-blocking with no
	// egress.
	bentoPath string
	// observe signals a profiling run: the launcher runs the target under the
	// ptrace observer instead of enforcing, and writes its report to an inherited
	// descriptor (FD observeReportFD), not a bound path - so the target's mount never
	// includes the report. That is not tamper-proof (a descendant can reach the fd via
	// /proc/<launcher>/fd; see the launcher's runObserve).
	observe bool
	// exists reports whether a host path exists. Injected so tests can compile
	// argv against a hypothetical filesystem.
	exists func(string) bool
	// isDir reports whether a host path is an existing directory. Injected
	// alongside exists; used to decide whether a write grant is a workspace (a
	// project checkout gets git-hook/editor-task shields) rather than a plain file.
	isDir func(string) bool
	// rootDirs lists the host's top-level entries to bind individually when a
	// read grant is "/". Injected alongside exists so the expansion is testable
	// against a hypothetical root. It must exclude the mounts baseFlags manages
	// (/proc, /dev, /tmp) so the host versions do not overmount them.
	rootDirs func() []string
	// resolve returns a path with its symlinks followed, or the path unchanged if
	// it does not resolve. Shields bind at the resolved path because bwrap cannot
	// create a mount point at a symlink (it aborts the whole run).
	resolve func(string) string
	// listDir returns a directory's immediate subdirectory names and whether it was
	// read successfully. ok is false when the path is not a directory OR cannot be
	// enumerated (e.g. an unreadable dir): the caller must distinguish an enumerated
	// empty directory from one it could not see into, so a chmod cannot silently hide
	// gitdirs from the scan. Injected alongside exists so the git-directory scan
	// (gitDirShields) is testable against a hypothetical filesystem.
	listDir func(string) (names []string, ok bool)
}

// Fixed in-sandbox paths for the egress bridge. The sandbox filesystem is ours,
// so these are constant.
const (
	sandboxBentoPath   = "/bento"
	sandboxProxySocket = "/proxy.sock"
)

// observeReportFD is the descriptor the profiling report is written through. The
// host passes the open report file as the bwrap child's first extra file, which
// Go places at FD 3; bwrap passes it through to the launcher. Using a descriptor
// rather than a bound path keeps the report out of the target's mount namespace.
const observeReportFD = 3

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

	reads, writes, err := resolveGrants(p)
	if err != nil {
		return nil, err
	}
	if err := checkNotShielded(sb, append(append([]string{}, reads...), writes...)); err != nil {
		return nil, err
	}
	if err := checkWriteNotAboveShield(sb, writes); err != nil {
		return nil, err
	}
	if err := checkWorkspaceShieldNotRedirected(sb, writes); err != nil {
		return nil, err
	}
	if err := checkGrantNotProcess(sb, p); err != nil {
		return nil, err
	}
	if err := checkGrantNotManagedMount(p); err != nil {
		return nil, err
	}
	if err := checkGrantNotLooped(p); err != nil {
		return nil, err
	}

	// Grants are bound at their resolved targets, so a grant that names a symlink
	// (~/.bashrc -> /nix/store/...) would leave the granted name itself absent.
	// Recreate it as a symlink, before the binds: bwrap refuses --symlink onto a
	// destination that already exists.
	symlinks, err := grantSymlinks(sb, p, reads, writes)
	if err != nil {
		return nil, err
	}
	args = append(args, symlinks...)

	args = append(args, systemMounts(sb)...)

	// The network namespace is always unshared: it is the egress fence for IP. With
	// no rules and no gate there is no route out at all. Otherwise the only reachable
	// peer is the loopback forwarder the re-exec'd bento sets up, which bridges to the
	// host-side allowlist proxy - the sandbox still has no IP route to the outside, so
	// nothing bypasses the proxy that way.
	//
	// The fence does not cover AF_UNIX: a path-named socket is scoped by the
	// filesystem, not the netns, and connect() to one succeeds even through a
	// read-only bind. A host daemon reached over such a socket has its own network
	// access, so the mount namespace - not this flag - is what keeps that route shut;
	// see denylist.Runtime, which shields the host's runtime directory whole, and the
	// residual it documents.
	args = append(args, "--unshare-net")

	for _, path := range reads {
		if path == "/" {
			// Binding the host root onto the sandbox root would make the root
			// read-only, and bwrap could then no longer create the top-level mount
			// points the launcher needs (/bento, /proxy.sock). Bind
			// the root's children individually instead, leaving the sandbox root the
			// writable tmpfs bwrap starts with. The literal "/" is still carried in
			// reads for deny-list reachability below.
			for _, top := range sb.rootDirs() {
				args = append(args, "--ro-bind-try", top, top)
			}
			continue
		}
		args = append(args, "--ro-bind-try", path, path)
	}
	for _, path := range writes {
		// Unlike a read grant, "/" is never expanded for writes: making the entire
		// host root writable would defeat the sandbox, and it is never a real grant.
		if path == "/" {
			return nil, fmt.Errorf("linux: write grant \"/\" would make the entire host root writable; grant a specific directory")
		}
		// Write grants are directory-granular: bwrap can only make a directory
		// writable in a way that supports creating and renaming files inside it.
		// Binding a file makes it a mount point, which returns EBUSY on the
		// save-to-temp-then-rename that editors and libraries use. So a grant that
		// names an existing file is refused, pointing at the directory instead.
		if sb.exists(path) && !sb.isDir(path) {
			return nil, fmt.Errorf("linux: write grant %q is a file; grant its parent directory instead", path)
		}
		args = append(args, "--bind-try", path, path)
	}

	// The deny-list goes after the grants so it always wins.
	args = append(args, denyArgs(sb, exposedPaths(sb, reads, writes), writes)...)

	// The entrypoint is bound read-only last so a write grant covering its
	// directory cannot leave the script itself writable mid-run.
	args = append(args, "--ro-bind", sb.entrypoint, sb.entrypoint)

	// The interpreter binary gets the same treatment for the same reason: it is bound
	// earlier by systemMounts (as the whole install prefix, or - for an interpreter at
	// or under $HOME - as just the file), and a write grant covering that directory
	// (write: ~/bin, write: ~/.pyenv) would otherwise overmount it read-write, letting
	// the target rewrite the binary it is currently executing - host persistence the
	// grant did not intend. Re-binding it read-only last shields exactly the running
	// binary; other files under a write-granted directory stay writable, as the grant
	// asks. Only the binary is covered, not every shared object the runtime loads: a
	// write grant over a runtime tree still authorizes writing those, a documented
	// residual of granting write there.
	if sb.interpreter != "" && sb.exists(sb.interpreter) {
		args = append(args, "--ro-bind", sb.interpreter, sb.interpreter)
	}

	// Every run goes through the in-sandbox launcher stage. It hosts the setup that
	// must happen inside the sandbox (the egress bridge, the exec-block filter, the
	// profiling observer), but it runs even when none of those is needed: it is the
	// one process bento controls between bwrap and the target, so it is where every
	// file descriptor bento's parent leaked without O_CLOEXEC is dropped before the
	// target can reach it. Running the target directly would let such a descriptor
	// bypass the mount namespace and the deny-list entirely.
	execMode := p.Exec
	if execMode == "" {
		execMode = policy.ExecNone
	}

	args = append(args, "--ro-bind", sb.bentoPath, sandboxBentoPath)
	if sb.proxySocket != "" {
		args = append(args, "--bind", sb.proxySocket, sandboxProxySocket)
	}

	// With every mount point now created, remount the sandbox root read-only. bwrap
	// starts the root as a writable tmpfs; left writable, a run could create files
	// directly at "/" that no grant allows. Making it read-only confines writes to
	// exactly the submounts made writable - the runtime scratch (/tmp, /dev, /proc)
	// and the write grants - which is also what the Landlock backstop confines to,
	// so the two layers agree. Must come last: an earlier remount would stop bwrap
	// creating the remaining root-level mount points.
	args = append(args, "--remount-ro", "/")

	args = append(args, envArgs(proc)...)
	args = append(args, "--chdir", filepath.Dir(sb.entrypoint), "--")

	socket := ""
	if sb.proxySocket != "" {
		socket = sandboxProxySocket
	}
	observeFD := 0
	if sb.observe {
		observeFD = observeReportFD
	}
	// The launcher's Landlock backstop confines writes to exactly the paths
	// passed here: the runtime scratch mounts plus the write grants. With the
	// root remounted read-only above, those are the only paths bwrap leaves
	// writable, so Landlock never denies a granted write bwrap would allow.
	// (Both layers are still stricter on the deny-list shields, by design - a
	// shield denies the write and that is the intent.) Deriving both from this
	// one place keeps them in sync.
	block, strictBlock := execBlockFlags(execMode, seccomp.Supported())
	cfg := launcher.Config{
		Socket:      socket,
		Block:       block,
		StrictBlock: strictBlock,
		Writable:    append(append([]string{}, sandboxWritableMounts...), writes...),
		ObserveFD:   observeFD,
		Target:      command(p, sb),
	}
	args = append(args, sandboxBentoPath)
	return append(args, launcher.EncodeLaunch(cfg)...), nil
}

// execBlockFlags reports the launcher's exec-block flags for execMode, gated on
// whether the kernel supports seccomp. The exec-block is a hardening layer
// (TierHardening): where seccomp BPF is absent the probe reports
// LayerExec=Unavailable and admission proceeds with a warning, so the launcher
// must run the target without the filter rather than hard-refuse to install one it
// cannot. Off amd64 none-strict still installs (installExecFilter degrades it to
// the execve-only block), so only the no-seccomp case drops the block. StrictBlock
// always implies Block.
func execBlockFlags(execMode policy.ExecMode, seccompOK bool) (block, strict bool) {
	if execMode == policy.ExecAll || !seccompOK {
		return false, false
	}
	return true, execMode == policy.ExecNoneStrict
}

// sandboxWritableMounts are the paths baseFlags makes writable for every run
// (independently of the policy's write grants). The Landlock backstop is handed
// these plus the grants; keep this list and baseFlags' writable mounts in step,
// or Landlock will deny a write bwrap permits.
var sandboxWritableMounts = []string{"/tmp", "/dev", "/proc"}

// baseFlagsPseudoFS are the pseudo-filesystems baseFlags mounts fresh for every
// sandbox: a hardened procfs, a minimal devtmpfs, and a tmpfs, plus the fresh
// tmpfs (/dev/shm) and devpts (/dev/pts) that bwrap's --dev sets up implicitly
// underneath /dev. A grant naming one of these whole would --ro-bind the host's
// version over the sandbox's (bwrap applies mounts in argv order, last wins),
// re-exposing host /proc/<pid>/environ, the full host device set, or other
// processes' shared-memory or temp files. hostRootDirs excludes the top-level
// entries from a read:/ expansion for exactly this reason; a direct grant of any
// is refused by checkGrantNotManagedMount.
var baseFlagsPseudoFS = []string{"/proc", "/dev", "/dev/shm", "/dev/pts", "/tmp"}

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
	for _, p := range systemMountPaths(sb) {
		args = append(args, "--ro-bind", p, p)
	}
	return args
}

// systemMountPaths lists what systemMounts binds, each at its own path. Kept
// apart from the argv so grantSymlinks can ask what these mounts already put in
// the sandbox without re-deriving the list and drifting out of step.
func systemMountPaths(sb sandbox) []string {
	var paths []string
	for _, p := range systemReadPaths {
		if sb.exists(p) {
			paths = append(paths, p)
		}
	}

	// A Nix interpreter's shared libraries are themselves separate store paths,
	// so binding only its own prefix leaves it unable to load. Bind the whole
	// store instead: it is immutable and world-readable package content, so it
	// carries no user data to protect.
	if strings.HasPrefix(sb.interpreter, nixStore+"/") && sb.exists(nixStore) {
		return append(paths, nixStore)
	}

	// Otherwise the interpreter may still live outside the system paths (pyenv,
	// mise). Bind its install prefix so its stdlib and shared objects resolve.
	prefix := interpreterPrefix(sb.interpreter)
	if prefix == "" {
		return paths
	}
	// The prefix comes from the symlink-resolved interpreter, so the home it is
	// compared against must be resolved too: on a host where $HOME reaches the real
	// tree through a link (/home -> var/home, or a relocated home), the raw
	// os.UserHomeDir value names a different path than the prefix and the floor below
	// would miss it, binding the whole home tree after all.
	home := sb.resolve(sb.home)
	if prefix == home || under(home, prefix) {
		// A ~/bin/python3 wrapper puts the prefix at the home directory itself, which
		// would bind every file in it into a sandbox whose policy granted none of them.
		// Naming the interpreter authorizes the interpreter, not the tree it happens to
		// sit in, so bind just the file - the same way the entrypoint is bound without a
		// grant. A wrapper script's real interpreter lives in the system paths, and a
		// single-file runtime links against system libraries, so both still run; a
		// runtime whose stdlib really is in ~/lib needs an explicit read grant for it.
		if sb.exists(sb.interpreter) {
			paths = append(paths, sb.interpreter)
		}
		return paths
	}
	if sb.exists(prefix) {
		paths = append(paths, prefix)
	}
	return paths
}

// exposedPaths lists everything the compiled sandbox exposes host content at, so
// the deny-list can shield whatever falls inside: the policy's grants plus every
// system mount. The mounts belong here because they are not all fixed system
// paths - the interpreter prefix can be a home subtree (~/.local for a pip --user
// runtime), which is what would otherwise leave ~/.local/share/gh readable to a
// policy that granted only /work - and a caller-supplied deny
// (ProfileOptions.DenyPaths) can name a path under any of them. Reachability only:
// these are all bound read-only and must never reach the writes set.
func exposedPaths(sb sandbox, reads, writes []string) []string {
	paths := append(append([]string{}, reads...), writes...)
	return append(paths, systemMountPaths(sb)...)
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

// shieldRules is the full deny-list for a run: the mandatory Home shields plus,
// for each write-granted checkout, the static Workspace shields and the git
// directories discovered under it (see gitDirShields). Building it in one place
// keeps denyArgs and createdShieldDirs enforcing and cleaning up the exact same
// set - a divergence would either leak a host artifact or leave a path unshielded.
// alwaysShields is the deny-list every run applies regardless of grants: the
// built-in home credential/config shields, the host's runtime state (its service
// sockets), plus any caller-supplied extra denies. The three places that enforce
// the always-on shields - shieldRules, checkNotShielded, checkWriteNotAboveShield -
// all derive from this, so a caller deny can never reach one and miss another
// (which would leak a host artifact or leave a path unshielded).
func alwaysShields(sb sandbox) []denylist.Rule {
	rules := append(denylist.Home(sb.home), denylist.Runtime()...)
	return append(rules, sb.extraDeny...)
}

func shieldRules(sb sandbox, writes []string) []denylist.Rule {
	rules := alwaysShields(sb)
	for _, w := range writes {
		// Workspace shields (git hooks, editor tasks) only make sense for a project
		// directory. A write grant that is a plain file - or a path that does not
		// exist yet - is not a checkout, and shielding a ".git/hooks" under it would
		// force bwrap to create that path inside a file, or pre-create the target as
		// a directory the script then cannot write as a file.
		if sb.isDir(w) {
			rules = append(rules, denylist.Workspace(w)...)
			rules = append(rules, gitDirShields(sb, w)...)
		}
	}
	return rules
}

// gitDirShields discovers, under a write-granted checkout dir, the git directories
// that sit at deterministic locations and returns DenyWrite shields for their
// code-execution surfaces. The top-level .git/hooks and .git/config shields cover
// the main repo, but a repo with submodules or linked worktrees keeps additional
// live hooks/config the main shields miss:
//
//   - submodule gitdirs at dir/.git/modules/<name>/ (recursively, so a nested
//     submodule at .git/modules/<a>/modules/<b>/ is covered too), each with its own
//     hooks/ and config that run when the developer uses that submodule on the host;
//   - linked-worktree config at dir/.git/worktrees/<name>/config.worktree.
//
// The hooks directory is shielded whether or not it exists yet, matching the
// top-level .git/hooks shield: an absent hooks/ under a real gitdir is still
// plantable, so it is tmpfs'd and reclaimed by createdShieldDirs. config and
// config.worktree are only shielded where they exist (they are files, not planting
// surfaces on their own - a new config.worktree is inert unless config, which is
// shielded, enables extensions.worktreeConfig).
//
// Not covered, because a concrete-path deny-list cannot express them (a documented
// residual): independent nested repos created anywhere under the grant,
// repos created during the run, and in-tree hook runners (husky, core.hooksPath
// pointing at a tracked directory) whose hooks are ordinary project files.
func gitDirShields(sb sandbox, dir string) []denylist.Rule {
	gitDir := filepath.Join(dir, ".git")
	var rules []denylist.Rule

	// worktreeConfigs shields the config.worktree of every linked worktree of a
	// gitdir. Linked worktrees share the gitdir's hooks (already shielded), but each
	// keeps its own config.worktree, which can carry core.hooksPath.
	worktreeConfigs := func(gd string) {
		wt := filepath.Join(gd, "worktrees")
		names, ok := sb.listDir(wt)
		if !ok {
			// Unreadable but traversable-by-name: fail closed like the module walk.
			if sb.isDir(wt) {
				rules = append(rules, denylist.Rule{Path: wt, Deny: denylist.DenyWrite, Dir: true})
			}
			return
		}
		for _, name := range names {
			if cfg := filepath.Join(wt, name, "config.worktree"); sb.exists(cfg) {
				rules = append(rules, denylist.Rule{Path: cfg, Deny: denylist.DenyWrite})
			}
		}
	}

	// Traversal is UNCONDITIONAL over real directories; identification gates only
	// whether shields are emitted, never whether recursion continues. .git/modules
	// is writable and unshielded across runs, so any predicate that decided *where to
	// walk* from attacker-writable content could be spoofed: a planted decoy config
	// file, or a fabricated gitdir-shaped container, could redirect or truncate the
	// walk and hide a real submodule's hooks. Walking every real subdirectory removes
	// that lever - a decoy can only add a harmless extra ro-bind. The cost is walking
	// git's store dirs (objects/refs/...), which hold no config file so emit nothing
	// and are bounded and setup-time. sb.listDir returns only real subdirectories
	// (symlinks skipped), so a planted symlink cannot escape the tree or loop; depth
	// bounds a deeply-nested planted tree as a backstop.
	var walk func(d string, depth int)
	walk = func(d string, depth int) {
		if depth > maxGitdirDepth {
			return
		}
		// A gitdir is identified by a regular config FILE (not a directory named
		// "config", which is how a submodule literally named "config" nests its own
		// gitdir at .git/modules/config/).
		if cfg := filepath.Join(d, "config"); sb.exists(cfg) && !sb.isDir(cfg) {
			rules = append(rules,
				denylist.Rule{Path: cfg, Deny: denylist.DenyWrite},
				denylist.Rule{Path: filepath.Join(d, "hooks"), Deny: denylist.DenyWrite, Dir: true},
			)
			if cw := filepath.Join(d, "config.worktree"); sb.exists(cw) {
				rules = append(rules, denylist.Rule{Path: cw, Deny: denylist.DenyWrite})
			}
			worktreeConfigs(d)
		}
		names, ok := sb.listDir(d)
		if !ok {
			// d could not be enumerated. If it is a real directory (traversable by
			// name, so host git still reaches gitdirs inside it) that we cannot read -
			// a prior run can chmod it 0111 to blind this scan - fail closed: shield the
			// whole subtree read-only so nothing new can be planted under it.
			if sb.isDir(d) {
				rules = append(rules, denylist.Rule{Path: d, Deny: denylist.DenyWrite, Dir: true})
			}
			return
		}
		for _, name := range names {
			walk(filepath.Join(d, name), depth+1)
		}
	}
	walk(filepath.Join(gitDir, "modules"), 0)
	worktreeConfigs(gitDir)
	return rules
}

// maxGitdirDepth bounds the .git/modules recursion so a symlink loop a prior run
// could plant cannot spin setup forever. Real submodule nesting is a handful deep.
const maxGitdirDepth = 64

// denyArgs shields every deny-list rule that a grant could otherwise expose.
//
// A rule whose path no grant reaches is skipped: it is already invisible under
// deny-by-default, and binding over it would force bwrap to create a mount point
// it has no parent for.
func denyArgs(sb sandbox, grants, writes []string) []string {
	rules := shieldRules(sb, writes)

	var args []string
	seen := map[denylist.Rule]bool{}
	for _, r := range rules {
		// Resolve the rule's path the same way grants are resolved, so the shield
		// decision compares like with like (a symlinked deny path, or a symlinked
		// /home component, would otherwise slip past reachability) and the shield
		// mounts where bwrap can actually create the mount point (never at a
		// symlink, which aborts the run).
		r.Path = sb.resolve(r.Path)
		if r.Path == "/" {
			// A deny dotfile that resolves to the root (a symlink to "/") would
			// otherwise tmpfs or bind over the whole sandbox root; never shield it.
			continue
		}
		// Two rules can name the same real path once resolved (/var/run and /run on a
		// merged host). Shielding it twice stacks a redundant mount rather than being
		// wrong, but only the identical rule is dropped, so a path shielded two
		// different ways still gets both and the stricter one still lands.
		if seen[r] {
			continue
		}
		seen[r] = true
		if !shieldNeeded(r, sb, grants, writes) {
			continue
		}
		args = append(args, shield(r, sb)...)
	}
	return args
}

// createdShieldDirs returns the DIRECTORY shield mount points bwrap will create on
// the host because the shielded path does not exist yet and a write grant makes its
// parent writable (a nonexistent path is only shielded when a write grant reaches
// it, so its parent is a read-write host bind). The caller removes these after the
// run so the sandbox leaves no directory artifact.
//
// Only directory shields are returned: removing a directory is empty-only by the
// rmdir syscall, so cleanup can never delete host data even if a process wrote into
// the path during the run. File shield mount points are deliberately excluded - an
// os.Remove of a file is unconditional, so cleaning one would race a host-side
// atomic save (write-temp then rename) over that path and could delete a real file.
// The rule selection mirrors denyArgs exactly.
func createdShieldDirs(sb sandbox, grants, writes []string) []string {
	rules := shieldRules(sb, writes)
	var dirs []string
	for _, r := range rules {
		r.Path = sb.resolve(r.Path)
		if r.Path == "/" || !r.Dir || !shieldNeeded(r, sb, grants, writes) {
			continue
		}
		if !sb.exists(r.Path) {
			dirs = append(dirs, r.Path)
		}
	}
	return dirs
}

// removeCreatedShieldDirs removes directory shield mount points bento caused bwrap
// to create (see createdShieldDirs), after the run. os.Remove on a directory is the
// rmdir syscall: it removes only an empty directory, so a path a host process wrote
// into during the run survives (ENOTEMPTY, ignored), and a pre-existing path is
// never in the list to begin with. Best effort: a kill before this runs, or an
// intermediate parent bwrap created, can survive.
func removeCreatedShieldDirs(dirs []string) {
	for _, d := range dirs {
		os.Remove(d)
	}
}

// shieldNeeded decides whether a deny rule needs a shield mount, given what the
// grants expose. Beyond protecting the path, this avoids asking bwrap to bind a
// shield over a path whose parent is read-only - which it cannot do - for paths
// that are not actually a threat there.
func shieldNeeded(r denylist.Rule, sb sandbox, grants, writes []string) bool {
	if !reachable(r.Path, grants) {
		return false // not exposed by any grant; already invisible
	}
	writable := reachable(r.Path, writes)
	if r.Deny == denylist.DenyAll {
		// Hide existing contents from reads; prevent creation only where a write
		// grant could create it (a read-only parent cannot).
		return sb.exists(r.Path) || writable
	}
	// DenyWrite: a read-only grant already prevents writes, so a shield is only
	// needed where the path is actually writable.
	return writable
}

// shield returns the bwrap arguments that enforce one deny rule.
//
// Both branches cover paths that do not exist yet, which is what closes the
// "plant a new credential file or shell profile under a broad write grant" hole:
// bwrap creates the mount point, and the shield - not the host - receives the
// write.
// shield's rule path is already symlink-resolved by denyArgs, so it binds where
// bwrap can create the mount point (never at a symlink, which aborts the run). A
// symlinked dotfile (~/.bashrc under home-manager) is thereby shielded via its
// real target: reads follow the symlink to it, and the bind makes it read-only.
// (Replacing the symlink itself under a broad home write grant is not preventable
// this way, but that grant is discouraged and the profiler no longer proposes it.)
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
		// - git must still read ~/.gitconfig - while rejecting writes. Shadowing it
		// with /dev/null, as v1 did, would have blinded those legitimate reads.
		if sb.exists(r.Path) {
			return []string{"--ro-bind", r.Path, r.Path}
		}
		return []string{"--ro-bind", sb.emptyFile, r.Path}
	}
}

// checkNotShielded rejects a grant that falls inside a fully-shielded location
// (a DenyAll deny-list directory such as ~/.ssh). Such a grant cannot be honored
// - the shield wins - so silently dropping it would leave the user believing a
// path is available when it is not. A READ grant that *contains* a shield is fine
// and common (read: ~ with ~/.ssh shielded inside it); a WRITE grant that contains
// one is refused separately by checkWriteNotAboveShield, since it would make the
// shield's parent writable.
func checkNotShielded(sb sandbox, grants []string) error {
	rules := alwaysShields(sb)
	for _, g := range grants {
		for _, r := range rules {
			if r.Deny != denylist.DenyAll {
				continue
			}
			// Resolve the rule path as grants are resolved, so a grant that names a
			// symlinked shield's real target (write: /data/keys with ~/.ssh ->
			// /data/keys) is still caught, not silently honored.
			rp := sb.resolve(r.Path)
			if g == rp || under(g, rp) {
				return fmt.Errorf("linux: grant %q is inside the always-shielded path %q and cannot be honored; remove it", g, r.Path)
			}
		}
	}
	return nil
}

// checkWriteNotAboveShield refuses a write grant that contains a DenyAll home
// shield (a credential directory such as ~/.ssh). Such a grant binds the shield's
// parent read-write, so a run could create the shield on the host where it did not
// exist (leaving an empty, wrong-permission directory that breaks ssh/gpg), or
// delete and replace a symlinked one - because bwrap cannot mount a shield over a
// symlink and so protects only its target, not the name in the granted directory.
// Read grants are not restricted: they cannot write the parent, and shielding a
// broad read grant is the deny-list's normal use.
// checkWorkspaceShieldNotRedirected refuses a write grant whose per-workspace shield
// (a git hooks/config path, an editor-task file) is redirected by a symlinked
// directory component so the emitted shield lands somewhere other than the literal
// name. denyArgs binds each shield at its RESOLVED path, but the tooling on the host
// opens the shield's LITERAL name inside the granted directory; when a symlinked
// component makes the two differ, the shield protects the wrong path while the
// symlink - which lives in the writable grant - stays free for the target to delete
// and replace with a real planted hook/task that runs on the host. This covers both
// a component escaping the grant (.vscode -> /outside) and one redirecting within it
// (.vscode -> ./realvscode); either leaves the literal name unshielded. A shield
// whose path is symlink-free resolves to itself and binds correctly. A .git that is
// a regular file (a linked-worktree gitfile) resolves to its literal path too, so it
// is not refused here - it hits bwrap's existing ENOTDIR abort, unchanged.
//
// checkWriteNotAboveShield handles the always-shields (HOME, runtime); this handles
// the grant-relative workspace shields, which it does not cover.
func checkWorkspaceShieldNotRedirected(sb sandbox, writes []string) error {
	for _, w := range writes {
		if w == "/" || !sb.isDir(w) {
			continue
		}
		rules := append(denylist.Workspace(w), gitDirShields(sb, w)...)
		for _, r := range rules {
			if real := sb.resolve(r.Path); real != r.Path {
				return fmt.Errorf("linux: write grant %q shields %q, but a symlinked directory component redirects it to %q, so the shield would protect the wrong path while the symlink stays writable; remove the symlink or grant a narrower directory", w, r.Path, real)
			}
		}
	}
	return nil
}

func checkWriteNotAboveShield(sb sandbox, writes []string) error {
	for _, w := range writes {
		if w == "/" {
			continue // rejected with a clearer message by the write-grant loop
		}
		for _, r := range alwaysShields(sb) {
			if r.Deny != denylist.DenyAll {
				continue
			}
			// The tamperable entry is the shield's name in the granted directory, so
			// compare its location - parent resolved so it shares the grant's namespace,
			// own name kept literal - rather than its symlink target, which lies outside
			// the grant.
			loc := filepath.Join(sb.resolve(filepath.Dir(r.Path)), filepath.Base(r.Path))
			if under(loc, w) {
				return fmt.Errorf("linux: write grant %q contains the always-shielded path %q, so its parent would be writable and a run could tamper with or expose it; grant a narrower directory instead", w, r.Path)
			}
		}
	}
	return nil
}

// checkGrantNotProcess refuses a grant that resolves into a host process's
// directory in procfs. /etc/mtab and /dev/fd are how one is reached by accident:
// they are host symlinks through /proc/self, which resolves here to the pid of
// *this* bento.
//
// The sandbox unshares its pid namespace and mounts a procfs of its own, so a
// host pid means one of two things there, both wrong. Usually the pid is absent -
// bwrap cannot create the mount point and aborts the whole run. But where the
// number happens to exist in the sandbox too (pid 1 is the launcher), the bind
// lands on it and the run reads the *host's* process instead: `read: /proc/1`
// served the host's init. Refusing covers both; grants are reported as written,
// since the resolved pid path is not what anyone typed.
//
// Only a resolved path that exists is refused: the grants bind with --ro-bind-try,
// which skips a source that is not there, so those abort nothing. That is what
// /dev/stdout relies on when it is a pipe rather than a terminal - it resolves to
// a /proc/<pid>/fd/pipe:[...] name that does not exist, and the grant is a no-op
// instead of a run-killer.
func checkGrantNotProcess(sb sandbox, p *policy.Policy) error {
	for _, g := range append(append([]string{}, p.Read...), p.Write...) {
		abs, err := filepath.Abs(g)
		if err != nil {
			return fmt.Errorf("linux: %q: %w", g, err)
		}
		real, err := resolve(abs)
		if err != nil {
			return err
		}
		if isProcessPath(real) && sb.exists(real) {
			return fmt.Errorf("linux: grant %q resolves to %q, a host process's directory in /proc; the sandbox has a pid namespace and a /proc of its own, where that pid is a different process or none at all; remove the grant - /proc is always mounted", g, real)
		}
	}
	return nil
}

// checkGrantNotManagedMount refuses a grant that resolves to a pseudo-filesystem
// baseFlags mounts fresh (/proc, /dev, /tmp). Bound whole, the host's version
// overmounts the sandbox's hardened one - the last mount in argv order wins - so a
// read:/proc grant would serve host /proc/<pid>/environ (routinely API tokens and
// DB passwords) of same-uid host processes, read:/dev the full host device set, and
// a /tmp grant other processes' temp files. A specific path inside one still binds
// fine; only the whole root is refused.
func checkGrantNotManagedMount(p *policy.Policy) error {
	for _, g := range append(append([]string{}, p.Read...), p.Write...) {
		abs, err := filepath.Abs(g)
		if err != nil {
			return fmt.Errorf("linux: %q: %w", g, err)
		}
		real, err := resolve(abs)
		if err != nil {
			return err
		}
		for _, m := range baseFlagsPseudoFS {
			if real == m {
				return fmt.Errorf("linux: grant %q resolves to %q, a pseudo-filesystem the sandbox mounts fresh; granting it whole would overmount the sandbox's hardened %s with the host's and re-expose host process environs, device nodes, or other processes' temp files; %s is always mounted - grant a specific path inside it instead", g, real, m, m)
			}
		}
	}
	return nil
}

// checkGrantNotLooped refuses a grant whose symlinks loop. resolveExisting leaves
// a loop unresolved on purpose - a shield on one still fails closed - but a grant
// is then bound at the looping path itself, and --ro-bind-try tolerates only a
// missing source (ENOENT), not ELOOP, so bwrap aborts the run naming itself
// rather than the grant. A dangling symlink is not a loop and stays supported:
// it resolves to a target that simply does not exist yet.
func checkGrantNotLooped(p *policy.Policy) error {
	for _, g := range append(append([]string{}, p.Read...), p.Write...) {
		abs, err := filepath.Abs(g)
		if err != nil {
			return fmt.Errorf("linux: %q: %w", g, err)
		}
		if _, err := os.Stat(abs); errors.Is(err, syscall.ELOOP) {
			return loopedGrantError(g)
		}
	}
	return nil
}

// loopedGrantError is shared so a looping read grant and a looping write grant -
// found at different points in the run - are refused in the same words.
func loopedGrantError(g string) error {
	return fmt.Errorf("linux: grant %q loops through itself on the host, so it names nothing that can be bound; fix the link or remove the grant", g)
}

// isProcessPath reports whether path is a per-process procfs directory or
// something inside one (/proc/<pid>/...). /proc itself and its system-wide files
// (/proc/cpuinfo) are not: those bind fine.
func isProcessPath(path string) bool {
	rel, err := filepath.Rel("/proc", path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return false
	}
	first, _, _ := strings.Cut(rel, "/")
	if first == "" {
		return false
	}
	return strings.IndexFunc(first, func(r rune) bool { return r < '0' || r > '9' }) < 0
}

// reachable reports whether a grant could expose path - either because a grant
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
// at ~/.ssh, we bind the real target, and the deny-list - which runs after and
// also works on real paths - still shields it. Binding the unresolved path would
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

// grantSymlinks recreates, inside the sandbox, every granted path that is a
// symlink on the host, pointing at the same target the host's symlink does.
//
// The grant itself is bound at its resolved target, which is what keeps the
// deny-list honest: shields mount on real paths, and reaching content through a
// symlink still lands on the real path underneath, so a shield there still wins.
// Binding the target at the granted name instead would alias the same content to
// a second name the shields do not cover, which is a hole - hence a symlink, not
// a bind.
//
// Only names that no mount would otherwise fill are recreated. A name already
// inside some mount needs nothing: the mount carries the host's own entry there.
// Recreating it anyway is worse than redundant - bwrap refuses a --symlink onto
// an existing destination, and resolves a later bind's destination *through* the
// link, so `read: /bin` on a usrmerge host (/bin -> usr/bin, and /bin bound by
// systemMounts) would abort the run rather than being bound as before.
func grantSymlinks(sb sandbox, p *policy.Policy, reads, writes []string) ([]string, error) {
	// Every path whose contents the sandbox already has, so a link is only made
	// where nothing else creates the name. The bind mounts carry the host's own
	// entries; --dev and --proc bring entries of their own (/dev/stdout is one of
	// them). Grants are bound at their resolved targets, which is what covers a
	// symlink granted alongside a broader path that already contains it. Note
	// --tmpfs /tmp is deliberately absent: it mounts empty, so a name under it
	// exists only if made here.
	filled := []string{"/dev", "/proc"}
	filled = append(filled, systemMountPaths(sb)...)
	filled = append(filled, writes...)
	filled = append(filled, sb.entrypoint)
	for _, r := range reads {
		// A read grant of "/" is never bound at "/" - it is carried in reads for
		// deny-list reachability and bound as its children, which is what fills the
		// sandbox. Taking it literally would cover every path there is and skip
		// every link, including under the empty /tmp that the expansion omits.
		if r == "/" {
			filled = append(filled, sb.rootDirs()...)
			continue
		}
		filled = append(filled, r)
	}

	var links [][2]string
	seen := map[string]bool{}
	for _, g := range append(append([]string{}, p.Read...), p.Write...) {
		abs, err := filepath.Abs(g)
		if err != nil {
			return nil, fmt.Errorf("linux: %q: %w", g, err)
		}
		real, err := resolve(abs)
		if err != nil {
			return nil, err
		}
		if real == abs {
			continue
		}
		hop := missingHop(abs, real, filled)
		if hop == "" || seen[hop] {
			continue
		}
		seen[hop] = true
		links = append(links, [2]string{real, hop})
	}
	sort.Slice(links, func(i, j int) bool { return links[i][1] < links[j][1] })

	var args []string
	var made []string
	for _, l := range links {
		// A symlink whose name sits under one already made would have to be created
		// through that link, into a target not mounted yet; the parent link already
		// leads to the right place, so the name resolves without this one. Sorting
		// above is what puts a parent link before the names beneath it.
		if coveredBy(l[1], made) {
			continue
		}
		made = append(made, l[1])
		args = append(args, "--symlink", l[0], l[1])
	}
	return args, nil
}

// missingHop returns the name to recreate so that following abs inside the
// sandbox reaches real, or "" when nothing needs recreating.
//
// Usually that is abs itself. But a name a mount already fills is the host's own
// symlink, which points at the next link in the chain rather than at real - and
// that next name can be one no mount fills, breaking the walk in the middle
// (~/link -> /elsewhere/mid -> real, with only ~ and real bound). So each filled
// name is followed the way the kernel will follow it, until one is missing: that
// is the name worth making, and pointing it at real short-circuits the rest.
func missingHop(abs, real string, filled []string) string {
	cur := abs
	for range maxSymlinkDepth {
		if !coveredBy(cur, filled) {
			return cur
		}
		target, err := os.Readlink(cur)
		if err != nil {
			// Filled and not a symlink: the mount already carries the real thing.
			return ""
		}
		// A relative target resolves from the directory the kernel *reads the link
		// in*, which is not the one the path spells when a parent is itself a
		// symlink - so resolve the parent before joining, rather than letting Join
		// clean ".." lexically and wander off.
		if !filepath.IsAbs(target) {
			target = filepath.Join(resolveExisting(filepath.Dir(cur), 0), target)
		}
		// Resolve the target's parent so it lands where the kernel would, but keep
		// its own name literal - the next link's location is wanted here, not the
		// thing it points at.
		next := filepath.Join(resolveExisting(filepath.Dir(target), 0), filepath.Base(target))
		if next == real {
			// The chain reaches the bound target on its own.
			return ""
		}
		cur = next
	}
	return "" // a symlink loop; resolve leaves these alone too
}

// coveredBy reports whether path is one of roots or sits inside one.
func coveredBy(path string, roots []string) bool {
	for _, r := range roots {
		if path == r || under(path, r) {
			return true
		}
	}
	return false
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
	return resolveExisting(abs, 0), nil
}

// maxSymlinkDepth bounds symlink following, matching the kernel's ELOOP limit, so
// a self-referential or cyclic deny-list symlink cannot spin forever.
const maxSymlinkDepth = 40

// resolveExisting resolves abs where it exists via the kernel (EvalSymlinks,
// which is accurate through parent symlinks, "..", and chains). Where a component
// does not exist - including a *dangling* leaf symlink pointing into a not-yet-
// populated store - it walks the components against a fully-resolved prefix,
// following each symlink before any later "..", so the result is the target a
// write through the path would actually reach (not the unmountable symlink, and
// not the wrong sibling filepath.Join's lexical ".." cleaning would produce).
func resolveExisting(abs string, depth int) string {
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		return real
	}
	if depth >= maxSymlinkDepth {
		return abs // a symlink loop; leave it - a shield here fails closed
	}

	resolved := "/"
	parts := strings.Split(strings.Trim(abs, "/"), "/")
	for i, c := range parts {
		switch c {
		case "", ".":
			continue
		case "..":
			resolved = filepath.Dir(resolved)
			continue
		}
		next := filepath.Join(resolved, c)
		target, err := os.Readlink(next)
		if err != nil {
			// A real directory/file, or a not-yet-existing component: take it as is.
			// Since resolved is already symlink-free, a later ".." on it is safe.
			resolved = next
			continue
		}
		// A symlink: rebuild the path as its target followed by the not-yet-walked
		// remainder - raw, not lexically joined, so a ".." *inside* the target still
		// follows its own leading symlink - and resolve that from the top.
		rebuilt := target
		if !filepath.IsAbs(target) {
			rebuilt = resolved + "/" + target
		}
		if rem := parts[i+1:]; len(rem) > 0 {
			rebuilt += "/" + strings.Join(rem, "/")
		}
		return resolveExisting(rebuilt, depth+1)
	}
	return resolved
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

// hostIsDir reports whether path is an existing directory, following symlinks so
// a symlinked workspace grant is recognized as one.
func hostIsDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// hostListDir returns the names of a directory's immediate children that are
// themselves real directories, or nil if it is not readable. Symlinks and regular
// files are excluded: gitDirShields walks the result unconditionally, so a symlink
// (DirEntry.Type reports it without a follow) must not be traversed or it could
// escape .git/modules or loop.
func hostListDir(path string) ([]string, bool) {
	entries, err := os.ReadDir(path)
	if err != nil {
		// Not a directory, or a directory we cannot read (e.g. mode 0111, still
		// traversable-by-name so host git reaches hooks inside it). ok=false lets the
		// caller fail closed rather than treat it as empty.
		return nil, false
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() { // DirEntry.IsDir is false for a symlink (even to a directory)
			names = append(names, e.Name())
		}
	}
	return names, true
}

// hostResolve resolves a deny-list path the same way grants are resolved, so the
// two are compared on the same footing (a symlinked /home component, a symlinked
// deny dir, or a dangling dotfile symlink all resolve to the target a write would
// reach). resolve already follows a dangling leaf against its resolved parent.
func hostResolve(path string) string {
	if resolved, err := resolve(path); err == nil {
		return resolved
	}
	return path
}

// hostRootDirs lists the host's top-level entries to bind for a "/" read grant,
// excluding the mounts baseFlags manages so the host's /proc, /dev, and /tmp
// never overmount the sandbox's own.
func hostRootDirs() []string {
	entries, err := os.ReadDir("/")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if slices.Contains(baseFlagsPseudoFS, "/"+e.Name()) {
			continue
		}
		out = append(out, "/"+e.Name())
	}
	return out
}
