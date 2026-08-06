//go:build linux

package linux

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/grantrefusal"
	"github.com/whiskeyjimbo/bento/internal/launcher"
	"github.com/whiskeyjimbo/bento/internal/pathresolve"
	"github.com/whiskeyjimbo/bento/policy"
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
	// homes are the host home directories the deny-list anchors on: $HOME and the
	// current uid's passwd entry, which legitimately disagree under containers, nix
	// shells, sudo and CI. Every one is shielded, so moving either does not relocate
	// the shields off the other.
	homes []string
	// runtimeDir is the host's XDG runtime directory, when it names one outside /run.
	// The runtime shields anchor on it the same way the credential shields anchor on
	// homes: a host that parks it under /tmp keeps the auth stores and agent sockets
	// there, where the /run shield does not reach them.
	runtimeDir string
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
	// interpreterName is the interpreter's absolute path BEFORE symlink resolution - the
	// name the policy asked for, kept so the observation record can show what a proposal
	// named. command() builds argv from the resolved interpreter, not from this.
	// Empty when there is no interpreter or when resolution changed nothing.
	interpreterName string
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
	// applied signals that the launcher should write its applied-layer report to an
	// inherited descriptor (FD appliedReportFD), which the host reconciles into the
	// run report so a layer is claimed only once the child confirms it. Mutually
	// exclusive with observe: profiling produces an observation, not a report.
	applied bool
	// runDir is the per-run 0700 directory holding the run's host-side files: the
	// empty shield file, the proxy socket, and the applied-layer report. Anything the
	// host must read back after the run belongs here rather than in shared /tmp.
	runDir string
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
	//
	// It errors rather than returning a short list, for the reason fileIDs does: an
	// empty expansion is indistinguishable from a root that legitimately has nothing
	// left to bind, so a swallowed failure turns the policy's broadest grant into a
	// run that mounted nothing and still reported its shields.
	rootDirs func() ([]string, error)
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
	// fileIDs returns the content identity and link count of every regular file at or
	// under a host path: the file itself for a file shield, the credential files inside
	// it for a directory shield. Injected alongside the other stat seams so the alias
	// scan is testable without a real filesystem. Like mountpoints below it errors
	// rather than returning a short list, because the link counts it reports are what
	// gate the granted-tree walk: an under-count reads as proof that no hardlink exists.
	fileIDs func(string) ([]identifiedFile, error)
	// aliasesUnder returns the files under a granted tree whose content identity is one
	// of want's, keyed to the credential each aliases. Injected beside fileIDs; the two
	// are separate seams because the credential trees are small enough to enumerate
	// whole while a granted tree must be filtered as it is walked. It errors for a
	// subtree it could not read that could hold a hardlink, so an unreadable tree does
	// not scan as clean.
	aliasesUnder func(root string, want map[fileID]string) ([]credentialAlias, error)
	// mountpoints returns where the host's filesystems are attached, with the identity
	// of what sits at each. A bind exposes a credential's inode at a second path without
	// adding a directory entry to it, so no link count reveals one and the mount table is
	// the only place it shows up. It errors rather than returning a short list: the
	// hardlink half of the scan cannot cover for a missed bind, so a partial answer here
	// would report clean because it could not look.
	mountpoints func(devs []uint64) ([]mountPoint, error)
	// statID returns a single host path's content identity. Injected beside the walking
	// seams: the mount scan compares a credential's ancestor directories against what a
	// mount is attached to, which is one stat per directory, not a walk.
	statID func(string) (fileID, bool)
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
func compile(p *policy.Policy, proc enforce.Process, sb sandbox) ([]string, []enforce.ShieldApplied, error) {
	if sb.entrypoint == "" {
		return nil, nil, fmt.Errorf("linux: no entrypoint")
	}
	// observeReportFD and appliedReportFD are the same descriptor - each is the child's
	// first extra file - so a sandbox asking for both would have the two reports
	// overwriting each other. They are mutually exclusive by design, profiling producing
	// an observation rather than an enforcement report, and this is where that is checked
	// rather than only stated.
	if sb.observe && sb.applied {
		return nil, nil, fmt.Errorf("linux: a run cannot be both profiled and reported on: the observation and applied-layer reports share descriptor %d", observeReportFD)
	}
	args := baseFlags()

	// A profiling run uses the real HOME so the target probes its real credential
	// paths, but default-deny leaves home unmounted - so the directory itself would
	// be absent and a program that stats or writes $HOME on startup would bail before
	// exercising anything. An empty tmpfs gives HOME an existing, writable scratch
	// root (like the base /tmp) while every path under it stays absent until a grant
	// binds real content over it, so existence-check and write-to-home programs
	// proceed and the manifest is fuller, still with nothing sensitive exposed. It
	// goes before the grants and system mounts so those overmount it where they apply.
	if home := observeHomeTmpfs(proc, sb); home != "" {
		args = append(args, "--tmpfs", home)
	}

	reads, writes, err := resolveGrants(sb, p)
	if err != nil {
		return nil, nil, err
	}
	if err := checkGrants(sb, p, reads, writes); err != nil {
		return nil, nil, err
	}

	// A "/" read grant is expanded into its top-level children twice - once to decide
	// which granted names still need a symlink, once to bind them - and the two must
	// be the same set, or an entry appearing between the reads leaves a name bound
	// that nothing accounted for. Enumerate once here and carry the result.
	var rootDirs []string
	if slices.Contains(reads, "/") {
		if rootDirs, err = sb.rootDirs(); err != nil {
			return nil, nil, fmt.Errorf("linux: expanding the read grant of %q: %w", "/", err)
		}
	}

	// Grants are bound at their resolved targets, so a grant that names a symlink
	// (~/.bashrc -> /nix/store/...) would leave the granted name itself absent.
	// Recreate it as a symlink, before the binds: bwrap refuses --symlink onto a
	// destination that already exists.
	symlinks, err := grantSymlinks(sb, p, reads, writes, rootDirs)
	if err != nil {
		return nil, nil, err
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
			for _, top := range rootDirs {
				args = append(args, "--ro-bind-try", top, top)
			}
			continue
		}
		args = append(args, "--ro-bind-try", path, path)
	}
	for _, path := range writes {
		// Write grants are directory-granular: bwrap can only make a directory
		// writable in a way that supports creating and renaming files inside it.
		// Binding a file makes it a mount point, which returns EBUSY on the
		// save-to-temp-then-rename that editors and libraries use. So a grant that
		// names an existing file is refused, pointing at the directory instead.
		if sb.exists(path) && !sb.isDir(path) {
			return nil, nil, grantrefusal.WriteIsFile(path)
		}
		args = append(args, "--bind-try", path, path)
	}

	// The deny-list goes after the grants so it always wins - except for a shield the
	// policy explicitly opts into (yz3.2), which denyArgs skips so the grant above binds.
	//
	// Two binds do follow it, below: the entrypoint and the interpreter. They are the
	// file the run was asked to execute and the binary that executes it, so a shield
	// hiding either leaves nothing to run at all - and they are re-bound precisely to
	// enforce a stricter rule than the deny-list, read-only over a write grant that
	// would otherwise leave the running code writable. Each covers one explicitly
	// named, executable file and adds no write anywhere, so what they can expose past
	// a DenyAll shield is exactly the program the user pointed bento at.
	optIns := optInTargets(explicitShieldOptIns(sb, p.Read))
	deny, appliedShields := denyArgs(sb, exposedPaths(sb, reads, writes), writes, optIns)
	args = append(args, deny...)

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
	// The bridge's liveness pipe is the enforcing path's second extra file, and only
	// that path appends it - a profiling run has egress too but passes just its
	// observation report, so claiming fd bridgeLivenessFD there would hand the bridge
	// whatever the launcher's runtime happens to hold at that number.
	livenessFD := 0
	if socket != "" && sb.applied {
		livenessFD = bridgeLivenessFD
	}
	observeFD := 0
	if sb.observe {
		observeFD = observeReportFD
	}
	appliedFD := 0
	if sb.applied {
		appliedFD = appliedReportFD
	}
	// The launcher's Landlock backstop confines writes to exactly the paths
	// passed here: the runtime scratch mounts plus the write grants. With the
	// root remounted read-only above, those are the only paths bwrap leaves
	// writable, so Landlock never denies a granted write bwrap would allow.
	// (Both layers are still stricter on the deny-list shields, by design - a
	// shield denies the write and that is the intent.) Deriving both from this
	// one place keeps them in sync.
	block, strictBlock := execBlockFlags(execMode, seccompSupported())
	cfg := launcher.Config{
		Socket:            socket,
		BridgeLivenessFD:  livenessFD,
		Block:             block,
		StrictBlock:       strictBlock,
		Writable:          append(append([]string{}, sandboxWritableMounts...), writes...),
		ObserveFD:         observeFD,
		AppliedFD:         appliedFD,
		AllowNetworkStdio: proc.AllowNetworkStdio,
		Target:            command(p, sb),
	}
	args = append(args, sandboxBentoPath)
	return append(args, launcher.EncodeLaunch(cfg)...), shieldsApplied(appliedShields), nil
}

// shieldsApplied converts the deny-list rules a run engaged into the operator-facing
// audit record: one entry per shielded path, sorted, with the kind of shield. A
// DenyAll rule (credential stores, ~/.ssh) reports hidden; a DenyWrite rule (shell rc
// files, git hooks, editor config trees) reports read-only.
func shieldsApplied(rules []denylist.Rule) []enforce.ShieldApplied {
	if len(rules) == 0 {
		return nil
	}
	out := make([]enforce.ShieldApplied, 0, len(rules))
	for _, r := range rules {
		kind := "hidden"
		if r.Deny == denylist.DenyWrite {
			kind = "read-only"
		}
		out = append(out, enforce.ShieldApplied{Path: r.Path, Kind: kind, Source: r.Source})
	}
	slices.SortFunc(out, func(a, b enforce.ShieldApplied) int { return cmp.Compare(a.Path, b.Path) })
	return out
}

// exposedShields reports the always-on shields a bwrap run would have engaged among the
// paths visible to this run, for the degraded tier to record as exposed rather than
// applied. It runs the same deny-list match denyArgs does - naming exactly what would have
// been hidden or made read-only - and discards the argv, since the degraded tier has no
// mount namespace to apply it in. visible is the set this tier actually exposes host
// content at (its Landlock read/write set), NOT the full tier's exposedPaths: the degraded
// tier never binds an out-of-FHS interpreter's whole prefix, so a credential under it is
// not exposed here and must not be reported as if it were. Opt-ins are dropped by denyArgs.
func exposedShields(sb sandbox, visible, writes, optIns []string) []enforce.ShieldApplied {
	_, applied := denyArgs(sb, visible, writes, optIns)
	return shieldsApplied(applied)
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

// namespaceFlags are the namespace unshares and the capability-bounding-set drop that
// the real run (baseFlags) and the pre-run probe (canUnshare) MUST exercise identically.
// A host that permits some of these but rejects one - most plausibly --unshare-cgroup on
// a pre-4.6 kernel, or --cap-drop on an old bwrap - would otherwise pass a probe built
// from a hand-copied subset, report the filesystem layer Enforced, then fail at launch.
// Sharing one list keeps the probe a guaranteed superset of the run's namespace flags
// rather than a parallel list that drifts.
//
// The --cap-drop drops the whole capability bounding set. The read-only shields (DenyWrite
// credentials, the re-bound entrypoint/interpreter) are plain --ro-bind mounts; nothing in
// bento's own layers stops the target from calling mount(MS_REMOUNT|MS_BIND) to clear their
// read-only flag - the exec filter blocks only execve/execveat, Landlock has no mount hook,
// and the cross-process block is degraded-tier only. What stops that remount is the target
// having no CAP_SYS_ADMIN plus the kernel's mount-lock on the read-only bind. Unprivileged
// bwrap already yields an empty bounding set, but requesting it explicitly makes the reliance
// bento's own (robust to a setuid bwrap or a stray --cap-add) rather than an unstated bwrap
// default. bento's launcher needs no capability inside the sandbox (seccomp/Landlock/prctl
// all work with none). The nested-userns remount path is a separate vector the kernel
// mount-lock denies; cap-drop does not affect it.
var namespaceFlags = []string{
	"--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-uts", "--unshare-cgroup",
	"--cap-drop", "ALL",
}

// pseudoFSFlags are the pseudo-filesystem mounts the real run (baseFlags) and the
// pre-run probe (canUnshare) MUST exercise identically, for the same reason as
// namespaceFlags: creating the namespace and mounting into it are separate host
// permissions. Docker masks paths under /proc by default, which makes the kernel
// refuse a fresh procfs inside the new namespace while the namespace itself is
// permitted - so a probe that only unshared reported the filesystem layer enforced
// on a host where every run died at "Can't mount proc on /newroot/proc".
var pseudoFSFlags = []string{
	"--proc", "/proc",
	"--dev", "/dev",
	"--tmpfs", "/tmp",
}

func baseFlags() []string {
	flags := append([]string{"--die-with-parent", "--new-session"}, namespaceFlags...)
	return append(flags, pseudoFSFlags...)
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

	if extra := interpreterReadPath(sb); extra != "" {
		paths = append(paths, extra)
	}
	return paths
}

// interpreterReadPath returns the one host path a run must be able to read for an
// interpreter that lives outside the system paths to load its stdlib and shared
// objects, or "" when the system paths already cover it. Both tiers use it - the
// bwrap tier ro-binds it, the degraded tier grants it to Landlock - so a manifest
// profiled against a pyenv/mise/conda runtime starts the same way under either.
func interpreterReadPath(sb sandbox) string {
	// A Nix interpreter's shared libraries are themselves separate store paths,
	// so binding only its own prefix leaves it unable to load. Bind the whole
	// store instead: it is immutable and world-readable package content, so it
	// carries no user data to protect.
	if strings.HasPrefix(sb.interpreter, nixStore+"/") && sb.exists(nixStore) {
		return nixStore
	}

	// Otherwise the interpreter may still live outside the system paths (pyenv,
	// mise). Bind its install prefix so its stdlib and shared objects resolve.
	prefix := interpreterPrefix(sb.interpreter)
	if prefix == "" {
		return ""
	}
	if prefixTooBroad(sb, prefix) {
		// Naming the interpreter authorizes the interpreter, not the tree it happens to
		// sit in, so bind just the file - the same way the entrypoint is bound without a
		// grant. A wrapper script's real interpreter lives in the system paths, and a
		// single-file runtime links against system libraries, so both still run; a
		// runtime whose stdlib really is in ~/lib needs an explicit read grant for it.
		if sb.exists(sb.interpreter) {
			return sb.interpreter
		}
		return ""
	}
	if sb.exists(prefix) {
		return prefix
	}
	return ""
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

// prefixTooBroad reports whether an interpreter's install prefix covers so much of the
// host that binding it would expose far more than the interpreter. The interpreter can
// be derived from the target script's shebang, so this is adversary-influenced input,
// and nothing under /srv, /opt, or another user's home is covered by any deny-list rule.
// Every check is a one-way ratchet toward "too broad": refusing only narrows the run to
// the interpreter file, which still starts a wrapper or a system-linked single-file
// runtime, while accepting a broad prefix silently exposes a tree nobody granted.
func prefixTooBroad(sb sandbox, prefix string) bool {
	// The root itself, and any top-level directory: /srv/bin/python yields /srv, and an
	// interpreter resolving to /python3 yields "/" - the exact bind compile refuses for a
	// read grant, since it both over-exposes and stops bwrap creating the top-level mount
	// points the launcher needs.
	if prefix == "/" || filepath.Dir(prefix) == "/" {
		return true
	}
	// A home-shaped directory: some user's home, whether or not it is this user's.
	// /home/other/bin/python3 yields /home/other, whose credential shields do not apply -
	// the deny-list is anchored on sb.homes - so its ~/.ssh would be readable where the
	// running user's is hidden. Same uid, so this is exposure surface rather than
	// privilege, but it is exposure nobody asked for. Structural rather than keyed on the
	// running user's home, because that comparison fails exactly when it matters most:
	// as root, home is /root, so a sibling test would never fire for anything under /home.
	if slices.Contains(homeContainers, filepath.Dir(prefix)) {
		return true
	}
	// The prefix comes from the symlink-resolved interpreter, so the home it is compared
	// against must be resolved too: on a host where $HOME reaches the real tree through a
	// link (/home -> var/home, or a relocated home), the raw os.UserHomeDir value names a
	// different path than the prefix and this would miss it, binding the whole home tree.
	if len(sb.homes) == 0 {
		// No home means no deny-list anchor either, so there is no shield over whatever a
		// prefix might contain. That is the worst moment to widen: refuse and bind the
		// interpreter file alone.
		return true
	}
	for _, h := range sb.homes {
		home := sb.resolve(h)
		if home == "" {
			return true
		}
		// This user's own home, or any tree containing it: a ~/bin/python3 wrapper puts the
		// prefix at the home directory itself, which would bind every file in it into a
		// sandbox whose policy granted none of them. A prefix INSIDE the home (a pyenv or
		// pipx install root) is allowed - that is the case this whole function exists to
		// serve, and the deny-list shields the credential stores beside it.
		if prefix == home || policy.CoversResolved(prefix, home) {
			return true
		}
		// A sibling of this user's home, for a host whose home base is not one of the
		// containers above. Nested layouts (/home/dept/other) are still missed; the floors
		// here are a ratchet, not a proof.
		if filepath.Dir(prefix) == filepath.Dir(home) {
			return true
		}
	}
	return false
}

// homeContainers are the directories user homes are conventionally created under, so a
// prefix sitting directly inside one is somebody's home rather than an install root.
var homeContainers = []string{"/home", "/var/home", "/export/home", "/Users"}

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

// alwaysShields is the deny-list every run applies regardless of grants: the
// built-in home credential/config shields, the host's runtime state (its service
// sockets), plus any caller-supplied extra denies. Everything that enforces or
// checks the always-on shields derives from this, so a caller deny can never reach
// one place and miss another; appliedShields carries that invariant for the grant
// checks, which need the rules as denyArgs will really mount them.
func alwaysShields(sb sandbox) []denylist.Rule {
	rules := append(homeShields(sb), denylist.Runtime(sb.runtimeDir, sb.homes...)...)
	return append(rules, sb.extraDeny...)
}

// appliedShield is a deny-list rule paired with the path its shield actually mounts
// at. The rule is kept whole because a refusal names the path the deny-list built
// (~/.gnupg), not the target the host's symlinks lead to.
type appliedShield struct {
	rule     denylist.Rule
	resolved string
}

// appliedShields returns the always-on shields as denyArgs will really apply them:
// resolved, with the rules denyArgs drops removed. Every grant check goes through
// this, so a refusal can never be raised over a shield that was never mounted, and a
// drop condition added to denyArgs cannot land on one check and miss the siblings.
func appliedShields(sb sandbox) []appliedShield {
	homes := resolvedHomes(sb)
	var out []appliedShield
	for _, r := range alwaysShields(sb) {
		if rp, ok := shieldTarget(sb, r.Path, homes); ok {
			out = append(out, appliedShield{rule: r, resolved: rp})
		}
	}
	return out
}

// shieldTarget resolves a deny-list path to where its shield would mount and reports
// whether denyArgs applies it at all. Two resolutions leave nothing to shield:
//
//   - the root, which a deny dotfile symlinked to "/" reaches: tmpfs or binding over
//     it would swallow the whole sandbox root;
//   - a path that moved onto a home or an ancestor of one, where the shield would hide
//     everything the policy granted rather than one store. Only where resolution MOVED
//     it: denylist.Shieldable already guarded what it chose to emit and deliberately
//     exempts a store that IS an anchor ($HOME=/home/u/.aws beside a passwd home of
//     /home/u), which a blanket test here would silently unshield.
//
// homes are the run's anchors already resolved, hoisted by the caller because every
// caller tests many rules against one set.
func shieldTarget(sb sandbox, literal string, homes []string) (string, bool) {
	rp := sb.resolve(literal)
	if rp == "/" {
		return "", false
	}
	if rp != literal && !denylist.Shieldable(rp, homes) {
		return "", false
	}
	return rp, true
}

// resolvedHomes is the run's home anchors as the host's symlinks leave them, the form
// shieldTarget compares a moved shield against.
func resolvedHomes(sb sandbox) []string {
	homes := make([]string, len(sb.homes))
	for i, h := range sb.homes {
		homes[i] = sb.resolve(h)
	}
	return homes
}

// homeShields is the credential deny-list anchored on every home the run knows about.
func homeShields(sb sandbox) []denylist.Rule {
	var rules []denylist.Rule
	for _, h := range sb.homes {
		// Every anchor is passed to every call: a relocation env var pointing at one
		// home must not produce a rule that swallows another.
		rules = append(rules, denylist.Home(h, sb.homes...)...)
	}
	return rules
}

// shieldRules is the full deny-list for a run: the mandatory Home shields plus,
// for each write-granted checkout, the static Workspace shields and the git
// directories discovered under it (see gitDirShields). Building it in one place
// keeps denyArgs and createdShields enforcing and cleaning up the exact same
// set - a divergence would either leak a host artifact or leave a path unshielded.
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
// plantable, so it is tmpfs'd and reclaimed by createdShields. config and
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
			rules = append(
				rules,
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
func denyArgs(sb sandbox, grants, writes, optIns []string) ([]string, []denylist.Rule) {
	rules := shieldRules(sb, writes)

	// Resolve and dedup first, so ancestry and ordering below compare real paths. A
	// symlinked deny path, or a symlinked /home component, would otherwise slip past
	// reachability, and the shield must mount where bwrap can create the mount point
	// (never at a symlink, which aborts the run). Two rules that resolve to the same
	// real path (/var/run and /run on a merged host) collapse to one; only the
	// identical rule is dropped, so a path shielded two different ways keeps both.
	// shieldTarget carries the drops, shared with the grant checks so neither side can
	// refuse over a shield the other never applied.
	homes := resolvedHomes(sb)
	// Keyed on what the shield actually does and not on the whole rule: two rules can
	// name one resolved path and differ only in fields that describe it to a reader
	// (which store it holds, which env var put it there). Those produce byte-identical
	// bwrap arguments, so keying on the rule would emit the same bind twice and let a
	// field that exists for the report change what is enforced.
	type shieldKey struct {
		path string
		deny denylist.Deny
		dir  bool
	}
	seen := map[shieldKey]int{}
	resolved := make([]denylist.Rule, 0, len(rules))
	for _, r := range rules {
		rp, ok := shieldTarget(sb, r.Path, homes)
		if !ok {
			continue
		}
		r.Path = rp
		k := shieldKey{r.Path, r.Deny, r.Dir}
		if i, ok := seen[k]; ok {
			// One path can be both a default store under one anchor and a relocation
			// target under another, and which arrives first is just anchor order. A
			// shield bento would have applied anyway must not be reported as something
			// an environment variable caused, so the default claim wins the merge.
			if r.Source == "" {
				resolved[i].Source = ""
			}
			continue
		}
		seen[k] = len(resolved)
		resolved = append(resolved, r)
	}

	// A DenyWrite directory shield binds its real subtree read-only, which re-exposes
	// any DenyAll path nested inside it: the readable parent bind wins over a hidden
	// child that landed earlier, or was never emitted because no grant reached it
	// directly. Collect the DenyWrite rules whose shield actually ro-binds a real
	// directory subtree, so a DenyAll descendant of one is shielded even when only the
	// parent is granted. The test is the real kind, not the declared r.Dir: shield()
	// binds by what is on disk, so a file-declared rule pointed at a directory (an env
	// relocation like GIT_CONFIG_GLOBAL) still ro-binds the whole tree. An absent path
	// becomes an empty tmpfs and a real file has no subtree, so both expose nothing.
	var exposed []string
	for _, r := range resolved {
		if r.Deny == denylist.DenyWrite && sb.exists(r.Path) && sb.isDir(r.Path) && shieldNeeded(r, sb, grants, writes, optIns) {
			exposed = append(exposed, r.Path)
		}
	}
	underExposed := func(p string) bool {
		for _, d := range exposed {
			if policy.CoversResolved(d, p) {
				return true
			}
		}
		return false
	}

	// Emit DenyWrite shields before DenyAll shields. bwrap mounts are last-wins, so the
	// stricter DenyAll (hide) must land after any DenyWrite (readable) bind that covers
	// the same subtree, or the readable parent re-exposes a hidden child. A forced child
	// must pre-exist: mounting over an existing path inside a read-only parent is a
	// namespace op, but creating a new mount point there is EROFS and aborts the run
	// (which is also why an absent DenyAll under an exposed parent needs no shield -
	// there is nothing to hide).
	//
	// No policy that survives checkGrants can currently reach the forced-child branch:
	// firing an exposed DenyWrite parent needs a write grant at, under, or above it, and
	// for a parent with a DenyAll child all three are refused - under by
	// checkWriteNotUnderReadOnlyShield, at and above by checkWriteNotAboveShield
	// (measured: instrumenting the branch panics under the full suite only with the
	// former check removed). It is kept because the ordering property is what makes the
	// refusals safe to relax: whichever of them a later rule shape loosens, the hidden
	// child must still land after the readable parent. Pinned directly against denyArgs
	// by the carve tests, which can no longer reach it through compile.
	var args []string
	var applied []denylist.Rule
	emit := func(want denylist.Deny) {
		for _, r := range resolved {
			if r.Deny != want {
				continue
			}
			needed := shieldNeeded(r, sb, grants, writes, optIns)
			if !needed && r.Deny == denylist.DenyAll && sb.exists(r.Path) &&
				!slices.Contains(optIns, r.Path) && underExposed(r.Path) {
				needed = true
			}
			if !needed {
				continue
			}
			args = append(args, shield(r, sb)...)
			applied = append(applied, r)
		}
	}
	emit(denylist.DenyWrite)
	emit(denylist.DenyAll)
	return args, applied
}

// createdShields returns the host paths bwrap will create for this run's shield mount
// points, because the shielded path does not exist yet and a write grant makes its
// parent writable (a nonexistent path is only shielded when a write grant reaches it,
// so its parent is a read-write host bind). dirs also carries the intermediate
// directories bwrap has to make to hold one (the .git/ above an unborn .git/hooks),
// deepest first, so the caller can reclaim the whole artifact. The caller removes
// these after the run so the sandbox leaves no artifact.
//
// EXISTENCE IS READ HERE, before the run, and that is the whole safety argument: a
// path already on the host - including an intermediate directory the user already had
// - is never in the list, so cleanup can only remove something bento itself caused to
// appear. Deciding an ancestor was "obviously bwrap's" at cleanup time instead would
// reclaim a user's own empty directory that a shield merely landed inside.
//
// This selects the same shieldNeeded rules denyArgs emits, minus the DenyAll children
// denyArgs force-emits under an exposed DenyWrite ancestor: those are gated on the path
// already existing, and this returns only nonexistent paths, so bwrap never creates a
// mount point for them and there is nothing to clean up.
func createdShields(sb sandbox, grants, writes, optIns []string) (dirs, files []string) {
	rules := shieldRules(sb, writes)
	homes := resolvedHomes(sb)
	seen := map[string]bool{}
	for _, r := range rules {
		rp, ok := shieldTarget(sb, r.Path, homes)
		if !ok {
			continue
		}
		r.Path = rp
		if !shieldNeeded(r, sb, grants, writes, optIns) || sb.exists(r.Path) {
			continue
		}
		if r.Dir {
			dirs = append(dirs, r.Path)
		} else {
			files = append(files, r.Path)
		}
		// The parents bwrap must create to reach the mount point. The walk stops at
		// the first one that already exists (nothing above it is bwrap's either) and
		// at a write grant, whose directory is the user's own - prepareWriteDirs has
		// already created a granted directory that was missing, so a grant is never
		// mistaken for an artifact here.
		for d := filepath.Dir(r.Path); insideAWriteGrant(d, writes) && !sb.exists(d); d = filepath.Dir(d) {
			if !seen[d] {
				seen[d] = true
				dirs = append(dirs, d)
			}
		}
	}
	// Deepest first, so a parent is only attempted once the mount points inside it are
	// gone. Sorting by length is enough: a parent is a strict prefix of its children.
	slices.SortStableFunc(dirs, func(a, b string) int { return len(b) - len(a) })
	return dirs, files
}

// insideAWriteGrant reports whether path is STRICTLY inside a write grant and is not
// itself one, so neither the createdShields walk nor the cleanup can reach a granted
// directory - the user's own - or anything above it. A grant nested inside another
// grant is still a grant, which is why equality is checked against every write.
func insideAWriteGrant(path string, writes []string) bool {
	inside := false
	for _, w := range writes {
		if path == w {
			return false
		}
		if policy.CoversResolved(w, path) {
			inside = true
		}
	}
	return inside
}

// removeCreatedShields removes the host paths bento caused bwrap to create (see
// createdShields) after the run - a write grant on a plain directory otherwise left an
// empty .git/ with two empty files in it, host clutter no run asked for.
//
// Removal cannot destroy host content. Every path here is one that did not exist when
// the run started. A directory goes only by rmdir, which refuses a non-empty one -
// and rmdir, not os.Remove, precisely so that a path which is no longer a directory
// is left alone rather than unlinked. A file goes only while it is still zero bytes,
// which holds nothing, so a host-side atomic save (write-temp then rename) leaves a
// non-empty file that is skipped.
//
// Two residuals, both requiring a host process to touch one of these paths during the
// window the run occupied. A process that CREATED one and still holds the descriptor
// loses its later writes to an unlinked inode. And the zero-length check is not atomic
// with the unlink: a write landing between the two is removed with the file.
//
// Best effort throughout: a kill before this runs leaves the artifact, as before.
func removeCreatedShields(dirs, files []string) {
	for _, f := range files {
		if fi, err := os.Lstat(f); err != nil || !fi.Mode().IsRegular() || fi.Size() != 0 {
			continue
		}
		os.Remove(f)
	}
	// dirs is deepest first, so the mount points inside an intermediate directory are
	// gone by the time it is tried.
	for _, d := range dirs {
		_ = syscall.Rmdir(d)
	}
}

// shieldNeeded decides whether a deny rule needs a shield mount, given what the
// grants expose. Beyond protecting the path, this avoids asking bwrap to bind a
// shield over a path whose parent is read-only - which it cannot do - for paths
// that are not actually a threat there.
func shieldNeeded(r denylist.Rule, sb sandbox, grants, writes, optIns []string) bool {
	// An exact opt-in grant (yz3.2) wins over the shield: skip it so the grant binds
	// the real content instead of being overmounted. r.Path is already resolved by the
	// caller, matching the resolved paths in optIns. Only DenyAll shields are opt-in-able:
	// the opt-in is a READ escape, and a DenyWrite shield's content is readable already,
	// so there is nothing for it to grant but the write it exists to refuse. A write grant
	// under one is rejected by checkWriteNotUnderReadOnlyShield rather than reaching here.
	if r.Deny == denylist.DenyAll && slices.Contains(optIns, r.Path) {
		return false
	}
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
	case r.Deny == denylist.DenyAll:
		// A tmpfs hides a directory's contents and absorbs new files; a file cannot take
		// a tmpfs, so an empty read-only bind hides it (contents unreadable, writes
		// rejected). Pick from the real kind when the path exists rather than the declared
		// r.Dir - ~/.cert is a directory on one host, a file on another - so bwrap is never
		// handed a tmpfs-over-file or file-over-dir mount that aborts the run. When absent,
		// synthesize per the declared kind.
		dir := r.Dir
		if sb.exists(r.Path) {
			dir = sb.isDir(r.Path)
		}
		if dir {
			return []string{"--tmpfs", r.Path}
		}
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

// checkGrants runs every grant-safety check that must hold before a policy's reads
// and writes are honored, whatever tier enforces them. The full (bwrap) tier and the
// degraded (Landlock-only) tier share it: a grant that names a credential shield, a
// host process, a managed pseudo-filesystem, or a symlink loop is refused the same way
// in both, so --allow-degraded can never accept a manifest the full tier hard-refuses.
// reads and writes are the resolved grants; p carries the unresolved paths the process
// and managed-mount checks re-resolve for their own diagnostics.
func checkGrants(sb sandbox, p *policy.Policy, reads, writes []string) error {
	// First: the shield checks below skip "/" and rely on it being refused already.
	if err := checkWriteNotRoot(writes); err != nil {
		return err
	}
	optInShields := optInTargets(explicitShieldOptIns(sb, p.Read))
	// Only reads carry the opt-in: a write grant under a shield the policy also reads
	// must stay refused, so it is checked against no opt-ins at all - and refused in a
	// sentence that does not offer the read's remedy.
	if err := checkReadNotShielded(sb, reads, optInShields); err != nil {
		return err
	}
	if err := checkWriteNotShielded(sb, writes); err != nil {
		return err
	}
	if err := checkWriteNotUnderReadOnlyShield(sb, writes); err != nil {
		return err
	}
	if err := checkWriteNotAboveShield(sb, writes); err != nil {
		return err
	}
	if err := checkWorkspaceShieldNotRedirected(sb, writes); err != nil {
		return err
	}
	if err := checkGrantNotProcess(sb, p); err != nil {
		return err
	}
	if err := checkGrantNotManagedMount(sb, p); err != nil {
		return err
	}
	return checkGrantNotLooped(p)
}

// checkReadNotShielded and checkWriteNotShielded are the two kinds the check below comes
// in. They share every rule and differ only in the sentence they refuse with, because the
// read opt-in InsideShield names is read-only by construction (see explicitShieldOptIns)
// - naming it to the author of a write grant instructs them to add a line that will not
// lift their refusal.
func checkReadNotShielded(sb sandbox, reads, optInShields []string) error {
	return checkNotShielded(sb, reads, optInShields, grantrefusal.InsideShield)
}

func checkWriteNotShielded(sb sandbox, writes []string) error {
	return checkNotShielded(sb, writes, nil, grantrefusal.WriteInsideShield)
}

// checkNotShielded rejects a grant that falls inside a fully-shielded location
// (a DenyAll deny-list directory such as ~/.ssh). Such a grant cannot be honored
// - the shield wins - so silently dropping it would leave the user believing a
// path is available when it is not. A READ grant that *contains* a shield is fine
// and common (read: ~ with ~/.ssh shielded inside it); a WRITE grant that contains
// one is refused separately by checkWriteNotAboveShield, since it would make the
// shield's parent writable.
//
// refuse is the sentence the grant's kind is refused in; the two wrappers above are the
// only callers, so a third kind cannot arrive without choosing one.
func checkNotShielded(sb sandbox, grants, optInShields []string, refuse func(grant, shield string) error) error {
	// The shields as denyArgs applies them: resolved, so a grant naming a symlinked
	// shield's real target (write: /data/keys with ~/.ssh -> /data/keys) is caught
	// rather than silently honored, and with denyArgs' drops carried, so a rule it
	// never mounts cannot refuse a run and blame an unrelated dotfile for it.
	shields := appliedShields(sb)
	for _, g := range grants {
		for _, s := range shields {
			r, rp := s.rule, s.resolved
			if r.Deny != denylist.DenyAll {
				continue
			}
			// A READ grant that names the shielded path itself is a deliberate, warned
			// opt-in (a program that legitimately reads ~/.ssh, no source change): honor it
			// - denyArgs skips the shield so the real content binds read-only, and Run
			// warns. optInShields carries the built-in shields whose LITERAL deny-list path
			// a READ named (see explicitShieldOptIns); a write grant, or a read of a
			// symlink's resolved target, is NOT an opt-in and stays refused, so the shield
			// cannot be written through or side-stepped by spelling out where it points. A
			// grant strictly inside a shield is likewise refused - a shield entry cannot be
			// partly lifted - so opting one file in means naming the shielding directory
			// and taking its siblings with it. Only a directory entry has an inside; where
			// the entry is a file (~/.netrc) the exact match is the only way in either way.
			if policy.CoversResolved(rp, g) && !slices.Contains(optInShields, rp) {
				// Which sentence depends on whose shield it is: the opt-in InsideShield
				// offers exists only for the built-ins, so pointing a caller-denied grant at
				// it would name an escape that is not there.
				if callerDenied(sb, rp) {
					return grantrefusal.InsideCallerShield(g, r.Path)
				}
				return refuse(g, r.Path)
			}
		}
	}
	return nil
}

// checkWriteNotUnderReadOnlyShield rejects a write grant at or inside a DenyWrite
// shield (~/.local/bin, ~/.cargo/bin, ~/.rustup, ~/.bashrc, ...). Such a grant never
// reached the host, and refusing says so at the one moment the author can act on it.
//
// It failed three different ways before, which is why the refusal is worth more than any
// of them: where the shield path exists, its ro-bind is emitted after the grant's bind
// and wins, so every write fails EROFS; where it does NOT exist, the shield is a tmpfs,
// so writes SUCCEED into a discarded scratch mount and the script exits zero having
// written nothing - the worst of the three, since nothing fails at all; and in the
// degraded Landlock-only tier there are no binds, so the write landed on the real host
// path. That last one is the reason this sits in checkGrants rather than beside the bind
// logic: both tiers share it, so --allow-degraded cannot accept what the full tier only
// pretended to honor.
//
// There is deliberately no opt-in, unlike the DenyAll shields. That escape (yz3.2) is
// READ-only by construction - explicitShieldOptIns takes the policy's reads, and a write
// grant to a shielded store is the key-planting threat the deny-list exists to stop. A
// DenyWrite shield is nothing BUT that write surface: its whole content is readable
// already, so an opt-in could only ever grant the plant. Extending the mechanism here
// would not be symmetry with DenyAll, it would be the case DenyAll's own opt-in refuses.
//
// The consequence is real and intended: `rustup update`, `nvm install`, `npm i -g`,
// `gem install --user-install` and `cargo install` cannot be granted, because each
// mutates the host's $PATH from inside a sandbox. The registry and build caches
// (~/.cargo/registry, ~/.m2, ~/.gradle) are not shielded, so an ordinary build is
// unaffected.
//
// Only the always-on shields are checked, never the workspace ones: those derive from
// the write grants themselves (.git/hooks and .vscode under a granted checkout), so
// refusing a grant that contains them would refuse every project write grant.
func checkWriteNotUnderReadOnlyShield(sb sandbox, writes []string) error {
	shields := appliedShields(sb)
	for _, g := range writes {
		for _, s := range shields {
			if s.rule.Deny != denylist.DenyWrite {
				continue
			}
			if policy.CoversResolved(s.resolved, g) {
				return grantrefusal.WriteUnderReadOnlyShield(g, s.rule.Path)
			}
		}
	}
	return nil
}

// explicitShieldOptIns finds the built-in DenyAll shields the policy opts into by
// READING them - the caveat-emptor escape yz3.2 adds (a program that legitimately reads
// ~/.ssh, exposed read-only with a warning). Deliberate scope:
//
//   - Read grants only. A WRITE grant to a credential store is the key-planting threat
//     the deny-list exists to stop, so it is never an opt-in and stays refused; passing
//     literalReads (not writes) is what enforces that.
//   - A shield is opted in only when a read names its LITERAL deny-list path (~/.ssh); a
//     read that merely resolves to the same place (a symlink's target) is a side-step the
//     shield still refuses, so the match is on the unresolved grant string. The names
//     that count are the ones the deny-list built, and those are built from the run's
//     homes - so where $HOME reaches the real home through a symlink, the grant that opts
//     in is spelled with the link and the store exposed is the link's target. That is not
//     closable from here: the same shape is a caller aliasing the home and a host whose
//     home is legitimately a symlink, and refusing it would break the second. The
//     frontend names the resolved store in its warning so the exposure is not read as
//     the literal path alone.
//   - Built-in Home/Runtime shields only, never sb.extraDeny: a caller-supplied deny (a
//     supervising embedder shielding its own control store from an untrusted target) is a
//     different trust domain the profiled policy must not be able to lift. Building the
//     set from the built-ins is not enough on its own, because both consumers match a
//     bare resolved path: where a caller deny lands on the same host path as a built-in
//     (it names ~/.aws defensively, or its own store is a symlink there), an opt-in of
//     the built-in would carry the caller's shield away with it. So a built-in whose
//     store a caller deny also covers is not opt-in-able at all, and the read grant
//     stays refused.
//
// literalReads are the policy's own absolute, un-symlink-resolved read paths. Sorted by
// literal path, which is the order the reported opt-ins keep.
func explicitShieldOptIns(sb sandbox, literalReads []string) []shieldOptIn {
	builtin := append(homeShields(sb), denylist.Runtime(sb.runtimeDir, sb.homes...)...)
	var out []shieldOptIn
	for _, r := range builtin {
		if r.Deny != denylist.DenyAll {
			continue
		}
		if slices.Contains(literalReads, r.Path) {
			onHost := sb.resolve(r.Path)
			if callerDenied(sb, onHost) {
				continue
			}
			out = append(out, shieldOptIn{path: r.Path, onHost: onHost, holds: r.Holds})
		}
	}
	slices.SortFunc(out, func(a, b shieldOptIn) int { return cmp.Compare(a.path, b.path) })
	return out
}

// callerDenied reports whether a caller-supplied deny covers a resolved host path. Both
// sides are resolved because a caller names its store in its own spelling and the shield
// binds where that lands.
func callerDenied(sb sandbox, onHost string) bool {
	for _, r := range sb.extraDeny {
		rp := sb.resolve(r.Path)
		if onHost == rp || policy.CoversResolved(rp, onHost) {
			return true
		}
	}
	return false
}

// shieldOptIn is one such shield: the grant's literal spelling, the store it binds (which
// checkNotShielded and denyArgs key off, since grants and shields are compared resolved),
// and what the lifted shield was hiding. The three travel together because a caller
// pairing separate slices by index reports one grant as reaching another's target the
// moment a symlink puts a store somewhere that sorts elsewhere.
type shieldOptIn struct {
	path   string
	onHost string
	holds  denylist.Holds
}

func optInPaths(optIns []shieldOptIn) []string {
	out := make([]string, 0, len(optIns))
	for _, o := range optIns {
		out = append(out, o.path)
	}
	return out
}

func optInTargets(optIns []shieldOptIn) []string {
	out := make([]string, 0, len(optIns))
	for _, o := range optIns {
		out = append(out, o.onHost)
	}
	return out
}

// reportedOptIns renders the opt-ins for the Result. OnHost is filled only where the
// grant reached somewhere other than its own name; the resolution is the compile-time one
// the binds themselves use, so the report names what was exposed rather than what the
// path points at once the target has exited.
func reportedOptIns(optIns []shieldOptIn) []enforce.ShieldedGrant {
	var out []enforce.ShieldedGrant
	for _, o := range optIns {
		g := enforce.ShieldedGrant{Path: o.path, Holds: o.holds.Code()}
		if o.onHost != o.path {
			g.OnHost = o.onHost
		}
		out = append(out, g)
	}
	return out
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
				return fmt.Errorf("write grant %q shields %q, but a symlinked directory component redirects it to %q, so the shield would protect the wrong path while the symlink stays writable; remove the symlink or grant a narrower directory", w, r.Path, real)
			}
		}
	}
	return nil
}

// checkWriteNotRoot refuses a write grant of the host root. Unlike a read grant,
// "/" is never expanded for writes: making the entire host root writable would
// defeat the sandbox, and it is never a real grant. It lives here rather than in
// compile's write-grant loop because the degraded tier never compiles an argv - it
// hands the grants to landlock.RestrictDegraded, where a "/" write is host-root
// write with nothing above it.
func checkWriteNotRoot(writes []string) error {
	if slices.Contains(writes, "/") {
		return fmt.Errorf("write grant \"/\" would make the entire host root writable; grant a specific directory")
	}
	return nil
}

func checkWriteNotAboveShield(sb sandbox, writes []string) error {
	// Only the shields denyArgs really mounts: a rule it drops protects nothing, so
	// refusing a grant that sits above it would blame a shield that never existed.
	// The comparison below stays on the literal path - see the loc comment.
	shields := appliedShields(sb)
	for _, w := range writes {
		if w == "/" {
			continue // rejected with a clearer message by checkWriteNotRoot
		}
		for _, s := range shields {
			r := s.rule
			if r.Deny != denylist.DenyAll {
				continue
			}
			// The tamperable entry is the shield's name in the granted directory, so
			// compare its location - parent resolved so it shares the grant's namespace,
			// own name kept literal - rather than its symlink target, which lies outside
			// the grant.
			loc := filepath.Join(sb.resolve(filepath.Dir(r.Path)), filepath.Base(r.Path))
			// The resolved location alone misses the case where it is the SHIELD that
			// moves out of the grant: with a symlinked home (/home/u -> /data/u), loc is
			// /data/u/.ssh while the grant is /home, so the containment is only visible in
			// the unresolved namespace. The grant still holds the home symlink, and a run
			// that can replace it points home at a directory it controls and plants a real
			// .ssh there - the exact key-planting this check exists to stop. Refusing on
			// either namespace costs nothing: a shield with no symlink above it resolves to
			// itself, so the two tests coincide everywhere else.
			if policy.CoversResolved(w, loc) || policy.CoversResolved(w, r.Path) {
				return grantrefusal.WriteAboveShield(w, r.Path)
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
		real, err := resolveGrant(sb, g)
		if err != nil {
			return err
		}
		if isProcessPath(real) && sb.exists(real) {
			return fmt.Errorf("grant %q resolves to %q, a host process's directory in /proc; the sandbox has a pid namespace and a /proc of its own, where that pid is a different process or none at all; remove the grant - /proc is always mounted", g, real)
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
func checkGrantNotManagedMount(sb sandbox, p *policy.Policy) error {
	for _, g := range append(append([]string{}, p.Read...), p.Write...) {
		real, err := resolveGrant(sb, g)
		if err != nil {
			return err
		}
		for _, m := range baseFlagsPseudoFS {
			if real == m {
				return fmt.Errorf("grant %q resolves to %q, a pseudo-filesystem the sandbox mounts fresh; granting it whole would overmount the sandbox's hardened %s with the host's and re-expose host process environs, device nodes, or other processes' temp files; %s is always mounted - grant a specific path inside it instead", g, real, m, m)
			}
		}
	}
	return nil
}

// checkGrantNotLooped refuses a grant whose symlinks loop. pathresolve.Existing leaves
// a loop unresolved on purpose - a shield on one still fails closed - but a grant
// is then bound at the looping path itself, and --ro-bind-try tolerates only a
// missing source (ENOENT), not ELOOP, so bwrap aborts the run naming itself
// rather than the grant. A dangling symlink is not a loop and stays supported:
// it resolves to a target that simply does not exist yet.
//
// The check asks the kernel (os.Stat/ELOOP) rather than the sandbox's resolver
// seam, and stays that way deliberately. sb.resolve cannot report a loop - it
// returns the path unchanged, which is also its answer for a path that is no
// symlink at all - and a fake that walked only the granted leaf would miss a loop
// in a parent component and pass where production refuses. A seam whose fake
// disagrees with the kernel is worse than none, so the loop cases are covered
// against real symlink trees instead (TestCheckGrantNotLoopedRealFilesystem).
func checkGrantNotLooped(p *policy.Policy) error {
	for _, g := range append(append([]string{}, p.Read...), p.Write...) {
		abs, err := filepath.Abs(g)
		if err != nil {
			return fmt.Errorf("linux: %q: %w", g, err)
		}
		if _, err := os.Stat(abs); errors.Is(err, syscall.ELOOP) {
			return grantrefusal.Looped(g)
		}
	}
	return nil
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
		if path == g || policy.CoversResolved(g, path) || policy.CoversResolved(path, g) {
			return true
		}
	}
	return false
}

// resolveGrants makes every granted path absolute and symlink-free.
//
// Resolving is the defense against a symlinked grant: if `write: /tmp/out` points
// at ~/.ssh, we bind the real target, and the deny-list - which runs after and
// also works on real paths - still shields it. Binding the unresolved path would
// have let the symlink redirect the mount.
func resolveGrants(sb sandbox, p *policy.Policy) (reads, writes []string, err error) {
	if reads, err = resolveAll(sb, p.Read); err != nil {
		return nil, nil, err
	}
	if writes, err = resolveAll(sb, p.Write); err != nil {
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
func grantSymlinks(sb sandbox, p *policy.Policy, reads, writes, rootDirs []string) ([]string, error) {
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
			filled = append(filled, rootDirs...)
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
		real, err := resolveGrant(sb, abs)
		if err != nil {
			return nil, err
		}
		if real == abs {
			continue
		}
		hop := missingHop(sb, abs, real, filled)
		if hop == "" || seen[hop] {
			continue
		}
		seen[hop] = true
		links = append(links, [2]string{real, hop})
	}
	slices.SortFunc(links, func(a, b [2]string) int { return cmp.Compare(a[1], b[1]) })

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
//
// The chain walk reads the host's links directly (os.Readlink), and only the
// parent resolution goes through sb.resolve, matching how grantSymlinks resolved
// the grant itself. There is no readlink seam: a fake one would have to
// reimplement kernel link-following, which is the same hybrid that resolving
// grants off the seam produced. The multi-hop cases are covered against real
// symlink trees instead (TestGrantSymlinksMultiHopRealFilesystem).
func missingHop(sb sandbox, abs, real string, filled []string) string {
	cur := abs
	for range pathresolve.MaxDepth {
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
			target = filepath.Join(sb.resolve(filepath.Dir(cur)), target)
		}
		// Resolve the target's parent so it lands where the kernel would, but keep
		// its own name literal - the next link's location is wanted here, not the
		// thing it points at.
		next := filepath.Join(sb.resolve(filepath.Dir(target)), filepath.Base(target))
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
		if path == r || policy.CoversResolved(r, path) {
			return true
		}
	}
	return false
}

func resolveAll(sb sandbox, paths []string) ([]string, error) {
	out := make([]string, 0, len(paths))
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		r, err := resolveGrant(sb, p)
		if err != nil {
			return nil, err
		}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	slices.Sort(out)
	return out, nil
}

// resolveGrant resolves a policy grant through the sandbox's resolver seam, so a
// grant and a shield are compared on the same footing. Both used to reach the host
// filesystem directly and so agreed in production, but only shields went through
// sb.resolve - which left every fake-filesystem test resolving fake shield paths
// against real-host-resolved grants, a hybrid that never runs.
func resolveGrant(sb sandbox, path string) (string, error) {
	abs := path
	if !filepath.IsAbs(path) {
		wd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("linux: %q: %w", path, err)
		}
		abs = filepath.Clean(wd) + "/" + path
	}
	return sb.resolve(abs), nil
}

// resolve returns an absolute, symlink-resolved path. A path that does not exist
// yet (a write target) is resolved as far as it does exist, so the parts that
// could be a symlink are still followed.
func resolve(path string) (string, error) {
	abs := path
	if !filepath.IsAbs(path) {
		wd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("linux: %q: %w", path, err)
		}
		abs = filepath.Clean(wd) + "/" + path
	}
	return pathresolve.Existing(abs), nil
}

// envArgs clears the inherited environment and sets only what the policy allowed
// through, plus the minimum an interpreter needs to run.
func envArgs(proc enforce.Process) []string {
	args := []string{"--clearenv"}
	for _, k := range slices.Sorted(maps.Keys(proc.Env)) {
		args = append(args, "--setenv", k, proc.Env[k])
	}
	if _, ok := proc.Env["PATH"]; !ok {
		args = append(args, "--setenv", "PATH", enforce.SandboxPath)
	}
	if _, ok := proc.Env["HOME"]; !ok {
		args = append(args, "--setenv", "HOME", enforce.SandboxHome)
	}
	return args
}

// observeHomeTmpfs returns the HOME path to cover with an empty tmpfs during a
// profiling run, or "" when none should be added. Only for profiling (sb.observe):
// an enforced run's HOME is either the base /tmp or built from the grants, and must
// not be shadowed by an empty overlay. Skips "/" (the tmpfs would swallow the whole
// root) and "/tmp" (already the base tmpfs). The path must be absolute; a relative
// HOME is not a mountable target and envArgs would pass it through unchanged.
func observeHomeTmpfs(proc enforce.Process, sb sandbox) string {
	if !sb.observe {
		return ""
	}
	home := proc.Env["HOME"]
	if !filepath.IsAbs(home) || home == "/" || home == "/tmp" {
		return ""
	}
	return filepath.Clean(home)
}

// command builds the argv both tiers launch: the interpreter and its own options
// (when there is one), then the entrypoint and the script's args. Shared rather than
// assembled per tier - a degraded run that ordered these differently would run a
// different program than the one bwrap runs from the same approved manifest.
//
// InterpreterArgs precede the entrypoint because that is where the interpreter reads
// its options; after it they would be the script's argv.
func command(p *policy.Policy, sb sandbox) []string {
	var cmd []string
	if sb.interpreter != "" {
		cmd = append(cmd, sb.interpreter)
		cmd = append(cmd, p.InterpreterArgs...)
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
func hostRootDirs() ([]string, error) {
	entries, err := os.ReadDir("/")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if slices.Contains(baseFlagsPseudoFS, "/"+e.Name()) {
			continue
		}
		out = append(out, "/"+e.Name())
	}
	return out, nil
}
