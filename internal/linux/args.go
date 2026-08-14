//go:build linux

package linux

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/grantrefusal"
	"github.com/whiskeyjimbo/bento/internal/launcher"
	"github.com/whiskeyjimbo/bento/internal/shield"
	"github.com/whiskeyjimbo/bento/policy"
	"github.com/whiskeyjimbo/bento/profile"
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
	// ProfileOptions.DenyPaths). Empty for an ordinary run. Every place that reads the
	// run's shields goes through the one assembled set, so these reach all of them.
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
	// recordExec signals that the run asked for a record of the execs it performs, which
	// the launcher writes into the applied report's second section. It rides the applied
	// report rather than a descriptor of its own: that channel is already the enforced
	// run's report, and there is nothing for a second one to separate.
	recordExec bool
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
	// writable reports whether this uid may create entries in an existing host
	// directory. Injected alongside exists; used to refuse a write grant whose tree
	// bwrap cannot carve a shield mount point into before the launch turns that into
	// an unattributed setup failure.
	writable func(string) bool
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
	// listDir returns a directory's immediate children, split into the real
	// subdirectories the scan may descend into and the symlinked entries it may not,
	// plus whether it was read WHOLE. ok is false when the path is not a directory OR
	// could not be enumerated to the end (e.g. an unreadable dir): the caller must
	// distinguish an enumerated empty directory from one it could not see into, so a
	// chmod cannot silently hide gitdirs from the scan. A read that fails part way
	// through still returns the entries it got, so a caller failing closed on the
	// remainder can cover them too. The links are reported rather
	// than dropped because a name the scan skips is a name no rule covers, and the
	// checks that refuse a redirected shield only inspect the rules it returned.
	// Injected alongside exists so the git-directory scan (gitDirShields) is testable
	// against a hypothetical filesystem.
	listDir func(string) (names, links []string, ok bool)
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
	// mount is attached to, which is one stat per directory, not a walk. Required on any
	// sandbox whose grants are checked - the shield set asks it whether the mount holding
	// a store folds case, and a sandbox without it cannot answer.
	statID func(string) (fileID, bool)
	// workspaceShieldCache memoizes workspaceShields per checkout root for one run.
	// Every consumer derives the same rules from the same tree - shieldRules, reached
	// by both denyArgs and createdShields, plus checkWriteNotUnderReadOnlyShield and
	// checkWorkspaceShieldNotRedirected - and checkGrants runs twice, so N write grants
	// under one checkout re-walk its .git/modules tree at least six times.
	//
	// The tree is not frozen across those calls - prepareWriteDirs mkdirs the granted
	// write directories after checkGrants has already populated the cache. What makes
	// the memo sound is that the KEY is recomputed every call: checkoutRoot runs fresh,
	// so a mkdir that moves the anchor (a grant of an unborn <repo>/.git) produces a
	// miss and a fresh walk, not a stale hit. Within one anchor the only mutation is
	// that mkdir, which adds an empty directory and no gitdir, so it emits nothing
	// either way. Single-goroutine: shields are derived before the sandbox starts.
	//
	// Allocated at construction rather than on first use because the sandbox is passed
	// by value: a map made lazily would live in one copy and be invisible to every other
	// call site. A test literal leaves it nil, where the walk simply runs each time.
	workspaceShieldCache map[string][]denylist.Rule
	// shieldCache memoizes the run's assembled shield set. Assembling it walks every
	// DenyAll credential/history/persistence store on the host - isDir/listDir/resolve per
	// entry - and the set is reached roughly ten times per compile: the mount emission from
	// both denyArgs and createdShields, each grant check with checkGrants running twice,
	// plus the alias scan, the degraded tier and the launch path. Bounded trees, but ten
	// enumerations of them on a cold cache or an NFS home is launch latency for nothing.
	//
	// Unkeyed, unlike workspaceShieldCache: the input is sb.homes, sb.runtimeDir and
	// sb.extraDeny, which do not change within a run. What makes it sound for the whole
	// run is that the walk descends only inside
	// DenyAll stores, where a write grant is refused outright - so prepareWriteDirs' mid-run
	// mkdir of the granted write directories cannot reach one, let alone plant a symlink in
	// it. Single-goroutine: shields are derived before the sandbox starts.
	//
	// A pointer allocated at construction rather than a value, because the sandbox is passed
	// by value: a memo written into one copy would be invisible to every other call site. A
	// test literal leaves it nil, where the walk simply runs each time.
	shieldCache *shieldMemo
}

// shieldMemo is one run's assembled shield set. done is carried apart from the set
// because assembling it walks the credential stores on disk and the ordinary host keeps
// no dotfile farm at all: an empty expansion is the answer, not a miss, and without the
// flag that host would re-walk on every question.
type shieldMemo struct {
	done bool
	set  shield.Set
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
	// policy explicitly opts into, which denyArgs skips so the grant above binds.
	//
	// Two binds do follow it, below: the entrypoint and the interpreter. They are the
	// file the run was asked to execute and the binary that executes it, so a shield
	// hiding either leaves nothing to run at all - and they are re-bound precisely to
	// enforce a stricter rule than the deny-list, read-only over a write grant that
	// would otherwise leave the running code writable. Each covers one explicitly
	// named, executable file and adds no write anywhere, so what they can expose past
	// a DenyAll shield is exactly the program the user pointed bento at.
	optIns := shield.Targets(explicitShieldOptIns(sb, p.Read))
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
		// Passed on whatever the exec mode, though only exec: all can honour it: the block
		// execveats the target over the launcher, leaving no supervisor to be the tracer.
		// Withholding the flag there would leave the host with no section to read and no
		// way to tell a mode that cannot be recorded from a stage that never reported;
		// the launcher writes the recorder absent with its own reason instead.
		RecordExec: sb.recordExec,
		Target:     command(p, sb),
	}
	args = append(args, sandboxBentoPath)
	return append(args, launcher.EncodeLaunch(cfg)...), shieldsApplied(sb, appliedShields), nil
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
// read-only flag - the exec filter blocks execve and leaves execveat open by construction,
// Landlock has no mount hook, and the cross-process block is degraded-tier only. What
// stops that remount is the target
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
	prefix := enforce.InterpreterPrefix(sb.interpreter)
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
	if slices.Contains(profile.HomeContainers(), filepath.Dir(prefix)) {
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
		// resolve answers the input unchanged when it cannot resolve, so a non-empty home
		// is always a non-empty comparison (TestHostResolveNeverAnswersEmpty pins it).
		home := sb.resolve(h)
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

// envArgs clears the inherited environment and sets only what the policy allowed
// through, plus the minimum an interpreter needs to run.
func envArgs(proc enforce.Process) []string {
	env := sandboxEnv(proc.Env, enforce.SandboxHome)
	args := []string{"--clearenv"}
	for _, k := range slices.Sorted(maps.Keys(env)) {
		args = append(args, "--setenv", k, env[k])
	}
	return args
}

// sandboxEnv fills in the HOME and PATH a target sees when the policy passes neither
// through. Both tiers build their environment from here, because a `~` or a bare command
// name resolving on one tier and not the other is one manifest meaning two things.
//
// home is the tier's own default rather than enforce.SandboxHome unconditionally: under
// bwrap /tmp is a fresh writable tmpfs, and on the degraded tier - which has no mount
// namespace - it is the host's, in neither the Landlock read set nor the write set. A
// default HOME there would name a path the target cannot touch, so the degraded tier
// passes the scratch directory that stands in for the tmpfs. What HOME MEANS is what has
// to match across the tiers; the literal cannot.
func sandboxEnv(policyEnv map[string]string, home string) map[string]string {
	env := maps.Clone(policyEnv)
	if env == nil {
		env = map[string]string{}
	}
	if _, ok := env["PATH"]; !ok {
		env["PATH"] = enforce.SandboxPath
	}
	if _, ok := env["HOME"]; !ok {
		env["HOME"] = home
	}
	return env
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
	// Cleaned before the guard: "/." and "//" both name the root and "/tmp/" the base
	// tmpfs, and comparing the raw spelling lets each past the skip above.
	home := filepath.Clean(proc.Env["HOME"])
	if !filepath.IsAbs(home) || home == "/" || home == "/tmp" {
		return ""
	}
	return home
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

// hostListDir splits a directory's immediate children into the real subdirectories
// and the symlinked entries. gitDirShields walks names unconditionally, so a symlink
// (DirEntry.Type reports it without a follow) must not be traversed or it could escape
// .git/modules or loop; it is reported as a link instead so the caller can still cover
// the name. Regular files are neither.
//
// ok=false means the read did not complete - not a directory, or one we cannot read (e.g.
// mode 0111, still traversable-by-name so host git reaches hooks inside it) - and lets the
// caller fail closed rather than treat it as empty. The entries read before the error come
// back anyway: a truncated read on a network home has real names in it, and the credential
// expansion covers link targets it can rediscover no other way.
func hostListDir(path string) (names, links []string, ok bool) {
	entries, err := os.ReadDir(path)
	for _, e := range entries {
		switch {
		case e.IsDir(): // DirEntry.IsDir is false for a symlink (even to a directory)
			names = append(names, e.Name())
		case e.Type()&os.ModeSymlink != 0:
			links = append(links, e.Name())
		}
	}
	return names, links, err == nil
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

// hostWritable reports whether this uid may create entries in a directory. It asks the
// kernel rather than comparing mode bits against the uid, so an ACL or a group grant
// answers the same way the mkdir bwrap is about to attempt will.
func hostWritable(dir string) bool {
	return unix.Access(dir, unix.W_OK) == nil
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
		if slices.Contains(denylist.ManagedMounts, "/"+e.Name()) {
			continue
		}
		out = append(out, "/"+e.Name())
	}
	return out, nil
}
