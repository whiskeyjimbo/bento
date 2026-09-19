//go:build linux

package launcher

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// sandboxTmp is the scratch directory bwrap mounts a fresh tmpfs over (--tmpfs /tmp, see
// internal/linux's pseudoFSFlags). It is read from inside the sandbox, so statfs answers
// for the mount the namespace actually carries and not for the host's.
const sandboxTmp = "/tmp"

// verifyFreshTmp is the launcher's own check that /tmp is the empty tmpfs the run was
// admitted on, for the reason verifyEmptyNetns exists: the flag that asks for it goes
// through the same PATH-resolved bwrap that would be doing the lying, and here nothing
// else backstops it. /tmp is in sandboxWritableMounts, so the Landlock ruleset grants
// writes to whatever is mounted there - a host /tmp left in place is readable AND
// writable to the target, exposing every other user's scratch files for the whole run
// while the report says the filesystem layer was enforced.
//
// The kernel answers it in one statfs: a fresh tmpfs reports TMPFS_MAGIC, a --bind of the
// host's /tmp reports whatever that filesystem is.
func verifyFreshTmp() error {
	var st unix.Statfs_t
	if err := unix.Statfs(sandboxTmp, &st); err != nil {
		// Loudly, not skipped, for verifyEmptyNetns' reason: the mount bento cannot
		// inspect is the one it was asked to vouch for.
		return fmt.Errorf("launcher: statfs of %s to verify the sandbox's scratch mount: %w", sandboxTmp, err)
	}
	if !isTmpfs(int64(st.Type)) {
		return fmt.Errorf("launcher: %s is not the fresh tmpfs this run was admitted on; it is filesystem type %#x, so the target holds a granted write over the host's scratch directory", sandboxTmp, st.Type)
	}
	return nil
}

// isTmpfs reports whether a statfs filesystem type is tmpfs. Split from the statfs so the
// verdict is testable without a mount namespace: on a host that restricts unprivileged
// user namespaces, a test cannot mount a tmpfs to produce the accepting case.
func isTmpfs(fsType int64) bool { return fsType == unix.TMPFS_MAGIC }

// verifyPidNamespace is the launcher's own check that it is in the unshared pid namespace
// the run was admitted on, for verifyEmptyNetns' reason and with less backstop than
// either: Landlock is a filesystem layer and has no pid-namespace analogue, and the
// pre-run capability probe goes through the same PATH-resolved bwrap a shim would be
// replacing, so it is lied to identically. A sandbox left on the host's pid namespace
// sees every process on the machine and their /proc entries.
//
// This runs before the bridge is started and before the target is reached, so the
// launcher has spawned nothing: the only processes that can legitimately be in its
// namespace are bwrap's pid 1 and the launcher itself. That is asserted rather than a
// count, because bwrap's own helper count varies by version and flags and a threshold
// here would refuse real runs.
func verifyPidNamespace() error {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return fmt.Errorf("launcher: reading %s to verify the pid namespace: %w", procRoot, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if extra := foreignPids(names, os.Getpid()); len(extra) > 0 {
		// Named rather than only counted, and capped: a host procfs holds hundreds, and an
		// operator needs enough to tell a shimmed bwrap from a bento bug, not all of them.
		return fmt.Errorf("launcher: the sandbox's pid namespace is not the unshared one this run was admitted on; it can see %d process(es) bento did not start, including pid %s",
			len(extra), strings.Join(extra[:min(len(extra), 8)], ", "))
	}
	return nil
}

// procRoot is the procfs bwrap mounts fresh into the sandbox's namespace (--proc /proc).
// A fresh mount is what makes the pid namespace visible at all: the procfs instance is
// bound to the namespace it was mounted in, so an inherited one keeps showing host pids
// however the namespace was unshared - which is why internal/linux keeps namespaceFlags
// and pseudoFSFlags as two lists that must both be exercised.
const procRoot = "/proc"

// foreignPids names every process in a /proc listing other than the namespace's init and
// the caller. Non-numeric entries are procfs' own files and are skipped.
func foreignPids(names []string, self int) []string {
	var extra []string
	for _, name := range names {
		pid, err := strconv.Atoi(name)
		if err != nil || pid == 1 || pid == self {
			continue
		}
		extra = append(extra, name)
	}
	return extra
}

// sandboxDev is the device directory bwrap mounts fresh into the sandbox (--dev /dev, see
// internal/linux's pseudoFSFlags). Like /tmp it is in sandboxWritableMounts, so the
// Landlock ruleset grants writes to whatever is mounted there.
const sandboxDev = "/dev"

// bwrapDevNodes is every top-level name bwrap's --dev creates: the six device nodes, the
// three stdio symlinks, fd and core, the ptmx symlink, and the pts and shm submounts.
// console is included unconditionally because bwrap binds it from the INVOKING process's
// controlling terminal, so it is present for a run started from a terminal and absent
// otherwise. --new-session does not change that: it setsid()s the child, which is after
// bwrap has already chosen what to bind.
//
// This is an allowlist, not the denylist of specific dangerous nodes that would be the
// wrong shape here: the question is whether every name present is one bwrap put there,
// which is the same question verifyPidNamespace asks of /proc. The set is closed because
// bwrap builds this directory from nothing, so a host /dev shows up as roughly two
// hundred names outside it rather than as one borderline entry - the margin is what makes
// an allowlist cheaper than reasoning about which nodes matter.
var bwrapDevNodes = map[string]bool{
	"null": true, "zero": true, "full": true, "random": true, "urandom": true, "tty": true,
	"stdin": true, "stdout": true, "stderr": true,
	"fd": true, "core": true, "ptmx": true,
	"pts": true, "shm": true, "console": true,
}

// verifyDevMount is the launcher's own check that /dev is the minimal device directory
// bwrap builds plus whatever this run's own grants added, for verifyFreshTmp's reason and
// with the same consequence: /dev is a granted write, so a host /dev left in place hands
// the target the machine's device nodes under a report saying the filesystem layer was
// enforced.
//
// statfs cannot answer this one. The host's /dev is a devtmpfs, which reports
// TMPFS_MAGIC, so verifyFreshTmp's single syscall accepts the host's directory as
// readily as bwrap's. The directory listing is the evidence that does distinguish them.
func verifyDevMount(granted []string) error {
	entries, err := os.ReadDir(sandboxDev)
	if err != nil {
		return fmt.Errorf("launcher: reading %s to verify the sandbox's device mount: %w", sandboxDev, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if extra := foreignDevNodes(names, granted); len(extra) > 0 {
		// Named and capped for verifyPidNamespace's reason: a host /dev holds hundreds, and
		// an operator needs enough to tell a shimmed bwrap from a bento bug.
		return fmt.Errorf("launcher: %s is not the device directory bwrap builds; it holds %d name(s) bwrap did not create, including %s, so the target holds a granted write over the host's device nodes",
			sandboxDev, len(extra), strings.Join(extra[:min(len(extra), 8)], ", "))
	}
	return nil
}

// foreignDevNodes names every entry in a /dev listing that neither bwrap's --dev created
// nor this run's own grants asked for. granted is Config.GrantedDevNames: the top-level
// names internal/linux derived from the run's resolved read and write grants.
//
// The grant set is what makes the allowlist exact. A policy naming a path inside /dev is
// permitted - internal/linux's checkGrantNotManagedMount refuses only the whole root - and
// the grant binds after baseFlags, so bwrap carves the mount point into the sandbox's own
// /dev and a run reading /dev/dri or /dev/net/tun legitimately puts a name there that
// --dev never creates. Before Config carried the grants this was answered by asking the
// kernel whether the name was a mount of its own, which could not tell bento's grant bind
// from a shim's: a "--dev-bind /dev/mem /dev/mem" appended to the argv is a mount too, and
// so is every entry of a host /dev assembled from per-node binds the way a rootless
// container runtime builds one. Comparing against what was granted refuses both.
//
// Kept separate from foreignPids rather than sharing a filter: the two lists answer
// different questions, and verifyPidNamespace is one of two legs holding the pid-namespace
// claim up (see internal/linux's sessionProof).
func foreignDevNodes(names, granted []string) []string {
	var extra []string
	for _, name := range names {
		if bwrapDevNodes[name] || slices.Contains(granted, name) {
			continue
		}
		extra = append(extra, name)
	}
	return extra
}

// verifyShields is the launcher's own check that the deny-list shields this run applied
// are really in place, for verifyFreshTmp's reason: every shield is a bwrap argument, and
// the PATH-resolved bwrap that would be dropping one is the same binary the host asked to
// apply it. A shim that drops a single --ro-bind argument pair exposes that credential
// store for the whole run under a report saying the filesystem layer was enforced, and the
// Landlock backstop does not cover it - the backstop read-grants "/", so no read fence has
// one.
//
// Only the shapes are checked, not the deny rules: hidden means nothing readable is left
// at the path, read-only means writes are rejected there. internal/linux decides which is
// which off the same shieldMount that built the argv (see shieldChecks), so a shield whose
// shape depends on what is on the host - a path that is a directory on one machine and a
// file on another - is compared against what was actually mounted for it.
//
// A path that is absent is not a failure: a shield over a path bwrap had no mount point to
// create, or one the run's own grants never made reachable, leaves nothing there, and
// nothing there is the strongest form of hidden.
func verifyShields(hidden, readOnly []string) error {
	all := append(append([]string{}, hidden...), readOnly...)
	for _, path := range hidden {
		empty, err := shieldHidden(path, nestedShieldNames(path, all))
		if err != nil {
			return err
		}
		if !empty {
			return fmt.Errorf("launcher: %s is not the empty stand-in this run's deny-list shielded it with; the host's own content is readable there, so the target holds an ungranted read of a path bento reported as hidden", path)
		}
	}
	for _, path := range readOnly {
		writable, err := shieldWritable(path)
		if err != nil {
			return err
		}
		if writable {
			return fmt.Errorf("launcher: %s is on a writable mount, and this run's deny-list shielded it read-only; the target can rewrite a path bento reported as protected", path)
		}
	}
	return nil
}

// shieldHidden reports whether nothing of the host's own content is left at a hidden
// shield's path. The two mounts that hide one are a tmpfs over a directory and an empty
// read-only bind over a file, so an empty listing and a zero-length file are what "hidden"
// looks like from in here; a populated directory or a non-empty file is the real thing
// showing through.
//
// own names the entries bento itself put in the directory: the deny-list can shield a path
// NESTED inside a hidden one, and bwrap has to create that mount point inside the parent's
// tmpfs, so the parent is legitimately non-empty. A credential store holding a symlink into
// itself produces exactly that - the link target gets a rule of its own - and it is an
// ordinary shape, not a shimmed argv.
//
// The cost is a residual, and it is the reason own is the mount-point names rather than a
// blanket skip: a store whose every top-level entry happens to be one of those names would
// also pass with the parent's tmpfs dropped. What is still covered there is each nested
// shield, which is checked on its own; what is exposed is whatever else sits beside them
// under the parent. A store with any other entry - which is the ordinary case, and every
// case in the deny-list's own corpus - still fails.
//
// Both are read through the ordinary filesystem calls rather than statfs, because statfs
// cannot tell bwrap's tmpfs from the host's /tmp (verifyFreshTmp's own problem) and says
// nothing at all about a bind of the real file.
func shieldHidden(path string, own []string) (bool, error) {
	st, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("launcher: stat of %s to verify the deny-list shield over it: %w", path, err)
	}
	if !st.IsDir() {
		return st.Size() == 0, nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return false, fmt.Errorf("launcher: reading %s to verify the deny-list shield over it: %w", path, err)
	}
	for _, e := range entries {
		if !slices.Contains(own, e.Name()) {
			return false, nil
		}
	}
	return true, nil
}

// nestedShieldNames are the entries of dir that are mount points bento's own argv created:
// for every shield nested under dir, the one component of it that dir holds. A shield two
// levels down (~/.store/versions/leaf) contributes "versions", because that is the name
// bwrap had to create in dir's tmpfs to reach the leaf.
func nestedShieldNames(dir string, shields []string) []string {
	prefix := dir + "/"
	var names []string
	for _, s := range shields {
		rest, ok := strings.CutPrefix(s, prefix)
		if !ok || rest == "" {
			continue
		}
		top, _, _ := strings.Cut(rest, "/")
		if !slices.Contains(names, top) {
			names = append(names, top)
		}
	}
	return names
}

// shieldWritable reports whether a read-only shield's path sits on a mount that still
// accepts writes. The mount flags are the kernel's own answer and the only one that holds
// for a path a write grant covers: the sandbox root is remounted read-only, so a path
// outside every write grant reads read-only whether or not its shield survived, and the
// paths where the shield is the only thing standing are exactly the ones inside a grant.
func shieldWritable(path string) (bool, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("launcher: statfs of %s to verify the deny-list shield over it: %w", path, err)
	}
	return !isReadOnlyMount(int64(st.Flags)), nil
}

// isReadOnlyMount reports whether statfs mount flags carry ST_RDONLY. Split from the
// syscall for isTmpfs' reason: a test cannot mount anything read-only on a host that
// restricts unprivileged user namespaces, so the verdict is exercised here instead.
func isReadOnlyMount(flags int64) bool { return flags&unix.ST_RDONLY != 0 }

// procSelfStatus carries the caller's capability sets, among much else. It is read from
// inside the sandbox for verifyEmptyNetns' reason: the kernel's own answer is the one leg
// that is not the suspect bwrap's word.
const procSelfStatus = "/proc/self/status"

// verifyEmptyCapBound is the launcher's own check that the capability bounding set is the
// empty one the run was admitted on. Unlike the other three this is not a hole on an
// ordinary host - unprivileged bwrap already yields an empty bounding set whether or not
// --cap-drop ALL is passed - and that is exactly why bento asks for it explicitly: the
// reliance becomes bento's own rather than an unstated bwrap default, robust to a setuid
// bwrap or a stray --cap-add (see internal/linux's namespaceFlags). Those are the hosts
// where a shim filtering the flag out of argv matters, and they are the hosts this check
// speaks for.
//
// It is load-bearing beyond the flag: the read-only shields are plain bind mounts, and
// what stops the target from remounting them read-write is having no CAP_SYS_ADMIN.
func verifyEmptyCapBound() error {
	held, err := readCapBounding()
	if err != nil {
		return fmt.Errorf("launcher: %w", err)
	}
	if held != 0 {
		return fmt.Errorf("launcher: the sandbox's capability bounding set is not the empty one this run was admitted on; it holds %016x, so the target can remount bento's read-only shields read-write", held)
	}
	return nil
}

// readCapBounding is this process's own bounding set, read from the kernel. Both tiers
// ask the question - the bwrap tier to verify bwrap emptied it, the degraded tier to
// find out whether it could empty it at all - so the read lives in one place.
func readCapBounding() (uint64, error) {
	data, err := os.ReadFile(procSelfStatus)
	if err != nil {
		return 0, fmt.Errorf("reading %s for the capability bounding set: %w", procSelfStatus, err)
	}
	return capBounding(data)
}

// capBounding parses the CapBnd mask out of a /proc/<pid>/status dump. A dump with no
// CapBnd line is an error rather than a zero: a missing line is a kernel that does not
// answer the question, not one answering "none".
func capBounding(status []byte) (uint64, error) {
	for line := range strings.SplitSeq(string(status), "\n") {
		mask, ok := strings.CutPrefix(line, "CapBnd:")
		if !ok {
			continue
		}
		held, err := strconv.ParseUint(strings.TrimSpace(mask), 16, 64)
		if err != nil {
			return 0, fmt.Errorf("parsing the capability bounding set %q from %s: %w", strings.TrimSpace(mask), procSelfStatus, err)
		}
		return held, nil
	}
	return 0, fmt.Errorf("%s named no capability bounding set, so the sandbox's cannot be vouched for", procSelfStatus)
}

// procSelfTasks holds one directory per thread, each with a children file listing that
// thread's live children. The list is per-thread because the kernel files a child under
// the thread that forked it, and the launcher's Go runtime forks from whichever thread
// the scheduler was on.
const procSelfTasks = "/proc/self/task"

// verifyNoStrayChild is the profiling stage's check that nothing but the bridge is a live
// child of this process when the tracer starts. observe.Trace dequeues stops with
// wait4(-1) - ptrace has no wait-on-this-set - so it CONSUMES the exit status of any child
// of the calling process, and its doc states the precondition that bento's profiling path
// is a dedicated stage with no such children. Nothing asserted that until here.
//
// The bridge is the one legitimate exception, and it is why this takes a pid rather than
// refusing outright: a profiling run with egress starts it before the observe dispatch
// (see Run), and the launcher deliberately never wait()s for it - its death is reported
// through the liveness pipe, not through a status - so Trace consuming its status costs
// nothing. Pass 0 where no bridge was started.
//
// Loudly on a read failure, for verifyFreshTmp's reason: the precondition bento cannot
// inspect is not one it may vouch for.
func verifyNoStrayChild(bridge int) error {
	children, err := ownChildren()
	if err != nil {
		return fmt.Errorf("launcher: %w", err)
	}
	if stray := strayChildren(children, bridge); len(stray) > 0 {
		// Named and capped for verifyPidNamespace's reason.
		return fmt.Errorf("launcher: the profiling stage has %d live child process(es) it did not start, including pid %s, and the tracer reaps with wait4(-1) - so their exit statuses would be consumed by the observation instead of by whatever is waiting for them",
			len(stray), strings.Join(stray[:min(len(stray), 8)], ", "))
	}
	return nil
}

// ownChildren is every live child pid of this process, as the kernel reports them across
// the process's threads.
//
// The calling thread's own list is read first and its absence is fatal, because that is
// the one thread that cannot have exited: a kernel built without CONFIG_PROC_CHILDREN has
// no such file anywhere, and tolerating that alongside the vanished-thread case would
// return an empty list on such a host and vouch for a stage nothing had looked at.
func ownChildren() ([]string, error) {
	self := strconv.Itoa(unix.Gettid())
	children, err := threadChildren(self)
	if err != nil {
		return nil, err
	}
	tasks, err := os.ReadDir(procSelfTasks)
	if err != nil {
		return nil, fmt.Errorf("reading %s to verify the stage's children: %w", procSelfTasks, err)
	}
	for _, t := range tasks {
		if t.Name() == self {
			continue
		}
		others, err := threadChildren(t.Name())
		if err != nil {
			// A thread that exited between the listing and the read is gone with its
			// directory, so a vanished entry is not a read bento was denied. Its children
			// are not lost with it: the kernel reparents them to a live thread of the
			// same group, so they are still this process's and still show up, under a
			// sibling's file. The file itself exists on this kernel - the read above
			// proved it - so this arm is only ever that race.
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		children = append(children, others...)
	}
	return children, nil
}

// threadChildren is one thread's live children.
func threadChildren(tid string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(procSelfTasks, tid, "children"))
	if err != nil {
		return nil, fmt.Errorf("reading the children of thread %s to verify the stage's: %w", tid, err)
	}
	return strings.Fields(string(data)), nil
}

// strayChildren names every child pid other than the one the stage started itself.
// known is 0 when it started none.
func strayChildren(children []string, known int) []string {
	var stray []string
	for _, pid := range children {
		if pid == strconv.Itoa(known) {
			continue
		}
		stray = append(stray, pid)
	}
	return stray
}
