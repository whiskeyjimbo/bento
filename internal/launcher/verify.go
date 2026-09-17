//go:build linux

package launcher

import (
	"fmt"
	"os"
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
// bwrap builds, for verifyFreshTmp's reason and with the same consequence: /dev is a
// granted write, so a host /dev left in place hands the target the machine's device nodes
// under a report saying the filesystem layer was enforced.
//
// statfs cannot answer this one. The host's /dev is a devtmpfs, which reports
// TMPFS_MAGIC, so verifyFreshTmp's single syscall accepts the host's directory as
// readily as bwrap's. The directory listing is the evidence that does distinguish them.
func verifyDevMount() error {
	entries, err := os.ReadDir(sandboxDev)
	if err != nil {
		return fmt.Errorf("launcher: reading %s to verify the sandbox's device mount: %w", sandboxDev, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	var devSt unix.Stat_t
	if err := unix.Lstat(sandboxDev, &devSt); err != nil {
		return fmt.Errorf("launcher: lstat of %s to verify the sandbox's device mount: %w", sandboxDev, err)
	}
	if extra := foreignDevNodes(names, ownMountUnderDev(devSt.Dev)); len(extra) > 0 {
		// Named and capped for verifyPidNamespace's reason: a host /dev holds hundreds, and
		// an operator needs enough to tell a shimmed bwrap from a bento bug.
		return fmt.Errorf("launcher: %s is not the device directory bwrap builds; it holds %d name(s) bwrap did not create, including %s, so the target holds a granted write over the host's device nodes",
			sandboxDev, len(extra), strings.Join(extra[:min(len(extra), 8)], ", "))
	}
	return nil
}

// foreignDevNodes names every entry in a /dev listing that neither bwrap's --dev created
// nor bento's own argv mounted. ownMount decides the second case; see ownMountUnderDev.
//
// Kept separate from foreignPids rather than sharing a filter: the two lists answer
// different questions, and verifyPidNamespace is one of two legs holding the pid-namespace
// claim up (see internal/linux's sessionProof).
func foreignDevNodes(names []string, ownMount func(string) bool) []string {
	var extra []string
	for _, name := range names {
		if bwrapDevNodes[name] || ownMount(name) {
			continue
		}
		extra = append(extra, name)
	}
	return extra
}

// ownMountUnderDev reports whether a name under /dev is a mount of its own rather than an
// entry of the device directory itself, given /dev's own st_dev.
//
// This is what keeps the allowlist from refusing a legitimate run. A grant naming a path
// inside /dev is permitted - internal/linux's checkGrantNotManagedMount refuses only the
// whole root, and the grant binds after baseFlags, so bwrap carves the mount point into
// the sandbox's own /dev - which means a policy reading /dev/dri or /dev/net/tun puts a
// name there that bwrap's --dev never creates. Config carries the write grants but not the
// read ones, so the set cannot be assembled from configuration; the kernel answers it
// instead, and a mount is exactly what bento's argv can add and what a host device node
// is not.
//
// The residual, and it is the honest cost of having no grant set here: mount-ness cannot
// tell bento's own grant bind from a shim's. A --dev-bind /dev/mem /dev/mem appended to
// the argv is a mount too, so it passes, while the host's /dev mounted whole is still
// refused - its plain device nodes (kvm, mem, sda, the tty and loop sets) share /dev's
// st_dev. So this fence catches the wholesale substitution and not single-node injection.
// A leaked host /dev's own submounts, mqueue and hugepages, pass for the same reason.
// What would close it is comparing against what the run actually granted, which means the
// grant set reaching Config from internal/linux.
func ownMountUnderDev(devFS uint64) func(string) bool {
	return func(name string) bool {
		var st unix.Stat_t
		if err := unix.Lstat(sandboxDev+"/"+name, &st); err != nil {
			// A name bento cannot inspect is not one it may vouch for, so it stays foreign.
			return false
		}
		return st.Dev != devFS
	}
}

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
	data, err := os.ReadFile(procSelfStatus)
	if err != nil {
		return fmt.Errorf("launcher: reading %s to verify the capability bounding set: %w", procSelfStatus, err)
	}
	held, err := capBounding(data)
	if err != nil {
		return fmt.Errorf("launcher: %w", err)
	}
	if held != 0 {
		return fmt.Errorf("launcher: the sandbox's capability bounding set is not the empty one this run was admitted on; it holds %016x, so the target can remount bento's read-only shields read-write", held)
	}
	return nil
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
