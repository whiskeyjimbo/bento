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
	if !isTmpfs(st.Type) {
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
