//go:build linux

package launcher

import (
	"fmt"

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
