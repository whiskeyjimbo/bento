// Package landlock applies a Landlock filesystem ruleset as a second,
// independent kernel confinement layer behind bubblewrap.
//
// bwrap confines the filesystem by only mounting the granted paths; Landlock
// confines it by denying access the kernel LSM does not permit. Running both
// means a bug or escape in the mount-namespace layer does not by itself grant
// filesystem access — the target's writes stay confined to its grants even then.
// Landlock is a backstop, not the primary guarantee, so it is best-effort: where
// the kernel lacks it the sandbox still holds via bwrap, and `doctor` reports
// whether the backstop is actually present.
package landlock

import (
	"fmt"
	"os"
	"strings"

	ll "github.com/landlock-lsm/go-landlock/landlock"
)

// runtimeWritable are scratch and device paths a target legitimately opens for
// writing inside the sandbox regardless of its grants (e.g. /dev/null, a
// redirect into the tmpfs). Missing one would break ordinary programs, so the
// set is deliberately generous — the confinement that matters is that the rest
// of the filesystem is read-only.
var runtimeWritable = []string{"/tmp", "/dev", "/proc", "/run", "/var/tmp"}

// Restrict makes the whole visible filesystem read-and-execute only, except the
// given writable paths plus runtime scratch. It is applied inside the sandbox
// after the mount confinement is already in place, so "the whole visible
// filesystem" is just the granted mounts — Landlock re-denies writes to anything
// outside the write grants, independently of bwrap.
//
// It is best-effort: on a kernel without Landlock this is a no-op (bwrap remains
// the guarantee). A genuine failure to apply an available ruleset is an error.
func Restrict(writable []string) error {
	return RestrictTo([]string{"/"}, append(append([]string{}, runtimeWritable...), writable...))
}

// RestrictTo confines the process to exactly the given read-and-execute path
// trees and read-write path trees; every path outside them is denied. It is the
// primitive Restrict builds on, and the basis for a future degraded tier that
// runs a target under Landlock alone. Paths that do not exist are skipped, since
// Landlock cannot add a rule for a missing path.
func RestrictTo(read, write []string) error {
	if err := ll.V9.BestEffort().RestrictPaths(
		ll.RODirs(existing(read)...),
		ll.RWDirs(existing(write)...),
	); err != nil {
		return fmt.Errorf("landlock: applying ruleset: %w", err)
	}
	return nil
}

func existing(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// Available reports whether this kernel exposes the Landlock LSM, so the
// filesystem backstop is actually in effect rather than silently absent.
func Available() bool {
	b, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}
	for _, lsm := range strings.Split(strings.TrimSpace(string(b)), ",") {
		if lsm == "landlock" {
			return true
		}
	}
	return false
}
