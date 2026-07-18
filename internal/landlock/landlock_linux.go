// Package landlock applies a Landlock filesystem ruleset as a second,
// independent kernel confinement layer behind bubblewrap.
//
// bwrap confines the filesystem by only mounting the granted paths; Landlock
// confines it by denying access the kernel LSM does not permit. Running both
// means a bug or escape in the mount-namespace layer does not by itself grant
// filesystem access - the target's writes stay confined to its grants even then.
// Landlock is a backstop, not the primary guarantee, so it is best-effort: where
// the kernel lacks it the sandbox still holds via bwrap, and `doctor` reports
// whether the backstop is actually present.
package landlock

import (
	"fmt"
	"os"

	ll "github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// Restrict makes the whole visible filesystem read-and-execute only, except the
// given writable paths. It is applied inside the sandbox after the mount
// confinement is already in place, so "the whole visible filesystem" is just the
// granted mounts - Landlock re-denies writes to anything outside the writable
// set, independently of bwrap.
//
// The writable set MUST include every path bwrap made writable that the target
// uses (the runtime scratch mounts plus the write grants); the caller assembles
// it from the same source as those binds, so the two layers cannot drift apart.
// It is best-effort: on a kernel without Landlock this is a no-op (bwrap remains
// the guarantee).
func Restrict(writable []string) error {
	return RestrictTo([]string{"/"}, writable)
}

// RestrictTo confines the process to exactly the given read-and-execute path
// trees and read-write path trees; every path outside them is denied. It is the
// primitive Restrict builds on, and the basis for a future degraded tier that
// runs a target under Landlock alone.
//
// Paths that do not exist are skipped, since Landlock cannot add a rule for a
// missing path. This does not weaken confinement of a not-yet-created write
// target: the target's parent must itself be writable to create it, and a
// writable parent is a directory rule that covers the child recursively.
func RestrictTo(read, write []string) error {
	if err := ll.V9.BestEffort().RestrictPaths(
		ll.RODirs(existing(read)...),
		ll.RWDirs(existing(write)...),
	); err != nil {
		return fmt.Errorf("landlock: applying ruleset: %w", err)
	}
	return nil
}

// RestrictDegraded is the PRIMARY filesystem confinement for the no-bwrap degraded
// tier: with no mount namespace the whole host filesystem is visible, so this
// ruleset is the only thing standing between the target and every path it is not
// granted. Unlike RestrictTo (a best-effort backstop behind bwrap), a failure to
// apply this is fatal to the caller - it must refuse to run the target rather than
// leave it unconfined.
//
// read paths get read access (directories also get execute and are recursive; a
// file gets read and execute - go-landlock's read-file right includes execute - but
// not directory reads, so a read file does not leak its siblings). write paths get
// read-write. exec paths get read+execute on the individual file, the entrypoint
// when it is its own compiled-binary interpreter; that right overlaps the read-file
// right above and is kept explicit. Missing paths are skipped, as in RestrictTo.
//
// It still uses BestEffort, which downgrades the ruleset to the kernel's Landlock
// ABI. That is acceptable here because every right used (read/write/execute path
// access) exists in ABI v1, the floor the probe already gates the tier on; there is
// no newer right whose silent loss would weaken the stated guarantee.
func RestrictDegraded(read, write, exec []string) error {
	var rules []ll.Rule
	classify := func(paths []string, dirRule, fileRule func(...string) ll.FSRule) {
		var dirs, files []string
		for _, p := range paths {
			fi, err := os.Stat(p)
			if err != nil {
				continue
			}
			if fi.IsDir() {
				dirs = append(dirs, p)
			} else {
				files = append(files, p)
			}
		}
		if len(dirs) > 0 {
			rules = append(rules, dirRule(dirs...))
		}
		if len(files) > 0 {
			rules = append(rules, fileRule(files...))
		}
	}
	classify(read, ll.RODirs, ll.ROFiles)
	classify(write, ll.RWDirs, ll.RWFiles)
	if e := existing(exec); len(e) > 0 {
		rules = append(rules, ll.PathAccess(ll.AccessFSSet(llsys.AccessFSExecute|llsys.AccessFSReadFile), e...))
	}
	if err := ll.V9.BestEffort().RestrictPaths(rules...); err != nil {
		return fmt.Errorf("landlock: applying degraded ruleset: %w", err)
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
//
// It asks the kernel directly, via the Landlock ABI-version syscall, rather than
// parsing /sys/kernel/security/lsm. That parse gave a false negative wherever
// securityfs is not mounted or /sys is restricted - common in containers - and
// reported "no backstop" while the syscalls, which BestEffort applies independently
// of any /sys read, actually worked. The syscall returns the ABI version (>= 1) when
// Landlock is usable, and errors (ENOSYS when the kernel lacks it, EOPNOTSUPP when it
// is compiled but disabled), so it reflects real usability with no filesystem
// dependency.
func Available() bool {
	v, err := llsys.LandlockGetABIVersion()
	return err == nil && v >= 1
}
