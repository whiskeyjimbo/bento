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
	"errors"
	"fmt"
	"os"

	ll "github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// errUnavailableABI is returned by RestrictDegraded when the effective Landlock ABI is
// below the usable floor, so the degraded tier refuses rather than run unconfined.
var errUnavailableABI = errors.New("landlock: kernel ABI unavailable, refusing to run the degraded tier unconfined")

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
//
// A path naming a regular file gets a file rule, not a directory one: the
// directory rules reject a non-directory with EINVAL, and RestrictPaths applies
// the ruleset as a whole, so one file in either set would abort EVERY rule and
// leave the process unconfined. The bwrap tier's callers happen to pass only
// directories today, but that invariant lives in another package and this is where
// its failure would be silent.
func RestrictTo(read, write []string) error {
	rules := classifyRules(nil, read, ll.RODirs, ll.ROFiles)
	rules = classifyRules(rules, write, ll.RWDirs, ll.RWFiles)
	if err := ll.V9.BestEffort().RestrictPaths(rules...); err != nil {
		return fmt.Errorf("landlock: applying ruleset: %w", err)
	}
	return nil
}

// classifyRules appends one rule per kind for the paths that exist, routing
// directories to dirRule and everything else to fileRule. Landlock's directory
// rules reject a non-directory with EINVAL and RestrictPaths is all-or-nothing, so
// misrouting one path discards the whole ruleset. Both Restrict tiers build their
// rules through here rather than each classifying its own way.
func classifyRules(rules []ll.Rule, paths []string, dirRule, fileRule func(...string) ll.FSRule) []ll.Rule {
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
	return rules
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
// ABI. That downgrade has a sharp edge: V9 declares it HANDLES the full access-right
// set, and BestEffort strips handled_access_fs down to the kernel's ABI - and a right
// absent from handled_access_fs is not restricted at all. So on a kernel below ABI 3
// (5.13-6.1) truncate is unhandled and a read-granted file can still be truncated
// (zeroed), and below ABI 5 (pre-6.10) the ioctl_dev right is unhandled. The read/
// write/execute access this tier grants all exists at the v1 floor, so path access is
// confined as intended; the residual is the newer rights BestEffort silently drops.
// The terminal-injection ioctls that make the ioctl_dev gap an escape are blocked
// separately by seccomp (BlockTerminalInjection); the truncate residual is disclosed
// in the degraded run report so the operator sees it on an old kernel.
func RestrictDegraded(read, write, exec []string) error {
	// BestEffort silently restricts nothing when it detects ABI 0 (an empty ruleset
	// returns success), which for this tier - where Landlock is the only filesystem
	// guarantee - is a fail-open. Refuse up front on the same effective ABI the gate
	// uses, so a run never reaches the target believing it is confined when it is not.
	if effectiveABI() < 1 {
		return errUnavailableABI
	}
	rules := classifyRules(nil, read, ll.RODirs, ll.ROFiles)
	rules = classifyRules(rules, write, ll.RWDirs, ll.RWFiles)
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
//
// It reports the EFFECTIVE ABI, floored the same way BestEffort's own detection floors
// it, not the raw kernel version: a raw version this build would silently downgrade to
// a no-op must read as unavailable here, or the gate and the enforcement disagree.
func Available() bool {
	return effectiveABI() >= 1
}

// TruncateRestricted reports whether this kernel's Landlock ABI (>= 3) can restrict
// truncate(2). Below it, truncate is absent from handled_access_fs and therefore
// unrestricted, so a read-only path rule does not stop the target from zeroing the
// file. The degraded tier - which has no mount namespace behind Landlock - discloses
// this in its run report so an operator on an old kernel sees the residual.
func TruncateRestricted() bool {
	return effectiveABI() >= 3
}

// signalScopeErratum is the errata bit go-landlock checks: when it is clear the
// kernel's ABI ≥ 6 has an unfixed signal-scoping bug, so go-landlock enforces only v5.
const signalScopeErratum = 0x2

// effectiveABI is the Landlock ABI this build will actually enforce: the kernel's
// version, or 0 when the kernel lacks Landlock or reports a version below the floor
// go-landlock requires (raised to 8 by the landlocktsync build tag). It mirrors
// go-landlock's DetectedABIVersion - including its errata downgrade of an ABI ≥ 6 with
// the signal-scoping fix absent to v5 - so Available and RestrictDegraded gate on the
// same version BestEffort enforces; the raw syscall alone would accept a version
// BestEffort then turns into a silent no-op.
func effectiveABI() int {
	v, err := llsys.LandlockGetABIVersion()
	if err == nil && v >= 6 {
		// A failed errata read is treated as "not fixed", matching go-landlock.
		if errata, eerr := llsys.LandlockGetErrata(); eerr != nil || errata&signalScopeErratum == 0 {
			v = 5
		}
	}
	return flooredABI(v, err)
}

// flooredABI applies the go-landlock minimum-ABI floor to a raw ABI-version result,
// returning 0 (unavailable) on a syscall error or a version below the floor.
func flooredABI(v int, err error) int {
	if err != nil || v < minRequiredABI() {
		return 0
	}
	return v
}
