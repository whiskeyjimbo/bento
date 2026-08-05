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
	"io/fs"
	"os"

	ll "github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// handledFS is the Landlock configuration the bwrap-backstop tier applies: the
// filesystem access rights this package has actually reasoned about for that tier,
// which is every right through ABI 8. It is deliberately NOT go-landlock's newest
// preset.
//
// Landlock only restricts a right that is in handled_access_fs, and a handled right is
// denied everywhere no rule grants it. The rule helpers this package builds on
// (RODirs/RWDirs/ROFiles/RWFiles) grant a fixed set that does not grow with the ABI, so
// tracking the newest preset silently converts each new ABI's rights into a blanket
// denial the moment a kernel supports them: no helper grants ABI 9's resolve_unix, so
// handling it without granting it anywhere denies every connect(2) and sendmsg(2) to a
// pathname AF_UNIX socket outside the domain - dbus, X11, /dev/log, glibc's NSS - while
// the run report still says the layer applied cleanly.
//
// Pinning the handled set here means a kernel newer than this build enforces what this
// build intends and nothing more. Adopting a new right is then a deliberate change: add
// it to a handled set AND grant it on the paths that need it - which is what withIoctlDev
// does for ABI 5's ioctl_dev in both tiers, and what degradedFS does for resolve_unix and
// this tier deliberately does not.
//
// RestrictPaths keeps only handledAccessFS from a Config, so the network and scoped sets
// never reach the ruleset.
var handledFS = ll.V8

// degradedFS is the handled set for the degraded tier: handledFS plus ABI 9's
// resolve_unix (V9's handled_access_fs is V8's plus exactly that right). The tiers
// differ because their exposure does.
//
// Under bwrap the mount namespace already hides the host's sockets, so handling
// resolve_unix would buy near nothing while /tmp and /dev are tmpfs the target may
// legitimately put its own sockets in - every miss a silent connect denial. The
// degraded tier has no mount namespace: the whole host filesystem is visible, and
// pre-ABI-9 Landlock does not govern connect(2) to a pathname socket at all, so a
// service socket a grant exposes is an egress route out of a tier whose netns-less
// egress fence is seccomp (see internal/linux/probe.go, which documents the residual
// this closes). Handling the right here is what makes the file grants govern that
// connect too.
//
// Only the WRITE rules grant it back (RestrictDegraded), so the target keeps reaching a
// socket it creates itself under its scratch or a write grant. A read grant deliberately
// does not: connecting to someone else's socket under a read-only grant is the hole, not
// a feature.
//
// BestEffort strips the right from the handled set below ABI 9, so on those kernels the
// tier keeps today's behaviour; the degraded run report discloses that next to the
// truncate and ioctl_dev residuals. Granting a right the downgraded set no longer handles
// is safe: go-landlock intersects it away per rule (v0.9.0 path_opt.go, FSRule.downgrade)
// rather than collapsing the ruleset to v0, which it does only for refer.
var degradedFS = ll.V9

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

// errAllowlistUnavailableABI is returned by RestrictExecAllowlist when the effective
// Landlock ABI is below the usable floor. Kept fail-closed for the reason the function's
// own comment gives: an allowlist that cannot be applied must refuse, never fall back to
// unrestricted spawn.
var errAllowlistUnavailableABI = errors.New("landlock: kernel ABI unavailable, refusing to run an exec allowlist that would not be enforced")

// RestrictExecAllowlist builds and applies the ruleset an exec allowlist would need:
// Restrict with execute withheld: the whole visible filesystem becomes readable but NOT
// executable, the writable set stays writable but not executable, and exactly the
// allowlisted files carry execute.
//
// Withholding execute from the read grants is the point, and it is what makes this
// different from every other rule this package builds. go-landlock's read helpers
// (RODirs/ROFiles) include the execute right, so under Restrict every readable file is
// executable; an allowlist that added a rule without taking that away would grant
// nothing new and bound nothing. The subtraction lives here rather than in the shared
// rule builders for the same reason: it changes what a read grant confers, and the other
// tiers' grants must keep meaning what they have always meant.
//
// NOTHING IN A POLICY REACHES THIS. There is no exec: allowlist mode, and ADR-0008
// records why Landlock cannot provide one. This is kept as the executable evidence for
// that decision: the probe's execallow_loader arm, which runs through here, is what
// demonstrates the finding rather than asserting it, and a claim about kernel behaviour
// with nothing to re-run it against is the thing an ADR is worst at holding.
//
// The two facts it demonstrates, both reproduced on ABI 4:
//
// A dynamically linked binary cannot be allowlisted. The kernel executes such a binary's
// PT_INTERP, so the loader would need execute here too - and a loader that has it will
// execute any readable ELF passed as its argument, including one the target just wrote
// into its own write grant. That is why no loader path is granted and no attempt is made
// to discover one, and it is why an allowlist entry would have to be statically linked.
//
// And that is not enough either: under such a mode no exec-block filter is installed, so
// the launcher would exec the TARGET through an ordinary exec.Command after this ruleset
// is in place. The target's own interpreter or entrypoint would need execute under the
// very ruleset withholding it, which rules out every script run under an interpreter.
//
// It is deliberately NOT best-effort, and stays that way: were anything ever to call it,
// this ruleset would be the entire mechanism rather than a backstop behind bwrap, so
// applying it must succeed or the run must not happen.
func RestrictExecAllowlist(writable, execAllow []string) error {
	if effectiveABI() < 1 {
		return errAllowlistUnavailableABI
	}
	rules, err := execAllowlistRules([]string{"/"}, writable, execAllow)
	if err != nil {
		return err
	}
	if err := handledFS.BestEffort().RestrictPaths(rules...); err != nil {
		return fmt.Errorf("landlock: applying exec allowlist ruleset: %w", err)
	}
	return nil
}

// execAllowlistRules is RestrictExecAllowlist's ruleset, split off for the reason
// backstopRules is: which rights the tier grants can then be asserted without applying
// the ruleset, which would Landlock the test process irreversibly.
//
// The read and write rules are go-landlock's sets with execute removed rather than
// hand-written ones, so a right added to those helpers is inherited here and only the
// one subtraction this mode is about stays local.
func execAllowlistRules(read, write, execAllow []string) ([]ll.Rule, error) {
	rules, err := classifyRules(nil, read, withIoctlDev(roDirsNoExec), withIoctlDev(roFilesNoExec))
	if err != nil {
		return nil, err
	}
	rules, err = classifyRules(rules, write, withIoctlDev(withRefer(rwDirsNoExec)), withIoctlDev(rwFilesNoExec))
	if err != nil {
		return nil, err
	}
	// Not classifyRules, and the refusal below rather than a routing choice: an allowlist
	// entry is one file, and Landlock's rules apply to everything beneath a path, so a
	// directory here would grant execute on the whole subtree - precisely the blanket this
	// ruleset exists to withhold. Refused here rather than left to a caller, because there
	// is no caller: a precondition this function does not enforce is one nothing enforces.
	e, err := execAllowFiles(execAllow)
	if err != nil {
		return nil, err
	}
	if len(e) > 0 {
		rules = append(rules, ll.PathAccess(ll.AccessFSSet(llsys.AccessFSExecute|llsys.AccessFSReadFile), e...))
	}
	return rules, nil
}

// execAllowFiles screens the allowlist down to the regular files that exist, refusing a
// directory outright.
//
// It does not share `existing`, whose skip-if-absent contract belongs to the path grants:
// there, a missing path buys no confinement to drop and the target simply finds nothing.
// An absent allowlist ENTRY is a different fact - the mode is narrower than the policy
// says, and a run that silently permits fewer binaries than were approved is a broken run
// rather than a safe one - so it is reported instead of skipped. That difference is why
// the two are not one helper with a flag.
func execAllowFiles(paths []string) ([]string, error) {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("landlock: exec allowlist entry %q: %w", p, err)
		}
		if fi.IsDir() {
			return nil, fmt.Errorf("landlock: exec allowlist entry %q is a directory; an entry names one binary, and Landlock would grant execute on everything beneath it", p)
		}
		out = append(out, p)
	}
	return out, nil
}

// The rights the exec allowlist's read and write rules grant: exactly what
// go-landlock's RODirs/ROFiles/RWDirs/RWFiles grant, minus AccessFSExecute.
//
// Landlock resolves an access against the rule for the most specific matching path
// rather than the union along the hierarchy, so a narrow execute rule on one file still
// wins over the broad no-execute rule above it. That is what lets the allowlist be a
// subtraction plus a small addition rather than an enumeration of every readable path.
//
// Spelled out rather than derived because go-landlock keeps a rule's access set
// unexported, so there is no way to ask a helper what it grants and take one right away.
// That makes this a copy that can drift: a right added to those helpers is inherited by
// every other rule this package builds and NOT by these. TestAllowlistRightsTrackTheHelpers
// pins the difference at exactly execute so the drift fails a test rather than silently
// narrowing what an allowlist run may do.
const (
	roDirNoExec  = ll.AccessFSSet(llsys.AccessFSReadFile | llsys.AccessFSReadDir)
	roFileNoExec = ll.AccessFSSet(llsys.AccessFSReadFile)
	rwDirNoExec  = roDirNoExec | ll.AccessFSSet(llsys.AccessFSWriteFile|llsys.AccessFSTruncate|
		llsys.AccessFSRemoveDir|llsys.AccessFSRemoveFile|llsys.AccessFSMakeChar|llsys.AccessFSMakeDir|
		llsys.AccessFSMakeReg|llsys.AccessFSMakeSock|llsys.AccessFSMakeFifo|llsys.AccessFSMakeBlock|
		llsys.AccessFSMakeSym)
	rwFileNoExec = ll.AccessFSSet(llsys.AccessFSReadFile | llsys.AccessFSWriteFile | llsys.AccessFSTruncate)
)

func roDirsNoExec(paths ...string) ll.FSRule  { return ll.PathAccess(roDirNoExec, paths...) }
func roFilesNoExec(paths ...string) ll.FSRule { return ll.PathAccess(roFileNoExec, paths...) }
func rwDirsNoExec(paths ...string) ll.FSRule  { return ll.PathAccess(rwDirNoExec, paths...) }
func rwFilesNoExec(paths ...string) ll.FSRule { return ll.PathAccess(rwFileNoExec, paths...) }

// RestrictTo confines the process to exactly the given read-and-execute path
// trees and read-write path trees; every path outside them is denied. It is the
// primitive Restrict builds on, and the basis for a future degraded tier that
// runs a target under Landlock alone.
//
// Paths that do not exist are skipped, since Landlock cannot add a rule for a
// missing path. This does not weaken confinement of a not-yet-created write
// target: the target's parent must itself be writable to create it, and a
// writable parent is a directory rule that covers the child recursively. Only
// ENOENT is skipped: any other stat failure (EACCES on an ancestor, EIO or
// ESTALE from a network mount, ELOOP, ENOTDIR under a regular-file parent) is a
// host problem this cannot classify, and dropping the path would over-restrict
// it - the target then gets EACCES on a path the policy granted, with nothing
// naming Landlock. Returning the errno instead makes the caller warn with it.
//
// The read set here is always "/" (Restrict is the only production caller), so the paths
// that can trip this are the writable ones, where a silent drop buys no
// confinement at all - bwrap still permits the write - and only breaks the
// target.
//
// A path naming a regular file gets a file rule, not a directory one: the
// directory rules reject a non-directory with EINVAL, and RestrictPaths applies
// the ruleset as a whole, so one file in either set aborts EVERY rule - the caller
// then warns and proceeds (bwrap is the primary guarantee), so the run simply has no
// backstop. The callers happen to pass only directories today, but that invariant
// lives in another package, and it is this one that has to hold the ruleset together.
func RestrictTo(read, write []string) error {
	rules, err := backstopRules(read, write)
	if err != nil {
		return err
	}
	if err := handledFS.BestEffort().RestrictPaths(rules...); err != nil {
		return fmt.Errorf("landlock: applying ruleset: %w", err)
	}
	return nil
}

// backstopRules is the bwrap tier's ruleset, split from RestrictTo so which rights the
// tier actually grants can be asserted without applying the ruleset - applying it would
// Landlock the test process irreversibly, and the newest rights are not even handled on
// every kernel a test runs on, so this is the only place the granted-versus-handled
// question is answerable at all.
func backstopRules(read, write []string) ([]ll.Rule, error) {
	rules, err := classifyRules(nil, read, withIoctlDev(ll.RODirs), withIoctlDev(ll.ROFiles))
	if err != nil {
		return nil, err
	}
	return classifyRules(rules, write, withIoctlDev(withRefer(ll.RWDirs)), withIoctlDev(ll.RWFiles))
}

// classifyRules appends one rule per kind for the paths that exist, routing
// directories to dirRule and everything else to fileRule. Landlock's directory
// rules reject a non-directory with EINVAL and RestrictPaths is all-or-nothing, so
// misrouting one path discards the whole ruleset. Both Restrict tiers build their
// rules through here rather than each classifying its own way.
//
// A path that does not exist is skipped; any other stat failure is returned, since a
// path this cannot classify is one it would silently over-restrict.
func classifyRules(rules []ll.Rule, paths []string, dirRule, fileRule func(...string) ll.FSRule) ([]ll.Rule, error) {
	var dirs, files []string
	for _, p := range paths {
		fi, err := os.Stat(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("landlock: %q: %w", p, err)
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
	return rules, nil
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
// right above and is kept explicit. Missing paths are skipped, as in RestrictTo, and a
// path that fails to stat for any other reason is refused there rather than dropped -
// fatal here, where Landlock is the only filesystem mechanism and a dropped grant is a
// denial the operator has nothing to attribute.
//
// Every path additionally grants ioctl_dev, which both handled sets contain from ABI 5 -
// see withIoctlDev, without which every device node this tier grants would be openable
// and un-ioctl-able.
//
// Write paths additionally grant resolve_unix, because degradedFS handles it: with no
// mount namespace hiding the host's sockets, connect(2) to a pathname AF_UNIX socket is
// governed by the grants like any other filesystem access, and a socket the target
// creates under its own scratch or write grant stays reachable. A read grant does not
// get it - see degradedFS.
//
// It still uses BestEffort, which downgrades the ruleset to the kernel's Landlock
// ABI. That downgrade has a sharp edge: degradedFS declares it HANDLES every access
// right through ABI 9, and BestEffort strips handled_access_fs down to the kernel's
// ABI on anything older - and a right absent from handled_access_fs is not restricted
// at all. So on a kernel below ABI 3
// (5.13-6.1) truncate is unhandled and a read-granted file can still be truncated
// (zeroed), below ABI 5 (pre-6.10) the ioctl_dev right is unhandled so an ioctl on a
// device node OUTSIDE the grants is unrestricted too, and below ABI 9 the
// resolve_unix right is unhandled so connect(2) to any pathname socket on the host is
// unrestricted whatever the grants say. The read/
// write/execute access this tier grants all exists at the v1 floor, so path access is
// confined as intended; the residual is the newer rights BestEffort silently drops.
// Both residuals are disclosed in the degraded run report so an operator on an old
// kernel sees them. seccomp's BlockTerminalInjection narrows the ioctl_dev gap to what
// matters most - it blocks the terminal-injection ioctls on the tty - but it does not
// close it: the unhandled right leaves every other ioctl on every device node the target
// can open unrestricted, and with no mount namespace that is the host's whole /dev, which
// is why the report names it rather than treating it as covered.
func RestrictDegraded(read, write, exec []string) error {
	// BestEffort silently restricts nothing when it detects ABI 0 (an empty ruleset
	// returns success), which for this tier - where Landlock is the only filesystem
	// guarantee - is a fail-open. Refuse up front on the same effective ABI the gate
	// uses, so a run never reaches the target believing it is confined when it is not.
	//
	// This guard covers the ABI-0 route only. BestEffort's downgrade has a second
	// silent-success path - a config it cannot satisfy collapses to v0 and returns nil,
	// having restricted nothing - which an ABI check cannot see. Reaching it needs a refer
	// rule on ABI 1, and withRefer asks for refer only from ABI 2 precisely so that
	// ruleset is never built. WithResolveUnix needs no such gate: refer is the only right
	// whose absence from the downgraded handled set makes a rule unsatisfiable rather than
	// merely intersected down.
	if effectiveABI() < 1 {
		return errUnavailableABI
	}
	rules, err := degradedRules(read, write, exec)
	if err != nil {
		return err
	}
	if err := degradedFS.BestEffort().RestrictPaths(rules...); err != nil {
		return fmt.Errorf("landlock: applying degraded ruleset: %w", err)
	}
	return nil
}

// degradedRules is the degraded tier's ruleset, split from RestrictDegraded for the
// reason backstopRules is split from RestrictTo.
func degradedRules(read, write, exec []string) ([]ll.Rule, error) {
	rules, err := classifyRules(nil, read, withIoctlDev(ll.RODirs), withIoctlDev(ll.ROFiles))
	if err != nil {
		return nil, err
	}
	rules, err = classifyRules(rules, write, withIoctlDev(withResolveUnix(withRefer(ll.RWDirs))), withIoctlDev(withResolveUnix(ll.RWFiles)))
	if err != nil {
		return nil, err
	}
	e, err := existing(exec)
	if err != nil {
		return nil, err
	}
	if len(e) > 0 {
		// The entrypoint is a regular file, so it needs no ioctl_dev.
		rules = append(rules, ll.PathAccess(ll.AccessFSSet(llsys.AccessFSExecute|llsys.AccessFSReadFile), e...))
	}
	return rules, nil
}

// withResolveUnix wraps a rule constructor so the rules it builds also grant
// resolve_unix, keeping a socket the target creates under its own write grant
// connectable once degradedFS handles the right. It wraps the constructor rather than
// the rule so both write kinds go through classifyRules unchanged.
func withResolveUnix(rule func(...string) ll.FSRule) func(...string) ll.FSRule {
	return func(paths ...string) ll.FSRule {
		return rule(paths...).WithResolveUnix()
	}
}

// withRefer wraps the DIRECTORY write-rule constructor so the rules it builds also grant
// refer, the right that governs rename(2) and link(2) ACROSS directories. Both handled sets contain
// it from ABI 2 (kernel 5.19) and none of go-landlock's RW helpers grant it, so without
// this it is handled and granted nowhere - which denies every cross-directory rename even
// when source and destination are inside the SAME write grant. The symptom is EXDEV or
// EACCES naming no layer, and it hits the write-a-temp-file-then-rename-into-place shape
// that most tools use to write atomically. Within one directory rename is unaffected,
// which is why it survives a casual test.
//
// Only the write rules get it, on least-privilege grounds rather than to close a hole:
// reparenting out of a read grant needs remove_file on the source and make_reg on the
// destination, which no read rule carries, and the kernel refuses any reparenting where
// the file would gain rights it did not have at the source - a check built into refer's
// own semantics, which runs wherever refer is granted. So a read rule carrying refer
// would not actually widen anything; it would just be a right the read side has no use
// for, in the one package whose whole subject is which rights are handled and granted.
//
// Only the DIRECTORY constructor, unlike withIoctlDev: refer names an operation on the two
// parent directories, so the kernel's file-rule check - a rule on a non-directory may only
// carry rights that apply to files - rejects it with EINVAL. RestrictPaths is
// all-or-nothing, so a file rule carrying refer discards the entire ruleset and the run
// has no backstop at all. A rename is governed by the directories either way, so scoping
// it here costs nothing.
//
// The ABI gate is not an optimisation, it is what keeps the fix from fail-open: refer is
// the one right whose absence from the downgraded handled set makes a rule UNSATISFIABLE
// rather than merely intersected down (v0.9.0 path_opt.go, FSRule.downgrade), and
// go-landlock answers that by collapsing the whole config to v0 and returning nil having
// restricted nothing. Asking for refer only where the kernel handles it means a ruleset is
// never built that BestEffort would rather discard than downgrade. Below ABI 2 the tier
// keeps today's behaviour, which is the kernel's own: Landlock denies cross-directory
// reparenting implicitly there, whatever the handled set says, so there is nothing to
// restore and nothing to disclose - unlike truncate or ioctl_dev, the old kernel is MORE
// restrictive, not less.
func withRefer(rule func(...string) ll.FSRule) func(...string) ll.FSRule {
	return func(paths ...string) ll.FSRule {
		if !referSupported() {
			return rule(paths...)
		}
		return rule(paths...).WithRefer()
	}
}

// referSupported reports whether this kernel's Landlock ABI (>= 2) has the refer right,
// so a rule may ask for it without BestEffort discarding the ruleset. See withRefer.
func referSupported() bool {
	return effectiveABI() >= 2
}

// withIoctlDev wraps a rule constructor so the rules it builds also grant ioctl_dev,
// which both handled sets contain and none of go-landlock's RO/RW helpers grant. Without
// it, from ABI 5 (kernel 6.10) the right is handled and granted nowhere, which denies
// EVERY ioctl on EVERY device node the target opens after enforcement - TCGETS and
// TIOCGWINSZ on a freshly opened /dev/tty or /dev/pts/N, so isatty, termios, and any
// curses or job-control consumer fails with an EACCES naming no layer. It applies to
// both tiers and to reads as well as writes: a device is as often read-granted as
// written, and an ioctl on a path the policy did not grant is already denied by the
// absence of any rule for it, so scoping the right to the grants is what the file rules
// were going to say anyway.
//
// A directory rule carrying it is not a new shape: the RO/RW dir helpers already put
// file-only rights (execute, read_file) into directory rules, and the kernel's
// file-rule restriction runs the other way - a rule on a non-directory may only carry
// rights that apply to files, which ioctl_dev does.
func withIoctlDev(rule func(...string) ll.FSRule) func(...string) ll.FSRule {
	return func(paths ...string) ll.FSRule {
		return rule(paths...).WithIoctlDev()
	}
}

// existing drops the paths that do not exist, as classifyRules does, and for the same
// reason returns any other stat failure rather than dropping it: this set is the
// entrypoint's own exec rule, so a swallowed EACCES leaves the target unable to execute
// itself with nothing naming the tier that stopped it.
func existing(paths []string) ([]string, error) {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		_, err := os.Stat(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("landlock: %q: %w", p, err)
		}
		out = append(out, p)
	}
	return out, nil
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

// IoctlDevRestricted reports whether this kernel's Landlock ABI (>= 5, i.e. 6.10+) can
// restrict ioctl(2) on device files. From ABI 5 both tiers grant the right on their own
// grants (withIoctlDev), so a granted device node keeps its ioctls either way and what
// the ABI decides is everything else: below it the right is absent from
// handled_access_fs and therefore unrestricted, so an ioctl on a device node the grants
// do NOT cover is available - not merely the terminal-injection set seccomp blocks
// separately. The degraded tier has no mount namespace behind Landlock, so "everything
// else" there is the host's whole /dev. It is disclosed in the run report for the same
// reason truncate is: 5.13 through 6.9 is most of the field.
func IoctlDevRestricted() bool {
	return effectiveABI() >= 5
}

// ResolveUnixRestricted reports whether this kernel's Landlock ABI (>= 9) can restrict
// connect(2) and sendmsg(2) on pathname AF_UNIX sockets. Below it the right is absent
// from handled_access_fs and therefore unrestricted, so the degraded tier's target can
// connect to any host daemon socket its path reaches - and with no mount namespace that
// is every socket on the host, whatever the file grants say. That is an egress route as
// much as a filesystem one, since the daemon has its own network access, which is why
// the degraded run report names it alongside truncate and ioctl_dev.
func ResolveUnixRestricted() bool {
	return effectiveABI() >= 9
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
