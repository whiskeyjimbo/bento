//go:build linux

package launcher

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/whiskeyjimbo/bento/internal/landlock"
	"github.com/whiskeyjimbo/bento/internal/seccomp"
)

// SentinelLaunchDegraded marks the no-bwrap launch stage: bento re-exec'd as a
// DIRECT child (not inside bubblewrap) to run a target under Landlock-only
// filesystem confinement plus the seccomp exec- and egress-blocks. It is the
// execution half of the degraded tier, entered only under
// --allow-degraded on a userns-blocked host.
const SentinelLaunchDegraded = "__bento_launch_degraded"

// DegradedConfig describes a no-bwrap run. Unlike Config it carries a Readable set:
// with a mount namespace the bwrap binds decide what is visible, but here Landlock
// is the only fence, so the read set must be named explicitly.
type DegradedConfig struct {
	// Readable are paths the target may read. A directory is granted read+execute
	// recursively; a file is granted read only, so a granted read file does not leak
	// its siblings.
	Readable []string
	// Writable are paths the target may read and write.
	Writable []string
	// ExecPaths are individual files granted read+execute - the interpreter and the
	// entrypoint, which a plain read-file rule would leave non-executable.
	ExecPaths []string
	// Block installs the exec-block seccomp filter (policy exec none/none-strict).
	Block bool
	// StrictBlock additionally blocks fork/vfork/process-clone where the architecture
	// supports it. Only meaningful with Block.
	StrictBlock bool
	// Scratch is a fresh writable directory (already in Writable) exported as TMPDIR,
	// so a target that writes temp files has a granted place for them instead of the
	// host /tmp, which the read/write set deliberately excludes.
	Scratch string
	// StripEnv names variables the enforcer added to the child's environment for its
	// own use (the session-bus variables systemd-run needs to create the limit scope)
	// and that the target must not see. They are dropped just before exec, so the
	// target still sees only the policy environment.
	StripEnv []string
	// AppliedFD, when > 0, is an inherited descriptor this stage writes its
	// applied-layer report to before the target is reached; see applied.go. Zero
	// means no report.
	AppliedFD int
	// Target is the absolute command to run: interpreter, entrypoint, and args.
	Target []string
}

// The kernel capability checks the degraded tier's refusals read. They are vars so a
// test can construct the host that lacks a capability: these are direct kernel and
// compile-time queries with no override, so on a host that HAS the capability the
// refusal path is otherwise unreachable, and a regression that dropped the guard
// entirely would look identical here.
var (
	landlockAvailable      = landlock.Available
	seccompEgressSupported = seccomp.EgressSupported
	strictExecSupported    = seccomp.StrictExecSupported
	terminalFenceSupported = seccomp.TerminalInjectionSupported
)

// The installs themselves, for the same reason: a seccomp install fails only on a kernel
// that refuses the syscall, so the refusal both launch tiers make when it does - the
// fail-closed stance the whole exec-block design rests on, since the alternative is
// running the target unconfined behind a report claiming otherwise - has no other way to
// be exercised. landlockRestrict is here for the opposite outcome: the bwrap tier's
// Landlock failure is the one place in either tier that warns and proceeds, so it is the
// branch a test most needs to reach and the one a live kernel never takes.
// reapChildren joins them for the same reason from the other direction: the wait loop
// fails only when the kernel refuses the wait (ECHILD, where an inherited
// SIGCHLD=SIG_IGN has it auto-reaping children), which no test can produce without
// taking the Go runtime's own signal handling with it - and it is the one dispatch
// failure that must NOT be reported as a target that never ran, since by then it has.
//
// blockEgress, blockProcessReach and blockTerminalInjection are here for a third reason,
// specific to the degraded tier: none of the three has a line in the applied report, so
// the only thing attesting them to the host is that the marker was written at all - the
// fatality of these calls IS the guarantee. A regression turning any of them into
// warn-and-proceed would produce a complete, marker-bearing report the host reconciles
// into an enforced network layer for a run with no netns and no egress filter. The
// coupling is the same one internal/linux/applied.go already flags for Landlock, so the
// three are seamed and pinned rather than left to fatality alone.
//
// restrictDegraded is the mirror of those three: it DOES have a line in the applied
// report, and that line is trustworthy only because the call above it is fatal - nothing
// about the record independently attests the fence. Warn-and-proceed there would produce
// the same marker-bearing report describing Landlock as applied, for a degraded run with
// no filesystem confinement at all - the tier's primary layer, and the one with no mount
// namespace behind it.
var (
	installExecBlock       = seccomp.BlockExec
	blockExecStrict        = seccomp.BlockExecStrict
	landlockRestrict       = landlock.Restrict
	reapChildren           = reapUntil
	blockEgress            = seccomp.BlockEgress
	blockProcessReach      = seccomp.BlockProcessReach
	blockTerminalInjection = seccomp.BlockTerminalInjection
	restrictDegraded       = landlock.RestrictDegraded
)

// The kernel facts restrictCapabilityBound decides on, seamed for the reason the fences
// above are: on an ordinary unprivileged host the drop always fails and the caller never
// holds a capability, so the refusal below is unreachable and a regression removing it
// would look identical.
var (
	capBoundingNow = readCapBounding
	dropCapBound   = dropCapBoundingSet
	heldCaps       = heldCapabilities
)

// restrictCapabilityBound is the degraded tier's counterpart to the bwrap tier's
// --cap-drop ALL and verifyEmptyCapBound. It empties the capability bounding set where
// the kernel permits it and refuses the run where it does not and the residual is live.
//
// PR_CAPBSET_DROP needs CAP_SETPCAP in the caller's user namespace, and this tier is
// entered precisely because a user namespace could not be created - so on an ordinary
// unprivileged host the drop is structurally unavailable. That residual is inert rather
// than dropped: this runs after the seccomp installs, every one of which sets
// PR_SET_NO_NEW_PRIVS, and a bounding set can only be spent through a setuid or
// file-capability exec, which no-new-privs already refuses. The case that is NOT inert
// is a caller that holds capabilities now (see heldCapabilities for why that means the
// PERMITTED set), where the bounding set bounds what its own children keep - and that
// is the root-started run F2 in the launcher state grid records as the one nothing
// refuses. It is refused here.
//
// The drop is never assumed: the bounding set is re-read from the kernel afterwards, so
// what this reports applied is what the kernel says applied.
func restrictCapabilityBound() error {
	held, err := capBoundingNow()
	if err != nil {
		return fmt.Errorf("launcher: %w", err)
	}
	if held == 0 {
		return nil
	}
	dropCapBound(held)
	if held, err = capBoundingNow(); err != nil {
		return fmt.Errorf("launcher: %w", err)
	}
	if held == 0 {
		return nil
	}
	eff, err := heldCaps()
	if err != nil {
		return fmt.Errorf("launcher: %w", err)
	}
	if !CapBoundResidualLive(held, eff) {
		return nil
	}
	return fmt.Errorf("launcher: refusing to run - the degraded tier could not empty the capability bounding set (%016x left) and this run holds capabilities %016x, so the target would inherit a bound the bwrap tier's --cap-drop ALL removes", held, eff)
}

// CapBoundResidualLive reports whether a capability bounding set this tier could not
// empty actually bounds anything. It is the whole of the decision restrictCapabilityBound
// acts on, exported because the probe's disclosure of that decision lives in another
// package (internal/linux, capBoundResidual) and prose was the only thing holding the two
// together: the sentence promises an unprivileged run proceeds with an inert set and a
// privileged one is refused, and without a shared source the decision could invert while
// the sentence stood still. internal/linux already imports this package, so the pairing is
// asserted there against this predicate rather than against a copy of it.
//
// A surviving set is inert unless the caller holds capabilities of its own: this runs
// after the seccomp installs set PR_SET_NO_NEW_PRIVS, and a bounding set is spendable
// only through a setuid or file-capability exec, which no-new-privs already refuses. What
// it still bounds is what the caller's OWN capabilities pass to its children, so a
// privileged caller - the root-started run - is the live case.
func CapBoundResidualLive(bounding, held uint64) bool {
	return bounding != 0 && held != 0
}

// dropCapBoundingSet asks the kernel to drop every capability in held. Individual
// failures are not reported: the caller re-reads the bounding set and decides on what
// the kernel actually did, which is the only answer worth acting on.
func dropCapBoundingSet(held uint64) {
	for cap := 0; cap < 64; cap++ {
		if held&(1<<uint(cap)) != 0 {
			_, _, _ = unix.Syscall(unix.SYS_PRCTL, unix.PR_CAPBSET_DROP, uintptr(cap), 0)
		}
	}
}

// heldCapabilities is what this process brings to an exec: the PERMITTED set, plus the
// effective set, which is a subset of it on every kernel that answers this call but is
// read rather than assumed.
//
// Permitted is the set that matters, not effective. Under no-new-privs the kernel
// intersects whatever a file's capabilities would grant with the caller's OLD permitted
// set, so the residual bounding set is inert exactly when permitted is empty - a caller
// that cleared its effective set but kept permitted, or one with an ambient set (always
// a subset of permitted, and one that survives exec regardless of no-new-privs), still
// has a live residual.
func heldCapabilities() (uint64, error) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return 0, fmt.Errorf("reading the capability sets: %w", err)
	}
	held := uint64(data[0].Permitted) | uint64(data[1].Permitted)<<32
	return held | uint64(data[0].Effective) | uint64(data[1].Effective)<<32, nil
}

// degradedPrerequisites refuses a degraded run whose confinement this host cannot
// supply. Each fence is the ONLY one of its kind in this tier - there is no mount
// namespace behind Landlock, no netns behind the egress block, and no --new-session
// detaching the target from the caller's terminal - so a missing one means running the
// target with the host filesystem, network or terminal exposed, never a quieter
// downgrade.
func degradedPrerequisites(landlockOK, egressOK, terminalOK bool) error {
	if !landlockOK {
		return fmt.Errorf("launcher: refusing to run - the degraded tier needs Landlock and this kernel has none")
	}
	if !egressOK {
		return fmt.Errorf("launcher: refusing to run - the degraded tier needs the seccomp egress block, unavailable on this architecture")
	}
	if !terminalOK {
		return fmt.Errorf("launcher: refusing to run - the degraded tier needs the seccomp terminal-injection block, unavailable on this architecture")
	}
	return nil
}

// RunDegraded is the no-bwrap execution stage. Every confinement here is the ONLY
// one of its kind - there is no mount namespace behind it - so each failure is
// fatal: the target is never run half-confined. Order mirrors the bwrap launcher
// (seccomp before the target is reached, Landlock last), minus the egress bridge,
// which the degraded tier does not run: a no-network manifest gets a seccomp egress
// block instead, closing the socket even for a proxy-ignoring static binary.
func RunDegraded(cfg DegradedConfig) (int, error) {
	if len(cfg.Target) == 0 {
		return 0, fmt.Errorf("launcher: no target command")
	}
	// The Landlock ruleset is only as good as the paths it names, and these arrive from
	// argv (--ro/--rw/--x). A relative one resolves against whatever working directory
	// this stage happens to start in, so it would confine the target to a tree the policy
	// never granted - and since this tier has no mount namespace behind it, that ruleset
	// is the whole confinement. Target[0] in the same struct is checked the same way.
	for _, set := range [][]string{cfg.Readable, cfg.Writable, cfg.ExecPaths} {
		for _, p := range set {
			if !filepath.IsAbs(p) {
				return 0, fmt.Errorf("launcher: degraded confinement paths must be absolute, got %q", p)
			}
		}
	}
	// Scratch arrives off the same wire (--scratch) and is exported as TMPDIR below, so
	// a relative one sends every temp file the target writes to a cwd-relative path the
	// ruleset never granted. Membership is checked too, because a scratch outside the
	// write set is a TMPDIR Landlock refuses - the struct's own invariant says it is
	// already in Writable, and nothing but this enforces it.
	if cfg.Scratch != "" {
		if !filepath.IsAbs(cfg.Scratch) {
			return 0, fmt.Errorf("launcher: degraded confinement paths must be absolute, got %q", cfg.Scratch)
		}
		if !slices.Contains(cfg.Writable, cfg.Scratch) {
			return 0, fmt.Errorf("launcher: degraded scratch %q is not in the write set", cfg.Scratch)
		}
	}
	if err := degradedPrerequisites(landlockAvailable(), seccompEgressSupported(), terminalFenceSupported()); err != nil {
		return 0, err
	}

	if err := dropInheritedFDs(); err != nil {
		return 0, err
	}
	// Unconditional here, unlike the bwrap tier's Socket check: this tier only ever runs
	// a no-network manifest, so there is no egress-allowed case to spare.
	if err := refuseNetworkStdio(); err != nil {
		return 0, err
	}
	if _, _, errno := unix.Syscall(unix.SYS_PRCTL, unix.PR_SET_DUMPABLE, 0, 0); errno != 0 {
		return 0, fmt.Errorf("launcher: making the launcher non-dumpable: %w", errno)
	}

	env := dropEnv(os.Environ(), cfg.StripEnv...)
	if cfg.Scratch != "" {
		// Drop any inherited TMPDIR/TMP/TEMP before appending the scratch override:
		// glibc getenv returns the first occurrence, so a policy-declared TMPDIR would
		// otherwise win and send temp files outside the granted scratch directory.
		env = dropEnv(env, "TMPDIR", "TMP", "TEMP")
		env = append(env, "TMPDIR="+cfg.Scratch, "TMP="+cfg.Scratch, "TEMP="+cfg.Scratch)
	}

	applied, err := newAppliedReport(cfg.AppliedFD)
	if err != nil {
		return 0, err
	}
	installed := AppliedExecNone
	if cfg.Block {
		var err error
		if installed, err = installExecFilter(cfg.StrictBlock); err != nil {
			return 0, fmt.Errorf("launcher: refusing to run - could not install the exec-block filter: %w", err)
		}
	}
	applied.record(AppliedExecFilter, installed, nil)
	// The degraded tier only ever runs a no-network manifest (a network manifest
	// requires LayerNetwork, which is Unavailable without a netns, so it refuses at
	// admission). So egress is always blocked here, giving even a static binary a real
	// no-egress guarantee in place of the netns.
	if err := blockEgress(); err != nil {
		return 0, fmt.Errorf("launcher: refusing to run - could not install the egress filter: %w", err)
	}
	// With no PID namespace the target shares the host's process table, so block the
	// syscalls that reach into another process (ptrace inject, cross-process memory,
	// pidfd fd-theft) - a same-user process the target injects into or steals a socket
	// fd from would otherwise defeat both the Landlock and the egress confinement.
	if err := blockProcessReach(); err != nil {
		return 0, fmt.Errorf("launcher: refusing to run - could not install the cross-process block: %w", err)
	}
	// The target inherits the parent's controlling terminal on stdin (this tier execs
	// it directly, with no bwrap --new-session to detach it), so block the ioctls that
	// forge terminal input - otherwise the target could push a command line into the
	// shell that reads after the sandbox exits.
	//
	// This is NARROWER than --new-session and is not a substitute for it: bwrap leaves
	// the target no controlling terminal at all, while this denies two ioctl requests
	// and leaves the terminal attached. Reading the user's keystrokes, TIOCSWINSZ,
	// writing escape sequences a terminal emulator acts on and foreground SIGINT all
	// stay open here. setsid is not available as a counterpart: the host starts this
	// stage with Setpgid so its descendants can be swept on teardown (see
	// internal/linux's launcherProcAttr), which makes it a process-group leader, and
	// setsid refuses one. TestTierDifferential measures both halves - the gap and what
	// the block does cover.
	//
	// Landlock's ioctl_dev right would also
	// cover this, but only at ABI 5 (kernel 6.10+). The tier is entered for a missing
	// bwrap or unprivileged userns rather than for an old kernel, so its hosts span both
	// sides of that line and the block cannot rest on Landlock.
	if err := blockTerminalInjection(); err != nil {
		return 0, fmt.Errorf("launcher: refusing to run - could not install the terminal-injection block: %w", err)
	}
	// After the seccomp installs, not before: they are what set PR_SET_NO_NEW_PRIVS, and
	// no-new-privs is what makes an undroppable bounding set inert rather than a silent
	// drop of the bwrap tier's --cap-drop ALL. See restrictCapabilityBound.
	if err := restrictCapabilityBound(); err != nil {
		return 0, err
	}

	// Landlock last, so the setup above (which does not touch confined paths) is not
	// itself restricted. A failure is fatal - this is the primary FS confinement.
	if err := restrictDegraded(cfg.Readable, cfg.Writable, cfg.ExecPaths); err != nil {
		return 0, fmt.Errorf("launcher: refusing to run - could not apply the Landlock confinement: %w", err)
	}
	applied.record(AppliedLandlock, AppliedYes, nil)

	// Every fence in this tier is fatal on failure, so a report that reaches its
	// marker is itself the proof that all of them are in place - and one that does not
	// is what stops the host reporting a confined run for a stage that confined
	// nothing. Written before the target is reached; see Run.
	if err := applied.write(); err != nil {
		return 0, err
	}

	// Never a recorder here, and no wire flag to ask for one: this tier installs
	// seccomp.BlockProcessReach above, which denies ptrace process-wide and before the
	// dispatch, so the launcher's own attach would be refused by its own filter. That
	// filter is load-bearing - with no pid namespace the target shares the host's process
	// table - and is not loosened for a diagnostic. The host knows which tier it ran and
	// reports the recorder absent from there rather than asking the stage to say so.
	return runTarget(cfg.Block, cfg.Target, env, applied, nil)
}

// EncodeLaunchDegraded renders the direct-child launch invocation for cfg. The
// caller prepends argv[0] (the bento binary path). It is the encode half of the wire
// contract DecodeLaunchDegraded parses; the two must change together.
func EncodeLaunchDegraded(cfg DegradedConfig) []string {
	args := []string{SentinelLaunchDegraded, "--exec", execModeString(Config{Block: cfg.Block, StrictBlock: cfg.StrictBlock})}
	if cfg.Scratch != "" {
		args = append(args, "--scratch", cfg.Scratch)
	}
	if cfg.AppliedFD > 0 {
		args = append(args, "--applied-fd", strconv.Itoa(cfg.AppliedFD))
	}
	for _, p := range cfg.Readable {
		args = append(args, "--ro", p)
	}
	for _, p := range cfg.Writable {
		args = append(args, "--rw", p)
	}
	for _, p := range cfg.ExecPaths {
		args = append(args, "--x", p)
	}
	for _, n := range cfg.StripEnv {
		args = append(args, "--strip-env", n)
	}
	args = append(args, "--")
	return append(args, cfg.Target...)
}

// DecodeLaunchDegraded parses a degraded-launch invocation back into a
// DegradedConfig. Errors are returned, not printed: this runs where the flag
// package's default output would land on the target's stderr.
func DecodeLaunchDegraded(args []string) (DegradedConfig, error) {
	if len(args) == 0 || args[0] != SentinelLaunchDegraded {
		return DegradedConfig{}, fmt.Errorf("launcher: not a degraded-launch invocation")
	}
	fs := flag.NewFlagSet(SentinelLaunchDegraded, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		execMode                    string
		scratch                     string
		appliedFD                   int
		read, write, exec, stripEnv stringList
	)
	fs.StringVar(&execMode, "exec", "none", "")
	fs.StringVar(&scratch, "scratch", "", "")
	fs.IntVar(&appliedFD, "applied-fd", 0, "")
	fs.Var(&read, "ro", "")
	fs.Var(&write, "rw", "")
	fs.Var(&exec, "x", "")
	fs.Var(&stripEnv, "strip-env", "")
	if err := fs.Parse(args[1:]); err != nil {
		return DegradedConfig{}, fmt.Errorf("launcher: parsing degraded-launch invocation: %w", err)
	}
	block, strict, err := parseExecMode(execMode)
	if err != nil {
		return DegradedConfig{}, err
	}
	return DegradedConfig{
		Readable:    read,
		Writable:    write,
		ExecPaths:   exec,
		Block:       block,
		StrictBlock: strict,
		Scratch:     scratch,
		StripEnv:    stripEnv,
		AppliedFD:   appliedFD,
		Target:      fs.Args(),
	}, nil
}

// dropEnv returns env with every VAR=... entry for the named variables removed, so
// a caller can append an authoritative value without losing to an inherited
// first-duplicate under glibc getenv semantics.
func dropEnv(env []string, names ...string) []string {
	drop := make(map[string]bool, len(names))
	for _, n := range names {
		drop[n] = true
	}
	out := env[:0:0]
	for _, e := range env {
		if k, _, ok := strings.Cut(e, "="); ok && drop[k] {
			continue
		}
		out = append(out, e)
	}
	return out
}
