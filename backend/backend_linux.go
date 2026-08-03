// Package backend selects the enforcement backend for the host platform.
//
// It exists so frontends depend only on the enforce.Enforcer seam and never on a
// platform package: the CLI asks for "the enforcer for this host" and gets one,
// or a clear error saying this platform is not supported.
package backend

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync/atomic"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/launcher"
	"github.com/whiskeyjimbo/bento/internal/linux"
	"github.com/whiskeyjimbo/bento/policy"
	"github.com/whiskeyjimbo/bento/profile"
)

// New returns the enforcer for this platform.
//
// Keep the result rather than calling this per run: the enforcer is reusable and safe
// for concurrent Runs (see enforce.Enforcer). Calling it again is cheap and equally
// correct - what an embedder actually wants to avoid is a fresh PROCESS per run, since
// that is what re-pays the host probes. On one Linux/amd64 host a no-op target with no
// network and no limits cost ~60 ms on the first run of a process and ~31 ms on every
// run after it, whether or not the same Enforcer was used. Treat the numbers as the
// shape, not a budget: they move with the host and with what the policy asks for.
func New() (enforce.Enforcer, error) {
	requireDispatched()
	if !dispatched.Load() {
		return nil, errNotDispatched
	}
	return linux.New(), nil
}

// dispatched records that DispatchReexec ran. Nothing else in the parent process is
// evidence of it: the parent's own argv carries no sentinel, so requireDispatched below
// answers only for a process that already IS a stage. Without this the omission surfaces
// after the run, as a report that attests nothing and a Refusal that can only offer the
// missed call as one candidate cause among several (see the SetupSilent branch of
// enforce.Run).
var dispatched atomic.Bool

// errNotDispatched is a returned error and not the exit requireDispatched takes: this
// is the embedder's own process asking for an enforcer, where a returned error is the
// contract, and unlike a live stage there is no fork-bomb risk to cut short.
var errNotDispatched = fmt.Errorf("bento: backend.DispatchReexec() was not called; " +
	"call it as the first statement in main() (and in TestMain for tests that run enforced), " +
	"or the sandbox stages this backend re-execs have nowhere to land")

// errUndispatchedStage is what a live stage that skipped the call is told, on the
// stderr the embedder handed the target.
var errUndispatchedStage = errors.New("this process was launched as a sandbox stage but DispatchReexec was not called first; " +
	"call backend.DispatchReexec() as the first statement in main() (and in TestMain for tests that run enforced)")

// requireDispatched ends this process when it is a re-exec stage that was never
// dispatched. DispatchReexec never returns for a stage sentinel - it runs the stage
// and exits - so a process still carrying one in os.Args[1] by the time it asks for
// an enforcer has provably skipped the call, and no ordinary invocation looks like
// that (the sentinels are a reserved argv namespace).
//
// It exits rather than returning an error because the condition is an embedder
// contract violation, not a runtime failure a caller could handle, and because
// cutting the process short is the only symptom that carries: the staged child
// otherwise runs the program normally, and in a test binary that means re-running the
// suite, which re-enters the sandbox and stages again - a fork bomb whose presenting
// symptom is a silent hang. It exits rather than panicking for the same reason a
// stage that fails setup does: an embedder's own recover() would resume the program
// here and start that fork bomb, and the exit code is 125 either way, where a panic's
// 2 is what a target that crashed on its own looks like.
func requireDispatched() {
	if len(os.Args) < 2 {
		return
	}
	switch os.Args[1] {
	case launcher.SentinelLaunch, launcher.SentinelLaunchDegraded, launcher.SentinelBridge:
		reexecFail(errUndispatchedStage)
	}
}

// DispatchReexec runs bento's launch stages. To confine a target the linux backend
// re-invokes the running binary as a hidden stage, so an embedder that hosts the
// backend must give those invocations somewhere to land. There are three: the
// enforced launch stage (bound into the sandbox), the egress-bridge stage (run from
// inside it), and the degraded launch stage, which is a DIRECT host child - it runs
// outside any sandbox, because the degraded tier is what --allow-degraded selects on
// a host that cannot create the namespace at all. Call it as the first statement in
// main(), before any flag parsing:
//
//	func main() {
//		backend.DispatchReexec()
//		// the program's own startup follows
//	}
//
// When os.Args names a re-exec stage it runs to completion and never returns: it
// exits with the target's exit code, or with 125 (bento's "could not run the
// target" code) on a setup failure. The exit code alone cannot tell the two apart -
// a target may exit 125 itself - but the Result's Report can: a stage that fails
// setup never writes its applied-layer report, so the layers it was to install come
// back unenforced, naming the exit code. An embedder reads that rather than parsing
// stderr. Otherwise it returns and the program's own startup proceeds.
//
// A stage is selected by argv[1] alone and carries no proof of who invoked it, so
// whoever controls the argv of a bento-embedding binary reaches all three - including
// the degraded stage, which confines a target of their choosing outside the sandbox.
// That is not a hole in bento's boundary: a stage runs with no more privilege than the
// process that started it, which holds the caller's own. It becomes one if the
// binary is installed across a privilege boundary, so don't: no setuid bit, no
// sudoers rule, and no wrapper that forwards a less-privileged caller's arguments.
//
// Every stage re-executes the whole binary, so every package init() runs again in the
// stage, under an environment bento constructed rather than the one the embedder was
// started with. Keep package init cheap and free of
// environment or other side-effect dependencies, and (for tests) call this from
// TestMain, before the testing package parses flags.
//
// Skipping the call is caught rather than tolerated: New and Profile refuse when it was
// never made, and exit 125 when they find a stage sentinel still in os.Args[1], where the
// caller is a live stage that must not go on to run the program (see requireDispatched).
func DispatchReexec() {
	// Recorded before the argv screen: an ordinary invocation takes the early return
	// below, and that is exactly the process New and Profile need the record for.
	dispatched.Store(true)
	if len(os.Args) < 2 {
		return
	}
	switch os.Args[1] {
	case launcher.SentinelLaunch:
		cfg, err := launcher.DecodeLaunch(os.Args[1:])
		if err != nil {
			reexecFail(err)
		}
		code, err := launcher.Run(cfg)
		if err != nil {
			reexecFail(err)
		}
		os.Exit(code)
	case launcher.SentinelLaunchDegraded:
		cfg, err := launcher.DecodeLaunchDegraded(os.Args[1:])
		if err != nil {
			reexecFail(err)
		}
		code, err := launcher.RunDegraded(cfg)
		if err != nil {
			reexecFail(err)
		}
		os.Exit(code)
	case launcher.SentinelBridge:
		if len(os.Args) != 4 {
			reexecFail(fmt.Errorf("%s takes exactly a socket and a liveness descriptor", launcher.SentinelBridge))
		}
		livenessFD, err := strconv.Atoi(os.Args[3])
		if err != nil {
			reexecFail(fmt.Errorf("%s: liveness descriptor %q is not a number", launcher.SentinelBridge, os.Args[3]))
		}
		if err := launcher.BridgeMain(os.Args[2], livenessFD); err != nil {
			reexecFail(fmt.Errorf("bridge: %w", err))
		}
		os.Exit(0)
	}
}

// reexecFail reports a setup failure of a re-exec stage and exits 125 - never 0,
// so an embedder cannot mistake a filter-install or bridge failure for a clean
// run. 125 matches env(1)/docker's "command could not be executed".
func reexecFail(err error) {
	fmt.Fprintf(os.Stderr, "bento: %v\n", err)
	os.Exit(125)
}

// Profile runs p under observation and reports what the target did. Linux-only.
// opts.AllowNetwork false records intended egress without forwarding it, so
// profiling untrusted code cannot exfiltrate; opts.DenyPaths shields caller-owned
// paths from the profiling run (see ProfileOptions).
func Profile(ctx context.Context, p *policy.Policy, proc enforce.Process, opts ProfileOptions) (profile.Observation, error) {
	requireDispatched()
	if !dispatched.Load() {
		return profile.Observation{}, errNotDispatched
	}
	return linux.New().Profile(ctx, p, proc, opts.AllowNetwork, opts.DenyPaths, opts.AcceptAliasesUnder)
}
