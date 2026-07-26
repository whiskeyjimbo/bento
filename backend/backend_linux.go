// Package backend selects the enforcement backend for the host platform.
//
// It exists so frontends depend only on the enforce.Enforcer seam and never on a
// platform package: the CLI asks for "the enforcer for this host" and gets one,
// or a clear error saying this platform is not supported.
package backend

import (
	"context"
	"fmt"
	"os"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/launcher"
	"github.com/whiskeyjimbo/bento/internal/linux"
	"github.com/whiskeyjimbo/bento/policy"
	"github.com/whiskeyjimbo/bento/profile"
)

// New returns the enforcer for this platform.
func New() (enforce.Enforcer, error) {
	return linux.New(), nil
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
// That is not a hole in bento's boundary: a stage runs with exactly the privileges of
// the process that started it, which are the caller's own. It becomes one if the
// binary is installed across a privilege boundary, so don't: no setuid bit, no
// sudoers rule, and no wrapper that forwards a less-privileged caller's arguments.
//
// Every stage re-executes the whole binary, so every package init() runs again in
// the stage, under a cleared environment. Keep package init cheap and free of
// environment or other side-effect dependencies, and (for tests) call this from
// TestMain, before the testing package parses flags.
func DispatchReexec() {
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
		if len(os.Args) != 3 {
			reexecFail(fmt.Errorf("%s takes exactly one socket argument", launcher.SentinelBridge))
		}
		if err := launcher.BridgeMain(os.Args[2]); err != nil {
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
	return linux.New().Profile(ctx, p, proc, opts.AllowNetwork, opts.DenyPaths)
}
