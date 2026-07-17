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

	"github.com/whiskeyjimbo/bento-v2/enforce"
	"github.com/whiskeyjimbo/bento-v2/internal/launcher"
	"github.com/whiskeyjimbo/bento-v2/internal/linux"
	"github.com/whiskeyjimbo/bento-v2/policy"
	"github.com/whiskeyjimbo/bento-v2/profile"
)

// New returns the enforcer for this platform.
func New() (enforce.Enforcer, error) {
	return linux.New(), nil
}

// DispatchReexec runs bento's in-sandbox re-exec stages. To confine a target the
// linux backend binds the running binary into the sandbox and re-invokes it as a
// hidden launch stage (and, from inside, an egress-bridge stage), so an embedder
// that hosts the backend must give those invocations somewhere to land. Call it as
// the first statement in main(), before any flag parsing:
//
//	func main() {
//		backend.DispatchReexec()
//		// the program's own startup follows
//	}
//
// When os.Args names a re-exec stage it runs to completion and never returns: it
// exits with the target's exit code, or with 125 (bento's "could not run the
// target" code) on a setup failure. A target that itself exits 125 is therefore
// indistinguishable from a bento failure - the same ambiguity the CLI carries, and
// something an embedder reading a Result cannot disambiguate from stderr the way a
// human can. Otherwise it returns and the program's own startup proceeds.
//
// The whole binary re-executes inside the sandbox, so every package init() runs
// again there, under a cleared environment. Keep package init cheap and free of
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
	case launcher.SentinelBridge:
		if len(os.Args) != 3 {
			reexecFail(fmt.Errorf("%s takes exactly one socket argument", launcher.SentinelBridge))
		}
		if err := launcher.BridgeMain(os.Args[2]); err != nil {
			reexecFail(err)
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
// When allowNetwork is false the run records intended egress but does not forward
// it, so profiling untrusted code cannot exfiltrate; passing true permits egress
// for a faithful run of network-dependent code.
func Profile(ctx context.Context, p *policy.Policy, proc enforce.Process, allowNetwork bool) (profile.Observation, error) {
	return linux.New().Profile(ctx, p, proc, allowNetwork)
}
