//go:build linux

package linux

import (
	"context"
	"testing"
	"time"
)

// measureScope runs its canary bare only on the failure path, which is the host that is
// already unhealthy - so an unbounded canary holds the caller exactly where holding it is
// worst. Probe calls measureScope with no deadline of its own, so the bound has to be the
// canary's, and the expiry has to be counted or the stall is invisible as well.
//
// The shim pair reproduces the bead's spike: a systemd-run that cannot create a scope
// forces the canary branch, and a `true` that never returns is the canary that hangs.
func TestMeasureScopeBoundsItsCanary(t *testing.T) {
	shimPATH(t, "systemd-run", "#!/bin/sh\nexit 1\n")
	shimPATH(t, "true", "#!/bin/sh\nsleep 30\n")

	before := ProbeDeadlines()

	// Past the 5s bound plus the 1s WaitDelay, well short of the 30s the canary sleeps.
	const bound = 10 * time.Second
	// The result is carried out of the abandoned goroutine rather than asserted inside it:
	// on the failure path that goroutine outlives the test, and a t.Error from there is a
	// panic on top of the real assertion.
	type verdict struct {
		v        scopeVerdict
		answered bool
	}
	got, ok := within(t, bound, func() verdict {
		v, answered := measureScope(context.Background())
		return verdict{v, answered}
	})
	if !ok {
		t.Fatalf("measureScope was still blocked after %s on a canary that never returns; its documented bound is %s", bound, scopeProbeTimeout)
	}
	if got.answered {
		t.Error("measureScope answered from a probe whose scope was never created")
	}
	if got.v.reason == "" {
		t.Error("measureScope gave no reason for a host whose scope probe failed")
	}
	if got := ProbeDeadlines() - before; got != 1 {
		t.Errorf("ProbeDeadlines rose by %d over an expired canary, want 1: an unbounded canary leaves nothing to count, so the stall is invisible", got)
	}
}
