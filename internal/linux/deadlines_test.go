//go:build linux

package linux

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/whiskeyjimbo/bento/policy"
)

// The probe deadlines are the limits with no observer: each expiry is decided and then
// either returned as an error or dropped, so a host that has started answering too slowly
// looks exactly like a healthy one. These assert the count exists and, more importantly,
// that it counts the right event - a probe's OWN bound expiring, not a caller that gave up
// first, which would make it a tally of caller impatience on a host that was answering
// fine.
func TestProbeDeadlinesCountsTheProbesOwnExpiry(t *testing.T) {
	t.Run("a walk that never answers", func(t *testing.T) {
		setWalkTimeout(t, time.Millisecond)

		before := ProbeDeadlines()
		_, err := bounded("a test call", func() (int, error) {
			time.Sleep(time.Second)
			return 0, nil
		})
		if !errors.Is(err, errDidNotAnswer) {
			t.Fatalf("bounded did not expire: %v", err)
		}
		if got := ProbeDeadlines() - before; got != 1 {
			t.Errorf("ProbeDeadlines rose by %d over an expiry of bounded's own timer, want 1", got)
		}
	})

	t.Run("a scope probe that never answers", func(t *testing.T) {
		shimPATH(t, "systemd-run", "#!/bin/sh\nexec sleep 60\n")

		before := ProbeDeadlines()
		if err := runScopeProbe(context.Background(), policy.Limits{Memory: "64M"}, nil); err == nil {
			t.Fatal("the scope probe returned success from a shim that never answers")
		}
		if got := ProbeDeadlines() - before; got != 1 {
			t.Errorf("ProbeDeadlines rose by %d over an expiry of scopeProbeTimeout, want 1", got)
		}
	})

	// The caller giving up measures nothing about how fast this host answers, and
	// measureScope already separates the two verdicts (limits.go's ctx.Err() arm). Counting
	// it here would send an operator to a machine that was never slow.
	t.Run("a caller that gave up first", func(t *testing.T) {
		shimPATH(t, "systemd-run", "#!/bin/sh\nexec sleep 60\n")

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		before := ProbeDeadlines()
		if err := runScopeProbe(ctx, policy.Limits{Memory: "64M"}, nil); err == nil {
			t.Fatal("the scope probe returned success under a cancelled caller")
		}
		if got := ProbeDeadlines() - before; got != 0 {
			t.Errorf("ProbeDeadlines rose by %d over a caller that cancelled, want 0 - this counts host slowness, not caller impatience", got)
		}
	})
}

func setWalkTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := credentialWalkTimeout
	credentialWalkTimeout = d
	t.Cleanup(func() { credentialWalkTimeout = old })
}
