//go:build linux

package linux

import (
	"context"
	"errors"
	"path/filepath"
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

	// canUnshare runs on the hot path of every Run, so its expiry is the one an operator
	// most needs counted.
	t.Run("a namespace probe that never answers", func(t *testing.T) {
		dir := shimPATH(t, "bwrap", "#!/bin/sh\nexec sleep 60\n")

		before := ProbeDeadlines()
		if err := canUnshare(context.Background(), filepath.Join(dir, "bwrap")); err == nil {
			t.Fatal("canUnshare returned success from a shim that never answers")
		}
		if got := ProbeDeadlines() - before; got != 1 {
			t.Errorf("ProbeDeadlines rose by %d over an expiry of canUnshare's bound, want 1", got)
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

// bounded cannot cancel the walk it abandons, so every expiry parks a goroutine on the
// mount. For the single-shot CLI that is one stack and the process exits; a long-lived
// embedder against a flapping mount accumulates one per expiry with nothing saying so.
// The count has to be a gauge rather than probeDeadlines' tally: what an operator can act
// on is how many are held now, which falls back when the mount answers again.
func TestParkedHostCallsCountsTheGoroutinesBoundedAbandons(t *testing.T) {
	setWalkTimeout(t, time.Millisecond)

	hung := make(chan struct{})
	before := ParkedHostCalls()
	_, err := bounded("a test call", func() (int, error) { <-hung; return 0, nil })
	if !errors.Is(err, errDidNotAnswer) {
		t.Fatalf("bounded did not expire: %v", err)
	}
	if got := ParkedHostCalls() - before; got != 1 {
		t.Fatalf("ParkedHostCalls rose by %d while a goroutine sat blocked on the mount, want 1", got)
	}

	// The mount answering releases it, which is the difference between this and a tally:
	// a gauge that only climbs reports a permanent leak on a mount that recovered.
	close(hung)
	deadline := time.Now().Add(10 * time.Second)
	for ParkedHostCalls() != before {
		if time.Now().After(deadline) {
			t.Fatalf("ParkedHostCalls stayed at %d after the call answered, want back to %d", ParkedHostCalls(), before)
		}
		time.Sleep(time.Millisecond)
	}
}

func setWalkTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := credentialWalkTimeout
	credentialWalkTimeout = d
	t.Cleanup(func() { credentialWalkTimeout = old })
}
