//go:build linux

package linux

import (
	"context"
	"sync/atomic"
)

// probeDeadlines counts the host probes this process gave up on because their OWN bound
// expired - scopeProbeTimeout at the two scope probes, canUnshare's own bound,
// hookResolveTimeout at the hook resolution, and bounded's credentialWalkTimeout. Each of those limits is
// decided and then either returned as an error or dropped, so a host that has started
// answering too slowly is invisible until it stops answering altogether.
//
// That is the signal worth having: the host whose scope probes are timing out is the same
// host where a probe left unbounded turns a timeout into a permanent block on admission,
// and it is visible here one degradation earlier. It counts events, not rates - a
// long-lived embedder (examples/supervise) samples the difference; the single-shot CLI
// exits before there is anything to sample, and pays one atomic add per expiry either way.
var probeDeadlines atomic.Int64

// ProbeDeadlines reports how many host probes this process has abandoned on their own
// deadline. It is a monotonic count for the life of the process.
func ProbeDeadlines() int { return int(probeDeadlines.Load()) }

// parkedHostCalls is how many goroutines bounded has abandoned on the host and that have
// not answered since. Unlike probeDeadlines it is a gauge, not a tally: bounded cannot
// cancel the walk it gave up on (see bounded), so each expiry leaves a goroutine and its
// stack blocked on the mount until the mount answers, and what an operator needs is how
// many are held right now rather than how many there have ever been.
//
// It matters for a long-lived embedder (examples/supervise) against a flapping mount,
// where the count climbs run over run; the single-shot CLI exits before it can grow. A
// limit enforced without reporting that it was reached is the gap this closes.
var parkedHostCalls atomic.Int64

// ParkedHostCalls reports how many abandoned host filesystem calls are still blocked in
// this process. It falls back as the mounts they are parked on start answering again.
func ParkedHostCalls() int { return int(parkedHostCalls.Load()) }

// noteProbeDeadline counts an expiry of probe's bound, but only when parent is still
// live. A probe whose caller has already given up measured nothing about the host and
// says nothing about its speed: counting it would make this a tally of caller impatience,
// which is the one reading that would make an operator chase the wrong machine.
func noteProbeDeadline(parent, probe context.Context) {
	if probe.Err() != nil && parent.Err() == nil {
		probeDeadlines.Add(1)
	}
}
