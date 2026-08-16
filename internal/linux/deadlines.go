//go:build linux

package linux

import (
	"context"
	"sync/atomic"
)

// probeDeadlines counts the host probes this process gave up on because their OWN bound
// expired - the scope probes' scopeProbeTimeout, the hook resolution's
// hookResolveTimeout, and bounded's credentialWalkTimeout. Each of those limits is
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

// noteProbeDeadline counts an expiry of probe's bound, but only when parent is still
// live. A probe whose caller has already given up measured nothing about the host and
// says nothing about its speed: counting it would make this a tally of caller impatience,
// which is the one reading that would make an operator chase the wrong machine.
func noteProbeDeadline(parent, probe context.Context) {
	if probe.Err() != nil && parent.Err() == nil {
		probeDeadlines.Add(1)
	}
}
