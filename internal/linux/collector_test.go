//go:build linux

package linux

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/proxy"
	"github.com/whiskeyjimbo/bento/policy"
)

// A panicking handler drops the connection, which is the safe direction, but the
// connection never reached an outcome - so it is counted apart from the tally rather
// than added to it. Folding it into the tally would report a run as having had its
// manifest enforced on a connection nothing decided.
func TestFaultedConnectionsAreCountedApartFromTheTally(t *testing.T) {
	c := &egressCollector{}
	c.observe(proxy.Allowed, "example.com", "443")
	c.observe(proxy.Faulted, "", "")
	c.observe(proxy.Faulted, "", "")

	if got := c.counted(); got != 1 {
		t.Errorf("counted() = %d, want 1: a fault is an outcome on a connection, not another connection", got)
	}
	if got := c.faultCount(); got != 2 {
		t.Errorf("faultCount() = %d, want 2", got)
	}
	if got := c.gateAdmitted(); len(got) != 0 {
		t.Errorf("gateAdmitted() = %v, want empty: a fault names no destination", got)
	}
}

// noteProxyFault is the fault count's only consumer, and the degraded network layer is
// its only effect: an Enforced layer cannot stand over connections whose handlers did
// not run to an outcome.
func TestProxyFaultDegradesAnEnforcedNetworkLayer(t *testing.T) {
	var r enforce.Report
	r.Set(enforce.LayerNetwork, enforce.Enforced, "")

	noteProxyFault(&r, 2)

	if got := r.StateOf(enforce.LayerNetwork); got != enforce.Degraded {
		t.Fatalf("LayerNetwork = %v, want Degraded after a proxy fault", got)
	}
	degradations := r.Degradations()
	if len(degradations) != 1 || !strings.Contains(degradations[0].Reason, "2 connection(s)") {
		t.Errorf("degradations = %+v, want the fault count: noteProxyFault is the count's only channel", degradations)
	}
}

// A refusal at the connection limit is a connection the allowlist never got to see, so
// it is tallied apart from the ones it decided. Counted with them as well: it reached the
// proxy, and a run that spent its window being refused must not read as one that never
// attempted egress.
func TestRefusalsAtCapacityAreTalliedApart(t *testing.T) {
	c := &egressCollector{}
	c.observe(proxy.Allowed, "example.com", "443")
	c.observe(proxy.RefusedAtCapacity, "", "")
	c.observe(proxy.RefusedAtCapacity, "", "")

	if got := c.atCapacityCount(); got != 2 {
		t.Errorf("atCapacityCount() = %d, want 2", got)
	}
	if got := c.counted(); got != 3 {
		t.Errorf("counted() = %d, want 3: a refusal at the limit is still a connection the proxy handled", got)
	}
}

// noteRefusedAtCapacity is that tally's only consumer, and a degraded network layer its
// only effect: an Enforced layer cannot stand over a window where a declared destination
// was refused by load rather than by policy.
func TestRefusalAtCapacityDegradesAnEnforcedNetworkLayer(t *testing.T) {
	var r enforce.Report
	r.Set(enforce.LayerNetwork, enforce.Enforced, "")

	noteRefusedAtCapacity(&r, 7)

	if got := r.StateOf(enforce.LayerNetwork); got != enforce.Degraded {
		t.Fatalf("LayerNetwork = %v, want Degraded after a refusal at the connection limit", got)
	}
	degradations := r.Degradations()
	if len(degradations) != 1 || !strings.Contains(degradations[0].Reason, "7 connection(s)") {
		t.Errorf("degradations = %+v, want the refusal count: this note is the count's only channel", degradations)
	}
}

// The gate-denied and untunneled sets are reported through Result the same way the
// admitted and guard-blocked ones are, deduped per destination and sorted.
func TestCollectorReportsGateDeniedAndUntunneledDestinations(t *testing.T) {
	c := &egressCollector{}
	c.observe(proxy.GateDenied, "denied.example", "443")
	c.observe(proxy.GateDenied, "denied.example", "443")
	c.observe(proxy.GateDenied, "2001:db8::1", "8443")
	c.observe(proxy.Untunneled, "plain.example", "80")

	wantGate := []enforce.HostPort{{Host: "2001:db8::1", Port: "8443"}, {Host: "denied.example", Port: "443"}}
	if got := c.gateRefused(); !slices.Equal(got, wantGate) {
		t.Errorf("gateRefused() = %v, want %v (deduped and sorted)", got, wantGate)
	}
	wantUntunneled := []enforce.HostPort{{Host: "plain.example", Port: "80"}}
	if got := c.untunneledDestinations(); !slices.Equal(got, wantUntunneled) {
		t.Errorf("untunneledDestinations() = %v, want %v", got, wantUntunneled)
	}
	if got := c.counted(); got != 4 {
		t.Errorf("counted() = %d, want 4: every refusal is still a connection the proxy handled", got)
	}
}

// Enforcer.Run's own degraded dispatch, rather than runDegraded called directly: the
// three refusal guards above it are covered, but nothing drove a policy that passes
// them through Run itself, so the tier the caller actually gets was never asserted.
func TestRunDispatchesToTheDegradedTier(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	script := filepath.Join(dir, "p.sh")
	if err := os.WriteFile(script, []byte("echo hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir, "/bin", "/usr"}}
	var out strings.Builder
	proc := enforce.Process{Stdout: &out, Stderr: &out}

	res, err := enforcerUsing(testBento(t)).Run(context.Background(), p, proc, enforce.RunOptions{Degraded: true})
	if err != nil {
		t.Fatalf("Run(Degraded) = %v\noutput:\n%s", err, out.String())
	}
	if res.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0\noutput:\n%s", res.ExitCode, out.String())
	}
	// This tier uses no namespaces at all, so its own probe forces LayerNetwork
	// Unavailable - which is what tells the result apart from Run having taken the full
	// tier anyway on a host where bubblewrap works.
	if got := res.Report.StateOf(enforce.LayerNetwork); got != enforce.Unavailable {
		t.Errorf("LayerNetwork = %v, want Unavailable: Run did not dispatch to the degraded tier", got)
	}
}

// noteLostRecords is the proxy's fault counts' only consumer, and a degraded network
// layer its only effect: an Enforced layer would present an egress record short by those
// events as a complete one.
//
// The two causes are asserted apart because the remedies are opposite - a panicking
// observer is the embedder's callback to fix, a post-decision handler panic is this
// project's own bug - and the disclosure is the only thing that survives to the operator.
// A count alone cannot answer which happened, so each case asserts that the OTHER
// cause's sentence is absent as well.
func TestLostRecordsNameWhichFaultDegradedTheNetworkLayer(t *testing.T) {
	for _, tc := range []struct {
		name             string
		observer, handler int
		want, absent     string
	}{
		{"observer", 3, 0, "observer panicked on 3 decision(s)", "after deciding them"},
		{"handler", 0, 2, "panicked on 2 connection(s) after deciding them", "observer panicked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var r enforce.Report
			r.Set(enforce.LayerNetwork, enforce.Enforced, "")

			noteLostRecords(&r, tc.observer, tc.handler)

			if got := r.StateOf(enforce.LayerNetwork); got != enforce.Degraded {
				t.Fatalf("LayerNetwork = %v, want Degraded after a proxy fault", got)
			}
			degradations := r.Degradations()
			if len(degradations) != 1 || !strings.Contains(degradations[0].Reason, tc.want) {
				t.Fatalf("degradations = %+v, want one naming %q", degradations, tc.want)
			}
			if strings.Contains(degradations[0].Reason, tc.absent) {
				t.Errorf("degradations = %+v, must not also name %q: the operator acts on which of the two happened", degradations, tc.absent)
			}
		})
	}
}

// Both at once, because a run can hit both and the operator then has two things to do.
func TestLostRecordsDiscloseBothFaultsWhenBothHappened(t *testing.T) {
	var r enforce.Report
	r.Set(enforce.LayerNetwork, enforce.Enforced, "")

	noteLostRecords(&r, 1, 1)

	// worsenNetwork joins successive notes into the layer's one reason, so both sentences
	// have to be in it; a summed counter can only produce one of them.
	degradations := r.Degradations()
	if len(degradations) != 1 {
		t.Fatalf("degradations = %+v, want 1 joined network degradation", degradations)
	}
	for _, want := range []string{"observer panicked on 1 decision(s)", "after deciding them"} {
		if !strings.Contains(degradations[0].Reason, want) {
			t.Errorf("degradations = %+v, missing %q: summing the two loses the rarer cause in the commoner one", degradations, want)
		}
	}
}

// A crash-looping gate and a supervisor declining every prompt refuse the same
// destinations, so the destination list cannot separate them and does not try: the host
// is named either way. The count is the separation, and noteGateFault is its only channel.
func TestCollectorCountsAGateFaultApartFromAGateDenial(t *testing.T) {
	c := &egressCollector{}
	c.observe(proxy.GateDenied, "declined.example", "443")
	c.observe(proxy.GateFaulted, "crashed.example", "443")

	want := []enforce.HostPort{{Host: "crashed.example", Port: "443"}, {Host: "declined.example", Port: "443"}}
	if got := c.gateRefused(); !slices.Equal(got, want) {
		t.Errorf("gateRefused() = %v, want %v: a destination a broken gate refused is still one the operator must see", got, want)
	}
	if got := c.gateFaultCount(); got != 1 {
		t.Errorf("gateFaultCount() = %d, want 1: without it a broken gate reads as a supervisor saying no", got)
	}
	if got := c.counted(); got != 2 {
		t.Errorf("counted() = %d, want 2: both are connections the proxy handled", got)
	}
}

// The count's only effect, and the reason it exists: an Enforced network layer cannot
// stand over destinations the report attributes to a supervisor that never decided them.
func TestGateFaultDegradesAnEnforcedNetworkLayer(t *testing.T) {
	var r enforce.Report
	r.Set(enforce.LayerNetwork, enforce.Enforced, "")

	noteGateFault(&r, 3)

	if got := r.StateOf(enforce.LayerNetwork); got != enforce.Degraded {
		t.Fatalf("LayerNetwork = %v, want Degraded after a panicking gate", got)
	}
	degradations := r.Degradations()
	if len(degradations) != 1 || !strings.Contains(degradations[0].Reason, "panicked on 3 connection(s)") {
		t.Errorf("degradations = %+v, want the gate-fault count: noteGateFault is the count's only channel", degradations)
	}
}

// noteNAT64Blackout is the blackout count's only channel: the guard's refusal is worded
// exactly like a dial failure so the sandbox cannot classify names against the host's DNS,
// which leaves the run's report the only place it can be said at all.
func TestANAT64BlackoutDegradesAnEnforcedNetworkLayer(t *testing.T) {
	var r enforce.Report
	r.Set(enforce.LayerNetwork, enforce.Enforced, "")

	noteNAT64Blackout(&r, 2)

	if got := r.StateOf(enforce.LayerNetwork); got != enforce.Degraded {
		t.Fatalf("LayerNetwork = %v, want Degraded after egress refused by a failed discovery", got)
	}
	degradations := r.Degradations()
	if len(degradations) != 1 || !strings.Contains(degradations[0].Reason, "2 IPv6 destination(s)") {
		t.Errorf("degradations = %+v, want the refusal count and what it cost", degradations)
	}
}

// A run on a host whose resolver never answers leaves discovery inconclusive on every
// run; the report must stay clean unless that actually cost the run a destination, or
// every air-gapped host degrades every run it serves.
func TestInconclusiveDiscoveryWithNoRefusalLeavesTheNetworkLayerAlone(t *testing.T) {
	var r enforce.Report
	r.Set(enforce.LayerNetwork, enforce.Enforced, "")

	noteNAT64Blackout(&r, 0)

	if got := r.StateOf(enforce.LayerNetwork); got != enforce.Enforced {
		t.Errorf("LayerNetwork = %v, want Enforced: nothing was refused", got)
	}
}

// noteAcceptRetries is the recovered-listener count's only channel. A run that spent a
// window with nothing accepting on the sandbox's socket is otherwise indistinguishable
// from one that never hit the condition - noteDeadListener covers only the terminal case.
func TestRecoveredAcceptRetriesDegradeAnEnforcedNetworkLayer(t *testing.T) {
	var r enforce.Report
	r.Set(enforce.LayerNetwork, enforce.Enforced, "")

	noteAcceptRetries(&r, 4, 1500*time.Millisecond)

	if got := r.StateOf(enforce.LayerNetwork); got != enforce.Degraded {
		t.Fatalf("LayerNetwork = %v, want Degraded after a recovered accept backoff", got)
	}
	degradations := r.Degradations()
	if len(degradations) != 1 {
		t.Fatalf("degradations = %+v, want one", degradations)
	}
	// The duration is what tells milliseconds of fd pressure apart from seconds of it,
	// so it travels beside the count rather than being summarized away.
	if !strings.Contains(degradations[0].Reason, "4 transient") || !strings.Contains(degradations[0].Reason, "1.5s") {
		t.Errorf("reason = %q, want the retry count and the time spent backed off", degradations[0].Reason)
	}
}

// A listener that never faltered says nothing, so an ordinary run's report is untouched.
func TestNoAcceptRetriesLeavesTheNetworkLayerAlone(t *testing.T) {
	var r enforce.Report
	r.Set(enforce.LayerNetwork, enforce.Enforced, "")

	noteAcceptRetries(&r, 0, 0)

	if got := r.StateOf(enforce.LayerNetwork); got != enforce.Enforced {
		t.Errorf("LayerNetwork = %v, want Enforced: the listener never faltered", got)
	}
}
