//go:build linux

package linux

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

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
