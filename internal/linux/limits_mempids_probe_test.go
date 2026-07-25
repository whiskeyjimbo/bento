//go:build linux

package linux

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
)

// The memory/pids delegation gate is host-safety critical - an uncapped memory bomb
// can OOM the host - and it fails closed: when the controllers are not delegated,
// canCreateScope reports the whole limits layer Unavailable so admission refuses a
// requested limit rather than run it unenforced. The pure function
// (TestHostControllersDelegatedFailsClosed) is covered; this proves the WIRING through
// the real Probe, which a hardcoded LayerLimits=Enforced would otherwise satisfy while
// silently reopening v1's fail-open.
//
// It runs in child processes because canCreateScope caches behind a sync.Once and reads
// delegation inside it - so the delegatedControllers seam can only be overridden in a
// process where that Once has not yet fired, which a fresh -test.run child gives us and
// the parent (whose Once fired in the skip guard) cannot. The baseline child is the
// positive control: same Probe path, no override, and it must report Enforced, so the
// override child's Unavailable is caused by the delegation loss and nothing else.
func TestProbeMemPidsLayerFailsClosedThroughRealProbe(t *testing.T) {
	nsOK, _ := usableNamespaces(context.Background())
	if ok, _ := canCreateScope(); !nsOK || !ok {
		t.Skip("no bwrap tier with a usable systemd scope on this host; the limits layer is not enforced to begin with")
	}

	baseline := runMemPidsChild(t, "baseline")
	if !strings.Contains(baseline, "STATE enforced") {
		t.Fatalf("positive control failed: baseline child did not report LayerLimits enforced: %q", baseline)
	}

	override := runMemPidsChild(t, "undelegated")
	if !strings.Contains(override, "STATE unavailable") {
		t.Errorf("with memory/pids undelegated LayerLimits is not Unavailable: %q - Probe is not reading the delegation check", override)
	}
	if !strings.Contains(override, "not delegated") {
		t.Errorf("the unavailable reason does not blame delegation: %q", override)
	}
}

// runMemPidsChild re-execs this test binary to run the helper below in a fresh process
// (un-fired sync.Once) and returns its one reported line.
func runMemPidsChild(t *testing.T, mode string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestProbeMemPidsLayerHelper")
	cmd.Env = append(os.Environ(), "BENTO_TEST_MEMPIDS="+mode)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s child failed: %v\n%s", mode, err, out)
	}
	return string(out)
}

// TestProbeMemPidsLayerHelper is the child half: in "undelegated" mode it forces the
// delegation read to a confirmed-undelegated memory/pids set (known=true, so it is
// provably the delegation branch and not the unreadable-delegation one) before the Once
// fires, then reports the real Probe's LayerLimits state and reason. Inert unless the
// parent set the trigger.
func TestProbeMemPidsLayerHelper(t *testing.T) {
	mode := os.Getenv("BENTO_TEST_MEMPIDS")
	if mode == "" {
		t.Skip("child helper for TestProbeMemPidsLayerFailsClosedThroughRealProbe")
	}
	if mode == "undelegated" {
		delegatedControllers = func() (map[string]bool, bool) {
			return map[string]bool{"memory": false, "pids": false}, true
		}
	}
	r := New().Probe(context.Background())
	var reason string
	for _, l := range r.Layers {
		if l.Layer == enforce.LayerLimits {
			reason = l.Reason
		}
	}
	os.Stdout.WriteString("STATE " + r.StateOf(enforce.LayerLimits).String() + " REASON " + reason + "\n")
}
