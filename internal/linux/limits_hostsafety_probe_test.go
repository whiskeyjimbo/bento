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
// Probe reports LayerLimitsMemory Unavailable so admission refuses a requested memory
// limit rather than run it unenforced. The pure function
// (TestHostSafetyDelegationStateFailsClosed) is covered; this proves the WIRING through
// the real Probe, which a hardcoded LayerLimitsMemory=Enforced would otherwise satisfy while
// silently reopening v1's fail-open.
//
// It runs in child processes to keep the delegatedControllers override off every other
// test in this package, and because a child is the only place the whole Probe path runs
// from a clean cache. The baseline child is the positive control: same Probe path, no
// override, and it must report Enforced, so the override child's Unavailable is caused
// by the delegation loss and nothing else.
func TestProbeHostSafetyLayersFailClosedThroughRealProbe(t *testing.T) {
	requireHostSafetyLimits(t)

	baseline := runHostSafetyChild(t, "baseline")
	if !strings.Contains(baseline, "STATE enforced") || !strings.Contains(baseline, "PIDSSTATE enforced") {
		t.Fatalf("positive control failed: baseline child did not report both host-safety layers enforced: %q", baseline)
	}

	// The two host-safety layers read their own controller through Probe, not one reading
	// shared by both: a wiring that asked for "memory" twice would leave LayerLimitsPIDs
	// Enforced whatever the host delegates, which is the fail-open direction this file
	// exists to refuse, and every other test in the tree would still pass.
	split := runHostSafetyChild(t, "pidsonly")
	if !strings.Contains(split, "STATE unavailable") || !strings.Contains(split, "PIDSSTATE enforced") {
		t.Errorf("with pids delegated and memory not, want memory Unavailable and pids Enforced; got %q", split)
	}

	override := runHostSafetyChild(t, "undelegated")
	if !strings.Contains(override, "STATE unavailable") {
		t.Errorf("with memory/pids undelegated LayerLimitsMemory is not Unavailable: %q - Probe is not reading the delegation check", override)
	}
	if !strings.Contains(override, "PIDSSTATE unavailable") {
		t.Errorf("with memory/pids undelegated LayerLimitsPIDs is not Unavailable: %q", override)
	}
	if !strings.Contains(override, "not delegated") {
		t.Errorf("the unavailable reason does not blame delegation: %q", override)
	}
}

// runHostSafetyChild re-execs this test binary to run the helper below in a fresh process
// (un-fired sync.Once) and returns its one reported line.
func runHostSafetyChild(t *testing.T, mode string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestProbeHostSafetyLayersHelper")
	cmd.Env = append(os.Environ(), "BENTO_TEST_HOSTSAFETY="+mode)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s child failed: %v\n%s", mode, err, out)
	}
	return string(out)
}

// TestProbeHostSafetyLayersHelper is the child half: in "undelegated" mode it forces the
// delegation read to a confirmed-undelegated memory/pids set (known=true, so it is
// provably the delegation branch and not the unreadable-delegation one) before the Once
// fires, then reports the real Probe's LayerLimitsMemory state and reason. Inert unless the
// parent set the trigger.
func TestProbeHostSafetyLayersHelper(t *testing.T) {
	mode := os.Getenv("BENTO_TEST_HOSTSAFETY")
	if mode == "" {
		t.Skip("child helper for TestProbeHostSafetyLayersFailClosedThroughRealProbe")
	}
	switch mode {
	case "undelegated":
		delegatedControllers = func(context.Context) (map[string]bool, bool) {
			return map[string]bool{"memory": false, "pids": false}, true
		}
	case "pidsonly":
		delegatedControllers = func(context.Context) (map[string]bool, bool) {
			return map[string]bool{"memory": false, "pids": true}, true
		}
	}
	r := New().Probe(context.Background())
	var reason string
	for _, l := range r.Layers {
		if l.Layer == enforce.LayerLimitsMemory {
			reason = l.Reason
		}
	}
	os.Stdout.WriteString("STATE " + r.StateOf(enforce.LayerLimitsMemory).String() +
		" PIDSSTATE " + r.StateOf(enforce.LayerLimitsPIDs).String() +
		" REASON " + reason + "\n")
}
