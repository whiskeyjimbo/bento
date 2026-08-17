//go:build linux

package linux

import (
	"context"
	"os"
	"regexp"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/launcher"
)

// declaredLayers reads the Layer constants out of enforce's source for the reason the
// twin in enforce/layergrid_test.go gives: Go cannot enumerate a string enum, and a grid
// restating the list stops being exhaustive the day someone adds a layer. Read across the
// package boundary because the enum is the thing being enumerated, not a fixture.
func declaredLayers(t *testing.T) []enforce.Layer {
	t.Helper()
	src, err := os.ReadFile("../../enforce/report.go")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\s*Layer[A-Za-z]+\s+Layer\s+=\s+"([^"]+)"`).FindAllStringSubmatch(string(src), -1)
	if len(m) == 0 {
		t.Fatal("no Layer constants found in enforce/report.go; the enumerator's pattern no longer matches the declaration, so this grid would pass vacuously")
	}
	out := make([]enforce.Layer, 0, len(m))
	for _, g := range m {
		out = append(out, enforce.Layer(g[1]))
	}
	return out
}

// correctableInRun is the layers this backend can still move after the probe, once the run
// has said what it actually applied. The rest are attested by the probe alone: whatever
// the probe said is what the run reports, however the run went.
//
// The three limits layers are the open column and are written down as open rather than
// skipped: nothing corrects them after the probe, so a run whose scope was created and
// whose properties were then silently ignored still reports them as the probe found them.
// A layer added here has to earn its entry by being moved by one of the two arms below.
var correctableInRun = map[enforce.Layer]bool{
	enforce.LayerFilesystem: true,
	enforce.LayerNetwork:    true,
	enforce.LayerExec:       true,
	enforce.LayerExecStrict: true,

	enforce.LayerLimitsMemory:   false,
	enforce.LayerLimitsPIDs:     false,
	enforce.LayerLimitsCPU:      false,
	enforce.LayerAutoExecReport: false,
}

// The probe column: every declared layer has to come back from Probe. A layer the probe
// never mentions reads as Unavailable through Report.StateOf, so the first thing a policy
// requiring it meets is a refusal naming a layer this host was never asked about.
func TestTheProbeAnswersForEveryLayer(t *testing.T) {
	r := (&Enforcer{}).Probe(context.Background())
	reported := map[enforce.Layer]bool{}
	for _, ls := range r.Layers {
		reported[ls.Layer] = true
	}
	for _, l := range declaredLayers(t) {
		if !reported[l] {
			t.Errorf("the probe reported nothing for %s; it reads as Unavailable with no reason, and no host can be made ready for it", l)
		}
	}
}

// The in-run column: for every layer the grid marks correctable there must really be an
// in-run input that moves it, and for every layer it marks uncorrectable nothing in-run
// may touch it. Both directions, because a row asserting only the first would let a layer
// quietly gain a correction path nobody wrote down.
func TestEveryLayerIsAnsweredForByTheInRunCorrections(t *testing.T) {
	layers := declaredLayers(t)

	// Every layer seeded Enforced, so any in-run write shows up as a change whichever
	// direction it goes.
	seed := func() enforce.Report {
		var r enforce.Report
		for _, l := range layers {
			r.Set(l, enforce.Enforced, "")
		}
		return r
	}

	moved := map[enforce.Layer]bool{}
	note := func(before, after enforce.Report) {
		for _, l := range layers {
			if before.StateOf(l) != after.StateOf(l) {
				moved[l] = true
			}
		}
	}

	// The applied report's own corrections: a stage that never reached its marker is the
	// widest of them, and the arms below it write nothing this one does not.
	silent := seed()
	before := seed()
	applied{}.reconcile(&silent, true, true, true, 125)
	note(before, silent)

	// A complete stage that fell back to the execve-only filter, which is the only arm
	// that writes a state other than Unavailable.
	fallback := seed()
	before = seed()
	applied{complete: true, execFilter: launcher.AppliedExecBasic, landlock: launcher.AppliedYes}.
		reconcile(&fallback, true, true, true, 0)
	note(before, fallback)

	// The mid-run egress notes, which run after reconcile and are the network layer's
	// only in-run channel.
	net := seed()
	before = seed()
	worsenNetwork(&net, enforce.Degraded, "the egress bridge stopped serving mid-run")
	note(before, net)

	for _, l := range layers {
		want, ok := correctableInRun[l]
		if !ok {
			t.Fatalf("layer %s has no row in correctableInRun: say whether the run can still move it after the probe, or that the probe's word is final for it", l)
		}
		if moved[l] != want {
			t.Errorf("%s: correctable in-run = %v, want %v", l, moved[l], want)
		}
	}
}
