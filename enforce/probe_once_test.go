package enforce

import (
	"context"
	"slices"
	"testing"

	"github.com/whiskeyjimbo/bento/policy"
)

// A probe builds namespaces and asks the systemd user manager, and the backend used to
// take its own moments after admission took one from the same inputs - every launch paid
// the host probe twice. The reading admission judged is the one the backend must report
// from.
func TestRunHandsItsProbeToTheBackend(t *testing.T) {
	f := &fakeEnforcer{probe: confinedHost()}
	if _, err := Run(context.Background(), f, validPolicy(), Process{}, Options{}); err != nil {
		t.Fatal(err)
	}
	if f.probes != 1 {
		t.Errorf("one run probed the host %d times", f.probes)
	}
	if f.gotProbed == nil || !slices.Equal(f.gotProbed.Layers, f.probe.Layers) {
		t.Errorf("the backend was not handed the probe admission took: got %v", f.gotProbed)
	}
}

// layerFake is a backend that can probe only what a run requires.
type layerFake struct {
	fakeEnforcer
	asked [][]Layer
}

func (f *layerFake) ProbeFor(_ context.Context, layers []Layer) Report {
	f.asked = append(f.asked, layers)
	return f.probe
}

// A manifest without limits never reads the limits layers, and measuring them costs a
// Linux run seven execs and two round trips to a user manager that may be too busy to
// answer. Where the backend can probe by layer, it is asked for exactly the run's.
func TestRunProbesOnlyTheLayersItRequires(t *testing.T) {
	for _, p := range []*policy.Policy{
		validPolicy(),
		{Entrypoint: "./x", Limits: policy.Limits{PIDs: 64}},
	} {
		f := &layerFake{fakeEnforcer: fakeEnforcer{probe: confinedHost()}}
		f.probe.Add(LayerLimitsPIDs, Enforced, "")
		if _, err := Run(context.Background(), f, p, Process{}, Options{}); err != nil {
			t.Fatal(err)
		}
		want := requiredLayers(p, Options{})
		if f.probes != 0 || len(f.asked) != 1 || !slices.Equal(f.asked[0], want) {
			t.Errorf("limits %+v: want one ProbeFor(%v) and no Probe; got ProbeFor %v and %d Probe", p.Limits, want, f.asked, f.probes)
		}
	}
}
