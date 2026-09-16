package enforce

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"github.com/whiskeyjimbo/bento/policy"
)

// declaredLayers reads the Layer constants out of the package's own source, because Go
// cannot enumerate a string enum and every grid over the layers otherwise restates a list
// that goes stale the day someone adds one. Parsing the declaration is the only source
// that cannot drift from the enum: a new constant lands in this set for free, and the
// tables below then fail until they answer for it.
func declaredLayers(t *testing.T, dir string) []Layer {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	// Every file of the package, not report.go alone: a constant declared beside the code
	// that emits it would otherwise be invisible here, and a grid that cannot see a layer
	// passes for it vacuously - the one failure this enumerator exists to prevent.
	var out []Layer
	pattern := regexp.MustCompile(`(?m)^\s*Layer\w+\s+Layer\s+=\s+"([^"]+)"`)
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, g := range pattern.FindAllStringSubmatch(string(src), -1) {
			out = append(out, Layer(g[1]))
		}
	}
	if len(out) == 0 {
		t.Fatalf("no Layer constants found under %s; the enumerator's pattern no longer matches the declaration, so every grid over it would pass vacuously", dir)
	}
	return out
}

// The two columns of the layer grid this package owns: which tier a layer is admitted
// under, and what makes a run require it. A layer added to the enum without an entry here
// fails, which is the point - a layer nobody classified is admitted as core by Tier's
// fail-safe default and required by nothing, so it silently gates every run and protects
// none of them.
//
// requires is a policy that must make the layer required; nil says no policy ever does,
// which is asserted against every other row's policy rather than taken on trust.
var layerGrid = map[Layer]struct {
	tier     Tier
	requires *policy.Policy
}{
	LayerFilesystem:     {TierCore, &policy.Policy{}},
	LayerNetwork:        {TierCore, &policy.Policy{Network: []policy.NetworkRule{{Host: "example.com", Port: "443"}}}},
	LayerExec:           {TierHardening, &policy.Policy{Exec: policy.ExecNone}},
	LayerExecStrict:     {TierHardening, &policy.Policy{Exec: policy.ExecNoneStrict}},
	LayerLimitsMemory:   {TierHardening, &policy.Policy{Limits: policy.Limits{Memory: "128M"}}},
	LayerLimitsPIDs:     {TierHardening, &policy.Policy{Limits: policy.Limits{PIDs: 32}}},
	LayerLimitsCPU:      {TierHardening, &policy.Policy{Limits: policy.Limits{CPU: "50%"}}},
	LayerAutoExecReport: {TierHardening, nil},
}

func TestEveryLayerIsClassifiedAndReachable(t *testing.T) {
	layers := declaredLayers(t, ".")

	for _, l := range layers {
		row, ok := layerGrid[l]
		if !ok {
			t.Fatalf("layer %q is in the enum with no grid row: say which tier admits it and which policy requires it, or that none does", l)
		}
		if got := l.Tier(); got != row.tier {
			t.Errorf("%s: Tier() = %v, want %v", l, got, row.tier)
		}
		if row.requires == nil {
			continue
		}
		if req := requiredLayers(row.requires, Options{}); !contains(req, l) {
			t.Errorf("%s: no policy reaches it - requiredLayers returned %v, so a host that cannot enforce this layer is admitted by every run", l, req)
		}
	}
	// The other half of a nil row: not merely that this test names no policy requiring
	// the layer, but that none of the policies the grid does name pulls it in.
	for l, row := range layerGrid {
		if row.requires != nil {
			continue
		}
		for _, other := range layerGrid {
			if other.requires != nil && contains(requiredLayers(other.requires, Options{}), l) {
				t.Errorf("%s is written down as required by nothing, but a policy in the grid requires it", l)
			}
		}
	}
	if len(layers) != len(layerGrid) {
		t.Errorf("the grid has %d rows for %d declared layers; a row naming a layer the enum dropped answers for nothing", len(layerGrid), len(layers))
	}
}

func contains(layers []Layer, l Layer) bool {
	return slices.Contains(layers, l)
}

// admissionLayers is written out rather than read from declaredLayers so that a new layer
// fails the guard below until someone decides it belongs in the agreement grid.
var admissionLayers = []Layer{
	LayerFilesystem, LayerNetwork, LayerExec, LayerExecStrict,
	LayerLimitsMemory, LayerLimitsPIDs, LayerLimitsCPU, LayerAutoExecReport,
}

// Admission and the post-run bar must agree cell for cell: a state that refuses a run
// before it starts must fault the completed run when the backend discovers it late, and a
// state admission accepts must not fault it. A report-only layer never faults.
func TestAdmissionAndPostRunShortfallAgree(t *testing.T) {
	for _, l := range declaredLayers(t, ".") {
		if !slices.Contains(admissionLayers, l) {
			t.Fatalf("layer %q is declared but missing from admissionLayers", l)
		}
	}
	// A limited policy, so admitRunID judges the limits layers rather than refusing on
	// the manifest alone, which no layer state could change.
	limited := &policy.Policy{Limits: policy.Limits{Memory: "128M"}}
	postures := []Options{
		{}, {AllowDegraded: true}, {Strict: true},
		{RunID: "job"}, {AllowDegraded: true, RunID: "job"}, {Strict: true, RunID: "job"},
	}
	for _, o := range postures {
		for _, l := range admissionLayers {
			for _, s := range []State{Enforced, Degraded, Unavailable} {
				r := Report{Layers: []LayerStatus{{Layer: l, State: s}}}
				faulted := len(postRunShortfall(o, r)) > 0
				if l.ReportOnly() {
					if faulted {
						t.Errorf("%+v %s %s: a report-only layer faulted the run", o, l, s)
					}
					continue
				}
				refused := o.admit(r) != nil || admitRunID(limited, o, r) != nil
				if refused != faulted {
					t.Errorf("%+v %s %s: admission refused=%v, post-run faulted=%v", o, l, s, refused, faulted)
				}
			}
		}
	}

	// A host doctor calls ready must be one every posture admits.
	for _, o := range postures {
		for _, s := range []State{Enforced, Degraded, Unavailable} {
			var r Report
			for _, l := range BaselineLayers() {
				r.Layers = append(r.Layers, LayerStatus{Layer: l, State: s})
			}
			if len(r.forLayers(BaselineLayers()).Degradations()) == 0 && o.admit(r) != nil {
				t.Errorf("%+v: a doctor-ready baseline was refused: %v", o, o.admit(r))
			}
		}
	}
}

// ReportOnly is derived from a hard-coded maximal policy. A layer some policy requires
// must not read as report-only, or a new policy field whose layer that policy omits
// would silently stop gating runs.
func TestARequirableLayerIsNeverReportOnly(t *testing.T) {
	for l, row := range layerGrid {
		if row.requires != nil && l.ReportOnly() {
			t.Errorf("%s is required by %+v but ReportOnly() says no policy can ask for it", l, row.requires)
		}
	}
}
