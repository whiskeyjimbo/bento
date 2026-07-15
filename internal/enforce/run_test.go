package enforce

import (
	"context"
	"errors"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/internal/policy"
)

// fakeEnforcer is an in-memory Enforcer for exercising the core orchestration
// without a platform backend: it records whether Run was reached and returns
// canned probe/result values.
type fakeEnforcer struct {
	probe  Report
	result Result
	ran    bool
}

func (f *fakeEnforcer) Probe(context.Context) Report { return f.probe }

func (f *fakeEnforcer) Run(context.Context, *policy.Policy, Process) (Result, error) {
	f.ran = true
	return f.result, nil
}

// validPolicy is the minimal policy that passes validation: no network, no
// limits, exec blocked.
func validPolicy() *policy.Policy {
	return &policy.Policy{Entrypoint: "./x"}
}

// fullyEnforced is a probe reporting every layer as enforced.
func fullyEnforced() Report {
	var r Report
	for _, l := range []Layer{LayerFilesystem, LayerNetwork, LayerExec, LayerLimits} {
		r.Add(l, Enforced, "")
	}
	return r
}

// none-strict asks for fork/clone blocking no backend enforces yet, so the exec
// layer must come back degraded through the orchestrator: --strict refuses it,
// and a default run proceeds (exec is hardening tier) but reports the shortfall
// rather than silently claiming the stricter mode.
func TestNoneStrictExecReportedDegraded(t *testing.T) {
	noneStrict := func() *policy.Policy {
		return &policy.Policy{Entrypoint: "./x", Exec: policy.ExecNoneStrict}
	}

	f := &fakeEnforcer{probe: fullyEnforced()}
	res, err := Run(context.Background(), f, noneStrict(), Process{}, Options{})
	if err != nil {
		t.Fatalf("default run should proceed for a hardening-tier gap; got %v", err)
	}
	if got := res.Report.StateOf(LayerExec); got != Degraded {
		t.Errorf("exec state = %v, want degraded", got)
	}

	f = &fakeEnforcer{probe: fullyEnforced()}
	_, err = Run(context.Background(), f, noneStrict(), Process{}, Options{Strict: true})
	var refusal *Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("--strict must refuse none-strict; got %v", err)
	}
	if f.ran {
		t.Error("a refused run must not reach the enforcer")
	}

	// Plain none must not be spuriously downgraded.
	f = &fakeEnforcer{probe: fullyEnforced()}
	res, err = Run(context.Background(), f, validPolicy(), Process{}, Options{Strict: true})
	if err != nil {
		t.Fatalf("plain none under --strict should pass; got %v", err)
	}
	if got := res.Report.StateOf(LayerExec); got != Enforced {
		t.Errorf("none exec state = %v, want enforced", got)
	}
}

func TestRunDelegatesAndPropagatesExit(t *testing.T) {
	f := &fakeEnforcer{probe: fullyEnforced(), result: Result{ExitCode: 7}}
	res, err := Run(context.Background(), f, validPolicy(), Process{}, Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !f.ran {
		t.Error("enforcer.Run was not reached")
	}
	if res.ExitCode != 7 {
		t.Errorf("exit code = %d, want 7", res.ExitCode)
	}
}

// The result must report only the layers the policy was judged against. Warning
// that egress allowlisting is unavailable to a policy that asked for no network
// is noise, and noise trains users to ignore the warnings that matter.
func TestResultReportsOnlyRequiredLayers(t *testing.T) {
	f := &fakeEnforcer{}
	f.probe.Add(LayerFilesystem, Enforced, "")
	f.probe.Add(LayerNetwork, Unavailable, "egress stack not built")
	f.probe.Add(LayerExec, Enforced, "")

	res, err := Run(context.Background(), f, validPolicy(), Process{}, Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, l := range res.Report.Layers {
		if l.Layer == LayerNetwork {
			t.Error("result reported the network layer to a policy that requested no network")
		}
	}
	if res.Report.HasDegradation() {
		t.Errorf("result should report no shortfall; got %+v", res.Report.Degradations())
	}
}

func TestRunValidatesPolicy(t *testing.T) {
	f := &fakeEnforcer{probe: fullyEnforced()}
	bad := &policy.Policy{Entrypoint: "./x", Env: []string{"NOT A NAME"}}
	if _, err := Run(context.Background(), f, bad, Process{}, Options{}); err == nil {
		t.Fatal("expected an invalid policy to be rejected")
	}
	if f.ran {
		t.Error("an invalid policy reached the enforcer")
	}
}

// A policy that asks for no network must not be blocked by a host that cannot
// run the egress stack: it never requested egress, and namespace isolation alone
// denies it.
func TestUnusedLayerDoesNotBlockRun(t *testing.T) {
	f := &fakeEnforcer{}
	f.probe.Add(LayerFilesystem, Enforced, "")
	f.probe.Add(LayerNetwork, Unavailable, "pasta not installed")
	f.probe.Add(LayerExec, Enforced, "")

	for _, opts := range []Options{{}, {Strict: true}} {
		f.ran = false
		if _, err := Run(context.Background(), f, validPolicy(), Process{}, opts); err != nil {
			t.Fatalf("opts %+v: unexpected refusal: %v", opts, err)
		}
		if !f.ran {
			t.Errorf("opts %+v: run was blocked by a layer the policy does not use", opts)
		}
	}
}

// The same host must refuse when the policy actually asks for egress.
func TestRequiredLayerBlocksRun(t *testing.T) {
	f := &fakeEnforcer{}
	f.probe.Add(LayerFilesystem, Enforced, "")
	f.probe.Add(LayerNetwork, Unavailable, "pasta not installed")

	p := validPolicy()
	p.Network = []policy.NetworkRule{{Host: "api.github.com", Port: "443"}}

	_, err := Run(context.Background(), f, p, Process{}, Options{})
	var refusal *Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("err = %v, want *Refusal", err)
	}
	if f.ran {
		t.Error("ran despite an unenforceable core layer the policy requires")
	}
}

// A hardening layer that cannot be enforced (no seccomp) is reported loudly but
// does not refuse the run by default - that is the macOS reality.
func TestHardeningGapRunsByDefaultButRefusesUnderStrict(t *testing.T) {
	newProbe := func() Report {
		var r Report
		r.Add(LayerFilesystem, Enforced, "")
		r.Add(LayerExec, Unavailable, "no seccomp on this platform")
		return r
	}

	f := &fakeEnforcer{probe: newProbe()}
	if _, err := Run(context.Background(), f, validPolicy(), Process{}, Options{}); err != nil {
		t.Fatalf("default mode should run despite a hardening gap: %v", err)
	}
	if !f.ran {
		t.Error("default mode refused on a hardening gap")
	}

	f = &fakeEnforcer{probe: newProbe()}
	if _, err := Run(context.Background(), f, validPolicy(), Process{}, Options{Strict: true}); err == nil {
		t.Error("strict mode should refuse on a hardening gap")
	}
	if f.ran {
		t.Error("strict mode ran despite a hardening gap")
	}
}

// A degraded core layer refuses by default, runs under --allow-degraded.
func TestDegradedCoreRefusesByDefaultAndRunsWhenAllowed(t *testing.T) {
	newProbe := func() Report {
		var r Report
		r.Add(LayerFilesystem, Degraded, "userns blocked; Landlock-only confinement")
		return r
	}

	f := &fakeEnforcer{probe: newProbe()}
	if _, err := Run(context.Background(), f, validPolicy(), Process{}, Options{}); err == nil {
		t.Error("default mode should refuse a degraded core layer")
	}
	if f.ran {
		t.Error("default mode ran with a degraded core layer")
	}

	f = &fakeEnforcer{probe: newProbe()}
	if _, err := Run(context.Background(), f, validPolicy(), Process{}, Options{AllowDegraded: true}); err != nil {
		t.Fatalf("--allow-degraded should permit a degraded core layer: %v", err)
	}
	if !f.ran {
		t.Error("--allow-degraded refused a degraded core layer")
	}
}

// --allow-degraded is reduced confinement, not absent confinement: a core layer
// that enforces nothing at all still refuses.
func TestAllowDegradedStillRefusesUnavailableCore(t *testing.T) {
	f := &fakeEnforcer{}
	f.probe.Add(LayerFilesystem, Unavailable, "no userns and no Landlock")

	_, err := Run(context.Background(), f, validPolicy(), Process{}, Options{AllowDegraded: true})
	if err == nil {
		t.Fatal("--allow-degraded should still refuse when a core layer enforces nothing")
	}
	if f.ran {
		t.Error("ran with no core confinement at all")
	}
}

// A requested resource limit that cannot be enforced must refuse by default -
// running untrusted code without its memory/CPU cap risks exhausting the host,
// which is worse than a merely weaker sandbox. --allow-degraded overrides.
func TestUnenforceableRequestedLimitRefusesByDefault(t *testing.T) {
	newProbe := func() Report {
		var r Report
		r.Add(LayerFilesystem, Enforced, "")
		r.Add(LayerLimits, Unavailable, "no systemd user manager")
		return r
	}
	limited := func() *policy.Policy {
		return &policy.Policy{Entrypoint: "./x", Limits: policy.Limits{Memory: "128M"}}
	}

	f := &fakeEnforcer{probe: newProbe()}
	if _, err := Run(context.Background(), f, limited(), Process{}, Options{}); err == nil {
		t.Error("default mode should refuse a requested limit it cannot enforce")
	}
	if f.ran {
		t.Error("ran an untrusted target unbounded despite a requested memory limit")
	}

	f = &fakeEnforcer{probe: newProbe()}
	if _, err := Run(context.Background(), f, limited(), Process{}, Options{AllowDegraded: true}); err != nil {
		t.Fatalf("--allow-degraded should permit running without the limit: %v", err)
	}
	if !f.ran {
		t.Error("--allow-degraded should have run the target")
	}
}

// A limit that is NOT requested (no limits in the policy) must not affect
// admission - the limits layer is only relevant when the manifest asks for it.
func TestUnrequestedLimitDoesNotRefuse(t *testing.T) {
	f := &fakeEnforcer{}
	f.probe.Add(LayerFilesystem, Enforced, "")
	f.probe.Add(LayerLimits, Unavailable, "no systemd user manager")

	if _, err := Run(context.Background(), f, validPolicy(), Process{}, Options{}); err != nil {
		t.Errorf("a policy that requests no limits must not be blocked by unavailable limits: %v", err)
	}
	if !f.ran {
		t.Error("run was blocked by a layer the policy does not use")
	}
}

func TestRunRejectsNilEnforcer(t *testing.T) {
	if _, err := Run(context.Background(), nil, validPolicy(), Process{}, Options{}); err == nil {
		t.Error("expected error for nil enforcer")
	}
}

func TestLayerTiers(t *testing.T) {
	for layer, want := range map[Layer]Tier{
		LayerFilesystem: TierCore,
		LayerNetwork:    TierCore,
		LayerExec:       TierHardening,
		LayerLimits:     TierHardening,
	} {
		if got := layer.Tier(); got != want {
			t.Errorf("%s.Tier() = %s, want %s", layer, got, want)
		}
	}
}

func TestReportForFiltersToRequestedLayers(t *testing.T) {
	var r Report
	r.Add(LayerFilesystem, Enforced, "")
	r.Add(LayerNetwork, Unavailable, "no pasta")

	got := r.For([]Layer{LayerFilesystem})
	if len(got.Layers) != 1 || got.Layers[0].Layer != LayerFilesystem {
		t.Fatalf("For([filesystem]) = %+v", got.Layers)
	}
	if got.HasDegradation() {
		t.Error("filtered report should not carry the excluded layer's degradation")
	}
}

func TestReportDegradation(t *testing.T) {
	var r Report
	if r.HasDegradation() {
		t.Error("empty report should not report degradation")
	}
	r.Add(LayerFilesystem, Enforced, "")
	r.Add(LayerExec, Unavailable, "no seccomp")
	if !r.HasDegradation() {
		t.Error("report with an unavailable layer should report degradation")
	}
	deg := r.Degradations()
	if len(deg) != 1 || deg[0].Layer != LayerExec {
		t.Errorf("degradations = %+v, want [exec-block]", deg)
	}
}

func TestStateString(t *testing.T) {
	for state, want := range map[State]string{Enforced: "enforced", Degraded: "degraded", Unavailable: "unavailable"} {
		if got := state.String(); got != want {
			t.Errorf("State(%d).String() = %q, want %q", state, got, want)
		}
	}
}

func TestReportSetReplacesOrAdds(t *testing.T) {
	var r Report
	r.Add(LayerLimits, Enforced, "")
	r.Set(LayerLimits, Degraded, "cpu not delegated")
	if len(r.Layers) != 1 || r.Layers[0].State != Degraded || r.Layers[0].Reason != "cpu not delegated" {
		t.Errorf("Set should replace an existing layer in place; got %+v", r.Layers)
	}
	r.Set(LayerNetwork, Enforced, "")
	if len(r.Layers) != 2 {
		t.Errorf("Set should add a missing layer; got %+v", r.Layers)
	}
}
