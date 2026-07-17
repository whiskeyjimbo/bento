package enforce

import (
	"context"
	"errors"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/policy"
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

// hasLayer reports whether a refusal's shortfall names a given layer.
func hasLayer(short []LayerStatus, layer Layer) bool {
	for _, l := range short {
		if l.Layer == layer {
			return true
		}
	}
	return false
}

// fullyEnforced is a probe reporting every layer as enforced.
func fullyEnforced() Report {
	var r Report
	for _, l := range []Layer{LayerFilesystem, LayerNetwork, LayerExec, LayerExecStrict, LayerLimits, LayerLimitsCPU} {
		r.Add(l, Enforced, "")
	}
	return r
}

// none-strict requires the exec-strict layer (fork/clone blocking). Where the host
// provides it, --strict admits and the report shows it enforced. Where it does not
// (e.g. a non-amd64 build that blocks only execve), the default run proceeds
// (exec-strict is hardening tier) but the report and --strict surface the gap
// rather than silently claiming the stricter mode.
func TestNoneStrictRequiresExecStrictLayer(t *testing.T) {
	noneStrict := &policy.Policy{Entrypoint: "./x", Exec: policy.ExecNoneStrict}

	// Host provides exec-strict: --strict admits, report shows it enforced.
	f := &fakeEnforcer{probe: fullyEnforced()}
	res, err := Run(context.Background(), f, noneStrict, Process{}, Options{Strict: true})
	if err != nil {
		t.Fatalf("--strict should admit none-strict where exec-strict is enforced; got %v", err)
	}
	if got := res.Report.StateOf(LayerExecStrict); got != Enforced {
		t.Errorf("exec-strict state = %v, want enforced", got)
	}

	// Host lacks exec-strict: default proceeds, but the report names the gap.
	degraded := fullyEnforced()
	degraded.Set(LayerExecStrict, Unavailable, "not implemented for this architecture")
	f = &fakeEnforcer{probe: degraded}
	res, err = Run(context.Background(), f, noneStrict, Process{}, Options{})
	if err != nil {
		t.Fatalf("default run should proceed for a hardening-tier gap; got %v", err)
	}
	if got := res.Report.StateOf(LayerExecStrict); got != Unavailable {
		t.Errorf("exec-strict state = %v, want unavailable", got)
	}

	// ...and --strict refuses it.
	f = &fakeEnforcer{probe: degraded}
	_, err = Run(context.Background(), f, noneStrict, Process{}, Options{Strict: true})
	var refusal *Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("--strict must refuse none-strict where exec-strict is unavailable; got %v", err)
	}
	if f.ran {
		t.Error("a refused run must not reach the enforcer")
	}

	// Plain none does not require exec-strict and passes --strict.
	f = &fakeEnforcer{probe: fullyEnforced()}
	if _, err := Run(context.Background(), f, validPolicy(), Process{}, Options{Strict: true}); err != nil {
		t.Fatalf("plain none under --strict should pass; got %v", err)
	}
}

// A manifest that requests a cpu limit requires the cpu-limits layer, which needs
// the cpu controller delegated. systemd-run silently ignores an undelegated
// CPUQuota, so an undelegated host must REFUSE the run by default (like an
// unenforceable memory limit) rather than run it uncapped - not just report it
// afterward. --allow-degraded is the explicit override.
func TestCPULimitRequiresDelegation(t *testing.T) {
	cpuLimited := &policy.Policy{Entrypoint: "./x", Limits: policy.Limits{CPU: "50%"}}

	undelegated := func() *fakeEnforcer {
		p := fullyEnforced()
		p.Set(LayerLimitsCPU, Unavailable, "the cpu controller is not delegated")
		return &fakeEnforcer{probe: p}
	}

	// Default: refuse naming the cpu-limits layer, and never reach the enforcer.
	f := undelegated()
	_, err := Run(context.Background(), f, cpuLimited, Process{}, Options{})
	var refusal *Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("default run should refuse an undelegated cpu limit; got %v", err)
	}
	if f.ran {
		t.Error("a refused cpu-limit run must not reach the enforcer")
	}
	if !hasLayer(refusal.Short, LayerLimitsCPU) {
		t.Errorf("refusal should name the limits-cpu layer; short = %+v", refusal.Short)
	}

	// No scope at all: the limits layer is unavailable and subsumes cpu, so the
	// cpu-limit policy is refused by that single layer, without a duplicate
	// limits-cpu entry (the probe does not emit one when there is no scope).
	var noScope Report
	noScope.Add(LayerFilesystem, Enforced, "")
	noScope.Add(LayerLimits, Unavailable, "no usable systemd user manager")
	f = &fakeEnforcer{probe: noScope}
	if _, err := Run(context.Background(), f, cpuLimited, Process{}, Options{}); !errors.As(err, &refusal) {
		t.Errorf("no-scope host should refuse a cpu-limit policy; got %v", err)
	} else if hasLayer(refusal.Short, LayerLimitsCPU) {
		t.Errorf("no-scope refusal should not duplicate a limits-cpu line; short = %+v", refusal.Short)
	}

	// --strict: also refuse.
	f = undelegated()
	if _, err := Run(context.Background(), f, cpuLimited, Process{}, Options{Strict: true}); !errors.As(err, &refusal) {
		t.Errorf("--strict should refuse an undelegated cpu limit; got %v", err)
	}

	// --allow-degraded: explicit opt-in runs, and the report still names the gap.
	f = undelegated()
	res, err := Run(context.Background(), f, cpuLimited, Process{}, Options{AllowDegraded: true})
	if err != nil {
		t.Fatalf("--allow-degraded should permit an undelegated cpu limit; got %v", err)
	}
	if got := res.Report.StateOf(LayerLimitsCPU); got != Unavailable {
		t.Errorf("cpu-limits state = %v, want unavailable (the gap must still be reported)", got)
	}

	// A delegated host admits and runs under --strict.
	f = &fakeEnforcer{probe: fullyEnforced()}
	if _, err := Run(context.Background(), f, cpuLimited, Process{}, Options{Strict: true}); err != nil {
		t.Fatalf("a delegated cpu limit should pass --strict; got %v", err)
	}

	// A policy that requests NO cpu limit is unaffected by cpu delegation.
	f = undelegated()
	memOnly := &policy.Policy{Entrypoint: "./x", Limits: policy.Limits{Memory: "128M"}}
	if _, err := Run(context.Background(), f, memOnly, Process{}, Options{}); err != nil {
		t.Errorf("a memory-only limit must not be refused for undelegated cpu; got %v", err)
	}
}

// A degradation the backend discovers during Run - such as a requested cgroup
// controller that is not delegated - must reach Result.Report, not be silently
// overwritten by the pre-run probe.
func TestRunPreservesBackendReportRefinement(t *testing.T) {
	limited := &policy.Policy{Entrypoint: "./x", Limits: policy.Limits{Memory: "128M"}}

	// The pre-run probe says limits are enforceable, but the backend's Run refines
	// the limits layer to degraded. The result must reflect the backend's view.
	refined := fullyEnforced()
	refined.Set(LayerLimits, Degraded, "systemd reported the limited scope degraded")
	f := &fakeEnforcer{probe: fullyEnforced(), result: Result{Report: refined}}

	res, err := Run(context.Background(), f, limited, Process{}, Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := res.Report.StateOf(LayerLimits); got != Degraded {
		t.Errorf("limits state = %v, want degraded (backend refinement was dropped)", got)
	}
	// And the report is still filtered to what the policy required (no network rules,
	// so the egress layer must not appear as noise, in any state).
	for _, l := range res.Report.Layers {
		if l.Layer == LayerNetwork {
			t.Errorf("a layer the policy did not require leaked into the report: %+v", l)
		}
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
		LayerLimitsCPU:  TierHardening,
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
	r.Set(LayerLimits, Degraded, "scope degraded")
	if len(r.Layers) != 1 || r.Layers[0].State != Degraded || r.Layers[0].Reason != "scope degraded" {
		t.Errorf("Set should replace an existing layer in place; got %+v", r.Layers)
	}
	r.Set(LayerNetwork, Enforced, "")
	if len(r.Layers) != 2 {
		t.Errorf("Set should add a missing layer; got %+v", r.Layers)
	}
}
