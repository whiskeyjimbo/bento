package enforce

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/policy"
)

// fakeEnforcer is an in-memory Enforcer for exercising the core orchestration
// without a platform backend: it records whether Run was reached and returns
// canned probe/result values.
type fakeEnforcer struct {
	probe  Report
	result Result
	err    error
	ran    bool
	// Func values are not comparable, so the fake proves what enforce.Run
	// forwarded by invoking the gate it received: gotGate is that gate's return,
	// gateNil records whether a nil gate arrived.
	gotGate bool
	gateNil bool
	// gotDegraded records the degraded flag enforce.Run passed, so a test can assert
	// the reduced-confinement tier is selected only when the probe reports it.
	gotDegraded      bool
	gotAcceptAliases []string
	gotDenyPaths     []string
	gotRunID         string
	// silentStage makes the fake return a stage that never attested its setup, which
	// Run refuses. A backend that reached the target attests, so that is the default
	// here rather than Result.Setup's zero value - otherwise every test that only
	// cares about admission would be asserting against a refused run.
	silentStage bool
}

func (f *fakeEnforcer) Probe(context.Context) Report { return f.probe }

func (f *fakeEnforcer) Run(ctx context.Context, _ *policy.Policy, _ Process, opts RunOptions) (Result, error) {
	f.ran = true
	f.gateNil = opts.Gate == nil
	f.gotDegraded = opts.Degraded
	f.gotAcceptAliases = opts.AcceptAliasesUnder
	f.gotDenyPaths = opts.DenyPaths
	f.gotRunID = opts.RunID
	if opts.Gate != nil {
		f.gotGate = opts.Gate(ctx, "example.com", "443")
	}
	res := f.result
	if res.Setup == SetupSilent && !f.silentStage {
		res.Setup = SetupAttested
	}
	return res, f.err
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

// A policy that declares egress requires the network layer, and the probe reports
// that layer only as Enforced or Unavailable (a namespace either fences egress or
// it does not - there is no partial). So a host that cannot fence egress must
// refuse a network-requiring policy under every posture, including --allow-degraded:
// reduced confinement is not no confinement, and admitting a run whose egress fence
// is gone would silently let an untrusted target reach the network.
func TestNetworkPolicyRefusedWhenEgressUnavailable(t *testing.T) {
	netPolicy := &policy.Policy{
		Entrypoint: "./x",
		Network:    []policy.NetworkRule{{Host: "a.com", Port: "443"}},
	}
	probe := func() Report {
		p := fullyEnforced()
		p.Set(LayerNetwork, Unavailable, "no network namespace on this host")
		return p
	}
	for _, opts := range []Options{{}, {AllowDegraded: true}, {Strict: true}} {
		f := &fakeEnforcer{probe: probe()}
		_, err := Run(context.Background(), f, netPolicy, Process{}, opts)
		var refusal *Refusal
		if !errors.As(err, &refusal) {
			t.Fatalf("opts %+v: want refusal when egress cannot be fenced, got %v", opts, err)
		}
		if !hasLayer(refusal.Short, LayerNetwork) {
			t.Errorf("opts %+v: refusal must name the network layer, got %v", opts, refusal.Short)
		}
		if f.ran {
			t.Errorf("opts %+v: a refused run must not reach the enforcer", opts)
		}
	}
}

// enforce.Run reserves err for a failure to set up or run the sandbox itself. When
// the backend returns such an error, Run must propagate it unchanged and must not
// panic or fabricate an Enforced report from a zero-value result - the report
// overlay runs even on the error path.
func TestRunPropagatesEnforcerError(t *testing.T) {
	wantErr := errors.New("bwrap: failed to set up sandbox")
	f := &fakeEnforcer{probe: fullyEnforced(), err: wantErr}
	res, err := Run(context.Background(), f, validPolicy(), Process{}, Options{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want the backend error propagated", err)
	}
	// The overlay still runs the required-layer report off the probe, so a caller
	// inspecting the report after an error sees the probed truth, not a fabricated
	// all-enforced report nor a panic on the zero-value backend report.
	if res.Report.StateOf(LayerFilesystem) != Enforced {
		t.Errorf("filesystem state = %v, want the probed Enforced even on the error path", res.Report.StateOf(LayerFilesystem))
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

// A probe that reports the limits layer Enforced but OMITS the cpu-limits layer for
// a cpu-requesting policy must still refuse: the absent cpu layer is synthesized
// Unavailable, since systemd-run silently ignores an undelegated CPUQuota and a
// probe regression that drops the layer must not admit an uncapped run. The limits
// layer being Enforced means it cannot itself carry the refusal.
func TestCPULimitLayerOmittedByProbeRefused(t *testing.T) {
	cpuLimited := &policy.Policy{Entrypoint: "./x", Limits: policy.Limits{CPU: "50%"}}

	var probe Report
	probe.Add(LayerFilesystem, Enforced, "")
	probe.Add(LayerLimits, Enforced, "") // limits-cpu deliberately omitted
	f := &fakeEnforcer{probe: probe}

	_, err := Run(context.Background(), f, cpuLimited, Process{}, Options{})
	var refusal *Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("a probe that omits the cpu-limits layer for a cpu policy must refuse; got %v", err)
	}
	if f.ran {
		t.Error("a run whose cpu-limits layer was unreported must not reach the enforcer")
	}
	if !hasLayer(refusal.Short, LayerLimitsCPU) {
		t.Errorf("refusal should name the limits-cpu layer; short = %+v", refusal.Short)
	}
}

// Run-time refinement may only worsen a layer, never improve it: a backend that
// reports a required layer better than the probe must not overwrite a degradation
// the admission relied on. Probe says filesystem Degraded (admitted under
// --allow-degraded); a backend claiming Enforced would make the returned report
// assert a guarantee the run never had.
func TestRunRefinementOnlyWorsens(t *testing.T) {
	probe := fullyEnforced()
	probe.Set(LayerFilesystem, Degraded, "userns blocked; Landlock-only")
	better := fullyEnforced() // filesystem Enforced - a backend contradicting the probe
	f := &fakeEnforcer{probe: probe, result: Result{Report: better}}

	res, err := Run(context.Background(), f, validPolicy(), Process{}, Options{AllowDegraded: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := res.Report.StateOf(LayerFilesystem); got != Degraded {
		t.Errorf("filesystem state = %v, want degraded (a backend must not mask a probed degradation)", got)
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

// enforce.Run forwards Options.NetworkGate to the enforcer unchanged, and a
// zero Options forwards a nil gate (the declarative default). Func values are
// not comparable, so the fake proves receipt by invoking the gate it got.
func TestRunForwardsNetworkGate(t *testing.T) {
	admitted := false
	f := &fakeEnforcer{probe: fullyEnforced()}
	_, err := Run(context.Background(), f, validPolicy(), Process{}, Options{
		NetworkGate: func(context.Context, string, string) bool { admitted = true; return true },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !admitted || !f.gotGate {
		t.Error("the NetworkGate was not forwarded to the enforcer")
	}

	f = &fakeEnforcer{probe: fullyEnforced()}
	if _, err := Run(context.Background(), f, validPolicy(), Process{}, Options{}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !f.gateNil {
		t.Error("a zero Options must forward a nil gate")
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

// An embedder who builds a policy by hand never goes through manifest.Resolve, so the
// tilde is still there when Run gets it. Enforcement would take it as a relative path
// and grant nothing while the run succeeded and attested every layer, which is the one
// outcome the refusal exists to prevent.
func TestRunRefusesAnUnexpandedTilde(t *testing.T) {
	f := &fakeEnforcer{probe: fullyEnforced()}
	p := &policy.Policy{Entrypoint: "/bin/true", Read: []string{"~/.config"}}
	_, err := Run(context.Background(), f, p, Process{}, Options{})
	if err == nil {
		t.Fatal("expected an unexpanded tilde grant to be rejected")
	}
	if !strings.Contains(err.Error(), "read[0]") {
		t.Errorf("the refusal must name the grant; got %v", err)
	}
	if f.ran {
		t.Error("a policy granting nothing reached the enforcer")
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
	// And the backend is told to use its reduced-confinement tier, so it does not try
	// its full mechanism (bwrap) that the Degraded state says cannot run.
	if !f.gotDegraded {
		t.Error("--allow-degraded on a degraded core layer must pass degraded=true to the backend")
	}

	// A fully-enforced host runs with degraded=false: the backend uses its full tier.
	f = &fakeEnforcer{probe: fullyEnforced()}
	if _, err := Run(context.Background(), f, validPolicy(), Process{}, Options{}); err != nil {
		t.Fatalf("a fully-enforced run should proceed: %v", err)
	}
	if f.gotDegraded {
		t.Error("a fully-enforced run must pass degraded=false")
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
	_, err := Run(context.Background(), f, limited(), Process{}, Options{})
	if err == nil {
		t.Error("default mode should refuse a requested limit it cannot enforce")
	}
	if f.ran {
		t.Error("ran an untrusted target unbounded despite a requested memory limit")
	}
	// The refusal names a host shortfall the caller cannot go fix - systemd-run is not
	// theirs to install - so the way past it has to travel with the refusal. It is only
	// honest here because the branch below proves the flag really does admit this run.
	var refusal *Refusal
	if !errors.As(err, &refusal) || !refusal.Waivable {
		t.Errorf("the limits refusal must be marked waivable; got %#v", err)
	}

	f = &fakeEnforcer{probe: newProbe()}
	if _, err := Run(context.Background(), f, limited(), Process{}, Options{AllowDegraded: true}); err != nil {
		t.Fatalf("--allow-degraded should permit running without the limit: %v", err)
	}
	if !f.ran {
		t.Error("--allow-degraded should have run the target")
	}

	// Strict refuses the same shortfall, but pointing its reader at --allow-degraded
	// would contradict the CLI's own rule that the two flags are opposites.
	f = &fakeEnforcer{probe: newProbe()}
	_, err = Run(context.Background(), f, limited(), Process{}, Options{Strict: true})
	if !errors.As(err, &refusal) {
		t.Fatalf("strict should refuse the same shortfall; got %v", err)
	}
	if refusal.Waivable {
		t.Error("a strict refusal must not offer the flag strict is defined against")
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

// The backend emits --setenv for every key it is handed, so a map an embedder built
// from os.Environ rather than ResolveEnv would carry the host's environment into the
// sandbox and the manifest would stop describing what the target can see.
func TestRunRefusesUndeclaredEnv(t *testing.T) {
	p := validPolicy()
	p.Env = []string{"HOME"}

	f := &fakeEnforcer{}
	f.probe.Add(LayerFilesystem, Enforced, "")
	_, err := Run(context.Background(), f, p, Process{Env: map[string]string{
		"HOME":           "/home/user",
		"AWS_SECRET_KEY": "hunter2",
		"GITHUB_TOKEN":   "ghp_x",
	}}, Options{})
	var refusal *Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("Run returned %v, want a *Refusal naming the undeclared names", err)
	}
	if !strings.Contains(refusal.Reason, "AWS_SECRET_KEY, GITHUB_TOKEN") {
		t.Errorf("reason = %q, want both undeclared names, sorted", refusal.Reason)
	}
	if f.ran {
		t.Error("the enforcer ran despite the refusal")
	}

	// The empty map ResolveEnv returns when the host set none of the declared names is
	// the subset case, and must admit.
	f = &fakeEnforcer{}
	f.probe.Add(LayerFilesystem, Enforced, "")
	if _, err := Run(context.Background(), f, p, Process{Env: map[string]string{}}, Options{}); err != nil {
		t.Fatalf("Run with an env the policy covers: %v", err)
	}
}

func TestRunRejectsNilEnforcer(t *testing.T) {
	if _, err := Run(context.Background(), nil, validPolicy(), Process{}, Options{}); err == nil {
		t.Error("expected error for nil enforcer")
	}
}

// BaselineLayers is the set every policy requires no matter what it declares. Only
// filesystem confinement is unconditional; network, exec, and limits are each pulled in
// by a policy that asks for them, so none of them appear in the baseline. A frontend
// gates host readiness on this, so a drift here would change what doctor fails on.
func TestBaselineLayersIsFilesystemOnly(t *testing.T) {
	got := BaselineLayers()
	if len(got) != 1 || got[0] != LayerFilesystem {
		t.Errorf("BaselineLayers() = %v, want just [filesystem]", got)
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

	got := r.forLayers([]Layer{LayerFilesystem})
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

// Report is copied by value all over this package, so a Set that compacted through the
// shared backing array would rewrite what a copy taken earlier still reads. The
// duplicate entry is what makes it visible: it shortens the slice, so the copy's own
// length reaches past the compacted end.
func TestReportSetDoesNotMutateAnEarlierCopy(t *testing.T) {
	var r Report
	r.Add(LayerFilesystem, Enforced, "")
	r.Add(LayerNetwork, Enforced, "")
	r.Add(LayerNetwork, Enforced, "")

	before := r
	r.Set(LayerFilesystem, Unavailable, "userns blocked")

	if got := before.StateOf(LayerFilesystem); got != Enforced {
		t.Errorf("the copy's filesystem state = %v, want the Enforced it held before the Set", got)
	}
	if got := before.StateOf(LayerNetwork); got != Enforced {
		t.Errorf("the copy's network state = %v, want Enforced - compaction must not shift entries under it", got)
	}
}

// StateOf must return the most severe state among duplicate layer entries, agreeing
// with shortfall/Degradations - else a first-match Enforced could mask a governing
// Degraded/Unavailable duplicate. A missing layer is Unavailable.
func TestStateOfWorstOfDuplicates(t *testing.T) {
	var r Report
	r.Add(LayerFilesystem, Enforced, "")
	r.Add(LayerFilesystem, Degraded, "userns blocked")
	if got := r.StateOf(LayerFilesystem); got != Degraded {
		t.Errorf("StateOf with [Enforced, Degraded] duplicates = %v, want Degraded (worst)", got)
	}
	if got := r.StateOf(LayerNetwork); got != Unavailable {
		t.Errorf("StateOf of a missing layer = %v, want Unavailable (fail-safe)", got)
	}
}

// A probe that omits a required CORE layer entirely must refuse the run: the missing
// layer is treated as Unavailable, not silently read as enforced.
func TestMissingRequiredCoreLayerRefused(t *testing.T) {
	var r Report
	r.Add(LayerNetwork, Enforced, "") // LayerFilesystem deliberately absent
	f := &fakeEnforcer{probe: r}
	if _, err := Run(context.Background(), f, validPolicy(), Process{}, Options{}); err == nil {
		t.Fatal("a run whose required filesystem layer is unreported must be refused")
	}
	if f.ran {
		t.Error("the enforcer must not run when a required core layer is unreported")
	}
}

// A gate brings the egress stack up even over a zero-rule manifest - the proxy is
// what consults it - so the run needs LayerNetwork whether or not the manifest asked
// for egress. A host that cannot provide it must refuse the gated run rather than run
// a live proxy on a run enforce judged as having no network concern.
// The degraded tier applies no shields, so a caller deny it cannot honor is a mistake
// in what the caller asked for - a *Refusal, which a frontend files apart from the runs
// that failed for reasons out of the caller's hands, and which a supervisor must not
// retry. The backend refuses this too, but only as a plain error.
func TestDegradedTierRefusesCallerDenyPaths(t *testing.T) {
	f := &fakeEnforcer{}
	f.probe.Add(LayerFilesystem, Degraded, "no user namespaces")

	_, err := Run(context.Background(), f, validPolicy(), Process{}, Options{
		AllowDegraded: true,
		DenyPaths:     []string{"/home/user/.ssh"},
	})
	var refusal *Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("Run returned %v, want a *Refusal - a deny the tier cannot apply is a caller-side mistake", err)
	}
	if f.ran {
		t.Error("the enforcer ran despite the refusal")
	}
}

func TestGatedRunRequiresTheNetworkLayer(t *testing.T) {
	gate := func(context.Context, string, string) bool { return true }

	f := &fakeEnforcer{}
	f.probe.Add(LayerFilesystem, Enforced, "")
	f.probe.Add(LayerNetwork, Unavailable, "no network namespace")
	if _, err := Run(context.Background(), f, validPolicy(), Process{}, Options{NetworkGate: gate}); err == nil {
		t.Error("a gated run was admitted on a host that cannot enforce the network layer")
	}
	if f.ran {
		t.Error("the enforcer ran despite the refusal")
	}

	// Where the host does provide it, the gated run is admitted and the layer it was
	// judged on reaches the caller: a report that dropped it would claim the run had no
	// egress concern while a proxy was serving one.
	f = &fakeEnforcer{}
	f.probe.Add(LayerFilesystem, Enforced, "")
	f.probe.Add(LayerNetwork, Enforced, "")
	res, err := Run(context.Background(), f, validPolicy(), Process{}, Options{NetworkGate: gate})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := res.Report.StateOf(LayerNetwork); got != Enforced {
		t.Errorf("gated run reports network %s, want enforced - the layer it was admitted on must be in the report", got)
	}
}

// A gated zero-rule run whose proxy dies mid-run is the case the pre-run probe cannot
// see. The backend's worse verdict must survive the overlay, and under --strict the
// run must not hand back the target's own exit code as if the posture had held.
func TestGatedRunSurfacesAMidRunNetworkDegradation(t *testing.T) {
	newFake := func() *fakeEnforcer {
		f := &fakeEnforcer{result: Result{ExitCode: 7}}
		f.probe.Add(LayerFilesystem, Enforced, "")
		f.probe.Add(LayerNetwork, Enforced, "")
		f.probe.Add(LayerExec, Enforced, "")
		f.result.Report.Add(LayerNetwork, Degraded, "the egress proxy stopped serving")
		return f
	}

	// Network is core tier, and the default posture refuses a degraded core layer at
	// admission - so the same state arriving from the backend must fault the run too,
	// not just under --strict. A nil here would hand back a clean success for a run that
	// lost a guarantee the posture exists to require.
	f := newFake()
	res, err := Run(context.Background(), f, validPolicy(), Process{},
		Options{NetworkGate: func(context.Context, string, string) bool { return true }})
	var deflt *Shortfall
	if !errors.As(err, &deflt) {
		t.Fatalf("Run under the default posture returned %v, want a *Shortfall for a core layer that lapsed mid-run", err)
	}
	if got := res.Report.StateOf(LayerNetwork); got != Degraded {
		t.Errorf("network state = %s, want degraded - the backend's mid-run verdict must survive the overlay", got)
	}

	f = newFake()
	res, err = Run(context.Background(), f, validPolicy(), Process{}, Options{
		Strict:      true,
		NetworkGate: func(context.Context, string, string) bool { return true },
	})
	var short *Shortfall
	if !errors.As(err, &short) {
		t.Fatalf("Run under --strict returned %v, want a *Shortfall for a guarantee that lapsed mid-run", err)
	}
	// The target ran, so its code and report still reach the caller: a Shortfall
	// describes a completed run, unlike a Refusal.
	if res.ExitCode != 7 {
		t.Errorf("exit code = %d, want the target's own 7 alongside the shortfall", res.ExitCode)
	}
	if len(short.Short) != 1 || short.Short[0].Layer != LayerNetwork {
		t.Errorf("shortfall names %v, want just the network layer", short.Short)
	}
}

// A strict run whose layers all held returns no error, so the shortfall above is a
// verdict about this run and not a blanket strict-mode failure.
func TestStrictRunThatHoldsReturnsNoError(t *testing.T) {
	f := &fakeEnforcer{probe: fullyEnforced(), result: Result{ExitCode: 3}}
	res, err := Run(context.Background(), f, validPolicy(), Process{}, Options{Strict: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 3 {
		t.Errorf("exit code = %d, want the target's own 3", res.ExitCode)
	}
}

// Set leaves exactly one entry for a layer. A probe that emitted a layer twice would
// otherwise keep the stale duplicate that StateOf and the admission scans still see,
// letting a report refuse on one entry and render the other as enforced.
func TestSetCollapsesDuplicateLayers(t *testing.T) {
	var r Report
	r.Add(LayerNetwork, Enforced, "")
	r.Add(LayerFilesystem, Enforced, "")
	r.Add(LayerNetwork, Degraded, "stale")

	r.Set(LayerNetwork, Enforced, "")
	if got := r.StateOf(LayerNetwork); got != Enforced {
		t.Errorf("StateOf(network) = %s after Set, want enforced - a duplicate survived", got)
	}
	if len(r.Layers) != 2 {
		t.Errorf("report has %d layers, want 2: %v", len(r.Layers), r.Layers)
	}
	if len(r.Degradations()) != 0 {
		t.Errorf("Degradations() = %v, want none - the rendered lines must agree with StateOf", r.Degradations())
	}
	if r.StateOf(LayerFilesystem) != Enforced {
		t.Error("Set dropped an unrelated layer")
	}
}

// Options.DenyPaths must reach the backend verbatim. It is the whole mechanism: a
// deny the core silently dropped would leave the caller believing a path was shielded
// on a run that read it.
func TestRunForwardsDenyPaths(t *testing.T) {
	deny := []string{"/home/u/.local/state/tack"}
	f := &fakeEnforcer{probe: fullyEnforced()}
	if _, err := Run(context.Background(), f, validPolicy(), Process{}, Options{DenyPaths: deny}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !slices.Equal(f.gotDenyPaths, deny) {
		t.Errorf("backend got DenyPaths %v, want %v", f.gotDenyPaths, deny)
	}
}

// Result.Setup must survive enforce.Run, which rebuilds Report from the probe and
// overlays the backend's. A tri-state stored in Report would be erased by that; on
// Result it is the only thing separating a setup failure from a mid-run lapse, both of
// which strict reports as a populated Result plus a *Shortfall.
func TestRunPreservesSetupState(t *testing.T) {
	for name, tc := range map[string]struct {
		setup  SetupState
		strict bool
	}{
		"attested":                           {SetupAttested, false},
		"target unreached":                   {SetupTargetUnreached, false},
		"target unreached under a shortfall": {SetupTargetUnreached, true},
	} {
		t.Run(name, func(t *testing.T) {
			backend := fullyEnforced()
			if tc.strict {
				// A layer the backend worsened mid-run is what turns strict into a
				// *Shortfall.
				backend.Set(LayerFilesystem, Unavailable, "the sandboxed launcher applied its layers but never reached the target")
			}
			f := &fakeEnforcer{
				probe:  fullyEnforced(),
				result: Result{ExitCode: 125, Setup: tc.setup, Report: backend},
			}
			res, err := Run(context.Background(), f, validPolicy(), Process{}, Options{Strict: tc.strict})
			if tc.strict {
				var short *Shortfall
				if !errors.As(err, &short) {
					t.Fatalf("strict with a worsened layer: err = %v, want a *Shortfall", err)
				}
			} else if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if res.Setup != tc.setup {
				t.Errorf("Result.Setup = %v, want %v", res.Setup, tc.setup)
			}
		})
	}
}

// A stage that never reported what it applied never reached the target - the marker it
// would have written comes before the dispatch. Run must refuse rather than hand back
// Result's zero exit code as the target's own answer, which is what an embedder whose
// stages never dispatched would otherwise read as a clean success.
func TestSilentStageIsRefused(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(fmt.Sprintf("strict=%v", strict), func(t *testing.T) {
			backend := fullyEnforced()
			backend.Set(LayerFilesystem, Unavailable, "the sandboxed launcher did not report what it applied")
			f := &fakeEnforcer{
				probe:       fullyEnforced(),
				result:      Result{ExitCode: 0, Setup: SetupSilent, Report: backend},
				silentStage: true,
			}
			res, err := Run(context.Background(), f, validPolicy(), Process{}, Options{Strict: strict})
			var refusal *Refusal
			if !errors.As(err, &refusal) {
				t.Fatalf("err = %v, want a *Refusal", err)
			}
			if !strings.Contains(refusal.Reason, "DispatchReexec") {
				t.Errorf("refusal reason %q does not name the call an embedder must make", refusal.Reason)
			}
			if !hasLayer(refusal.Short, LayerFilesystem) {
				t.Errorf("refusal shortfall %v does not name the filesystem layer", refusal.Short)
			}
			if res.Setup != SetupSilent {
				t.Errorf("Result.Setup = %v, want %v", res.Setup, SetupSilent)
			}
		})
	}
}

// A refusal's Error() is the whole account a library consumer gets: unlike the CLI, an
// embedder printing the error has nowhere else to be sent for the rest, so a status
// that carries its consequences separately must still surface them here. The split
// exists to keep a remedy visible in the CLI, not to shrink what an embedder is told.
func TestRefusalErrorCarriesTheWholeDisclosure(t *testing.T) {
	const consequences = "no PID namespace, and no network namespace"
	short := LayerStatus{
		Layer: LayerFilesystem, State: Degraded,
		Reason: "bwrap cannot make a user namespace here", Consequences: consequences,
	}
	for name, err := range map[string]error{
		"refusal":   &Refusal{Reason: "a core guarantee cannot be fully enforced on this host", Short: []LayerStatus{short}},
		"shortfall": &Shortfall{Short: []LayerStatus{short}},
	} {
		if !strings.Contains(err.Error(), consequences) {
			t.Errorf("%s dropped the layer's consequences: %v", name, err)
		}
	}
}

// runIDPolicy is a policy that would actually get a scope: a run id is only admitted
// over limits, so every run-id test needs one.
func runIDPolicy() *policy.Policy {
	p := validPolicy()
	p.Limits = policy.Limits{Memory: "128M"}
	return p
}

func TestRunIDReachesTheBackend(t *testing.T) {
	f := &fakeEnforcer{probe: fullyEnforced()}
	if _, err := Run(context.Background(), f, runIDPolicy(), Process{}, Options{RunID: "job_17"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if f.gotRunID != "job_17" {
		t.Errorf("backend got run id %q, want job_17", f.gotRunID)
	}
}

func TestRunIDRefusedWithoutLimits(t *testing.T) {
	// No limits means no scope, so the supervisor would hold a unit name that never
	// exists - the exact failure the id is for.
	f := &fakeEnforcer{probe: fullyEnforced()}
	_, err := Run(context.Background(), f, validPolicy(), Process{}, Options{RunID: "job_17"})
	var refusal *Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("err = %v, want a Refusal", err)
	}
	if f.ran {
		t.Error("the run reached the backend despite being refused")
	}
	if !strings.Contains(refusal.Reason, "no resource limits") {
		t.Errorf("refusal does not say why: %q", refusal.Reason)
	}
}

func TestRunIDRefusedWhenTheHostCannotScope(t *testing.T) {
	// --allow-degraded waives an unenforceable limit, but it must not silently waive
	// the supervisor's ability to kill the target along with it.
	probe := fullyEnforced()
	probe.Set(LayerLimits, Unavailable, "no usable systemd user manager")
	f := &fakeEnforcer{probe: probe}
	_, err := Run(context.Background(), f, runIDPolicy(), Process{}, Options{RunID: "job_17", AllowDegraded: true})
	var refusal *Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("err = %v, want a Refusal", err)
	}
	if f.ran {
		t.Error("the run reached the backend despite being refused")
	}
	if !hasLayer(refusal.Short, LayerLimits) {
		t.Errorf("refusal does not name the limits layer: %+v", refusal.Short)
	}
}

func TestRunIDSpellingIsScreened(t *testing.T) {
	// The id is interpolated into a unit name, where these select a different unit or
	// come back systemd-escaped and unrecognizable to the caller that chose them.
	for _, id := range []string{"job-17", "job.17", "job/17", "job@17", "job 17", "jöb", strings.Repeat("j", 65)} {
		f := &fakeEnforcer{probe: fullyEnforced()}
		if _, err := Run(context.Background(), f, runIDPolicy(), Process{}, Options{RunID: id}); err == nil {
			t.Errorf("run id %q was admitted", id)
		} else if f.ran {
			t.Errorf("run id %q reached the backend", id)
		}
	}
}
