package enforce

import (
	"context"
	"fmt"
	"strings"

	"github.com/whiskeyjimbo/bento/policy"
)

// Options tunes a Run. The zero value is the default posture: refuse to run when
// a core guarantee the policy depends on cannot be fully enforced.
type Options struct {
	// Strict refuses unless every layer the policy needs - hardening included -
	// is fully enforced.
	Strict bool
	// AllowDegraded opts into a reduced-confinement run when a core layer can
	// only be partially enforced (e.g. Landlock-only, with no mount namespace).
	// It does not permit running with a core layer that enforces nothing at all.
	AllowDegraded bool
	// NetworkGate, when set, is consulted for an egress host the manifest does not
	// allow; returning true admits that connection for this run only. It is the
	// additive seam a supervising caller uses to prompt a human. Unset means deny
	// (the declarative default). A gate admission is surfaced in
	// Result.GateAdmitted, never folded into the policy or its fingerprint.
	NetworkGate NetworkGate
}

// Run orchestrates a sandboxed execution: it validates the policy, probes what
// this host can enforce of the layers the policy needs, admits or refuses the
// run per Options, then delegates enforcement to e.
//
// Frontends call only this, so the refuse-versus-degrade decision lives in one
// place regardless of backend or frontend.
func Run(ctx context.Context, e Enforcer, p *policy.Policy, proc Process, opts Options) (Result, error) {
	if e == nil {
		return Result{}, fmt.Errorf("enforce: nil enforcer")
	}
	if err := p.Validate(); err != nil {
		return Result{}, err
	}
	required := e.Probe(ctx).forLayers(requiredLayers(p))
	if err := opts.admit(required); err != nil {
		return Result{}, err
	}
	// A Degraded filesystem layer that reached here was admitted under
	// --allow-degraded (default and strict both refuse it); the backend cannot run
	// its full mechanism, so tell it to take its reduced-confinement tier. Selecting
	// on the probed state, not on the flag, keeps the decision tied to what the host
	// can actually do.
	degraded := required.StateOf(LayerFilesystem) == Degraded
	res, err := e.Run(ctx, p, proc, opts.NetworkGate, degraded)

	// Report exactly what was judged. Start from the pre-run probe (already filtered
	// to the required layers - warning about egress a no-network policy never asked
	// for is noise that trains users to ignore the warnings that matter), then
	// overlay any refinement the backend made during the run. The backend may
	// discover a shortfall only while running - e.g. that a requested cgroup
	// controller is not delegated - and that must reach the caller rather than being
	// overwritten by the pre-run probe. Overlaying only the required layers keeps a
	// partial or empty backend report from dropping a layer the probe already judged.
	//
	// The overlay only ever worsens a layer: a run-time report is a refinement, and a
	// backend claiming a layer is better than the probe judged - e.g. Enforced over a
	// filesystem the probe called Degraded and that was admitted under
	// --allow-degraded - would mask a degradation the admission relied on, making the
	// returned report assert a guarantee the run never had.
	wanted := requiredLayers(p)
	want := make(map[Layer]bool, len(wanted))
	for _, l := range wanted {
		want[l] = true
	}
	for _, l := range res.Report.Layers {
		if want[l.Layer] && l.State > required.StateOf(l.Layer) {
			required.Set(l.Layer, l.State, l.Reason)
		}
	}
	res.Report = required
	return res, err
}

// BaselineLayers returns the layers every policy requires regardless of its contents -
// the guarantees a host must provide to run anything at all. A frontend that gates on
// host readiness (doctor) uses it so its gate stays in sync with what admission
// actually requires: a host short only on a conditionally-required layer still runs the
// manifests that never asked for it, so failing it wholesale would be a false verdict.
func BaselineLayers() []Layer {
	return requiredLayers(&policy.Policy{Exec: policy.ExecAll})
}

// requiredLayers returns the layers a policy actually depends on.
//
// A policy with no network rules denies all egress, which namespace isolation
// alone provides - it does not need the egress-allowlist stack, so a host that
// cannot run that stack must not block it. Likewise a policy that permits
// subprocesses does not need exec-blocking, and one with no limits does not need
// cgroups.
func requiredLayers(p *policy.Policy) []Layer {
	layers := []Layer{LayerFilesystem}
	if len(p.Network) > 0 {
		layers = append(layers, LayerNetwork)
	}
	if p.Exec != policy.ExecAll {
		layers = append(layers, LayerExec)
	}
	if p.Exec == policy.ExecNoneStrict {
		layers = append(layers, LayerExecStrict)
	}
	if !p.Limits.IsZero() {
		layers = append(layers, LayerLimits)
	}
	if p.Limits.CPU != "" {
		layers = append(layers, LayerLimitsCPU)
	}
	return layers
}

// admit decides whether a run may proceed given what this host can enforce of
// the layers the policy requires.
func (o Options) admit(r Report) error {
	switch {
	case o.Strict:
		if short := r.Degradations(); len(short) > 0 {
			return &Refusal{Report: r, Reason: "strict mode requires every layer to be fully enforced", Short: short}
		}
	case o.AllowDegraded:
		// Reduced confinement was opted into, but a core layer that enforces
		// nothing at all is not reduced confinement - it is none.
		if short := r.shortfall(TierCore, Unavailable); len(short) > 0 {
			return &Refusal{Report: r, Reason: "a core guarantee cannot be enforced at all on this host", Short: short}
		}
		// A requested-but-unenforceable resource limit is deliberately not re-checked
		// here: --allow-degraded waives it along with the confinement layers, so an
		// untrusted target may run without its memory/pid cap and could exhaust host
		// resources. The default branch refuses exactly that; the flag accepts the risk,
		// which is its purpose - the operator has taken on the reduced guarantees.
	default:
		// Core guarantees hold on every supported platform, so falling short of
		// one means silently substituting a weaker sandbox. Refuse instead, and
		// let --allow-degraded be an explicit, informed choice.
		if short := r.shortfall(TierCore, Degraded); len(short) > 0 {
			return &Refusal{Report: r, Reason: "a core guarantee cannot be fully enforced on this host", Short: short}
		}
		// Resource limits are hardening-tier, but unlike the others a limit the
		// manifest explicitly requested protects the *host*: running an untrusted
		// target without its requested memory/CPU cap risks exhausting host
		// resources. So a requested-but-unenforceable limit refuses by default,
		// rather than running unbounded. --allow-degraded overrides.
		if short := unenforcedRequestedLimits(r); len(short) > 0 {
			return &Refusal{Report: r, Reason: "the manifest requests resource limits this host cannot enforce; running unbounded could exhaust host resources", Short: short}
		}
	}
	return nil
}

// unenforcedRequestedLimits returns the limits layer when the policy required it
// (it is present in the required-filtered report) but it is not fully enforced.
func unenforcedRequestedLimits(r Report) []LayerStatus {
	var out []LayerStatus
	for _, l := range r.Layers {
		if (l.Layer == LayerLimits || l.Layer == LayerLimitsCPU) && l.State != Enforced {
			out = append(out, l)
		}
	}
	return out
}

// Refusal is returned when Bento declines to run because this host cannot
// enforce what the policy requires. It carries the shortfall so a frontend can
// name exactly which guarantees fell short and why.
type Refusal struct {
	// Report covers only the layers the policy required.
	Report Report
	// Reason is the posture that triggered the refusal.
	Reason string
	// Short is the set of layers that fell short.
	Short []LayerStatus
}

func (e *Refusal) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "refusing to run: %s", e.Reason)
	for _, l := range e.Short {
		fmt.Fprintf(&b, "\n  %s (%s): %s", l.Layer, l.State, l.Reason)
	}
	return b.String()
}
