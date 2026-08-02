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
	// DenyPaths are absolute host paths this run must not reach, shielded on top of
	// the built-in deny-list. It is how an embedder says "never let the target read
	// X" over a policy that grants a tree covering X, and how it protects its own
	// control state (a permission store) without having to refuse every grant that
	// covers it. A deny nested inside a granted tree is the normal mode - it is how
	// ~/.ssh survives a home read grant. A policy cannot lift one: the shield opt-in
	// path covers the built-in credential shields only.
	//
	// It is not a policy field for the same reason AcceptAliasesUnder is not: it is a
	// fact about this host and this caller, and folding it into a portable,
	// fingerprinted manifest would carry one deployment's layout to every other. What
	// it shields is reported in Result.Shields alongside the built-in shields.
	//
	// Four limits, because callers reach for this for security:
	//
	//   - It shields a PATH, not the content behind it. A second name for the content
	//     inside a tree the run can read still reaches it. The credential-alias hunt
	//     that would catch that covers a deny naming an existing file, but not one
	//     naming a directory (nor a path that does not exist yet, which is shielded as
	//     a directory so no host artifact is left behind).
	//   - It covers read-covering grants only. A WRITE grant containing a deny path is
	//     refused outright rather than shielded: a shield inside a writable tree is not
	//     a boundary the sandbox can hold.
	//   - Shielding a single file leaves its siblings exposed. Widening a file deny to
	//     its directory is the caller's job; the built-in list shields directories for
	//     exactly this reason.
	//   - A run that actually lands on the degraded tier (AllowDegraded on a host whose
	//     filesystem layer probes Degraded) is REFUSED rather than admitted without the
	//     deny: that tier applies no shields at all. It is refused, not reported through
	//     Result.Exposed the way the built-in shields it drops are, because by the time
	//     a report is read the target has already had the path.
	DenyPaths []string

	// AcceptAliasesUnder acknowledges the credential aliases inside the named host
	// trees, which would otherwise refuse the run. See RunOptions.AcceptAliasesUnder
	// for why it is a tree and why it is not a policy field.
	AcceptAliasesUnder []string
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
	if err := p.RequireExpanded(); err != nil {
		return Result{}, err
	}
	// One required set for both the admission below and the report overlay further
	// down: judging admission on one set and reporting on another is how a layer gets
	// admitted on and then erased from the report.
	wanted := requiredLayers(p, opts)
	required := e.Probe(ctx).forLayers(wanted)
	if err := opts.admit(required); err != nil {
		return Result{}, err
	}
	// A Degraded filesystem layer that reached here was admitted under
	// --allow-degraded (default and strict both refuse it); the backend cannot run
	// its full mechanism, so tell it to take its reduced-confinement tier. Selecting
	// on the probed state, not on the flag, keeps the decision tied to what the host
	// can actually do. It reads only the filesystem layer because that flag selects a
	// filesystem mechanism (see RunOptions.Degraded) - another core layer's
	// degradation travels to the caller in the Report, not here.
	degraded := required.StateOf(LayerFilesystem) == Degraded
	res, err := e.Run(ctx, p, proc, RunOptions{
		Gate:               opts.NetworkGate,
		Degraded:           degraded,
		DenyPaths:          opts.DenyPaths,
		AcceptAliasesUnder: opts.AcceptAliasesUnder,
	})

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
	want := make(map[Layer]bool, len(wanted))
	for _, l := range wanted {
		want[l] = true
	}
	for _, l := range res.Report.Layers {
		if want[l.Layer] && l.State > required.StateOf(l.Layer) {
			required.SetStatus(l)
		}
	}
	res.Report = required
	if err != nil {
		return res, err
	}
	// A silent stage leaves no attestation for any layer, so the exit code beside it is
	// not an answer this run is entitled to hand back: returning nil would present
	// Result's zero as the target's own, which is how an embedder whose stages never
	// dispatched reads a clean success for a target that never started.
	//
	// The reason states what is known and offers the causes, rather than asserting one,
	// for the same reason reconcile's does: the marker is written before the target is
	// dispatched, so the usual silent stage is one that died in setup and never ran
	// anything - but a report the host could not read back, or one it read as tampered,
	// covers a target that ran and whose outcome is simply unattested. A caller that
	// retries must expect either.
	//
	// A Refusal and not a Shortfall: a Shortfall means the target ran and a guarantee
	// slipped, only strict mode looks at one, and the whole point here is that a default
	// run must not pass this by.
	if res.Setup == SetupSilent {
		return res, &Refusal{
			Report: res.Report,
			Reason: "the sandbox stage never reported what it applied, so nothing about this run is attested. " +
				"Usually the stage died during setup and the target never ran; an embedder that hosts the backend " +
				"and called backend.DispatchReexec() somewhere other than the first statement in main() looks the same",
			Short: res.Report.Degradations(),
		}
	}
	// Strict admitted this run against the pre-run probe, but the overlay above can
	// have worsened a layer with what the backend learned while running - a proxy
	// listener that died mid-run leaves the egress guarantee strict required unmet. A
	// nil error here would hand back the target's own exit code as if the posture had
	// held for the whole run, so report the lapse. It is deliberately not a Refusal:
	// the target ran, and a caller that retried on it would run it twice.
	if opts.Strict {
		if short := res.Report.Degradations(); len(short) > 0 {
			return res, &Shortfall{Report: res.Report, Short: short}
		}
	}
	return res, nil
}

// BaselineLayers returns the layers every policy requires regardless of its contents -
// the guarantees a host must provide to run anything at all. A frontend that gates on
// host readiness (doctor) uses it so its gate stays in sync with what admission
// actually requires: a host short only on a conditionally-required layer still runs the
// manifests that never asked for it, so failing it wholesale would be a false verdict.
func BaselineLayers() []Layer {
	return requiredLayers(&policy.Policy{Exec: policy.ExecAll}, Options{})
}

// requiredLayers returns the layers a run actually depends on - what the policy
// declares plus what the caller's Options bring.
//
// A policy with no network rules denies all egress, which namespace isolation
// alone provides - it does not need the egress-allowlist stack, so a host that
// cannot run that stack must not block it. Likewise a policy that permits
// subprocesses does not need exec-blocking, and one with no limits does not need
// cgroups.
//
// A gate is the one thing outside the policy that adds a layer: it brings the egress
// stack up even over a zero-rule manifest, because the proxy is what consults it. So
// the run needs LayerNetwork whether or not the manifest asked for egress.
func requiredLayers(p *policy.Policy, opts Options) []Layer {
	layers := []Layer{LayerFilesystem}
	if len(p.Network) > 0 || opts.NetworkGate != nil {
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

// Refusal is returned when Bento declines to run because this host cannot enforce what
// the policy requires, or when a run it admitted came back with nothing attested at all.
// It carries the shortfall so a frontend can name exactly which guarantees fell short and
// why. In the second case the target usually never started, but a caller must not assume
// it - see the SetupSilent branch in Run.
type Refusal struct {
	// Report covers only the layers the policy required.
	Report Report
	// Reason is the posture that triggered the refusal.
	Reason string
	// Short is the set of layers that fell short.
	Short []LayerStatus
}

// Shortfall is returned when a run that strict mode admitted did not hold its
// posture for the whole run: the backend reported a layer worse than the pre-run
// probe did. Unlike a Refusal the target ran and Result carries its exit code, so a
// caller must treat it as a completed run whose guarantees lapsed, never retry it.
type Shortfall struct {
	// Report is the final report, covering only the layers the run required.
	Report Report
	// Short is the set of layers that fell short.
	Short []LayerStatus
}

func (e *Shortfall) Error() string {
	var b strings.Builder
	b.WriteString("the run completed but strict mode's guarantees did not hold for it")
	for _, l := range e.Short {
		fmt.Fprintf(&b, "\n  %s (%s): %s", l.Layer, l.State, l.Reason)
	}
	return b.String()
}

func (e *Refusal) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "refusing to run: %s", e.Reason)
	for _, l := range e.Short {
		fmt.Fprintf(&b, "\n  %s (%s): %s", l.Layer, l.State, l.Reason)
	}
	return b.String()
}
