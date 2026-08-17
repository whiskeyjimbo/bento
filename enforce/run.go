package enforce

import (
	"context"
	"fmt"
	"regexp"
	"slices"
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

	// RecordExec asks for a record of the execs the run performed, returned in
	// Result.ExecRecord. See RunOptions.RecordExec for what it costs the target and why
	// a run that cannot have one is not refused over it.
	RecordExec bool

	// AcceptAliasesUnder acknowledges the credential aliases inside the named host
	// trees, which would otherwise refuse the run. See RunOptions.AcceptAliasesUnder
	// for why it is a tree and why it is not a policy field.
	AcceptAliasesUnder []string

	// RunID names this run so a supervisor outside it can reap the whole process tree
	// rather than the one pid it happened to record. See RunOptions.RunID for the unit
	// name it derives and why the caller supplies the id instead of reading one back.
	//
	// Setting it refuses a run that would not reliably get a scope - a policy with no
	// limits, or a host whose limits layer is not fully Enforced - because the
	// alternative is the failure this exists to prevent: a supervisor holding a handle to
	// nothing while the target runs. Degraded refuses alongside Unavailable, and not
	// because a Degraded host cannot create a scope: it means something about the scope
	// fell short, the backend can only ever refine that judgment downward once the run
	// starts, and a handle that might not be there is exactly what a supervisor cannot
	// act on. That refusal stands under --allow-degraded too, which otherwise waives an
	// unenforceable limit: waiving the limit is a choice about the target's resource
	// ceiling, and it must not silently take the supervisor's ability to kill it along
	// with it.
	//
	// Reusing an id while a run still holds it is refused by systemd, not here: the unit
	// name is taken, systemd-run says so on stderr, and the run fails before the target
	// starts. It surfaces as bento's unattested-stage refusal, whose prose describes the
	// usual cause rather than this one, so a supervisor recycling ids reads systemd's line
	// above it. Checking the name here first would be a guess with a race behind it - the
	// name can be claimed between the check and the start - so the authoritative refusal
	// is left where it actually holds.
	RunID string
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
	if err := ValidateRunID(opts.RunID); err != nil {
		return Result{}, err
	}
	if err := admitEnv(p, proc); err != nil {
		return Result{}, err
	}
	wanted := requiredLayers(p, opts)
	probed := e.Probe(ctx)
	required := probed.forLayers(wanted)
	if err := opts.admit(required); err != nil {
		return Result{}, err
	}
	if err := admitRunID(p, opts, required); err != nil {
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
	// requiredLayers leaves LayerNetwork out of a zero-rule gateless manifest because
	// denying all egress is what namespace isolation already provides. That rests on there
	// BEING a namespace, and a probe reporting the layer Unavailable says there is not -
	// so the layer is filtered out of `required` and nothing sees it, on the reasoning that
	// the run had no egress concern.
	//
	// The unfiltered probe is read here for that reason. The two ways a run gets an egress
	// fence are the netns and the degraded tier's seccomp block, which is why a degraded
	// run is exempt: the backend is told to install one. A run that has neither has no
	// fence at all, and nothing downstream can supply one - Run passes no other signal that
	// would make a backend fence egress in this shape.
	//
	// The Linux backend never reaches this: its probe ties LayerNetwork Unavailable to the
	// same missing namespace that degrades the filesystem layer, so `degraded` is already
	// true. But that is an invariant of one backend's probe, and Run takes any Enforcer -
	// the same reason the gate and network-rule refusals above do not rest on it either.
	//
	// Read with StateOf, so a probe that never mentions the layer refuses alongside one
	// that reports it Unavailable. The two say the same thing about the run - there is no
	// netns and nothing else will fence egress - and telling them apart here would make
	// the guarantee rest on an Enforcer remembering to declare a layer. See Enforcer for
	// the obligation that follows from it.
	if !degraded && probed.StateOf(LayerNetwork) == Unavailable {
		return Result{}, &Refusal{
			Report: required,
			Reason: "this host has no network namespace to fence egress into, and only the degraded tier substitutes a seccomp egress block for one",
		}
	}
	// The degraded tier has no mount namespace and applies no shields, so it cannot
	// honor a caller deny. The backend refuses on this too, and keeps its copy because
	// it is reachable without Run - but a backend refusal is a plain error, and a
	// frontend that sorts the two apart files it under the runs that failed for reasons
	// out of the caller's hands. It is decidable here, where the tier and the options
	// are both in hand, and it is a mistake in what the caller asked for: the category
	// ValidateRunID describes, which a supervisor must not retry.
	//
	// A gate gets the same treatment. On the Linux backend admit has already refused it
	// - a gate requires LayerNetwork, and the userns-blocked host this tier is for
	// probes that Unavailable, which no posture admits - but that is an invariant of one
	// backend's probe, and Run takes any Enforcer. An enforcer whose probe pairs a
	// degraded filesystem with a usable network reopens exactly this bug.
	//
	// And network RULES with it, on the same predicate requiredLayers uses: the two are
	// one class there (either brings LayerNetwork up) and splitting them here is what let
	// a network manifest through. On the Linux backend it fails the other way from the
	// gate - the target gets strictly LESS network than declared, since runDegraded never
	// listens on the proxy socket newSandbox sets and the launcher blocks egress outright
	// - so what breaks is the attestation: Result.Report would assert LayerNetwork
	// Enforced for a run in which no proxy listened and no allowlist was consulted. The
	// Linux backend does now correct that layer itself, but the refusal cannot rest on a
	// backend doing so: Run takes any Enforcer, and the overlay here only ever worsens,
	// so a backend that claims Enforced is believed.
	if degraded {
		if len(opts.DenyPaths) > 0 {
			return Result{}, &Refusal{
				Report: required,
				Reason: "caller deny paths cannot be honored by the degraded tier: it has no mount namespace and applies no shields",
			}
		}
		if opts.NetworkGate != nil {
			return Result{}, &Refusal{
				Report: required,
				Reason: "a network gate cannot be honored by the degraded tier: it has no network namespace to run the egress proxy in",
			}
		}
		if len(p.Network) > 0 {
			return Result{}, &Refusal{
				Report: required,
				Reason: "network rules cannot be honored by the degraded tier: it has no network namespace to run the egress proxy in",
			}
		}
	}
	res, err := e.Run(ctx, p, proc, RunOptions{
		Gate:               opts.NetworkGate,
		Degraded:           degraded,
		DenyPaths:          opts.DenyPaths,
		RecordExec:         opts.RecordExec,
		AcceptAliasesUnder: opts.AcceptAliasesUnder,
		RunID:              opts.RunID,
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
	// Report-only layers ride along, filtered out of everything that judges. A layer no
	// policy can ask for is in no run's required set, so forLayers drops it and a run on a
	// host missing that host fact says nothing about it at all - the operator sees only
	// whatever per-item notice the shortfall produces, which is also what one bad item
	// looks like. Carrying it here keeps one source for the fact (the probe) rather than
	// having the run path consult a second one, and it cannot affect admission by
	// construction: admit already ran, against `required`, which this does not touch.
	// postRunShortfall's strict branch excludes them for the same reason - see there.
	for _, l := range probed.Layers {
		if l.Layer.ReportOnly() {
			required.SetStatus(l)
		}
	}
	res.Report = required
	if err != nil {
		// The posture bar below applies to this arm too: the overlay has already run, so the
		// report handed back here can carry a core layer the backend downgraded mid-run -
		// the exact state admission refuses - and the error beside it is the backend's own
		// (the target's exit status, a wrapper that vanished), which says nothing about
		// enforcement. A caller sorting the two apart with errors.As would file the run as an
		// ordinary program failure over a posture that did not hold.
		//
		// The backend's error is wrapped rather than replaced: it is what says why the run
		// failed, and the shortfall is an additional verdict on it, not a substitute.
		//
		// The silent-stage Refusal below is deliberately NOT re-applied here. A Refusal is
		// retry-safe by contract, and this arm's premise is that the target may already have
		// run - telling a supervisor to run it again is the hazard the Shortfall wording
		// exists to avoid. Its own reason does not reach here either: it guards against
		// presenting Result's zero exit code as the target's own, and there is a non-nil
		// error here doing that job.
		if short := postRunShortfall(opts, res.Report); len(short) > 0 {
			return res, &Shortfall{Report: res.Report, Short: short, Err: err}
		}
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
	// A Refusal and not a Shortfall: a Shortfall describes a completed run whose report
	// named which guarantee slipped, and there is no report here to name one from - the
	// point of this branch is that nothing at all was attested.
	if res.Setup == SetupSilent {
		return res, &Refusal{
			Report: res.Report,
			Reason: "the sandbox stage never reported what it applied, so nothing about this run is attested. " +
				"Usually the stage died during setup and the target never ran; an embedder that hosts the backend " +
				"and called backend.DispatchReexec() somewhere other than the first statement in main() looks the same",
			Short: judgedDegradations(res.Report),
		}
	}
	// Admission judged the pre-run probe, but the overlay above can have worsened a
	// layer with what the backend learned while running - a proxy listener that died
	// mid-run, or an in-sandbox Landlock ruleset that failed to apply. A nil error here
	// would hand back the target's own exit code as if the posture had held for the
	// whole run, so hold the run to the same bar it was admitted on, whichever posture
	// that was: a core layer that came back Degraded is the exact state the default
	// posture refuses, and it must not pass merely because the probe learned of it two
	// microseconds late.
	//
	// Deliberately not a Refusal under any posture: the target ran, and a caller that
	// retried on it would run it twice. That is why the bar is re-applied here rather
	// than by calling admit again - the judgment is the same, the verdict is not.
	if short := postRunShortfall(opts, res.Report); len(short) > 0 {
		return res, &Shortfall{Report: res.Report, Short: short}
	}
	return res, nil
}

// judgedLayers is the report without the layers that only ride along for disclosure. A
// report-only layer is in no policy's required set, so no posture ever admitted a run ON
// one, and nothing that judges a run may read it: naming it in a refusal's shortfall or
// faulting a completed run for it presents a host fact the manifest could not have asked
// for as a guarantee that slipped.
func judgedLayers(r Report) []LayerStatus {
	var out []LayerStatus
	for _, l := range r.Layers {
		if !l.Layer.ReportOnly() {
			out = append(out, l)
		}
	}
	return out
}

// judgedDegradations is Degradations over judgedLayers, for the refusals and shortfalls
// that name which guarantee fell short.
func judgedDegradations(r Report) []LayerStatus {
	return Report{Layers: judgedLayers(r)}.Degradations()
}

// postRunShortfall returns the layers of the final report that fall below what the
// caller's posture admitted the run on. It mirrors admit's branches: strict requires
// every layer fully enforced, --allow-degraded waives a degraded core layer but not one
// that enforces nothing, and the default posture refuses a core layer that is anything
// less than enforced.
//
// Only core layers outside strict, because that is what admission gates on: a
// hardening layer the backend downgraded mid-run was never grounds to refuse the run,
// so it is not grounds to fault the completed one either. The requested-limits check is
// the one exception, and it rides along with the default branch for the same reason it
// refuses at admission: a limit the manifest asked for protects the *host*, and a
// controller found undelegated only once the scope exists is the same unbounded target
// arriving late. The identical state at admission refuses, so the completed run must
// not pass merely because the backend learned of it second.
func postRunShortfall(opts Options, r Report) []LayerStatus {
	// Report-only layers are filtered out of every branch, not only the strict one that
	// scans them all: Tier() defaults an un-enumerated layer to core, so a report-only
	// layer whose author forgets that switch would be faulted by the two tier-scanning
	// branches below. Filtering here rather than in each keeps the two classifications
	// from having to agree.
	r = Report{Layers: judgedLayers(r)}
	switch {
	case opts.Strict:
		return r.Degradations()
	case opts.AllowDegraded:
		// --allow-degraded waives the requested-limits bar at admission, so it is not
		// re-applied here either: the operator took on running unbounded.
		return r.shortfall(TierCore, Unavailable)
	default:
		return append(r.shortfall(TierCore, Degraded), unenforcedRequestedLimits(r)...)
	}
}

// BaselineLayers returns the layers every policy requires regardless of its contents -
// the guarantees a host must provide to run anything at all. A frontend that gates on
// host readiness (doctor) uses it so its gate stays in sync with what admission
// actually requires: a host short only on a conditionally-required layer still runs the
// manifests that never asked for it, so failing it wholesale would be a false verdict.
func BaselineLayers() []Layer {
	return requiredLayers(&policy.Policy{Exec: policy.ExecAll}, Options{})
}

// ReportOnly reports whether a layer is one no policy and no option can ask for, so its
// state never admits or refuses a run and it is visible only in a host report like
// doctor's. LayerAutoExecReport is the case: it covers a hint, not a guarantee.
//
// Derived from requiredLayers over a policy asking for everything rather than named
// here, so a layer added to one of them cannot drift from the other - a frontend saying
// "a manifest that needs this runs with the gap reported" about a layer no manifest can
// name is telling a reader to check something that cannot happen.
func (l Layer) ReportOnly() bool {
	return !slices.Contains(requiredLayers(&policy.Policy{
		Network: []policy.NetworkRule{{}},
		Exec:    policy.ExecNoneStrict,
		Limits:  policy.Limits{Memory: "1", CPU: "1%", PIDs: 1},
	}, Options{}), l)
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
	// Per requested limit, not per "any limit set": the three limits layers rest on
	// different controllers, so requiring more than one for any limit refuses a manifest
	// over a controller it never asked for - which is what a pids-only manifest hit on a
	// host delegating pids but not memory.
	if p.Limits.Memory != "" {
		layers = append(layers, LayerLimitsMemory)
	}
	if p.Limits.PIDs != 0 {
		layers = append(layers, LayerLimitsPIDs)
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
			return &Refusal{
				Report:   r,
				Reason:   "the manifest requests resource limits this host cannot enforce; running unbounded could exhaust host resources",
				Short:    short,
				Waivable: true,
			}
		}
	}
	return nil
}

// runIDRe is the spelling a RunID may take. It is deliberately narrow: the id is
// interpolated into a systemd unit name, where a separator or a template character
// ("/", "@", "-", ".") does not merely look odd but selects a different unit, and where
// anything systemd escapes comes back as a name the supervisor that chose the id would
// not recognize. Refusing the character is the only answer that keeps the derivation
// one-way, which is the whole basis on which a caller reaps without reading anything
// back. The 64-byte bound leaves room for the prefix and suffix inside the unit-name
// limit systemd enforces.
var runIDRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

// ValidateRunID screens a caller-supplied run id before it can reach a unit name.
// Exported because a backend is an entry point an embedder can call without going
// through Run, and the id is the one option that reaches an external command's argv:
// the backend re-screens with this rather than carrying a second copy of the spelling.
//
// A Refusal and not a plain error, even though it is settled before anything is probed
// and so carries an empty Report: it is a mistake in what the caller asked for, which is
// the category a supervisor must not retry, and a frontend that sorts the two apart -
// run --json emits "refusal" for one and "failed" for the other - would otherwise file a
// misspelled id under the runs that failed for reasons out of the caller's hands.
func ValidateRunID(id string) error {
	if id == "" || runIDRe.MatchString(id) {
		return nil
	}
	return &Refusal{Reason: fmt.Sprintf("run id %q must be 1-64 characters of letters, digits, or underscore", id)}
}

// admitEnv refuses a run whose resolved environment carries a name the manifest does
// not declare. The backend emits --setenv for every key it is given and makes no
// judgment about them, and ResolveEnv is where the allowlist is applied - so a map an
// embedder assembled by any other path (os.Environ, or its own literal) reaches the
// sandbox whole, and the manifest stops describing what the target can see.
//
// A Refusal, and settled before anything is probed: it is a mistake in what the caller
// asked for, the category a supervisor must not retry. The names are sorted so the
// message is the same on every run of the same mistake.
func admitEnv(p *policy.Policy, proc Process) error {
	var undeclared []string
	for name := range proc.Env {
		if !slices.Contains(p.Env, name) {
			undeclared = append(undeclared, name)
		}
	}
	if len(undeclared) == 0 {
		return nil
	}
	slices.Sort(undeclared)
	return &Refusal{
		Reason: fmt.Sprintf("the environment passed to this run carries %s, which the manifest does not declare; build it with enforce.ResolveEnv or add the name to `env:` so the manifest still describes what the script can see",
			strings.Join(undeclared, ", ")),
	}
}

// admitRunID refuses a run that asked to be reapable but would not get a scope to be
// reaped through. Both conditions are silent failures otherwise: a policy with no limits
// is never wrapped at all, and a host that cannot create a scope runs the target
// unwrapped after --allow-degraded waives the limit. In each case the supervisor holds a
// unit name that never comes into existence, and learns so only when its kill does
// nothing to a target that is still running.
//
// It runs after admit rather than inside it because it is not a judgment about what the
// host can enforce - the layer states it reads have already been judged there - but
// about whether one thing the caller asked for can be delivered at all.
func admitRunID(p *policy.Policy, opts Options, required Report) error {
	if opts.RunID == "" {
		return nil
	}
	if p.Limits.IsZero() {
		return &Refusal{
			Report: required,
			Reason: "a run id asks for a reapable scope, but this manifest sets no resource limits and a run without them is not wrapped in one; set a limit (memory, cpu, or pids) or drop the run id",
		}
	}
	// Read through the limits layers the policy actually required, not one of them
	// alone: a cpu-only manifest requires neither of the others, and StateOf reports a
	// missing layer as Unavailable, so keying on one refused a reapable cpu-only run on a
	// host that could deliver the scope perfectly well.
	if short := unenforcedRequestedLimits(required); len(short) > 0 {
		return &Refusal{
			Report: required,
			Reason: "a run id asks for a reapable scope, and the resource limits a scope is created for are not fully enforced on this host, so there would be nothing to reap through",
			Short:  short,
		}
	}
	return nil
}

// unenforcedRequestedLimits returns the limits layer when the policy required it
// (it is present in the required-filtered report) but it is not fully enforced.
func unenforcedRequestedLimits(r Report) []LayerStatus {
	var out []LayerStatus
	for _, l := range r.Layers {
		if (l.Layer == LayerLimitsMemory || l.Layer == LayerLimitsPIDs || l.Layer == LayerLimitsCPU) && l.State != Enforced {
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
	// Waivable says that reduced enforcement would have admitted this exact run, so a
	// frontend can name the escape hatch it offers. It is set only where that is
	// unconditionally true: the requested-limits refusal, which AllowDegraded skips
	// outright. A core shortfall is not marked, because AllowDegraded still refuses the
	// half of it that enforces nothing at all.
	Waivable bool
}

// Shortfall is returned when an admitted run did not hold for the whole run the posture
// it was admitted on: the backend reported a layer worse than the pre-run probe did.
// Unlike a Refusal it is never retryable - the target was dispatched, whatever came of it.
//
// Whether it COMPLETED is the Err field's question, not this type's. With Err nil the
// target ran and Result carries its own exit code, and a caller reports the run exactly
// as a clean one plus the lapse. With Err set the backend also failed - a wrapper that
// vanished, a cancelled context - and the target may never have started, so Result's exit
// code is not its own and Err is what says what happened.
type Shortfall struct {
	// Report is the final report, covering only the layers the run required.
	Report Report
	// Short is the set of layers that fell short.
	Short []LayerStatus
	// Err is the backend's own failure, on the runs that had one - a wrapper that
	// vanished, a cancelled context. It is nil for the ordinary shortfall, where the
	// target ran to completion and the posture is the only thing that went wrong. A
	// frontend that renders a failure reads it through errors.Is/As, so a run does not
	// have to choose between reporting its cause and reporting its posture.
	Err error
}

func (e *Shortfall) Unwrap() error { return e.Err }

func (e *Shortfall) Error() string {
	var b strings.Builder
	if e.Err != nil {
		fmt.Fprintf(&b, "%v, and the guarantees the run was admitted on did not hold for it", e.Err)
	} else {
		b.WriteString("the run completed but the guarantees it was admitted on did not hold for it")
	}
	for _, l := range e.Short {
		fmt.Fprintf(&b, "\n  %s (%s): %s", l.Layer, l.State, l.Disclosure())
	}
	return b.String()
}

func (e *Refusal) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "refusing to run: %s", e.Reason)
	for _, l := range e.Short {
		fmt.Fprintf(&b, "\n  %s (%s): %s", l.Layer, l.State, l.Disclosure())
	}
	return b.String()
}
