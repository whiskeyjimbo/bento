package enforce

// Layer names a distinct enforcement concern that is reported independently, so
// a host that enforces some layers but not others is described precisely rather
// than as a single pass/fail.
type Layer string

const (
	LayerFilesystem Layer = "filesystem"
	LayerNetwork    Layer = "network"
	LayerExec       Layer = "exec-block"
	// LayerExecStrict is the extra none-strict guarantee (fork/vfork/process-clone
	// blocking) on top of the execve block. A policy needs it only for exec:
	// none-strict; a host that blocks execve but not fork reports it degraded.
	LayerExecStrict Layer = "exec-strict"
	// LayerLimits is the ability to run under a limited transient scope at all,
	// which needs the host-safety controllers (memory, pids) delegated. LayerLimitsCPU
	// is the separate ability to enforce a cpu limit: systemd-run accepts a CPUQuota
	// even when the cpu controller is not delegated (a common default) and silently
	// ignores it, so a policy that requests a cpu limit needs this layer specifically.
	LayerLimits    Layer = "limits"
	LayerLimitsCPU Layer = "limits-cpu"
)

// Tier separates the guarantees Bento makes on every supported platform from
// those only Linux can enforce. It is what lets one manifest run in both places
// without either platform lying about what protected it.
type Tier int

const (
	// TierCore is enforced on every supported platform. A core layer that falls
	// short of Enforced refuses the run by default: silently substituting a
	// weaker sandbox is the failure this tool exists to prevent.
	TierCore Tier = iota
	// TierHardening has no unprivileged equivalent on every platform (seccomp and
	// cgroup limits are Linux-only). A hardening layer that cannot be enforced is
	// reported loudly and the run proceeds.
	TierHardening
)

func (t Tier) String() string {
	if t == TierHardening {
		return "hardening"
	}
	return "core"
}

// Tier reports which tier a layer belongs to.
func (l Layer) Tier() Tier {
	switch l {
	case LayerExec, LayerExecStrict, LayerLimits, LayerLimitsCPU:
		return TierHardening
	default:
		return TierCore
	}
}

// State is how fully a layer is enforced on this host. The values are ordered by
// severity (Enforced < Degraded < Unavailable) and admission checks compare
// against that order, so a new state must be inserted at its correct severity.
type State int

const (
	// Enforced: the layer holds as specified.
	Enforced State = iota
	// Degraded: partially enforced, with a weaker guarantee than intended.
	Degraded
	// Unavailable: not enforced at all on this host.
	Unavailable
)

func (s State) String() string {
	switch s {
	case Enforced:
		return "enforced"
	case Degraded:
		return "degraded"
	case Unavailable:
		return "unavailable"
	default:
		return "unknown"
	}
}

// LayerStatus is one layer's enforcement state, with the reason it is not fully
// enforced (empty when Enforced).
type LayerStatus struct {
	Layer  Layer
	State  State
	Reason string
	// Consequences is what this state costs the run: the standing disclosure for the
	// state, identical on every host that lands in it, as opposed to Reason's account
	// of what is broken here and how to fix it. An Enforced layer carries one when the
	// guarantee has a limit by construction rather than by host - a seam that holds
	// wherever the layer holds - so "enforced" is never read as "complete". It is
	// separate so a refusal can lead
	// with the actionable half and point at a fuller report for this one, rather than
	// burying the remedy under a paragraph the reader did not ask for. Every frontend
	// that describes a layer in full must still print it: no fact is dropped, only
	// relocated.
	Consequences string
}

// Disclosure is everything the layer has to say about itself, for a frontend that
// describes it in full rather than pointing at one that does. Every such frontend uses
// this rather than joining the halves itself: a second place that knows how a status
// is assembled is a place a later field is dropped from.
func (l LayerStatus) Disclosure() string {
	if l.Consequences == "" {
		return l.Reason
	}
	// An Enforced layer has no Reason, so joining unconditionally would lead the
	// disclosure with a space.
	if l.Reason == "" {
		return l.Consequences
	}
	return l.Reason + " " + l.Consequences
}

// Report is the per-layer enforcement status for a host (from Probe) or a run
// (from Run). It is the backend-independent basis for loud degradation:
// frontends render it, and strict mode refuses on it.
type Report struct {
	Layers []LayerStatus
}

// Add records a layer's status. Reason should explain why, whenever state is not
// Enforced.
func (r *Report) Add(layer Layer, state State, reason string) {
	r.AddStatus(LayerStatus{Layer: layer, State: state, Reason: reason})
}

// AddStatus records a status a caller already holds whole. Copying a status forward
// field by field is how a disclosure gets silently dropped - a new field on
// LayerStatus is invisible to a call site that names three of them - so every path
// that forwards a status another layer produced uses this.
func (r *Report) AddStatus(l LayerStatus) {
	r.Layers = append(r.Layers, l)
}

// Set replaces a layer's status, or adds it if absent. A backend uses it to
// refine what the policy-independent Probe reported with policy-specific facts -
// e.g. that a requested cgroup controller is not actually delegated.
//
// Any further entry for the layer is dropped, so Set leaves exactly one. A probe that
// emitted the layer twice would otherwise keep a stale duplicate that StateOf and the
// admission scans still see, and a report can then refuse on one entry while rendering
// the other as enforced.
func (r *Report) Set(layer Layer, state State, reason string) {
	r.SetStatus(LayerStatus{Layer: layer, State: state, Reason: reason})
}

// SetStatus replaces a layer's status with one the caller holds whole, for the same
// reason AddStatus exists.
func (r *Report) SetStatus(s LayerStatus) {
	out, replaced := r.Layers[:0], false
	for _, l := range r.Layers {
		switch {
		case l.Layer != s.Layer:
			out = append(out, l)
		case !replaced:
			out = append(out, s)
			replaced = true
		}
	}
	r.Layers = out
	if !replaced {
		r.AddStatus(s)
	}
}

// StateOf returns the recorded state of a layer. A layer the report does not
// mention is not enforced, so it reports Unavailable.
func (r Report) StateOf(layer Layer) State {
	// Return the most severe state among any duplicate entries, so this agrees with
	// shortfall/Degradations (which scan every matching layer): a first-match here
	// could report Enforced while a later duplicate Degraded/Unavailable entry is the
	// one that governs admission. A missing layer is Unavailable, the fail-safe.
	state, found := Enforced, false
	for _, l := range r.Layers {
		if l.Layer == layer && (!found || l.State > state) {
			state, found = l.State, true
		}
	}
	if !found {
		return Unavailable
	}
	return state
}

// HasDegradation reports whether any layer is not fully enforced.
func (r Report) HasDegradation() bool {
	for _, l := range r.Layers {
		if l.State != Enforced {
			return true
		}
	}
	return false
}

// Degradations returns the layers that are not fully enforced, in report order.
func (r Report) Degradations() []LayerStatus {
	var out []LayerStatus
	for _, l := range r.Layers {
		if l.State != Enforced {
			out = append(out, l)
		}
	}
	return out
}

// forLayers returns the subset of the report covering the given layers. Admission
// decisions use it to judge a host only on the layers a policy actually needs: a
// manifest with no network rules must not be blocked by a host that cannot run
// the egress stack, because it never asked for egress.
func (r Report) forLayers(layers []Layer) Report {
	want := make(map[Layer]bool, len(layers))
	for _, l := range layers {
		want[l] = true
	}
	present := make(map[Layer]bool, len(layers))
	var out Report
	for _, l := range r.Layers {
		if want[l.Layer] {
			out.Layers = append(out.Layers, l)
			present[l.Layer] = true
		}
	}
	// A required layer the probe did not report is recorded as Unavailable, not left
	// absent: admission scans the returned layers, so a missing entry would otherwise
	// read as "no shortfall" and admit a run whose required guarantee was never
	// actually evaluated. Fail-safe for a probe that forgets a layer.
	for _, l := range layers {
		if present[l] {
			continue
		}
		// LayerLimitsCPU's absence is subsumed by LayerLimits only while LayerLimits is
		// itself not Enforced - then LayerLimits already carries the refusal and a
		// synthesized cpu line would just duplicate it. But if the probe reports
		// LayerLimits=Enforced and merely drops the cpu refinement (a probe regression),
		// nothing else refuses, and admitting the run would run it under an unenforced
		// CPUQuota that systemd-run silently ignores. So synthesize it there.
		if l == LayerLimitsCPU && r.StateOf(LayerLimits) != Enforced {
			continue
		}
		out.Layers = append(out.Layers, LayerStatus{Layer: l, State: Unavailable, Reason: "not reported by the host probe"})
	}
	return out
}

// shortfall returns the layers in the given tier that are not fully enforced.
func (r Report) shortfall(tier Tier, atLeast State) []LayerStatus {
	var out []LayerStatus
	for _, l := range r.Layers {
		if l.Layer.Tier() == tier && l.State >= atLeast {
			out = append(out, l)
		}
	}
	return out
}
