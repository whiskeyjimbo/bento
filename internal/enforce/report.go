package enforce

// Layer names a distinct enforcement concern that is reported independently, so
// a host that enforces some layers but not others is described precisely rather
// than as a single pass/fail.
type Layer string

const (
	LayerFilesystem Layer = "filesystem"
	LayerNetwork    Layer = "network"
	LayerExec       Layer = "exec-block"
	LayerLimits     Layer = "limits"
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
	case LayerExec, LayerLimits:
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
	r.Layers = append(r.Layers, LayerStatus{Layer: layer, State: state, Reason: reason})
}

// Set replaces a layer's status, or adds it if absent. A backend uses it to
// refine what the policy-independent Probe reported with policy-specific facts —
// e.g. that a requested cgroup controller is not actually delegated.
func (r *Report) Set(layer Layer, state State, reason string) {
	for i := range r.Layers {
		if r.Layers[i].Layer == layer {
			r.Layers[i] = LayerStatus{Layer: layer, State: state, Reason: reason}
			return
		}
	}
	r.Add(layer, state, reason)
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

// For returns the subset of the report covering the given layers. Admission
// decisions use it to judge a host only on the layers a policy actually needs: a
// manifest with no network rules must not be blocked by a host that cannot run
// the egress stack, because it never asked for egress.
func (r Report) For(layers []Layer) Report {
	want := make(map[Layer]bool, len(layers))
	for _, l := range layers {
		want[l] = true
	}
	var out Report
	for _, l := range r.Layers {
		if want[l.Layer] {
			out.Layers = append(out.Layers, l)
		}
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
