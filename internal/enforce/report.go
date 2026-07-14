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

// State is how fully a layer is enforced on this host.
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
