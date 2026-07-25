package launcher

import (
	"fmt"
	"os"
	"strings"
)

// The in-sandbox stages report what they ACTUALLY applied through an inherited
// descriptor, so the host's run report rests on the child's own outcome rather than
// on host-side capability probes alone. A probe answers "this kernel can enforce
// X"; only the child can answer "X was installed on this run". Without this channel
// a filter that failed to install, or a stage that died before applying anything,
// still reached the caller as a Result reporting the layer Enforced.
//
// The keys and values below are the vocabulary of that channel. They are the
// launcher's own facts, not enforce.Layer/State names: the host maps them onto
// report layers, which keeps policy meaning out of the in-sandbox stage and keeps
// the wire private to the encode/decode pair in this package.
const (
	// AppliedExecFilter carries which exec-block filter was installed:
	// AppliedExecNone, AppliedExecBasic (execve only), or AppliedExecStrict
	// (execve plus fork/vfork/process-clone).
	AppliedExecFilter = "exec-filter"
	// AppliedLandlock carries whether the Landlock confinement was applied:
	// AppliedYes, or AppliedNo with the failure as its detail.
	AppliedLandlock = "landlock"

	AppliedExecNone   = "none"
	AppliedExecBasic  = "basic"
	AppliedExecStrict = "strict"
	AppliedYes        = "yes"
	AppliedNo         = "no"

	// AppliedMarker terminates the report. It is written last and only after every
	// layer decision, so a stage that died partway through setup - or never ran at all
	// - leaves a report without it, which the host reads as "the child did not report
	// what it applied" rather than as a clean run. This is what makes a bento setup
	// failure distinguishable from a target that itself exits 125.
	AppliedMarker = "APPLIED"
)

// appliedReport accumulates the layer outcomes of one in-sandbox stage and writes
// them to the inherited descriptor. A zero fd means the caller wants no report (an
// embedder driving the stage directly, or the profiling path, which produces an
// observation rather than an enforcement report), and every method is a no-op.
type appliedReport struct {
	fd int
	b  strings.Builder
}

// record notes one layer outcome. detail explains a value the host will read as a
// shortfall; it is quoted so a newline in an error message cannot forge a record.
func (a *appliedReport) record(key, value string, detail error) {
	if a.fd == 0 {
		return
	}
	if detail != nil {
		fmt.Fprintf(&a.b, "%s %s %q\n", key, value, detail.Error())
		return
	}
	fmt.Fprintf(&a.b, "%s %s\n", key, value)
}

// write appends the completion marker and writes the report in one call, then
// closes the descriptor. It must be called after every layer is decided and before
// the target is reached: on the exec-block path the stage is replaced by the target,
// so there is no "after the run" in which to write it.
func (a *appliedReport) write() error {
	if a.fd == 0 {
		return nil
	}
	f := os.NewFile(uintptr(a.fd), "applied-report")
	if f == nil {
		return fmt.Errorf("launcher: applied-report descriptor %d is not valid", a.fd)
	}
	a.b.WriteString(AppliedMarker + "\n")
	if _, err := f.Write([]byte(a.b.String())); err != nil {
		return fmt.Errorf("launcher: writing the applied-layer report: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("launcher: closing the applied-layer report: %w", err)
	}
	return nil
}
