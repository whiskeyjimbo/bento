//go:build linux

package launcher

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
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
	// AppliedYes, AppliedNo with the failure as its detail, or AppliedAbsent when this
	// kernel has no usable Landlock at all. Absent is distinct from failed because the
	// host already knows an ABI-less kernel has no backstop and reports it - what it
	// cannot otherwise know is that a kernel WITH Landlock installed no ruleset.
	AppliedLandlock = "landlock"

	AppliedExecNone   = "none"
	AppliedExecBasic  = "basic"
	AppliedExecStrict = "strict"
	AppliedYes        = "yes"
	AppliedNo         = "no"
	AppliedAbsent     = "absent"

	// AppliedMarker terminates the report. It is written last and only after every
	// layer decision, so a stage that died partway through setup - or never ran at all
	// - leaves a report without it, which the host reads as "the child did not report
	// what it applied" rather than as a clean run. This is what makes a bento setup
	// failure distinguishable from a target that itself exits 125.
	AppliedMarker = "APPLIED"

	// AppliedTargetUnreached is the one record that may follow the marker: the layers
	// above it were applied, but the target they were applied for never ran. Setup
	// completing and the target running are different facts, and the marker can only
	// attest the first - see appliedReport.targetUnreached for why nothing but a failed
	// run can write this.
	AppliedTargetUnreached = "target-unreached"
)

// appliedReport accumulates the layer outcomes of one in-sandbox stage and writes
// them to the inherited descriptor. A nil file means the caller wants no report (an
// embedder driving the stage directly, or the profiling path, which produces an
// observation rather than an enforcement report), and every method is a no-op.
type appliedReport struct {
	f *os.File
	b strings.Builder
}

// newAppliedReport prepares the report channel for the descriptor the caller was given.
// Zero means no report is wanted.
//
// A nonzero descriptor is validated here rather than at the write, because it arrives
// from the launch invocation (--applied-fd) and by the time the report is written the
// exec filter is installed and the target is one syscall away: a descriptor naming
// nothing would lose the report under an error about the report rather than about the
// descriptor, and one naming a standard stream would write the layer report into the
// target's own stdio and then close it out from under the target. The same stance
// runObserve takes with the observation descriptor.
func newAppliedReport(fd int) (*appliedReport, error) {
	if fd == 0 {
		return &appliedReport{}, nil
	}
	if fd < firstInheritableFD {
		return nil, fmt.Errorf("launcher: applied-report descriptor %d is one of the target's standard streams", fd)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
		return nil, fmt.Errorf("launcher: applied-report descriptor %d is not valid: %w", fd, err)
	}
	return &appliedReport{f: os.NewFile(uintptr(fd), "applied-report")}, nil
}

// record notes one layer outcome. detail explains a value the host will read as a
// shortfall; it is quoted so a newline in an error message cannot forge a record.
func (a *appliedReport) record(key, value string, detail error) {
	if a.f == nil {
		return
	}
	if detail != nil {
		fmt.Fprintf(&a.b, "%s %s %q\n", key, value, detail.Error())
		return
	}
	fmt.Fprintf(&a.b, "%s %s\n", key, value)
}

// write appends the completion marker and writes the report in one call. It must be
// called after every layer is decided and before the target is reached: on the
// exec-block path the stage is replaced by the target, so there is no "after the run"
// in which to write it.
//
// The descriptor is deliberately left open. It is close-on-exec, so reaching the target
// is what closes it and ends the report at the marker; a stage still holding it after
// this point is one whose target was never reached, which is the only thing that can
// write the record below.
func (a *appliedReport) write() error {
	if a.f == nil {
		return nil
	}
	a.b.WriteString(AppliedMarker + "\n")
	if _, err := a.f.Write([]byte(a.b.String())); err != nil {
		return fmt.Errorf("launcher: writing the applied-layer report: %w", err)
	}
	return nil
}

// targetUnreached appends the record saying the layers above the marker were applied
// but the target itself never ran, and closes the report.
//
// The marker alone cannot say this. It is written before the target is reached because
// on the exec-block path there is no later moment to write from - which leaves the most
// common setup failure of all, an entrypoint that does not exist inside the sandbox, on
// the far side of it, giving the host a complete report for a run that never happened.
// Only a stage that outlived its own dispatch can get here: a reached target has
// replaced this process on the exec path, and on the supervise path the dispatch returns
// only when the target could not be started. So the record is something the stage
// observed, not a guess from the exit code, which cannot tell a failed setup from a
// target that itself exits 125. It is not a guarantee against a stage killed outright
// between the marker and the dispatch - the host would read that report as complete -
// but that window is the width of one syscall rather than the whole of the target's
// startup.
func (a *appliedReport) targetUnreached(cause error) error {
	if a.f == nil {
		return nil
	}
	// Quoted for the same reason record quotes its detail: a newline in the cause must
	// not be able to forge a record.
	if _, err := fmt.Fprintf(a.f, "%s %q\n", AppliedTargetUnreached, cause.Error()); err != nil {
		// This append is the only thing between the host and a complete report for a run
		// that never happened, so failing loud here is not enough - the marker above would
		// still be there, and the host would read every layer as enforced. Discard the
		// report instead: with nothing to read the host falls back to its "the stage did
		// not report what it applied" branch, which claims nothing. Truncating is a
		// different operation on the same descriptor and survives what stops a write, a
		// full filesystem most of all.
		if truncErr := a.f.Truncate(0); truncErr != nil {
			return errors.Join(fmt.Errorf("launcher: writing the unreached-target record: %w", err),
				fmt.Errorf("launcher: discarding the applied-layer report: %w", truncErr))
		}
		return fmt.Errorf("launcher: writing the unreached-target record: %w", err)
	}
	if err := a.f.Close(); err != nil {
		return fmt.Errorf("launcher: closing the applied-layer report: %w", err)
	}
	return nil
}
