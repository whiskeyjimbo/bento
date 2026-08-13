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

	// AppliedExecRecorder says whether the exec recorder was watching this run:
	// AppliedYes, AppliedNo with the failure as its detail, or AppliedAbsent for a mode
	// that cannot have one at all. It is what makes "no execs happened" distinguishable
	// from "nothing was watching", and it cannot ride the first section - that is written
	// before the target is reached, and the attach has not been tried by then.
	AppliedExecRecorder = "exec-recorder"

	// AppliedExecRan carries one observed exec: the pid, the image the kernel ran, and
	// the argv, both quoted. The argv is one NUL-joined field rather than a record per
	// word, so an argument containing a space cannot split into two.
	AppliedExecRan = "exec-ran"

	// AppliedExecArgvTruncated is the optional last field of an exec-ran record, saying
	// the argv above it was cut. Marked rather than quietly shortened: an argv that is
	// missing its tail and does not say so is a record that lies about what ran, and one
	// that can lie is worse than none.
	AppliedExecArgvTruncated = "argv-truncated"

	// maxRecordedArgv caps the NUL-joined argv of one record. The reader scans the report
	// a line at a time and refuses one it cannot buffer, so an uncapped argv is not a long
	// line but a LOST section - and %q expands each NUL separator to four bytes, so the
	// wire form outgrows the argv it came from. A link or compile step's command line
	// reaches this length in normal use, which is the workload the record exists for; the
	// cap keeps the rest of the record readable at the price of one marked entry.
	maxRecordedArgv = 4096

	// AppliedExecRecordMarker terminates the exec-record section, and it is why the
	// section can be trusted to be whole. The recorder deliberately runs without
	// PTRACE_O_EXITKILL, so a tracer that dies detaches and the record ends where it
	// ended; without a marker of its own a truncated record would read as a run that
	// simply stopped exec'ing, which is the silently-incomplete record that is worse
	// than none.
	AppliedExecRecordMarker = "EXEC-RECORD"

	// AppliedTargetUnreached says the layers above the marker were applied but the target
	// they were applied for never ran. Setup completing and the target running are
	// different facts, and the marker can only attest the first - see
	// appliedReport.targetUnreached for why nothing but a failed run can write this.
	//
	// It and the exec-record section are the two things that may follow the marker, and
	// both can be present: the exec-block path writes the record BEFORE execveat, since
	// after it there is no process left to write from, so a transition that fails appends
	// this line behind an already-closed section. It is still the last line of the report
	// either way - targetUnreached closes it - which is what the reader relies on.
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
// target's own stdio and then close it out from under the target. runObserve validates
// its own descriptor up front for the first of those reasons, but has no standard-stream
// floor: it writes its report after the traced target has already exited.
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

// writeExecRecord appends the exec-record section: whether the recorder was watching,
// every exec it saw, and the section's own marker. A nil recorder means the run did not
// ask for a record, and nothing is written at all - the host then has no section to read
// rather than an empty one claiming nothing ran.
//
// This is a SECOND write phase, after the first marker, and that is the point. The first
// write fires before the target is reached and the invariant that a report reaching its
// marker proves the fences held depends on it; exec records only exist once the target
// has run. Folding them into the first write would trade a fail-closed proof for a
// diagnostic, so the record gets its own section and its own marker instead, and the
// first write, the first marker and their meaning are untouched.
func (a *appliedReport) writeExecRecord(rec *execRecorder) error {
	if a.f == nil || rec == nil {
		return nil
	}
	var b strings.Builder
	switch {
	case rec.unavailable != nil:
		fmt.Fprintf(&b, "%s %s %q\n", AppliedExecRecorder, AppliedAbsent, rec.unavailable.Error())
	case rec.failed != nil:
		fmt.Fprintf(&b, "%s %s %q\n", AppliedExecRecorder, AppliedNo, rec.failed.Error())
	default:
		fmt.Fprintf(&b, "%s %s\n", AppliedExecRecorder, AppliedYes)
	}
	// Quoted for the reason record quotes its detail: an image path or an argument may
	// contain a newline, and an unquoted one would forge a record.
	for _, r := range rec.runs {
		argv, truncated := cappedArgv(r.argv)
		fmt.Fprintf(&b, "%s %d %q %q", AppliedExecRan, r.pid, r.exe, argv)
		if truncated {
			fmt.Fprintf(&b, " %s", AppliedExecArgvTruncated)
		}
		b.WriteString("\n")
	}
	b.WriteString(AppliedExecRecordMarker + "\n")
	if _, err := a.f.Write([]byte(b.String())); err != nil {
		// Loud but not fatal to the run: the target has already finished under fences the
		// first marker already attested, and losing a diagnostic may not change what the
		// run reports. An unmarked section is what the host reads as truncated.
		return fmt.Errorf("launcher: writing the exec record: %w", err)
	}
	return nil
}

// cappedArgv renders one record's argv, cut to maxRecordedArgv. It cuts on the argument
// boundary rather than mid-argument, so what is reported is a prefix of the real argv
// and never a mangled last word - a half-written path in a record reads as a path that
// was passed.
func cappedArgv(argv []string) (string, bool) {
	var b strings.Builder
	for i, a := range argv {
		if i > 0 {
			if b.Len()+1+len(a) > maxRecordedArgv {
				return b.String(), true
			}
			b.WriteString("\x00")
		} else if len(a) > maxRecordedArgv {
			// A single argument over the cap has no boundary to cut on, so the entry keeps
			// its image and reports no argv at all rather than a prefix of one argument.
			return "", true
		}
		b.WriteString(a)
	}
	return b.String(), false
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
