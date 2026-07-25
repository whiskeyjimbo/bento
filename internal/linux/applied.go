package linux

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/launcher"
)

// appliedReportFD is the descriptor the in-sandbox stage writes its applied-layer
// report through. The host passes the open report file as the child's first extra
// file, which Go places at FD 3, and bwrap passes it through to the launcher - the
// same route the profiling observation report takes (observeReportFD), and the two
// never coexist: profiling produces an observation, not an enforcement report.
const appliedReportFD = 3

// applied is what the in-sandbox stage reported installing. Absent (complete=false)
// is not the zero value of a clean run: it means the stage never got far enough to
// report, so nothing it was supposed to apply can be claimed.
type applied struct {
	// complete is whether the report reached its marker. A stage that refused to run
	// (an uninstallable filter, a Landlock failure in the degraded tier) or died before
	// setup finished leaves it false.
	complete bool
	// execFilter is which exec-block filter landed: launcher.AppliedExecNone/Basic/Strict.
	execFilter string
	// landlockErr is why the Landlock confinement was not applied, when it was not.
	landlockErr string
}

// newAppliedReport creates the file the in-sandbox stage writes its applied-layer
// report to, returning it and a cleanup. The caller passes it as the child's first
// extra file and reads it back by path after the run.
func newAppliedReport() (*os.File, func(), error) {
	f, err := os.CreateTemp("", "bento-applied-")
	if err != nil {
		return nil, nil, fmt.Errorf("linux: creating the applied-layer report: %w", err)
	}
	return f, func() { f.Close(); os.Remove(f.Name()) }, nil
}

// parseApplied reads back what the stage reported. A read failure is reported as an
// absent report rather than an error: the run already happened, and the honest
// outcome is a report that claims nothing, not a failed run.
func parseApplied(path string) applied {
	f, err := os.Open(path)
	if err != nil {
		return applied{}
	}
	defer f.Close()

	var a applied
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if a.complete {
			// Anything after the marker did not come from the stage's single write, so the
			// report is treated as tampered - the same stance parseObservations takes.
			if line != "" {
				return applied{}
			}
			continue
		}
		key, rest, _ := strings.Cut(line, " ")
		value, detail, _ := strings.Cut(rest, " ")
		switch {
		case line == launcher.AppliedMarker:
			a.complete = true
		case key == launcher.AppliedExecFilter:
			a.execFilter = value
		case key == launcher.AppliedLandlock && value == launcher.AppliedNo:
			// Quoted by the writer so a newline in the error cannot forge a record; an
			// unquotable detail still counts as a failure, just without the reason.
			if a.landlockErr, err = strconv.Unquote(detail); err != nil {
				a.landlockErr = "reason unreadable"
			}
		}
	}
	if err := s.Err(); err != nil {
		return applied{}
	}
	return a
}

// reconcile overlays what the sandboxed stage reported onto the host's probe-derived
// report, so a layer is only claimed once the child confirms it applied.
//
// The probe answers what this HOST can enforce; only the child can answer what this
// RUN enforced. Where they disagree the child wins, and it only ever worsens a layer:
// exitCode is carried into the reason because a stage that reported nothing usually
// exited 125 (reexecFail), and naming it is what distinguishes bento failing to
// confine from a target that itself exits 125.
func (a applied) reconcile(r *enforce.Report, strictWanted bool, exitCode int) {
	if !a.complete {
		r.Set(enforce.LayerExec, enforce.Unavailable, fmt.Sprintf(
			"the sandboxed launcher did not report installing the exec-block filter (it exited %d before completing setup), "+
				"so this run has no proof the filter was applied", exitCode))
		r.Set(enforce.LayerExecStrict, enforce.Unavailable, fmt.Sprintf(
			"the sandboxed launcher did not report what it applied (it exited %d before completing setup)", exitCode))
		r.Set(enforce.LayerFilesystem, enforce.Unavailable, fmt.Sprintf(
			"the sandboxed launcher did not report applying its filesystem confinement (it exited %d before completing setup)", exitCode))
		return
	}
	// The exec layers are only as strong as the filter that actually landed. basic
	// where strict was asked for is the architecture fallback: execve is blocked, but
	// fork/vfork/process-clone are not.
	if strictWanted && a.execFilter == launcher.AppliedExecBasic {
		r.Set(enforce.LayerExecStrict, enforce.Degraded,
			"the sandbox installed the execve-only block; fork/vfork/process-clone blocking is not available on this architecture")
	}
	if a.landlockErr != "" {
		// Degraded, not Unavailable: on the bwrap tier the mount namespace still confines
		// the filesystem and only the second-layer backstop is missing. Reported as a
		// state change rather than a detail rewrite because enforce.Run's overlay
		// propagates only a worsening state, so an Enforced-with-a-new-reason would be
		// dropped and the run would still claim the backstop was active.
		r.Set(enforce.LayerFilesystem, enforce.Degraded,
			"the Landlock backstop could not be applied inside the sandbox ("+a.landlockErr+
				"); bubblewrap's mount namespace still confines the filesystem, but the second kernel layer behind it is absent")
	}
}
