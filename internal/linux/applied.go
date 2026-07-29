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
	// landlock is the outcome the stage reported for the Landlock confinement:
	// launcher.AppliedYes/No/Absent, or "" when it reported none at all.
	landlock string
	// landlockErr is why the Landlock confinement was not applied, when it was not and
	// the stage's reason could be read.
	landlockErr string
	// targetUnreached is whether the stage reported that it applied its layers and then
	// never reached the target; targetErr is what stopped it, when it could be read.
	targetUnreached bool
	targetErr       string
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
		key, rest, _ := strings.Cut(line, " ")
		value, detail, _ := strings.Cut(rest, " ")
		if a.complete {
			// One record may legitimately follow the marker: the stage saying the layers
			// above it were applied but the target never ran. Accepting it is safe because
			// it can only ever WORSEN the report - the same monotonicity the rest of
			// reconcile rests on - so it cannot be used to claim a layer. Anything else did
			// not come from the stage's writes, so the report is treated as tampered, the
			// same stance parseObservations takes.
			switch {
			case key == launcher.AppliedTargetUnreached:
				a.targetUnreached = true
				if a.targetErr, err = strconv.Unquote(rest); err != nil {
					a.targetErr = ""
				}
			case line != "":
				return applied{}
			}
			continue
		}
		switch {
		case line == launcher.AppliedMarker:
			a.complete = true
		case key == launcher.AppliedExecFilter:
			a.execFilter = value
		case key == launcher.AppliedLandlock:
			// The value is kept whatever it is, including one this host does not recognize:
			// reconcile judges it against what was asked for rather than reading a failure
			// reason, so a record whose reason is empty or unreadable cannot pass as success.
			// Absent - a kernel with no usable Landlock ABI - is the one non-"yes" value that
			// is not a shortfall: the probe already reports that this host has no backstop
			// and that bwrap alone confines.
			a.landlock = value
			if value == launcher.AppliedNo {
				// Quoted by the writer so a newline in the error cannot forge a record; an
				// unquotable detail still counts as a failure, just without the reason.
				if a.landlockErr, err = strconv.Unquote(detail); err != nil {
					a.landlockErr = "reason unreadable"
				}
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
// RUN enforced. Where they disagree the child wins, and it only ever worsens a layer.
// blockWanted/strictWanted are what the policy asked the child to install, so a report
// that names a weaker filter - or none - is judged against the request rather than
// taken at face value. exitCode goes into the reason for a silent child: the exit code
// alone cannot separate a bento setup failure from a target that exits 125 itself, and
// the report is what does.
func (a applied) reconcile(r *enforce.Report, blockWanted, strictWanted bool, exitCode int) {
	if !a.complete {
		// The reason states what is known - no report, and the code the run ended with -
		// rather than asserting a cause: the same absence covers a launcher that died in
		// setup (the usual case, exiting 125 via reexecFail), a bwrap or scope wrapper that
		// never reached the launcher, and a report the host could not read back.
		silent := fmt.Sprintf("the sandboxed launcher did not report what it applied (the run ended with exit code %d), "+
			"so this run has no proof the layer was in place", exitCode)
		r.Set(enforce.LayerExec, enforce.Unavailable, silent)
		r.Set(enforce.LayerExecStrict, enforce.Unavailable, silent)
		r.Set(enforce.LayerFilesystem, enforce.Unavailable, silent)
		return
	}
	if a.targetUnreached {
		// The layers really were installed - on the launcher, which then could not reach
		// the target they were installed for. Claiming them Enforced would attest a
		// confinement that confined nothing, the same lie the missing-marker branch above
		// exists to refuse; the marker cannot catch it because on the exec-block path it
		// must be written before the target is reached.
		unreached := "the sandboxed launcher applied its layers but never reached the target"
		if a.targetErr != "" {
			unreached += " (" + a.targetErr + ")"
		}
		unreached += ", so nothing ran under this layer"
		r.Set(enforce.LayerExec, enforce.Unavailable, unreached)
		r.Set(enforce.LayerExecStrict, enforce.Unavailable, unreached)
		r.Set(enforce.LayerFilesystem, enforce.Unavailable, unreached)
		return
	}
	// The exec layers are only as strong as the filter that actually landed. A report
	// naming no filter (or a value this host does not recognize) where the policy asked
	// for one is the case a marker alone cannot catch: the child completed setup and
	// truthfully said it installed nothing, so claiming the probe's Enforced would be
	// the same lie by a shorter route.
	if blockWanted && a.execFilter != launcher.AppliedExecBasic && a.execFilter != launcher.AppliedExecStrict {
		reason := fmt.Sprintf("the sandbox reported installing no exec-block filter (%q) though the policy asked for one", a.execFilter)
		r.Set(enforce.LayerExec, enforce.Unavailable, reason)
		r.Set(enforce.LayerExecStrict, enforce.Unavailable, reason)
	} else if strictWanted && a.execFilter == launcher.AppliedExecBasic {
		// basic where strict was asked for is the architecture fallback: execve is
		// blocked, but fork/vfork/process-clone are not.
		r.Set(enforce.LayerExecStrict, enforce.Degraded,
			"the sandbox installed the execve-only block; fork/vfork/process-clone blocking is not available on this architecture")
	}
	// Judged against what was asked for, like the exec layers above: both tiers apply the
	// backstop unconditionally, so anything but a ruleset that landed - a reported
	// failure, a value this host does not recognize, or no Landlock record at all - is a
	// run without it. Keying on the failure REASON instead read a report whose reason was
	// empty, and one that never mentioned the layer, as success.
	if a.landlock != launcher.AppliedYes && a.landlock != launcher.AppliedAbsent {
		why := a.landlockErr
		if why == "" {
			why = fmt.Sprintf("the sandbox reported no Landlock outcome, %q", a.landlock)
		}
		// Degraded, not Unavailable: on the bwrap tier the mount namespace still confines
		// the filesystem and only the second-layer backstop is missing. Reported as a
		// state change rather than a detail rewrite because enforce.Run's overlay
		// propagates only a worsening state, so an Enforced-with-a-new-reason would be
		// dropped and the run would still claim the backstop was active.
		r.Set(enforce.LayerFilesystem, enforce.Degraded,
			"the Landlock backstop could not be applied inside the sandbox ("+why+
				"); bubblewrap's mount namespace still confines the filesystem, but the second kernel layer behind it is absent")
	}
}
