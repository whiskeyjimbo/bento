package observe

import (
	"fmt"
	"strings"
)

// ReportEnd is the marker the launcher writes to the observation report as its
// last line, once the observer has run and every record is serialized. Its
// presence means the report is complete, so a reader tells a real (possibly
// empty) observation apart from one the launcher never finished - the sandbox
// failed to start, tracing failed, or the write was truncated - which would
// otherwise be mistaken for a run that touched nothing.
const ReportEnd = "#bento-observe"

// FormatReport renders a traced run as the observation report text the launcher
// writes to its report descriptor and the host parses back into a
// profile.Observation. It is the single source for the record verbs and their
// formatting: the writer is the in-sandbox stage and the reader is the host, two
// sides of the re-exec boundary with no call between them, so without one function
// both could reach the verbs lived in two places and a rename on either side left
// the other agreeing with itself.
//
// Three things hold the pair together, and none of them alone is enough. This
// function is the only writer. internal/linux's
// TestObservationReportRoundTripsEveryRecord drives its output through the parser and
// asserts every field of Result survives, so an arm dropped here fails there.
// And the parser refuses an unrecognized record rather than skipping it, so a verb
// renamed here - which this function cannot propagate, the reader being a parser of
// text and not a caller - surfaces as a parse error instead of a silently missing
// fact. A shared table of verbs is deliberately not the shape here: it would make a
// rename agree by construction and take away the only proof binding the two sides,
// and the parser handles each verb's payload its own way - a bare verb, a quoted
// path, an integer that refuses rather than counts - so the table would have to carry
// those parse functions and would be the parser rather than a source it reads.
//
// Paths are quoted (%q) so a newline inside one cannot forge extra records, and
// ReportEnd is written last: a caller that did not complete a trace writes nothing
// at all, and a report without the marker is rejected rather than read as a run
// that touched nothing.
func FormatReport(res Result) string {
	var b strings.Builder
	absent := map[string]bool{}
	probed := map[string]bool{}
	for _, a := range res.Accesses {
		verb := "R"
		if a.Write {
			verb = "W"
		}
		fmt.Fprintf(&b, "%s %q\n", verb, a.Path)
		// The access is reported either way; this only says nothing was ever found
		// at the path, so the host can report a probe as a probe rather than as a
		// file the run read. It is a fact about the path, so a path recorded both
		// read and written annotates once rather than twice.
		if a.Absent && !absent[a.Path] {
			absent[a.Path] = true
			fmt.Fprintf(&b, "ABSENT %q\n", a.Path)
		}
		// Annotated the same way and for the same shape of reason: the access stands
		// on its own R/W line, and this says only that nothing ever opened the path,
		// so the host can tell what the program reached for from what the kernel
		// resolved on its behalf.
		if a.Probed && !probed[a.Path] {
			probed[a.Path] = true
			fmt.Fprintf(&b, "PROBED %q\n", a.Path)
		}
	}
	// Two records rather than one, because the two facts do different work on the
	// host: EXEC is the attempt, which the 127 warning reads, and EXECRAN is the
	// spawn that actually happened, which is what grants exec: all. A run that
	// spawned wrote both.
	if res.ExecAttempted {
		b.WriteString("EXEC\n")
	}
	if res.Execed {
		b.WriteString("EXECRAN\n")
	}
	// The run's exit status, so the host can warn when a signaled/nonzero run may
	// have stopped partway and the observations are incomplete. Written before the
	// marker, like the records.
	if res.Signaled {
		fmt.Fprintf(&b, "SIGNAL %d\n", res.Signal)
	} else {
		fmt.Fprintf(&b, "EXIT %d\n", res.ExitCode)
	}
	// Accesses the observer could not read. Without this the host cannot tell a
	// target that touched nothing from one whose paths the observer failed to fetch,
	// and a manifest short of what the run needs looks complete.
	if res.Dropped > 0 {
		fmt.Fprintf(&b, "DROPPED %d\n", res.Dropped)
	}
	if res.SeccompKilled {
		b.WriteString("SECCOMPKILLED\n")
	}
	b.WriteString(ReportEnd + "\n")
	return b.String()
}
