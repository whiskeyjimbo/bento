//go:build linux

package linux

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/observe"
	"github.com/whiskeyjimbo/bento/profile"
)

// fuzzObservationBases are reports the launcher itself could have written, spanning the
// arms parseObservations has: opens of both kinds with their absent/probed annotations, an
// exec that was attempted and one that also spawned, a seccomp kill, and both status
// shapes (EXIT and SIGNAL) with a dropped-access count. They are the well-formed halves
// the fuzzer corrupts.
var fuzzObservationBases = []string{
	fmt.Sprintf("R %q\nW %q\n%s\n", "/etc/hosts", "/tmp/out", observe.ReportEnd),
	fmt.Sprintf("R %q\nABSENT %q\nPROBED %q\nEXEC\nEXECRAN\nEXIT 0\n%s\n", "/a", "/a", "/b", observe.ReportEnd),
	fmt.Sprintf("W %q\nEXEC\nSECCOMPKILLED\nSIGNAL 9\nDROPPED 3\n%s\n", "/tmp/x", observe.ReportEnd),
	fmt.Sprintf("R %q\nEXIT 7\n%s\n", "/usr/lib/libc.so.6", observe.ReportEnd),
}

// FuzzParseObservationsNeverOverClaims corrupts a well-formed observation report by
// splicing arbitrary bytes into it at an arbitrary offset, and holds parseObservations to
// never-over-claim. The report feeds profile.Synthesize, whose proposal `bento approve`
// stamps, so a record the observer never wrote becoming a grant is the failure that
// matters - not a record lost, which only narrows the manifest.
//
// The oracle: splicing junk may lose observations or error, but a Read or a Write the
// intact report does not carry must appear in the corrupted bytes as the launcher would
// have spelled it, and ExecAttempted, Execed and SeccompKilled may not go from false to
// true without their literal line being there. Stated against the bytes rather than
// against the parser, so the decoder it bounds has no say in it.
//
// Splicing rather than appending, for FuzzParseAppliedNeverOverClaims' reason: the
// interesting class is as much a record inserted AHEAD of the completion marker as a tail
// behind it, and an append only ever reaches the second.
func FuzzParseObservationsNeverOverClaims(f *testing.F) {
	// One seed per arm the table pins: a record spliced past the completion marker (the
	// tamper check), a second marker, a record ahead of the marker, a garbled status line,
	// a truncation inside a quoted path, and raw bytes at a boundary.
	f.Add(0, len(fuzzObservationBases[0]), []byte("R \"/etc/shadow\"\n"))
	f.Add(0, strings.Index(fuzzObservationBases[0], observe.ReportEnd), []byte("W \"/root/.ssh\"\n"))
	f.Add(1, len(fuzzObservationBases[1]), []byte(observe.ReportEnd+"\n"))
	f.Add(1, strings.Index(fuzzObservationBases[1], "EXIT"), []byte("EXECRAN\nSECCOMPKILLED\n"))
	f.Add(2, strings.Index(fuzzObservationBases[2], "DROPPED"), []byte("EXIT notanumber\n"))
	f.Add(3, 3, []byte("\x00\xff"))
	// A CR-tailed line, which the scanner reads whole and a "\n" split does not.
	f.Add(0, 0, []byte("EXEC\r\n"))

	f.Fuzz(func(t *testing.T, baseIdx, at int, junk []byte) {
		base := fuzzObservationBases[((baseIdx%len(fuzzObservationBases))+len(fuzzObservationBases))%len(fuzzObservationBases)]
		at = ((at % (len(base) + 1)) + (len(base) + 1)) % (len(base) + 1)
		corrupted := base[:at] + string(junk) + base[at:]

		intact, err := parseObservation(t, base)
		if err != nil {
			t.Fatalf("a base the launcher could have written must parse: %v\n%q", err, base)
		}
		got, err := parseObservation(t, corrupted)
		if err != nil {
			return // refusing is always an honest answer to corrupted bytes
		}

		// Counted, not merely membership-tested: two reads of one path where the intact
		// report carries one is a record the run did not observe, and a set comparison
		// would call it covered.
		for kind, paths := range map[string][]string{"R": got.Reads, "W": got.Writes} {
			was := intact.Reads
			if kind == "W" {
				was = intact.Writes
			}
			for _, p := range paths {
				if count(paths, p) <= count(was, p) {
					continue
				}
				if !namedOnALine(beforeTheMarker(corrupted), kind, p) {
					t.Fatalf("splicing %q at %d added a %s of %q that no line ahead of the completion marker names:\n%q", junk, at, kind, p, corrupted)
				}
			}
		}

		// The flags are what the proposal's exec: rule and the run's own warnings are
		// drawn from, so each one flipping on has to be carried by the line that says it.
		// Matched as a whole line: "EXEC" is a prefix of "EXECRAN", and a substring test
		// would let a spliced EXECRAN vouch for an exec attempt it never reported.
		for line, claimed := range map[string]bool{
			"EXEC":          got.ExecAttempted && !intact.ExecAttempted,
			"EXECRAN":       got.Execed && !intact.Execed,
			"SECCOMPKILLED": got.SeccompKilled && !intact.SeccompKilled,
		} {
			if claimed && !hasLine(beforeTheMarker(corrupted), line) {
				t.Fatalf("splicing %q at %d claimed %s with no such line in the report:\n%q", junk, at, line, corrupted)
			}
		}
	})
}

// parseObservation parses one report body through the descriptor path the host uses, so
// the fuzzer exercises the rewind and the scanner rather than a string the test split.
func parseObservation(t *testing.T, body string) (profile.Observation, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return parseObservations(openReport(t, path))
}

// namedOnALine reports whether some line of the report is an open of kind naming path.
// The comparison is against the DECODED path rather than strconv.Quote of it: junk spliced
// between the quotes leaves a line the report genuinely names, spelled with the raw bytes
// where Quote would re-escape them, and a literal test calls that an over-claim. What is
// still caught is a path arriving in Reads off a line that is not an "R " line at all.
func namedOnALine(report, kind, path string) bool {
	for _, line := range reportLines(report) {
		if !strings.HasPrefix(line, kind+" ") {
			continue
		}
		if p, err := strconv.Unquote(line[2:]); err == nil && p == path {
			return true
		}
	}
	return false
}

// beforeTheMarker is the report up to its completion marker, which is the most any
// observation can honestly rest on: the launcher writes the marker last, in a single
// write, so a record behind it came from something else holding the descriptor open. This
// is what generalizes the tamper arm - without the cut, a record spliced past the marker
// would vouch for itself, and the oracle would bless exactly the forgery the arm refuses.
//
// The marker is matched as a WHOLE LINE, for the reason execRanLinesBeforeTheRecordMarker
// gives: cut on the first substring occurrence and a marker spelled inside a quoted path
// ends the scan early, failing the oracle on a report that over-claims nothing.
func beforeTheMarker(report string) string {
	lines := reportLines(report)
	if i := slices.Index(lines, observe.ReportEnd); i >= 0 {
		lines = lines[:i]
	}
	return strings.Join(lines, "\n")
}

// reportLines splits the report the way the parser's own bufio.Scanner does, trailing CR
// and all. Splitting on "\n" alone diverges: ScanLines strips a CR the oracle would keep,
// so a spliced "EXEC\r" is a whole line to the parser and an unrecognized one here - and
// the fuzzer would eventually synthesize a \r and file a corpus entry against the stdlib
// rather than against a tamper the parser missed.
func reportLines(report string) []string {
	lines := strings.Split(report, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSuffix(l, "\r")
	}
	return lines
}

func hasLine(report, line string) bool {
	return slices.Contains(reportLines(report), line)
}

func count(paths []string, want string) int {
	var n int
	for _, p := range paths {
		if p == want {
			n++
		}
	}
	return n
}
