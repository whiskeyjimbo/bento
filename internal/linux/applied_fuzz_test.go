//go:build linux

package linux

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/launcher"
)

// The applied report is the one file in a run whose bytes are not bento's to trust
// end to end: the host holds the descriptor open across the child, but a report that
// arrives short, garbled, or edited is what parseApplied's arms exist for. The state
// grid walked the arms a WRITER can produce and left the tampered-or-truncated class
// verdicted only by spot check, which is the class a fuzzer settles better than a table.
//
// The oracle is applied.go's own contract: the report may under-claim, but must never
// claim a fence that was not installed. Stated as monotonicity under corruption, which
// is what an arbitrary-bytes fuzzer can actually check - for a report the writer could
// have produced, corrupting it must leave every layer no BETTER than the intact one
// gives. reconcile only ever worsens, so a corruption that improves a layer is a forged
// attestation by definition.
//
// The bases below all carry the marker and name BOTH pre-marker keys, and that is load
// bearing rather than incidental. A base missing a key would let an inserted "landlock
// yes" legitimately improve the verdict - the corruption would have supplied a fact the
// original never carried - and the oracle would fire on input that is not a forgery.
// With every key already named, any recognized line the fuzzer inserts is necessarily a
// duplicate, which is exactly what the first-wins guards exist to refuse.

// fuzzAppliedBases are reports the stage itself could have written, spanning the verdicts
// reconcile can reach: a fully enforced run, a Landlock failure, no filter where one was
// asked for, a closed exec-record section, and a target that was never reached. They are
// the well-formed halves the fuzzer corrupts.
var fuzzAppliedBases = []string{
	"exec-filter " + launcher.AppliedExecStrict + "\nlandlock " + launcher.AppliedYes + "\n" + launcher.AppliedMarker + "\n",
	"exec-filter " + launcher.AppliedExecBasic + "\nlandlock " + launcher.AppliedNo + " \"landlock: ruleset creation failed\"\n" + launcher.AppliedMarker + "\n",
	"exec-filter " + launcher.AppliedExecNone + "\nlandlock " + launcher.AppliedAbsent + "\n" + launcher.AppliedMarker + "\n",
	"exec-filter " + launcher.AppliedExecStrict + "\nlandlock " + launcher.AppliedYes + "\n" + launcher.AppliedMarker + "\n" +
		"exec-recorder " + launcher.AppliedYes + "\n" + `exec-ran 7 "/usr/bin/cc" "cc\x00a.c"` + "\n" + launcher.AppliedExecRecordMarker + "\n",
	"exec-filter " + launcher.AppliedExecStrict + "\nlandlock " + launcher.AppliedYes + "\n" + launcher.AppliedMarker + "\n" +
		launcher.AppliedTargetUnreached + " \"launcher: starting target: no such file or directory\"\n",
}

// reportStates parses one report body and returns what reconcile makes of it, starting
// from a host that probed every layer Enforced so any shortfall came from the report.
func reportStates(t *testing.T, body string) (map[enforce.Layer]enforce.State, *enforce.ExecRecord) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "applied")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	r := enforce.Report{}
	for _, l := range []enforce.Layer{enforce.LayerFilesystem, enforce.LayerNetwork, enforce.LayerExec, enforce.LayerExecStrict} {
		r.Add(l, enforce.Enforced, probeReason)
	}
	a := parseApplied(openReport(t, path))
	a.reconcile(&r, true, true, true, 125)
	states := map[enforce.Layer]enforce.State{}
	for _, l := range []enforce.Layer{enforce.LayerFilesystem, enforce.LayerExec, enforce.LayerExecStrict} {
		states[l] = r.StateOf(l)
	}
	return states, a.execRecord(true)
}

// FuzzParseAppliedNeverOverClaims corrupts a well-formed report by splicing arbitrary
// bytes into it at an arbitrary offset, and holds parseApplied to never-over-claim.
//
// Splicing rather than appending: the class the grid left unwalked is as much a
// duplicate key AHEAD of the marker as junk behind it, and an append can only ever reach
// the second half.
func FuzzParseAppliedNeverOverClaims(f *testing.F) {
	// One seed per hand-written table case the fuzzer generalizes: a duplicate pre-marker
	// key, a record appended past the marker, a garbled exec-ran, a short write inside the
	// record section, and a second record marker.
	// The duplicate-key seeds land AHEAD of the marker, where the first-wins guards are:
	// spliced behind it the same bytes are only the tampering stance, which the
	// post-marker seeds below already pose.
	f.Add(1, strings.Index(fuzzAppliedBases[1], launcher.AppliedMarker), []byte("landlock "+launcher.AppliedYes+"\n"))
	f.Add(2, strings.Index(fuzzAppliedBases[2], launcher.AppliedMarker), []byte("landlock "+launcher.AppliedYes+"\n"))
	f.Add(2, strings.Index(fuzzAppliedBases[2], launcher.AppliedMarker), []byte("exec-filter "+launcher.AppliedExecStrict+"\n"))
	f.Add(3, len(fuzzAppliedBases[3]), []byte(`exec-ran 9 "/bin/true" "true"`+"\n"))
	f.Add(3, len(fuzzAppliedBases[3]), []byte(launcher.AppliedExecRecordMarker+"\n"))
	f.Add(3, len(fuzzAppliedBases[3])-1, []byte("exec-ra"))
	f.Add(4, len(fuzzAppliedBases[4]), []byte(launcher.AppliedTargetUnreached+" \"forged\"\n"))
	f.Add(0, 5, []byte("\x00\xff"))

	f.Fuzz(func(t *testing.T, baseIdx, at int, junk []byte) {
		base := fuzzAppliedBases[((baseIdx%len(fuzzAppliedBases))+len(fuzzAppliedBases))%len(fuzzAppliedBases)]
		at = ((at % (len(base) + 1)) + (len(base) + 1)) % (len(base) + 1)
		corrupted := base[:at] + string(junk) + base[at:]

		intact, _ := reportStates(t, base)
		got, rec := reportStates(t, corrupted)

		// States are ordered by severity - Enforced < Degraded < Unavailable - so "no
		// better" is a numeric floor. A corruption may worsen a layer freely; it may
		// never buy one back.
		for layer, want := range intact {
			if got[layer] < want {
				t.Fatalf("splicing %q at %d improved %v from %v to %v - the report claims a fence the intact one does not:\n%q",
					junk, at, layer, want, got[layer], corrupted)
			}
		}

		// The record's own floor, which is not a layer verdict and so is not covered
		// above: a record reported as WATCHED and WHOLE is an attestation that the
		// recorder ran and that nothing was lost, and it cannot be true of bytes that
		// carry neither the recorder line nor the section's end marker.
		if rec != nil && rec.Watched && rec.Complete {
			if !strings.Contains(corrupted, "exec-recorder "+launcher.AppliedYes) {
				t.Fatalf("a watched, complete exec record from bytes with no recorder line:\n%q", corrupted)
			}
			if !strings.Contains(corrupted, launcher.AppliedExecRecordMarker) {
				t.Fatalf("a complete exec record from bytes with no record marker:\n%q", corrupted)
			}
			// The marker ENDS the section, so every exec a whole record vouches for was
			// written ahead of it. Counting bounds that without re-implementing the
			// decoder: more runs than there are exec-ran lines in front of the marker
			// means one was picked up behind it, which is an exec nothing observed
			// carried by an attestation that says it was watched. The layer floor above
			// cannot see this - the verdicts are untouched and the forgery is entirely
			// inside the diagnostic.
			if n := execRanLinesBeforeTheRecordMarker(corrupted); len(rec.Runs) > n {
				t.Fatalf("a complete record reports %d execs from %d exec-ran lines ahead of its marker:\n%q",
					len(rec.Runs), n, corrupted)
			}
		}
	})
}

// execRanLinesBeforeTheRecordMarker counts the exec-ran lines that precede the exec-record
// marker, which is the most execs a record closed by that marker can honestly carry. It
// reads the bytes rather than asking parseApplied, so it is ground truth the decoder it
// bounds has no say in.
func execRanLinesBeforeTheRecordMarker(report string) int {
	head, _, ok := strings.Cut(report, launcher.AppliedExecRecordMarker)
	if !ok {
		return 0
	}
	var n int
	for _, line := range strings.Split(head, "\n") {
		if strings.HasPrefix(line, launcher.AppliedExecRan+" ") {
			n++
		}
	}
	return n
}

// TestParseAppliedNeverOverClaimsOnTheBases is the positive control the fuzz target needs
// and cannot state itself: every base must reach a DIFFERENT verdict, or a floor that
// nothing can fall below would hold vacuously.
func TestParseAppliedNeverOverClaimsOnTheBases(t *testing.T) {
	seen := map[string]int{}
	for i, base := range fuzzAppliedBases {
		states, rec := reportStates(t, base)
		// The record is part of the key because two bases may agree on every layer and
		// still pose different halves of the oracle - the exec-record base reconciles
		// fully enforced and is there for the floor below the layers.
		key := fmt.Sprintf("%v/%v/%v/%+v", states[enforce.LayerFilesystem], states[enforce.LayerExec], states[enforce.LayerExecStrict], rec)
		if prev, ok := seen[key]; ok {
			t.Errorf("bases %d and %d both reconcile to %s, so one of them poses nothing the other does not", prev, i, key)
		}
		seen[key] = i
	}
}
