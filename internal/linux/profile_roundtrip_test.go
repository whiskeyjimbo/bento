//go:build linux

package linux

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/observe"
	"github.com/whiskeyjimbo/bento/profile"
)

// An access the observer could not name has to arrive at the proposal as a drop and
// never as a grant. The observe package's own test assembles the profile.Observation by
// hand, so the leg between them - the report text and the parser here - was asserted
// nowhere: a drop that leaked into Reads on the way would reach Synthesize as a path the
// run was seen touching, and be proposed. Both halves of that matter, so both are
// checked: the count survives, and the proposal carries no grant for it.
func TestObservationReportRoundTripCountsDropsNotGrants(t *testing.T) {
	// Fabricated absolute paths rather than a t.TempDir(): Synthesize drops anything
	// under /tmp as sandbox scratch, so a real temporary directory would make the
	// "not proposed" half hold whatever the parser did with the record.
	const seen = "/data/lane/input.txt"
	const unnamed = "/data/lane/secret"

	synth := func(t *testing.T, report string) profile.Observation {
		t.Helper()
		path := filepath.Join(t.TempDir(), "report")
		if err := os.WriteFile(path, []byte(report), 0o644); err != nil {
			t.Fatal(err)
		}
		obs, err := parseObservations(openReport(t, path))
		if err != nil {
			t.Fatalf("parseObservations: %v", err)
		}
		return obs
	}
	proposes := func(t *testing.T, obs profile.Observation, path string) bool {
		t.Helper()
		pol, err := profile.Synthesize("/data/lane/run", "", nil, obs)
		if err != nil {
			t.Fatalf("Synthesize: %v", err)
		}
		return slices.Contains(pol.Read, path) || slices.Contains(pol.Write, path)
	}

	// The observer's own count: accesses it saw and could not name at all, so the
	// report carries a number and no path.
	t.Run("observer count", func(t *testing.T) {
		res := observe.Result{
			Accesses: []observe.Access{{Path: seen}},
			Dropped:  2,
		}
		obs := synth(t, observe.FormatReport(res))
		if obs.Dropped != 2 {
			t.Errorf("Dropped = %d, want the observer's 2", obs.Dropped)
		}
		if !proposes(t, obs, seen) {
			t.Errorf("the readable access %q was not proposed, so the drop assertions below prove nothing", seen)
		}
	})

	// A record whose quoting the parser cannot read is the same loss with a path
	// attached, and it is the one that can turn into a grant: taking the raw text as
	// the path would propose %q's argument, which is a path the run may never have
	// touched under the name the report shows.
	t.Run("unquotable record", func(t *testing.T) {
		res := observe.Result{Accesses: []observe.Access{{Path: seen}}}
		raw := "R " + unnamed + "\n"
		report := strings.Replace(observe.FormatReport(res), observe.ReportEnd, raw+observe.ReportEnd, 1)

		obs := synth(t, report)
		if obs.Dropped != 1 {
			t.Errorf("Dropped = %d, want 1 for the unquotable record", obs.Dropped)
		}
		if proposes(t, obs, unnamed) {
			t.Errorf("the proposal grants %q, a record the parser could not read", unnamed)
		}
	})
}

// The launcher's writer and this parser sit on the two sides of the re-exec boundary
// with no call between them, so the only thing that can bind them is driving the real
// writer's output through the real parser. Every field of observe.Result is set to a
// value distinguishable from its zero, because an arm this test leaves at zero is one
// the writer can stop emitting with nothing failing - which is exactly how the copy
// this test used to carry hid the writer from the reader.
func TestObservationReportRoundTripsEveryRecord(t *testing.T) {
	res := observe.Result{
		Accesses: []observe.Access{
			{Path: "/data/lane/read"},
			{Path: "/data/lane/written", Write: true},
			{Path: "/data/lane/missing", Absent: true},
			{Path: "/data/lane/statted", Probed: true},
		},
		ExecAttempted: true,
		Execed:        true,
		Signaled:      true,
		Signal:        9,
		Dropped:       3,
		SeccompKilled: true,
	}

	path := filepath.Join(t.TempDir(), "report")
	if err := os.WriteFile(path, []byte(observe.FormatReport(res)), 0o644); err != nil {
		t.Fatal(err)
	}
	obs, err := parseObservations(openReport(t, path))
	if err != nil {
		t.Fatalf("parseObservations on the launcher's own report text: %v", err)
	}

	want := profile.Observation{
		Reads:         []string{"/data/lane/read", "/data/lane/missing", "/data/lane/statted"},
		Writes:        []string{"/data/lane/written"},
		Absent:        []string{"/data/lane/missing"},
		Probed:        []string{"/data/lane/statted"},
		ExecAttempted: true,
		Execed:        true,
		Signaled:      true,
		Signal:        9,
		// A signaled run has no exit code of its own; the parser reports the shell's.
		ExitCode:      128 + 9,
		Dropped:       3,
		SeccompKilled: true,
	}
	if !reflect.DeepEqual(obs, want) {
		t.Errorf("the report round-tripped to\n\t%+v\nwant\n\t%+v", obs, want)
	}

	// The signal arm suppresses EXIT, so a separate run is the only way to hold the
	// writer to emitting an exit status at all.
	path = filepath.Join(t.TempDir(), "report")
	if err := os.WriteFile(path, []byte(observe.FormatReport(observe.Result{ExitCode: 7})), 0o644); err != nil {
		t.Fatal(err)
	}
	obs, err = parseObservations(openReport(t, path))
	if err != nil {
		t.Fatalf("parseObservations on an unsignaled run's report: %v", err)
	}
	if obs.ExitCode != 7 || obs.Signaled {
		t.Errorf("ExitCode = %d, Signaled = %v; want the writer's exit status 7 unsignaled", obs.ExitCode, obs.Signaled)
	}
}
