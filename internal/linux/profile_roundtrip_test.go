//go:build linux

package linux

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/observe"
	"github.com/whiskeyjimbo/bento/profile"
)

// observationReport renders an observe.Result the way the launcher writes it to the
// report descriptor (internal/launcher/launcher.go, runObserve): a %q-quoted R/W line
// per access, the ABSENT/PROBED annotations once per path, the exec records, the run's
// status, the observer's own drop count, and the completion marker last.
//
// It is a copy of that writer rather than a call to it: the launcher builds the report
// inline in the stage that runs inside the sandbox, so there is nothing to call from the
// host side. The copy is what this test can reach, and it leaves the writer/reader
// agreement itself uncovered - see bv2-nk1he.
func observationReport(res observe.Result) string {
	var b strings.Builder
	absent := map[string]bool{}
	probed := map[string]bool{}
	for _, a := range res.Accesses {
		verb := "R"
		if a.Write {
			verb = "W"
		}
		fmt.Fprintf(&b, "%s %q\n", verb, a.Path)
		if a.Absent && !absent[a.Path] {
			absent[a.Path] = true
			fmt.Fprintf(&b, "ABSENT %q\n", a.Path)
		}
		if a.Probed && !probed[a.Path] {
			probed[a.Path] = true
			fmt.Fprintf(&b, "PROBED %q\n", a.Path)
		}
	}
	if res.ExecAttempted {
		b.WriteString("EXEC\n")
	}
	if res.Execed {
		b.WriteString("EXECRAN\n")
	}
	if res.Signaled {
		fmt.Fprintf(&b, "SIGNAL %d\n", res.Signal)
	} else {
		fmt.Fprintf(&b, "EXIT %d\n", res.ExitCode)
	}
	if res.Dropped > 0 {
		fmt.Fprintf(&b, "DROPPED %d\n", res.Dropped)
	}
	if res.SeccompKilled {
		b.WriteString("SECCOMPKILLED\n")
	}
	b.WriteString(observe.ReportEnd + "\n")
	return b.String()
}

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
		obs := synth(t, observationReport(res))
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
		report := strings.Replace(observationReport(res), observe.ReportEnd, raw+observe.ReportEnd, 1)

		obs := synth(t, report)
		if obs.Dropped != 1 {
			t.Errorf("Dropped = %d, want 1 for the unquotable record", obs.Dropped)
		}
		if proposes(t, obs, unnamed) {
			t.Errorf("the proposal grants %q, a record the parser could not read", unnamed)
		}
	})
}
