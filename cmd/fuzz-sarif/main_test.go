package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// The discriminating case: a run's untracked crasher reports, and everything else in the
// tree - a committed seed among the same untracked listing's siblings, an ordinary
// scratch file, a testdata path that is not a fuzz corpus - does not. Reporting a
// tracked seed is the failure mode that would file the same alert every night forever.
func TestSarifReportsOnlyCrashers(t *testing.T) {
	report, err := sarif([]string{
		"manifest/testdata/fuzz/FuzzManifestRoundTrip/1ec216c1df15d2f2",
		"profile/testdata/fuzz/FuzzProfileSynthesize/9d064b850c7be0ce",
		"manifest/testdata/golden/manifest.yaml",
		"internal/linux/testdata/fuzz/FuzzResolveSymlinkTree",
		"notes.md",
		"",
	})
	if err != nil {
		t.Fatal(err)
	}

	results := resultsOf(t, report)
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2: %v", len(results), results)
	}
	for _, want := range []string{"FuzzManifestRoundTrip", "FuzzProfileSynthesize"} {
		if !strings.Contains(results[0]+results[1], want) {
			t.Errorf("no result for %s: %v", want, results)
		}
	}
	if !strings.Contains(results[0], "go test ./manifest -run=FuzzManifestRoundTrip/1ec216c1df15d2f2") {
		t.Errorf("message does not carry a runnable repro: %s", results[0])
	}
}

// A clean night still uploads a report, because an empty result set is what retires the
// alert a fixed target raised the night before.
func TestSarifIsWellFormedWhenNothingFailed(t *testing.T) {
	report, err := sarif([]string{"README.md"})
	if err != nil {
		t.Fatal(err)
	}
	if got := resultsOf(t, report); len(got) != 0 {
		t.Fatalf("got %d results, want none: %v", len(got), got)
	}
	if report["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", report["version"])
	}
}

// resultsOf round-trips through JSON, so the test reads the report the uploader does
// rather than the map the builder happens to hold.
func resultsOf(t *testing.T, report map[string]any) []string {
	t.Helper()
	b, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID  string `json:"ruleId"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("got %d runs, want 1", len(doc.Runs))
	}
	var got []string
	for _, r := range doc.Runs[0].Results {
		if len(r.Locations) != 1 || r.Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
			t.Errorf("result %s has no location", r.RuleID)
		}
		got = append(got, r.RuleID+" "+r.Message.Text)
	}
	return got
}
