package linux

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/internal/observe"
)

func TestParseObservationsRequiresCompletionMarker(t *testing.T) {
	// A complete report (records then the trailing marker) parses.
	good := filepath.Join(t.TempDir(), "report")
	if err := os.WriteFile(good, []byte("R /a\nW /b\nEXEC\n"+observe.ReportStart+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	obs, err := parseObservations(good)
	if err != nil {
		t.Fatalf("a complete report should parse: %v", err)
	}
	if len(obs.Reads) != 1 || len(obs.Writes) != 1 || !obs.Execed {
		t.Fatalf("parsed = %+v, want one read, one write, execed", obs)
	}

	// The empty file bwrap leaves when it aborts before the launcher runs, and a
	// truncated write that never reached the trailing marker, both lack the marker
	// and must surface an error — not a silent empty or partial observation the
	// profiler would turn into a wrong manifest.
	for name, content := range map[string]string{
		"empty":     "",
		"truncated": "R /a\nW /partial-pa", // records but no completion marker
	} {
		bad := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(bad, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := parseObservations(bad); err == nil {
			t.Errorf("%s report (no completion marker) should be an error, not a silent observation", name)
		}
	}
}
