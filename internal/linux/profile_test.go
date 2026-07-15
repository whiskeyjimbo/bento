package linux

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/internal/observe"
)

func TestParseObservationsRequiresStartMarker(t *testing.T) {
	// A report the launcher wrote (marker present) parses into observations.
	good := filepath.Join(t.TempDir(), "report")
	if err := os.WriteFile(good, []byte(observe.ReportStart+"\nR /a\nW /b\nEXEC\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	obs, err := parseObservations(good)
	if err != nil {
		t.Fatalf("a valid report should parse: %v", err)
	}
	if len(obs.Reads) != 1 || len(obs.Writes) != 1 || !obs.Execed {
		t.Fatalf("parsed = %+v, want one read, one write, execed", obs)
	}

	// The empty file bwrap leaves when it aborts before the launcher runs has no
	// marker: it must surface an error, not a silent empty observation the profiler
	// would turn into a manifest that grants nothing.
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := parseObservations(empty); err == nil {
		t.Fatal("a marker-less report should be an error, not a silent empty observation")
	}
}
