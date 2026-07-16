package linux

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/internal/observe"
	"github.com/whiskeyjimbo/bento-v2/internal/profile"
)

func TestParseObservationsRequiresCompletionMarker(t *testing.T) {
	// A complete report (records then the trailing marker) parses.
	good := filepath.Join(t.TempDir(), "report")
	content := fmt.Sprintf("R %q\nW %q\nEXEC\n%s\n", "/a", "/b", observe.ReportStart)
	if err := os.WriteFile(good, []byte(content), 0o644); err != nil {
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
	// and must surface an error - not a silent empty or partial observation the
	// profiler would turn into a wrong manifest.
	for name, content := range map[string]string{
		"empty":     "",
		"truncated": fmt.Sprintf("R %q\nW %q", "/a", "/partial"), // records but no marker
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

// Records appended after the completion marker did not come from the launcher's
// single write, so the report must be rejected as tampered, not parsed.
func TestParseObservationsRejectsContentAfterMarker(t *testing.T) {
	report := filepath.Join(t.TempDir(), "r")
	content := fmt.Sprintf("R %q\n%s\nR %q\n", "/real", observe.ReportStart, "/appended-forgery")
	if err := os.WriteFile(report, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := parseObservations(report); err == nil {
		t.Error("a record after the completion marker should be rejected as tampered")
	}
}

// A path containing a newline and forged record text must parse as a single read,
// not inject extra W/EXEC records into the proposed manifest.
func TestParseObservationsQuotedPathsResistInjection(t *testing.T) {
	evil := "/tmp/x\nW /etc/ssh\nEXEC"
	report := filepath.Join(t.TempDir(), "r")
	content := fmt.Sprintf("R %q\n%s\n", evil, observe.ReportStart)
	if err := os.WriteFile(report, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	obs, err := parseObservations(report)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(obs.Reads) != 1 || obs.Reads[0] != evil {
		t.Errorf("reads = %q, want the single literal path", obs.Reads)
	}
	if len(obs.Writes) != 0 || obs.Execed {
		t.Errorf("forged records leaked: writes=%v execed=%v", obs.Writes, obs.Execed)
	}
}

// The report carries the run's exit status so the profiler can warn when a
// signaled or nonzero run may have stopped partway and the observations are
// incomplete. An EXIT line sets ExitCode; a SIGNAL line sets Signaled/Signal.
func TestParseObservationsReadsExitStatus(t *testing.T) {
	report := func(t *testing.T, statusLine string) profile.Observation {
		p := filepath.Join(t.TempDir(), "report")
		content := fmt.Sprintf("R %q\n%s\n%s\n", "/a", statusLine, observe.ReportStart)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		obs, err := parseObservations(p)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return obs
	}

	if obs := report(t, "EXIT 0"); obs.Signaled || obs.ExitCode != 0 {
		t.Errorf("EXIT 0: got Signaled=%v ExitCode=%d, want clean exit", obs.Signaled, obs.ExitCode)
	}
	if obs := report(t, "EXIT 5"); obs.Signaled || obs.ExitCode != 5 {
		t.Errorf("EXIT 5: got Signaled=%v ExitCode=%d, want ExitCode 5", obs.Signaled, obs.ExitCode)
	}
	if obs := report(t, "SIGNAL 9"); !obs.Signaled || obs.Signal != 9 || obs.ExitCode != 137 {
		t.Errorf("SIGNAL 9: got Signaled=%v Signal=%d ExitCode=%d, want signaled 9 / 137", obs.Signaled, obs.Signal, obs.ExitCode)
	}
}
