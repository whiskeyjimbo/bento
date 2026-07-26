package linux

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/observe"
	"github.com/whiskeyjimbo/bento/policy"
	"github.com/whiskeyjimbo/bento/profile"
)

func TestParseObservationsRequiresCompletionMarker(t *testing.T) {
	// A complete report (records then the trailing marker) parses.
	good := filepath.Join(t.TempDir(), "report")
	content := fmt.Sprintf("R %q\nW %q\nEXEC\n%s\n", "/a", "/b", observe.ReportEnd)
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
	content := fmt.Sprintf("R %q\n%s\nR %q\n", "/real", observe.ReportEnd, "/appended-forgery")
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
	content := fmt.Sprintf("R %q\n%s\n", evil, observe.ReportEnd)
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
		content := fmt.Sprintf("R %q\n%s\n%s\n", "/a", statusLine, observe.ReportEnd)
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

// The observation backend is chosen at build time - the ptrace decoder reads amd64
// syscall numbers and register layout, so every other architecture links a stub
// that only returns an error. Profile must refuse up front on such a host.
//
// Without the pre-flight check the failure still surfaced, but misdiagnosed: the
// sandbox launched, the launcher failed inside it, and the host found a report
// with no completion marker - which it reports as a sandbox that failed to start,
// pointing the reader at bwrap rather than at an architecture that cannot profile.
func TestProfileRefusesWithoutAnObservationBackend(t *testing.T) {
	orig := observeSupported
	observeSupported = func() bool { return false }
	t.Cleanup(func() { observeSupported = orig })

	dir := t.TempDir()
	script := filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(script, []byte("echo RAN\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir}}

	var out strings.Builder
	_, err := New().Profile(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out}, false, nil)
	if err == nil {
		t.Fatal("Profile must refuse on a host with no observation backend, not run and report an empty observation")
	}
	// The message has to name what is missing, or the reader is left with the same
	// misdiagnosis the pre-flight exists to prevent.
	for _, want := range []string{"profiling is not supported", runtime.GOARCH} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not mention %q", err, want)
		}
	}
	if strings.Contains(out.String(), "RAN") {
		t.Error("a refused profile must not execute the target")
	}
}

// The observer counts accesses it saw but could not name, and that count has to reach
// the Observation - otherwise a manifest short of what the run needs is indistinguishable
// from one for a run that touched nothing. A record whose quoting is unreadable is the
// same kind of loss and counts too, rather than vanishing.
func TestParseObservationsCarriesDroppedAccesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report")
	content := fmt.Sprintf("R %q\nR not-a-quoted-path\nDROPPED 3\nEXIT 0\n%s\n", "/a", observe.ReportEnd)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	obs, err := parseObservations(path)
	if err != nil {
		t.Fatalf("parseObservations: %v", err)
	}
	if len(obs.Reads) != 1 {
		t.Errorf("Reads = %v, want only the readable record", obs.Reads)
	}
	if obs.Dropped != 4 {
		t.Errorf("Dropped = %d, want 4 (the observer's 3 plus the unquotable record)", obs.Dropped)
	}
}
