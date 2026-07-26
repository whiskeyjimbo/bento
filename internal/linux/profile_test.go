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

// A profiled policy that requests resource limits must run under the same transient
// scope the enforced run uses. Profiling is by construction the untrusted-code case -
// the target has not been reviewed yet - so it is the last path that should run with
// the manifest's memory caps silently dropped. `bento profile` on an existing limited
// manifest carries those limits into the discovery policy, so this is the shape that
// reaches it.
//
// Three runs of one allocating target pin both halves of that. The generous limit is
// the load-bearing one: it proves the scope wrapper carries the observation FD and the
// target through intact, so the tight limit's dead target is the cap biting rather than
// a wrapper that broke profiling outright - which, on its own, would look identical.
func TestProfileRunsUnderTheRequestedLimits(t *testing.T) {
	requireSandbox(t)
	if ok, reason := canCreateScope(); !ok {
		t.Skip("no usable systemd user scope: " + reason)
	}

	// profileAllocating profiles a target that holds ~96MB, reporting whether it
	// reached its marker and what the observer saw.
	profileAllocating := func(t *testing.T, limits policy.Limits) (profile.Observation, bool) {
		t.Helper()
		dir := t.TempDir()
		marker := filepath.Join(dir, "done")
		script := filepath.Join(dir, "alloc.sh")
		body := "x=$(head -c 96000000 /dev/urandom | base64)\ntouch " + marker + "\n"
		if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		p := &policy.Policy{
			Entrypoint:  script,
			Interpreter: "sh",
			Read:        []string{dir},
			Write:       []string{dir},
			Exec:        policy.ExecAll,
			Limits:      limits,
		}
		var out strings.Builder
		obs, err := sandboxEnforcer(t).Profile(context.Background(), p,
			enforce.Process{Stdout: &out, Stderr: &out}, false, nil)
		// The kernel picks its OOM victim by size, so it usually takes the allocating
		// shell and the observer still reports - but it can take the observer instead,
		// which surfaces as a truncated report. Both are the cap biting, and only the
		// tight run below tolerates it; any other error is a broken test.
		if err != nil && (limits.Memory != "32M" || !strings.Contains(err.Error(), "did not complete")) {
			t.Fatalf("Profile with limits %+v failed: %v\noutput:\n%s", limits, err, out.String())
		}
		_, statErr := os.Stat(marker)
		return obs, statErr == nil
	}

	unlimited, reached := profileAllocating(t, policy.Limits{})
	if !reached {
		t.Fatal("the unlimited profiling run never reached its marker, so the limited runs below would prove nothing")
	}

	// A cap the target fits under must change nothing: the run completes and the
	// observation is as rich as the unwrapped one. This is what a wrapper that silently
	// broke the observation FD or never launched bwrap would fail.
	generous, reached := profileAllocating(t, policy.Limits{Memory: "512M"})
	if !reached {
		t.Error("a target well under its memory limit was stopped anyway - the scope wrapper is not passing the run through")
	}
	if len(generous.Reads) == 0 {
		t.Errorf("a scoped profiling run observed no file accesses (unscoped saw %d) - the observation report does not survive the scope wrapper", len(unlimited.Reads))
	}

	// And a cap the target blows past must stop it.
	if _, reached := profileAllocating(t, policy.Limits{Memory: "32M"}); reached {
		t.Error("a target allocating far past the manifest's memory limit ran to completion - profiling applied no scope")
	}
}

// A host that cannot create a scope at all refuses the profiling run instead of
// profiling unbounded. Run may proceed unwrapped in the same spot because enforce.Run
// already ruled on that shortfall and the Report carries it; profiling has neither, so
// dropping the cap silently here would be the one place an unreviewed target runs with
// no ceiling on the host's memory.
func TestProfileRefusesLimitsItCannotEnforce(t *testing.T) {
	if ok, _ := canCreateScope(); ok {
		t.Skip("this host can create a transient scope; the refusal is unreachable here")
	}
	p := &policy.Policy{Entrypoint: "/bin/true", Exec: policy.ExecNone, Limits: policy.Limits{Memory: "256M"}}
	_, err := New().Profile(context.Background(), p, enforce.Process{}, false, nil)
	if err == nil || !strings.Contains(err.Error(), "cannot enforce") {
		t.Fatalf("profiling must refuse limits this host cannot enforce; got err=%v", err)
	}
}
