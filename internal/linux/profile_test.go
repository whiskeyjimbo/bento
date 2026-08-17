//go:build linux

package linux

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/observe"
	"github.com/whiskeyjimbo/bento/internal/proxy"
	"github.com/whiskeyjimbo/bento/policy"
	"github.com/whiskeyjimbo/bento/profile"
)

func TestParseObservationsRequiresCompletionMarker(t *testing.T) {
	// A complete report (records then the trailing marker) parses.
	good := filepath.Join(t.TempDir(), "report")
	content := fmt.Sprintf("R %q\nW %q\nEXEC\nEXECRAN\n%s\n", "/a", "/b", observe.ReportEnd)
	if err := os.WriteFile(good, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	obs, err := parseObservations(openReport(t, good))
	if err != nil {
		t.Fatalf("a complete report should parse: %v", err)
	}
	if len(obs.Reads) != 1 || len(obs.Writes) != 1 || !obs.Execed || !obs.ExecAttempted {
		t.Fatalf("parsed = %+v, want one read, one write, an exec attempt and a spawn", obs)
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
		if _, err := parseObservations(openReport(t, bad)); err == nil {
			t.Errorf("%s report (no completion marker) should be an error, not a silent observation", name)
		}
	}
}

// The host parses the descriptor it held open across the run, and the child's writes
// went through a dup of it - so the handle sits at end-of-file by the time the parse
// starts. Without the rewind every report scans as empty and surfaces as one the
// launcher never wrote, which is a run that observed nothing rather than an error.
func TestParseObservationsRewindsTheSharedDescriptor(t *testing.T) {
	f := openReport(t, filepath.Join(t.TempDir(), "report"))
	if _, err := fmt.Fprintf(f, "R %q\nEXIT 0\n%s\n", "/a", observe.ReportEnd); err != nil {
		t.Fatal(err)
	}

	obs, err := parseObservations(f)
	if err != nil {
		t.Fatalf("parse from a descriptor left at EOF: %v", err)
	}
	if !slices.Equal(obs.Reads, []string{"/a"}) {
		t.Errorf("reads = %q, want the written record", obs.Reads)
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
	if _, err := parseObservations(openReport(t, report)); err == nil {
		t.Error("a record after the completion marker should be rejected as tampered")
	}
}

// A path containing a newline and forged record text must parse as a single read,
// not inject extra W/EXEC records into the proposed manifest. EXECRAN is in the forgery
// because it is the record a grant hangs off - exec: all for the whole run - which makes
// it the most valuable line for a target to smuggle in through a path it controls.
func TestParseObservationsQuotedPathsResistInjection(t *testing.T) {
	evil := "/tmp/x\nW /etc/ssh\nEXEC\nEXECRAN"
	report := filepath.Join(t.TempDir(), "r")
	content := fmt.Sprintf("R %q\n%s\n", evil, observe.ReportEnd)
	if err := os.WriteFile(report, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	obs, err := parseObservations(openReport(t, report))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(obs.Reads) != 1 || obs.Reads[0] != evil {
		t.Errorf("reads = %q, want the single literal path", obs.Reads)
	}
	if len(obs.Writes) != 0 || obs.Execed || obs.ExecAttempted {
		t.Errorf("forged records leaked: writes=%v execed=%v attempted=%v", obs.Writes, obs.Execed, obs.ExecAttempted)
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
		obs, err := parseObservations(openReport(t, p))
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

// A status line that cannot be read leaves the run's outcome unknown, and the
// profiler's warning about a run that may have stopped partway rides on exactly that
// line - so an unreadable one silently reported a clean exit 0, the most reassuring
// answer available. It refuses instead, like the missing completion marker. An
// unquotable R/W line is deliberately NOT this case: there the loss is one path, and
// counting it as a drop reports it honestly.
func TestParseObservationsRefusesUnreadableStatusLines(t *testing.T) {
	for _, line := range []string{"EXIT nope", "EXIT ", "SIGNAL nine", "DROPPED lots", "EXIT -1", "SIGNAL -9", "DROPPED -5"} {
		t.Run(line, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "report")
			content := fmt.Sprintf("R %q\n%s\n%s\n", "/a", line, observe.ReportEnd)
			if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			if obs, err := parseObservations(openReport(t, p)); err == nil {
				t.Errorf("parse accepted %q and reported ExitCode=%d Dropped=%d", line, obs.ExitCode, obs.Dropped)
			}
		})
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
	_, err := New().Profile(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out}, false, nil, nil)
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
	obs, err := parseObservations(openReport(t, path))
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
	if ok, reason := canCreateScope(t.Context()); !ok {
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
			enforce.Process{Stdout: &out, Stderr: &out}, false, nil, nil)
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
	if ok, _ := canCreateScope(t.Context()); ok {
		t.Skip("this host can create a transient scope; the refusal is unreachable here")
	}
	p := &policy.Policy{Entrypoint: "/bin/true", Exec: policy.ExecNone, Limits: policy.Limits{Memory: "256M"}}
	_, err := New().Profile(context.Background(), p, enforce.Process{}, false, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "cannot enforce") {
		t.Fatalf("profiling must refuse limits this host cannot enforce; got err=%v", err)
	}
}

// mqwl: profiling applies the same path shields an enforced run does, so it has to run
// the same alias scan. The profiled target is untrusted by construction - that is the
// whole reason it is being profiled - so a hardlink to a shielded credential inside a
// granted tree is read past the shield here exactly as it would be under Run, and
// --allow-network would forward what it read. The acknowledgement is honored, because the
// refusal prints it as a paste-ready flag and a host with a deduplicated backup would
// otherwise be unprofilable.
func TestProfileRefusesAnAliasedCredential(t *testing.T) {
	requireSandbox(t)
	// newSandbox takes the home the deny-list anchors on from os.UserHomeDir, i.e. $HOME.
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(home, ".ssh", "id_rsa")
	if err := os.WriteFile(key, []byte("PRIVATE KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(home, "project")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(project, "notes.txt")
	if err := os.Link(key, alias); err != nil {
		t.Skipf("no hardlink support: %v", err)
	}
	entrypoint := filepath.Join(project, "run.sh")
	if err := os.WriteFile(entrypoint, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{Entrypoint: entrypoint, Interpreter: "/bin/sh", Read: []string{project}}
	proc := enforce.Process{Env: map[string]string{"HOME": home}}

	_, err := sandboxEnforcer(t).Profile(context.Background(), p, proc, false, nil, nil)
	if err == nil {
		t.Fatal("Profile observed a policy whose granted tree holds a hardlink to a shielded credential")
	}
	for _, want := range []string{alias, key} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q must name %q", err, want)
		}
	}

	if _, err := sandboxEnforcer(t).Profile(context.Background(), p, proc, false, nil, []string{project}); err != nil {
		t.Fatalf("acknowledging the tree must let the profiling run proceed: %v", err)
	}
}

// A write grant naming a directory that does not exist yet is bound with --bind-try, so
// without the mkdir the bind is a silent no-op: the target's write fails, the observer
// records the attempt as ungranted, and the convergence loop proposes the same grant
// again forever. Run prepares these directories before launching; profiling has to as
// well, or the manifest it converges on is one it never actually exercised.
func TestProfileCreatesAWriteGrantsDirectory(t *testing.T) {
	requireSandbox(t)
	dir := t.TempDir()
	unborn := filepath.Join(dir, "out", "nested")
	script := filepath.Join(dir, "write.sh")
	if err := os.WriteFile(script, []byte("echo hi > "+filepath.Join(unborn, "f")+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir}, Write: []string{unborn}, Exec: policy.ExecAll}
	var out strings.Builder
	if _, err := sandboxEnforcer(t).Profile(context.Background(), p,
		enforce.Process{Stdout: &out, Stderr: &out}, false, nil, nil); err != nil {
		t.Fatalf("Profile: %v\noutput:\n%s", err, out.String())
	}

	// The write landed on the host, which is only possible if the directory existed to
	// be bound: --bind-try would have skipped a missing source without a word.
	if _, err := os.Stat(filepath.Join(unborn, "f")); err != nil {
		t.Errorf("the profiled write did not persist, so the write grant was never bound: %v\noutput:\n%s", err, out.String())
	}
}

// The absence annotation rides alongside the access it describes rather than replacing
// it: the run meant to open the path and the manifest still has to grant it. An
// unquotable one is skipped without counting a drop, unlike its R/W neighbours - the
// access was already counted on its own line, and all that is lost is the precision of a
// warning.
func TestParseObservationsReadsAbsentAnnotations(t *testing.T) {
	p := filepath.Join(t.TempDir(), "report")
	content := fmt.Sprintf("R %q\nABSENT %q\nR %q\nABSENT /unquoted\n%s\n",
		"/tmp/gone", "/tmp/gone", "/tmp/there", observe.ReportEnd)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	obs, err := parseObservations(openReport(t, p))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !slices.Equal(obs.Reads, []string{"/tmp/gone", "/tmp/there"}) {
		t.Errorf("reads = %q, want both paths recorded", obs.Reads)
	}
	if !slices.Equal(obs.Absent, []string{"/tmp/gone"}) {
		t.Errorf("absent = %q, want only the annotated path", obs.Absent)
	}
	if obs.Dropped != 0 {
		t.Errorf("dropped = %d, want 0: an unquotable annotation loses no access", obs.Dropped)
	}
}

// A cpu limit needs its own delegation answer. canCreateScope confirms only memory and
// pids, and systemd-run accepts a CPUQuota for an undelegated cpu controller without
// enforcing it, so gating on scope creation alone profiled the target with the manifest's
// cpu cap silently absent. Run is covered by admission reading LayerLimitsCPU off the
// probe; Profile produces no Report, so it owes the check directly.
func TestProfileRefusesACPULimitTheHostCannotEnforce(t *testing.T) {
	requireSandbox(t)
	if ok, _ := canCreateScope(t.Context()); !ok {
		t.Skip("this host cannot create a transient scope; the scope refusal fires first")
	}
	// canCreateScope memoized its own reading above, so this override reaches only the
	// per-controller cpu check - the undelegated cpu controller is the sole difference.
	orig := delegatedControllers
	delegatedControllers = func(context.Context) (map[string]bool, bool) {
		return map[string]bool{"memory": true, "pids": true}, true
	}
	t.Cleanup(func() { delegatedControllers = orig })

	p := &policy.Policy{Entrypoint: "/bin/true", Exec: policy.ExecNone, Limits: policy.Limits{CPU: "25%"}}
	_, err := New().Profile(context.Background(), p, enforce.Process{}, false, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "cpu controller is not delegated") {
		t.Fatalf("profiling must refuse a cpu limit this host cannot enforce; got err=%v", err)
	}
}

// A profiling run's proxy sees the two decisions that name no destination the same
// way an enforced run's does. There is nothing to propose for either, but the
// connection must not vanish from the observation: the enforced path keeps it in a
// count and a degraded network layer, and here the count is all there is.
func TestRecordedEgressCountsConnectionsItCannotName(t *testing.T) {
	var rec recordedEgress
	rec.observe(proxy.Denied, "recorded.example", "443")
	rec.observe(proxy.Untunneled, "plain.example", "80")
	rec.observe(proxy.Refused, "", "")
	rec.observe(proxy.Faulted, "", "")

	var obs profile.Observation
	rec.into(&obs)
	if want := []profile.HostPort{{Host: "recorded.example", Port: "443"}}; !slices.Equal(obs.Hosts, want) {
		t.Errorf("Hosts = %v, want %v", obs.Hosts, want)
	}
	if obs.DroppedConnections != 2 {
		t.Errorf("DroppedConnections = %d, want 2 (a refused and a faulted connection)", obs.DroppedConnections)
	}
	if obs.UnproposableHosts != nil {
		t.Errorf("UnproposableHosts = %v, want none - neither refusal named a destination", obs.UnproposableHosts)
	}
}

// A refusal that named a host after all - a target with no port, or a port spelling the
// dialer would refuse - is still nothing to propose, so it stays in the count. But the
// warning that count drives tells the operator to add the missing hosts by hand, and the
// one thing they cannot do that with is a count, so the host is carried beside it.
func TestRecordedEgressKeepsTheHostARefusalDidName(t *testing.T) {
	var rec recordedEgress
	rec.observe(proxy.Refused, "noport.example", "")
	rec.observe(proxy.Refused, "cutshort.example", "443")
	rec.observe(proxy.Refused, "", "")

	var obs profile.Observation
	rec.into(&obs)
	if obs.Hosts != nil {
		t.Errorf("Hosts = %v, want none - a refused destination is not proposable", obs.Hosts)
	}
	if obs.DroppedConnections != 3 {
		t.Errorf("DroppedConnections = %d, want 3 - a named refusal is still a connection the proposal is short", obs.DroppedConnections)
	}
	want := []profile.HostPort{{Host: "noport.example"}, {Host: "cutshort.example", Port: "443"}}
	if !slices.Equal(obs.UnproposableHosts, want) {
		t.Errorf("UnproposableHosts = %v, want %v", obs.UnproposableHosts, want)
	}
}

// A host the run reached for and could not reach is not a rule to propose: the operator
// would be offered a grant for a destination nothing ever used. The intended-egress
// record of the refusing mode is the deliberate opposite and has to survive beside it -
// there the proxy never dials at all, and recording what the script asked for is the
// whole point of the mode.
func TestRecordedEgressDropsADestinationTheDialNeverReached(t *testing.T) {
	var rec recordedEgress
	rec.observe(proxy.Unreachable, "down.example", "443")
	rec.observe(proxy.Denied, "recorded.example", "443")

	var obs profile.Observation
	rec.into(&obs)
	if want := []profile.HostPort{{Host: "recorded.example", Port: "443"}}; !slices.Equal(obs.Hosts, want) {
		t.Errorf("Hosts = %v, want %v - only the destination a run has evidence of", obs.Hosts, want)
	}
	if obs.DroppedConnections != 0 || obs.UnproposableHosts != nil {
		t.Errorf("DroppedConnections = %d, UnproposableHosts = %v, want none - an unreachable host is not a connection the proposal is short, it is one with nothing to propose", obs.DroppedConnections, obs.UnproposableHosts)
	}
}
