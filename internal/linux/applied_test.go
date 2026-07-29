package linux

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/launcher"
	"github.com/whiskeyjimbo/bento/policy"
)

// The run report must rest on what the sandboxed child actually applied, not on the
// host probe alone. This is the end-to-end proof that the channel carries: a real
// run whose launcher installs the filter and the Landlock backstop reports no
// shortfall, and the same run with a launcher that never reports one - which is
// every setup failure, since the report is written only after the last layer lands -
// reports the child-applied layers unenforced instead of carrying the probe's
// Enforced through.
func TestRunReportRestsOnWhatTheChildApplied(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	script := filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(script, []byte("exit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir}}

	var out bytes.Buffer
	res, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out}, enforce.RunOptions{})
	if err != nil {
		t.Fatalf("Run: %v (output: %s)", err, out.String())
	}
	// The exec layer is claimed only because the child said it installed the filter. A
	// broken channel - the descriptor not passed through bwrap, the report not written,
	// the marker missing - lands here as Unavailable, so this is not a tautology.
	if st := res.Report.StateOf(enforce.LayerExec); st != enforce.Enforced {
		t.Errorf("exec layer = %v after a successful confined run; the child's applied-layer report did not reach the host: %v",
			st, res.Report.Degradations())
	}
	if st := res.Report.StateOf(enforce.LayerFilesystem); st != enforce.Enforced {
		t.Errorf("filesystem layer = %v; the Landlock backstop reported failure on a run that should have applied it: %v",
			st, res.Report.Degradations())
	}
}

// A launcher that exits without reporting is exactly the case the host could not
// previously see: it exits 125 (reexecFail) having confined nothing, and a target
// that itself exits 125 was indistinguishable. The stand-in launcher below is that
// child - it applies nothing and exits 125 - and the report must say so.
func TestRunReportRefusesToClaimLayersWhenTheChildIsSilent(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	script := filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(script, []byte("exit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir}}

	var out bytes.Buffer
	e := enforcerUsing(silentLauncher(t))
	res, err := e.Run(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out}, enforce.RunOptions{})
	if err != nil {
		t.Fatalf("Run: %v (output: %s)", err, out.String())
	}
	if res.ExitCode != 125 {
		t.Fatalf("exit code = %d, want the stand-in launcher's 125 (output: %s)", res.ExitCode, out.String())
	}
	for _, l := range []enforce.Layer{enforce.LayerExec, enforce.LayerFilesystem} {
		if st := res.Report.StateOf(l); st != enforce.Unavailable {
			t.Errorf("%s layer = %v for a run whose launcher applied nothing and never reported; want unavailable", l, st)
		}
	}
	// The reason names the exit code, which is what lets a reader tell bento failing to
	// confine from a target that chose 125 itself.
	var reasons strings.Builder
	for _, d := range res.Report.Degradations() {
		reasons.WriteString(d.Reason)
	}
	if !strings.Contains(reasons.String(), "125") {
		t.Errorf("no degradation reason names the exit code the silent launcher died with: %q", reasons.String())
	}
}

// silentLauncher builds a stand-in for the bento binary that the sandbox re-execs:
// it applies no confinement, writes no applied-layer report, and exits 125, the code
// a real setup failure exits with. Building a program (rather than pointing selfPath
// at a shell script) keeps it independent of what the sandbox's mount namespace makes
// executable.
func silentLauncher(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		skipMissingDep(t, "go toolchain not available")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	const prog = "package main\n\nimport \"os\"\n\nfunc main() { os.Exit(125) }\n"
	if err := os.WriteFile(src, []byte(prog), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "silent-launcher")
	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "GOWORK=off", "HOME="+toolchainHome)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the stand-in launcher: %v\n%s", err, out)
	}
	return bin
}

// The degraded tier carries the same channel, and it matters more there: every fence
// is the only one of its kind, so a stage that died before applying them confined
// nothing. This drives runDegraded directly (as the other degraded tests do, since a
// userns-capable host would otherwise take the bwrap path) and proves the report the
// stage writes reaches the host - a broken channel reports the layers unavailable.
func TestDegradedRunReportRestsOnWhatTheChildApplied(t *testing.T) {
	requireDegraded(t)

	bin := buildDegradedProbe(t)
	granted := t.TempDir()
	if err := os.WriteFile(filepath.Join(granted, "ok.txt"), []byte("granted"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: bin, Read: []string{granted}, Exec: policy.ExecNone}

	var out strings.Builder
	res, err := enforcerUsing(testBento(t)).runDegraded(context.Background(), p,
		enforce.Process{Stdout: &out, Stderr: &out, Env: map[string]string{"GRANTED": filepath.Join(granted, "ok.txt"), "UNGRANTED": filepath.Join(t.TempDir(), "absent")}})
	if err != nil {
		t.Fatalf("runDegraded: %v\noutput:\n%s", err, out.String())
	}
	for _, l := range []enforce.Layer{enforce.LayerExec, enforce.LayerFilesystem} {
		if st := res.Report.StateOf(l); st == enforce.Unavailable {
			t.Errorf("%s layer = %v after the degraded stage confined the run; its applied-layer report did not reach the host: %v",
				l, st, res.Report.Degradations())
		}
	}
}

// The reconciliation itself, over the reports a child can produce. The end-to-end
// tests above cover the two outcomes a real host reaches; these cover the ones that
// need an architecture or a kernel this host may not have (the strict-filter
// fallback, a failing Landlock backstop) plus the tampered report.
func TestAppliedReconcile(t *testing.T) {
	cases := []struct {
		name         string
		report       string
		blockWanted  bool
		strictWanted bool
		want         map[enforce.Layer]enforce.State
	}{
		{
			name:        "a complete report naming no filter where the policy asked for one claims neither exec layer",
			report:      launcher.AppliedExecFilter + " " + launcher.AppliedExecNone + "\n" + launcher.AppliedLandlock + " " + launcher.AppliedYes + "\n" + launcher.AppliedMarker + "\n",
			blockWanted: true,
			want:        map[enforce.Layer]enforce.State{enforce.LayerExec: enforce.Unavailable, enforce.LayerExecStrict: enforce.Unavailable, enforce.LayerFilesystem: enforce.Enforced},
		},
		{
			name:        "a complete report with no exec-filter line at all claims neither exec layer",
			report:      launcher.AppliedLandlock + " " + launcher.AppliedYes + "\n" + launcher.AppliedMarker + "\n",
			blockWanted: true,
			want:        map[enforce.Layer]enforce.State{enforce.LayerExec: enforce.Unavailable, enforce.LayerExecStrict: enforce.Unavailable},
		},
		{
			name:   "no filter is no shortfall when the policy did not ask for one",
			report: launcher.AppliedExecFilter + " " + launcher.AppliedExecNone + "\n" + launcher.AppliedLandlock + " " + launcher.AppliedYes + "\n" + launcher.AppliedMarker + "\n",
			want:   map[enforce.Layer]enforce.State{enforce.LayerExec: enforce.Enforced, enforce.LayerExecStrict: enforce.Enforced},
		},
		{
			name:   "a kernel without Landlock is the probe's business, not a run shortfall",
			report: launcher.AppliedExecFilter + " " + launcher.AppliedExecStrict + "\n" + launcher.AppliedLandlock + " " + launcher.AppliedAbsent + "\n" + launcher.AppliedMarker + "\n",
			want:   map[enforce.Layer]enforce.State{enforce.LayerFilesystem: enforce.Enforced},
		},
		{
			name:   "a complete report claims nothing extra",
			report: launcher.AppliedExecFilter + " " + launcher.AppliedExecStrict + "\n" + launcher.AppliedLandlock + " " + launcher.AppliedYes + "\n" + launcher.AppliedMarker + "\n",
			want:   map[enforce.Layer]enforce.State{enforce.LayerExec: enforce.Enforced, enforce.LayerExecStrict: enforce.Enforced, enforce.LayerFilesystem: enforce.Enforced},
		},
		{
			name:         "the execve-only fallback degrades exec-strict only",
			report:       launcher.AppliedExecFilter + " " + launcher.AppliedExecBasic + "\n" + launcher.AppliedLandlock + " " + launcher.AppliedYes + "\n" + launcher.AppliedMarker + "\n",
			blockWanted:  true,
			strictWanted: true,
			want:         map[enforce.Layer]enforce.State{enforce.LayerExec: enforce.Enforced, enforce.LayerExecStrict: enforce.Degraded, enforce.LayerFilesystem: enforce.Enforced},
		},
		{
			name:   "the same fallback is no shortfall when strict was not asked for",
			report: launcher.AppliedExecFilter + " " + launcher.AppliedExecBasic + "\n" + launcher.AppliedLandlock + " " + launcher.AppliedYes + "\n" + launcher.AppliedMarker + "\n",
			want:   map[enforce.Layer]enforce.State{enforce.LayerExec: enforce.Enforced, enforce.LayerExecStrict: enforce.Enforced},
		},
		{
			name:   "a failed Landlock backstop degrades the filesystem layer",
			report: launcher.AppliedExecFilter + " " + launcher.AppliedExecBasic + "\n" + launcher.AppliedLandlock + " " + launcher.AppliedNo + " " + `"landlock: ruleset creation failed"` + "\n" + launcher.AppliedMarker + "\n",
			want:   map[enforce.Layer]enforce.State{enforce.LayerFilesystem: enforce.Degraded, enforce.LayerExec: enforce.Enforced},
		},
		{
			// strconv.Unquote turns `""` into an empty string with a nil error, so a reason
			// keyed on emptiness read a reported failure as a success.
			name:   "a failure with an empty reason is still a failure",
			report: launcher.AppliedExecFilter + " " + launcher.AppliedExecBasic + "\n" + launcher.AppliedLandlock + " " + launcher.AppliedNo + " " + `""` + "\n" + launcher.AppliedMarker + "\n",
			want:   map[enforce.Layer]enforce.State{enforce.LayerFilesystem: enforce.Degraded},
		},
		{
			// The backstop is applied unconditionally in both tiers, so silence about it is
			// a run that did not report applying it, not a run that had it.
			name:   "a complete report with no Landlock record at all claims no backstop",
			report: launcher.AppliedExecFilter + " " + launcher.AppliedExecBasic + "\n" + launcher.AppliedMarker + "\n",
			want:   map[enforce.Layer]enforce.State{enforce.LayerFilesystem: enforce.Degraded},
		},
		{
			name:   "a Landlock outcome this host does not recognize claims no backstop",
			report: launcher.AppliedExecFilter + " " + launcher.AppliedExecBasic + "\n" + launcher.AppliedLandlock + " partly\n" + launcher.AppliedMarker + "\n",
			want:   map[enforce.Layer]enforce.State{enforce.LayerFilesystem: enforce.Degraded},
		},
		{
			// Every layer really was applied - to the launcher, which then never reached the
			// target. The marker cannot catch this: on the exec-block path it must be written
			// before the target is reached, so a nonexistent entrypoint lands past it.
			name: "layers applied to a run that never happened are claimed by no layer",
			report: launcher.AppliedExecFilter + " " + launcher.AppliedExecStrict + "\n" + launcher.AppliedLandlock + " " + launcher.AppliedYes + "\n" +
				launcher.AppliedMarker + "\n" + launcher.AppliedTargetUnreached + " " + `"launcher: starting target: no such file or directory"` + "\n",
			blockWanted:  true,
			strictWanted: true,
			want:         map[enforce.Layer]enforce.State{enforce.LayerExec: enforce.Unavailable, enforce.LayerExecStrict: enforce.Unavailable, enforce.LayerFilesystem: enforce.Unavailable},
		},
		{
			name:   "records appended after the marker discard the whole report",
			report: launcher.AppliedExecFilter + " " + launcher.AppliedExecStrict + "\n" + launcher.AppliedMarker + "\n" + launcher.AppliedLandlock + " " + launcher.AppliedYes + "\n",
			want:   map[enforce.Layer]enforce.State{enforce.LayerExec: enforce.Unavailable, enforce.LayerExecStrict: enforce.Unavailable, enforce.LayerFilesystem: enforce.Unavailable},
		},
		{
			name:   "a report that never reached its marker claims nothing",
			report: launcher.AppliedExecFilter + " " + launcher.AppliedExecStrict + "\n",
			want:   map[enforce.Layer]enforce.State{enforce.LayerExec: enforce.Unavailable, enforce.LayerExecStrict: enforce.Unavailable, enforce.LayerFilesystem: enforce.Unavailable},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "applied")
			if err := os.WriteFile(path, []byte(tc.report), 0o600); err != nil {
				t.Fatal(err)
			}
			// Start from a host that probed every layer Enforced, so any shortfall below
			// came from the child's report and not from the probe.
			r := enforce.Report{}
			for _, l := range []enforce.Layer{enforce.LayerFilesystem, enforce.LayerNetwork, enforce.LayerExec, enforce.LayerExecStrict} {
				r.Add(l, enforce.Enforced, "")
			}
			parseApplied(path).reconcile(&r, tc.blockWanted, tc.strictWanted, 125)

			for layer, want := range tc.want {
				if got := r.StateOf(layer); got != want {
					t.Errorf("%s = %v, want %v (report %q)", layer, got, want, tc.report)
				}
			}
			// The network layer is bwrap's, not the child's: nothing the child reports may
			// touch it, or a silent launcher would look like a run with no egress fence.
			if got := r.StateOf(enforce.LayerNetwork); got != enforce.Enforced {
				t.Errorf("network layer = %v; the child's report must not reach a layer it does not apply", got)
			}
		})
	}
}

// A missing report file is the same claim-nothing case as an unfinished one: the run
// happened, so this must not be an error, and it must not read as a clean report.
func TestParseAppliedMissingFileClaimsNothing(t *testing.T) {
	a := parseApplied(filepath.Join(t.TempDir(), "does-not-exist"))
	if a.complete {
		t.Fatal("an absent applied-layer report was read as complete")
	}
	if a.execFilter != "" {
		t.Errorf("execFilter = %q, want empty", a.execFilter)
	}
}

// The quoted reason is the report's only free-form field, so it is the only one a
// hostile or merely multi-line error message could use to forge records - including a
// premature completion marker, which would make the host accept a partial report as
// whole. The end-to-end test above pins the writer against this parser; this pins the
// parser against the one input it cannot get from a real host.
func TestParseAppliedQuotedReasonCannotForgeRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "applied")

	// A multi-line error is the case that could forge records: the writer quotes it, so
	// the newline must not end up starting a line of its own.
	detail := fmt.Errorf("landlock: %s", "line one\n"+launcher.AppliedMarker)
	written := launcher.AppliedExecFilter + " " + launcher.AppliedExecBasic + "\n" +
		launcher.AppliedLandlock + " " + launcher.AppliedNo + " " + fmt.Sprintf("%q", detail.Error()) + "\n" +
		launcher.AppliedMarker + "\n"
	if err := os.WriteFile(path, []byte(written), 0o600); err != nil {
		t.Fatal(err)
	}
	a := parseApplied(path)
	if !a.complete {
		t.Fatal("a quoted multi-line reason broke the completion marker")
	}
	if !strings.Contains(a.landlockErr, "line one") {
		t.Errorf("landlockErr = %q, want the quoted reason back intact", a.landlockErr)
	}
}

// The unreached-target reason is what tells an operator WHY nothing ran, and it is the
// one thing separating this from the silent-launcher case, which reports the exit code
// instead because it has nothing else. It travels the same quoted field as the Landlock
// reason and must survive the round trip.
func TestReconcileNamesWhyTheTargetWasNeverReached(t *testing.T) {
	path := filepath.Join(t.TempDir(), "applied")
	written := launcher.AppliedExecFilter + " " + launcher.AppliedExecBasic + "\n" +
		launcher.AppliedLandlock + " " + launcher.AppliedYes + "\n" + launcher.AppliedMarker + "\n" +
		launcher.AppliedTargetUnreached + " " + fmt.Sprintf("%q", "launcher: starting target: /app/run.sh: no such file") + "\n"
	if err := os.WriteFile(path, []byte(written), 0o600); err != nil {
		t.Fatal(err)
	}
	var r enforce.Report
	r.Add(enforce.LayerExec, enforce.Enforced, "")
	parseApplied(path).reconcile(&r, true, false, 125)

	if got := r.StateOf(enforce.LayerExec); got != enforce.Unavailable {
		t.Fatalf("exec layer = %v for a target that never ran, want unavailable", got)
	}
	if !strings.Contains(r.Degradations()[0].Reason, "/app/run.sh") {
		t.Errorf("reason = %q, want the cause the launcher reported", r.Degradations()[0].Reason)
	}
}

// A proxy listener that stops accepting mid-run leaves the declared egress unserved
// for the remainder, and the run must say so. The note lands after reconcile, so a
// child that installed its netns cannot overwrite it, and it replaces the network
// layer's status rather than adding a second contradictory entry.
func TestNoteDeadListenerDegradesTheNetworkLayer(t *testing.T) {
	var r enforce.Report
	r.Add(enforce.LayerNetwork, enforce.Enforced, "")
	noteDeadListener(&r, nil)
	if got := r.StateOf(enforce.LayerNetwork); got != enforce.Enforced {
		t.Fatalf("StateOf(network) = %v, want enforced when the listener ended with the run", got)
	}

	noteDeadListener(&r, errors.New("accept: bad file descriptor"))
	if got := r.StateOf(enforce.LayerNetwork); got != enforce.Degraded {
		t.Errorf("StateOf(network) = %v, want degraded after the listener died", got)
	}
	var network int
	for _, l := range r.Layers {
		if l.Layer == enforce.LayerNetwork {
			network++
		}
	}
	if network != 1 {
		t.Errorf("network layer appears %d times, want 1 (the dead listener replaces the status)", network)
	}
	if !strings.Contains(r.Degradations()[0].Reason, "bad file descriptor") {
		t.Errorf("reason = %q, want the listener's error named", r.Degradations()[0].Reason)
	}
}
