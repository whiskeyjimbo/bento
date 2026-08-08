//go:build linux

package linux

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
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
		enforce.Process{Stdout: &out, Stderr: &out, Env: map[string]string{"GRANTED": filepath.Join(granted, "ok.txt"), "UNGRANTED": filepath.Join(t.TempDir(), "absent")}}, "", nil)
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
// A stand-in for the accurate explanation the probe writes, so a case can assert
// reconcile left it alone rather than replacing it with a worse one.
const probeReason = "this host cannot do it, and here is the actionable reason"

// The report exposes only StateOf; a reason assertion needs the layer itself.
func reasonOf(r enforce.Report, layer enforce.Layer) string {
	for _, l := range r.Layers {
		if l.Layer == layer {
			return l.Reason
		}
	}
	return ""
}

func TestAppliedReconcile(t *testing.T) {
	cases := []struct {
		name         string
		report       string
		blockWanted  bool
		strictWanted bool
		unconfined   bool // no mount namespace behind Landlock: the degraded tier
		want         map[enforce.Layer]enforce.State
		wantReason   map[enforce.Layer]string
	}{
		{
			// The probe, not reconcile, is what knows why: on a seccomp-less host
			// execBlockFlags returns block=false, so the launcher's honest "none" is what
			// was asked for and the probe's reason must survive intact.
			name:       "no filter asked for keeps the probe's reason for the exec layer",
			report:     launcher.AppliedExecFilter + " " + launcher.AppliedExecNone + "\n" + launcher.AppliedLandlock + " " + launcher.AppliedYes + "\n" + launcher.AppliedMarker + "\n",
			want:       map[enforce.Layer]enforce.State{enforce.LayerExec: enforce.Enforced},
			wantReason: map[enforce.Layer]string{enforce.LayerExec: probeReason},
		},
		{
			// Landlock is the only filesystem confinement on the degraded tier, so a
			// kernel without it leaves the run unconfined rather than merely unbacked.
			name:       "a kernel without Landlock leaves the degraded tier unconfined",
			report:     launcher.AppliedExecFilter + " " + launcher.AppliedExecStrict + "\n" + launcher.AppliedLandlock + " " + launcher.AppliedAbsent + "\n" + launcher.AppliedMarker + "\n",
			unconfined: true,
			want:       map[enforce.Layer]enforce.State{enforce.LayerFilesystem: enforce.Unavailable},
		},
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
				r.Add(l, enforce.Enforced, probeReason)
			}
			parseApplied(openReport(t, path)).reconcile(&r, tc.blockWanted, tc.strictWanted, !tc.unconfined, 125)

			for layer, want := range tc.want {
				if got := r.StateOf(layer); got != want {
					t.Errorf("%s = %v, want %v (report %q)", layer, got, want, tc.report)
				}
			}
			for layer, want := range tc.wantReason {
				if got := reasonOf(r, layer); got != want {
					t.Errorf("%s reason = %q, want %q", layer, got, want)
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

// A report the host cannot read back is the same claim-nothing case as an unfinished
// one: the run happened, so this must not be an error, and it must not read as a clean
// report. The handle is closed, which is the one way the read can fail now that the host
// holds the descriptor open across the run instead of re-opening a path.
func TestParseAppliedUnreadableClaimsNothing(t *testing.T) {
	f := openReport(t, filepath.Join(t.TempDir(), "applied"))
	f.Close()
	a := parseApplied(f)
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
	a := parseApplied(openReport(t, path))
	if !a.complete {
		t.Fatal("a quoted multi-line reason broke the completion marker")
	}
	if !strings.Contains(a.landlockErr, "line one") {
		t.Errorf("landlockErr = %q, want the quoted reason back intact", a.landlockErr)
	}
}

// A failed Landlock ruleset means different things on the two tiers, and the report has
// to say which. Behind bwrap the mount namespace still confines the filesystem, so the
// layer is Degraded; on the degraded tier Landlock is the whole confinement, so the same
// report means the filesystem was not confined at all. Reporting that one as Degraded
// would name a mount namespace the run never had.
func TestReconcileGradesLandlockFailureByTier(t *testing.T) {
	path := filepath.Join(t.TempDir(), "applied")
	written := launcher.AppliedExecFilter + " " + launcher.AppliedExecBasic + "\n" +
		launcher.AppliedLandlock + " " + launcher.AppliedNo + " " + fmt.Sprintf("%q", "landlock: applying ruleset: invalid argument") + "\n" +
		launcher.AppliedMarker + "\n"
	if err := os.WriteFile(path, []byte(written), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name          string
		mountConfined bool
		want          enforce.State
		unwanted      string
	}{
		{name: "behind bwrap", mountConfined: true, want: enforce.Degraded},
		{name: "degraded tier", mountConfined: false, want: enforce.Unavailable, unwanted: "mount namespace still confines"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var r enforce.Report
			r.Add(enforce.LayerFilesystem, enforce.Enforced, "")
			parseApplied(openReport(t, path)).reconcile(&r, true, false, tc.mountConfined, 125)

			if got := r.StateOf(enforce.LayerFilesystem); got != tc.want {
				t.Errorf("filesystem layer = %v, want %v", got, tc.want)
			}
			var reason string
			for _, l := range r.Layers {
				if l.Layer == enforce.LayerFilesystem {
					reason = l.Reason
				}
			}
			if !strings.Contains(reason, "invalid argument") {
				t.Errorf("reason = %q, want the child's own failure in it", reason)
			}
			if tc.unwanted != "" && strings.Contains(reason, tc.unwanted) {
				t.Errorf("reason = %q, must not claim %q on a tier with no mount namespace", reason, tc.unwanted)
			}
		})
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
	parseApplied(openReport(t, path)).reconcile(&r, true, false, true, 125)

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

// The note only ever worsens the layer. It runs after reconcile, so a network layer the
// child already reported unavailable must not be softened to degraded by the listener
// dying too - a report reading better because a second thing went wrong.
func TestNoteDeadListenerNeverUpgradesTheNetworkLayer(t *testing.T) {
	var r enforce.Report
	r.Add(enforce.LayerNetwork, enforce.Unavailable, "the child installed no netns")
	noteDeadListener(&r, errors.New("accept: bad file descriptor"))
	if got := r.StateOf(enforce.LayerNetwork); got != enforce.Unavailable {
		t.Errorf("StateOf(network) = %v, want unavailable to stand", got)
	}
	noteDeadBridge(&r, true)
	if got := r.StateOf(enforce.LayerNetwork); got != enforce.Unavailable {
		t.Errorf("StateOf(network) = %v after the bridge note, want unavailable to stand", got)
	}
}

// reconcile is the one place that decides how far the stage got, so the SetupState it
// returns must track the same three cases the layer verdicts above are drawn from: a
// stage that never reported, one that applied its layers but never reached the target,
// and one that completed. An embedder maps these onto its own exit codes, so a state
// that disagreed with the layers would be worse than no state at all.
func TestReconcileReportsSetupState(t *testing.T) {
	complete := launcher.AppliedExecFilter + " " + launcher.AppliedExecStrict + "\n" +
		launcher.AppliedLandlock + " " + launcher.AppliedYes + "\n" + launcher.AppliedMarker + "\n"
	for name, tc := range map[string]struct {
		report string
		want   enforce.SetupState
	}{
		"no report at all":             {"", enforce.SetupSilent},
		"setup died before the marker": {launcher.AppliedExecFilter + " " + launcher.AppliedExecStrict + "\n", enforce.SetupSilent},
		"target never reached": {complete + launcher.AppliedTargetUnreached + " " + `"launcher: starting target: no such file or directory"` + "\n",
			enforce.SetupTargetUnreached},
		"setup completed and the target ran": {complete, enforce.SetupAttested},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "applied")
			if err := os.WriteFile(path, []byte(tc.report), 0o600); err != nil {
				t.Fatal(err)
			}
			r := enforce.Report{}
			for _, l := range []enforce.Layer{enforce.LayerFilesystem, enforce.LayerExec, enforce.LayerExecStrict} {
				r.Add(l, enforce.Enforced, "")
			}
			if got := parseApplied(openReport(t, path)).reconcile(&r, true, true, true, 125); got != tc.want {
				t.Errorf("reconcile setup state = %v, want %v", got, tc.want)
			}
		})
	}
}

// openReport gives a test the descriptor the host would have held open across the run.
func openReport(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// The host reads the report back through the descriptor it opened before the child
// started, never by re-opening the path. Two things have to hold for that: a file
// substituted at the path after the run is not what gets parsed - the substitution is
// how a same-uid host process could otherwise have reconcile attest layers that were
// never installed - and the rewind happens, because the child inherits a dup of this
// descriptor and shares its offset, so the writes leave it at end-of-file.
func TestParseAppliedReadsTheRetainedDescriptorNotThePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "applied")
	f := openReport(t, path)

	// Write through a dup, as the child does, so the shared offset is left at EOF.
	child := os.NewFile(uintptr(mustDup(t, f)), path)
	defer child.Close()
	written := launcher.AppliedExecFilter + " " + launcher.AppliedExecBasic + "\n" +
		launcher.AppliedLandlock + " " + launcher.AppliedYes + "\n" + launcher.AppliedMarker + "\n"
	if _, err := child.Write([]byte(written)); err != nil {
		t.Fatal(err)
	}

	// Substitute a report claiming the strict layers, exactly as an attacker at the path
	// would. Unlinking first is what a re-opening host would follow.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	forged := launcher.AppliedExecFilter + " " + launcher.AppliedExecStrict + "\n" +
		launcher.AppliedLandlock + " " + launcher.AppliedYes + "\n" + launcher.AppliedMarker + "\n"
	if err := os.WriteFile(path, []byte(forged), 0o600); err != nil {
		t.Fatal(err)
	}

	a := parseApplied(f)
	if !a.complete {
		t.Fatal("the report written through the inherited descriptor did not read back; the rewind is missing")
	}
	if a.execFilter != launcher.AppliedExecBasic {
		t.Errorf("execFilter = %q, want %q - the forged file at the path was parsed instead of the retained descriptor", a.execFilter, launcher.AppliedExecBasic)
	}
}

func mustDup(t *testing.T, f *os.File) int {
	t.Helper()
	fd, err := syscall.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	return fd
}

// The strict exec filter is a VALUE of the exec-filter record, not a record of its own -
// so the tamper stance below, which discards a report holding any line the stage does not
// write, must not fire on an ordinary strict run.
func TestParseAppliedAcceptsStrictAndRejectsAnExtraLine(t *testing.T) {
	for name, tc := range map[string]struct {
		report string
		want   bool
	}{
		"a strict-filter run":          {"exec-filter strict\nlandlock yes\nAPPLIED\n", true},
		"a basic-filter run":           {"exec-filter basic\nlandlock yes\nAPPLIED\n", true},
		"a line the stage never wrote": {"exec-filter strict\nstrict yes\nlandlock yes\nAPPLIED\n", false},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "applied")
			if err := os.WriteFile(path, []byte(tc.report), 0o600); err != nil {
				t.Fatal(err)
			}
			a := parseApplied(openReport(t, path))
			if a.complete != tc.want {
				t.Errorf("complete = %v, want %v (%+v)", a.complete, tc.want, a)
			}
			if tc.want && a.execFilter == "" {
				t.Errorf("the exec-filter value must survive; got %+v", a)
			}
		})
	}
}

// The exec record is a diagnostic, and the first driver of the design that added it is
// that nothing about its presence, absence or failure may change what is enforced. The
// parser's tamper stance is what makes that hard: a line it does not recognize discards
// the WHOLE report, which reconcile then reads as three Unavailable layers. So a record
// line that will not decode has to drop that one exec and nothing else - otherwise a
// garbled diagnostic silently downgrades the attestation of a run that was fully fenced.
func TestGarbledExecRecordDoesNotTouchTheLayerVerdicts(t *testing.T) {
	clean := "exec-filter none\nlandlock yes\nAPPLIED\n"
	record := "exec-recorder yes\n" +
		`exec-ran 41 "/usr/bin/true" "/bin/true"` + "\n" +
		"exec-ran this-is-not-a-pid\n" +
		`exec-ran 42 "/usr/bin/echo" "/bin/echo\x00hi"` + "\n" +
		"EXEC-RECORD\n"

	path := filepath.Join(t.TempDir(), "applied")
	if err := os.WriteFile(path, []byte(clean+record), 0o600); err != nil {
		t.Fatal(err)
	}
	a := parseApplied(openReport(t, path))
	if !a.complete {
		t.Fatal("a garbled exec record discarded the whole report; the layers above the marker are not the record's to touch")
	}
	if a.landlock != launcher.AppliedYes || a.execFilter != launcher.AppliedExecNone {
		t.Errorf("the layer records did not survive the record section: %+v", a)
	}
	// The undecodable line is dropped, and the section is reported as untrustworthy
	// rather than as a run that simply exec'd twice.
	if len(a.execRuns) != 2 {
		t.Errorf("execRuns = %+v, want the two decodable records", a.execRuns)
	}
	if a.execRecordComplete {
		t.Error("a record that lost a line was reported as whole")
	}

	var r enforce.Report
	r.Set(enforce.LayerExec, enforce.Enforced, "")
	r.Set(enforce.LayerFilesystem, enforce.Enforced, "")
	if got := a.reconcile(&r, false, false, true, 0); got != enforce.SetupAttested {
		t.Errorf("setup state = %v, want SetupAttested; the record decided the run", got)
	}
	if st := r.StateOf(enforce.LayerFilesystem); st != enforce.Enforced {
		t.Errorf("filesystem layer = %v; a garbled diagnostic downgraded an enforced layer", st)
	}
}

// The record round-trips what the stage wrote, including the two shapes a naive split
// would break: an argument holding a space, and the NUL-joined argv itself. A run that
// asked for no record writes no section at all, which is distinct from a section saying
// nothing was watching.
func TestParseExecRecordRoundTrip(t *testing.T) {
	for name, tc := range map[string]struct {
		section  string
		recorder string
		runs     []execRun
		complete bool
	}{
		"no section at all": {"", "", nil, false},
		"nothing was watching": {
			"exec-recorder absent \"the exec block replaces the launcher with the target\"\nEXEC-RECORD\n",
			launcher.AppliedAbsent, nil, true,
		},
		"an argument holding a space": {
			"exec-recorder yes\n" + `exec-ran 7 "/usr/bin/cc" "cc\x00-DMSG=hello there\x00a.c"` + "\nEXEC-RECORD\n",
			launcher.AppliedYes,
			[]execRun{{Pid: 7, Exe: "/usr/bin/cc", Argv: []string{"cc", "-DMSG=hello there", "a.c"}}},
			true,
		},
		"the seeded target, which no stop reported": {
			"exec-recorder yes\n" + `exec-ran 0 "/bin/sh" "/bin/sh\x00-c\x00true"` + "\nEXEC-RECORD\n",
			launcher.AppliedYes,
			[]execRun{{Pid: 0, Exe: "/bin/sh", Argv: []string{"/bin/sh", "-c", "true"}}},
			true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "applied")
			if err := os.WriteFile(path, []byte("exec-filter none\nlandlock yes\nAPPLIED\n"+tc.section), 0o600); err != nil {
				t.Fatal(err)
			}
			a := parseApplied(openReport(t, path))
			if !a.complete {
				t.Fatal("the layer report did not survive its own record section")
			}
			if a.execRecorder != tc.recorder {
				t.Errorf("execRecorder = %q, want %q", a.execRecorder, tc.recorder)
			}
			if a.execRecordComplete != tc.complete {
				t.Errorf("execRecordComplete = %v, want %v", a.execRecordComplete, tc.complete)
			}
			if !reflect.DeepEqual(a.execRuns, tc.runs) {
				t.Errorf("execRuns = %+v, want %+v", a.execRuns, tc.runs)
			}
		})
	}
}

// The exec-record marker ENDS the section, and everything past it but a target-unreached
// line is content the stage did not write. An appended exec-ran used to be decoded,
// appended to the record, and reported inside a COMPLETE one - an exec nobody observed,
// carried by an attestation that says it was watched. A second marker used to re-set
// completeness, and junk used to set a garbled flag the first marker had already read.
func TestParseAppliedClosesTheExecRecordAtItsMarker(t *testing.T) {
	const head = "exec-filter none\nlandlock yes\nAPPLIED\nexec-recorder yes\n" +
		`exec-ran 7 "/usr/bin/cc" "cc\x00a.c"` + "\nEXEC-RECORD\n"

	for name, tail := range map[string]string{
		"an exec appended after the marker": `exec-ran 9 "/bin/true" "true"` + "\n",
		"a second marker":                   "EXEC-RECORD\n",
		"junk":                              "exec-ra\n",
		"a recorder line reopening it":      "exec-recorder no \"tampered\"\n",
		// The in-section stance tolerates a short write ("exec-ra" is garbled, not
		// tampering) because the stage writes the section in one call. Past the marker the
		// same accident reads as tampering, which is the fail-closed direction and costs
		// nothing: the target it would have described never ran.
		"a short-written unreached line": "target-unre\n",
		// The stage writes target-unreached at most once, and reconcile prints its detail,
		// so a second one is the report being edited rather than worsened.
		"a second unreached line": `target-unreached "real"` + "\n" + `target-unreached "forged"` + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "applied")
			if err := os.WriteFile(path, []byte(head+tail), 0o600); err != nil {
				t.Fatal(err)
			}
			if a := parseApplied(openReport(t, path)); a.complete {
				t.Errorf("content past the record marker must void the report; got %+v", a)
			}
		})
	}

	// The one thing that legitimately follows: the exec-block path writes the record
	// before execveat, so a failed transition appends the unreached line behind a closed
	// section. It must still be read, and the record it follows still stands.
	path := filepath.Join(t.TempDir(), "applied")
	if err := os.WriteFile(path, []byte(head+`target-unreached "no such file"`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := parseApplied(openReport(t, path))
	if !a.complete || !a.targetUnreached || a.targetErr != "no such file" {
		t.Errorf("a target-unreached line past the record marker must be read; got %+v", a)
	}
	if !a.execRecordComplete || len(a.execRuns) != 1 {
		t.Errorf("the record it follows must stand; got complete=%v runs=%+v", a.execRecordComplete, a.execRuns)
	}
}

// A record that never reached its marker is what a tracer dying mid-run leaves: the
// recorder deliberately runs without PTRACE_O_EXITKILL, so the record ends where it
// ended. It must read as truncated rather than as a run that stopped exec'ing.
func TestUnmarkedExecRecordReadsAsTruncated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "applied")
	written := "exec-filter none\nlandlock yes\nAPPLIED\nexec-recorder yes\n" +
		`exec-ran 9 "/usr/bin/true" "/bin/true"` + "\n"
	if err := os.WriteFile(path, []byte(written), 0o600); err != nil {
		t.Fatal(err)
	}
	a := parseApplied(openReport(t, path))
	if !a.complete {
		t.Fatal("a truncated record section discarded the layer report")
	}
	if a.execRecordComplete {
		t.Error("a record with no marker of its own was read as whole")
	}
	if len(a.execRuns) != 1 {
		t.Errorf("the records written before the truncation were lost: %+v", a.execRuns)
	}
}

// The end-to-end pin for the exec record: a real confined run under exec: all, with the
// launcher writing the section and this host parsing it back. It is what keeps the
// writer and the parser from drifting - every other test here hands the parser bytes it
// wrote itself.
func TestExecRecordOfARealRun(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	script := filepath.Join(dir, "tree.sh")
	if err := os.WriteFile(script, []byte("/bin/true\n/bin/echo recorded\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir}, Exec: policy.ExecAll}

	var out bytes.Buffer
	res, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out},
		enforce.RunOptions{RecordExec: true})
	if err != nil {
		t.Fatalf("Run: %v (output: %s)", err, out.String())
	}
	if res.ExecRecord == nil {
		t.Fatal("a run that asked for an exec record got none")
	}
	if !res.ExecRecord.Watched {
		t.Skipf("this host refused the attach (%s); yama ptrace_scope 2 and 3 both do", res.ExecRecord.Reason)
	}
	if !res.ExecRecord.Complete {
		t.Error("the record did not reach its own marker, so it reads as truncated")
	}
	// The record's claim is that the target cannot hide an exec: the script's two
	// commands are grandchildren of the launcher and are recorded like anything else.
	var images []string
	for _, r := range res.ExecRecord.Runs {
		images = append(images, r.Exe)
	}
	for _, want := range []string{"true", "echo"} {
		if !containsSuffix(images, want) {
			t.Errorf("the record is missing the %s exec: %q", want, images)
		}
	}
	// The diagnostic may not touch the attestation.
	if res.Setup != enforce.SetupAttested {
		t.Errorf("setup state = %v on a recorded run; the record changed what was attested", res.Setup)
	}
	if st := res.Report.StateOf(enforce.LayerFilesystem); st != enforce.Enforced {
		t.Errorf("filesystem layer = %v on a recorded run: %v", st, res.Report.Degradations())
	}
}

// A run that did not ask gets no record at all, and must be the run it would otherwise
// have been - the recorder is what takes ptrace away from everything in the sandbox, so
// "off means off" is the property that keeps it from changing unrelated runs.
func TestUnaskedRunHasNoExecRecord(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	script := filepath.Join(dir, "quiet.sh")
	if err := os.WriteFile(script, []byte("exit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir}, Exec: policy.ExecAll}

	var out bytes.Buffer
	res, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out}, enforce.RunOptions{})
	if err != nil {
		t.Fatalf("Run: %v (output: %s)", err, out.String())
	}
	if res.ExecRecord != nil {
		t.Errorf("a run that asked for no record got one: %+v", res.ExecRecord)
	}
}

// exec: none replaces the launcher with the target, so there is no supervisor left to
// trace. Asking there is not an error and does not produce an empty record - it comes
// back saying nothing was watching, which is the distinction the section exists to make.
func TestExecNoneReportsTheRecorderAbsent(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	script := filepath.Join(dir, "blocked.sh")
	if err := os.WriteFile(script, []byte("exit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir}, Exec: policy.ExecNone}

	var out bytes.Buffer
	res, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out},
		enforce.RunOptions{RecordExec: true})
	if err != nil {
		t.Fatalf("Run: %v (output: %s)", err, out.String())
	}
	if res.ExecRecord == nil {
		t.Fatal("a run that asked for an exec record got none at all")
	}
	if res.ExecRecord.Watched {
		t.Error("exec: none reported a recorder, but the block leaves no supervisor to be one")
	}
	if res.ExecRecord.Reason == "" {
		t.Error("nothing was watching and the report did not say why")
	}
	if res.Setup != enforce.SetupAttested {
		t.Errorf("setup state = %v; asking for an unavailable record changed what was attested", res.Setup)
	}
}

func containsSuffix(paths []string, suffix string) bool {
	for _, p := range paths {
		if strings.HasSuffix(p, "/"+suffix) {
			return true
		}
	}
	return false
}

// The failure mode the cap and the post-marker scan tolerance exist for. bufio.Scanner
// refuses a line it cannot buffer, and turning that into an absent report would set every
// layer Unavailable and refuse a fully fenced run - the exec record deciding what is
// enforced, on exactly the long-command-line workload the record is for. Once the marker
// is in hand the proof is in hand, and only the diagnostic can still be lost.
func TestAnUnreadableExecRecordLineKeepsTheAttestation(t *testing.T) {
	huge := strings.Repeat("a", 100_000)
	path := filepath.Join(t.TempDir(), "applied")
	written := "exec-filter none\nlandlock yes\nAPPLIED\nexec-recorder yes\n" +
		`exec-ran 7 "/usr/bin/cc" "` + huge + `"` + "\nEXEC-RECORD\n"
	if err := os.WriteFile(path, []byte(written), 0o600); err != nil {
		t.Fatal(err)
	}
	a := parseApplied(openReport(t, path))
	if !a.complete {
		t.Fatal("one unreadable record line discarded the whole report")
	}
	if a.landlock != launcher.AppliedYes {
		t.Errorf("the layer records did not survive: %+v", a)
	}
	if a.execRecordComplete {
		t.Error("a record whose scan died was reported as whole")
	}

	var r enforce.Report
	r.Set(enforce.LayerFilesystem, enforce.Enforced, "")
	if got := a.reconcile(&r, false, false, true, 0); got != enforce.SetupAttested {
		t.Errorf("setup state = %v, want SetupAttested; an unreadable diagnostic refused the run", got)
	}
	if st := r.StateOf(enforce.LayerFilesystem); st != enforce.Enforced {
		t.Errorf("filesystem layer = %v; an unreadable diagnostic downgraded an enforced layer", st)
	}
}

// A report whose scan fails BEFORE the marker read nothing that can be relied on, so it
// must still claim nothing - the tolerance above is scoped to the diagnostic, not
// extended to the layer facts.
func TestAnUnreadableLineBeforeTheMarkerStillClaimsNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "applied")
	written := "exec-filter none\nlandlock " + strings.Repeat("y", 100_000) + "\nAPPLIED\n"
	if err := os.WriteFile(path, []byte(written), 0o600); err != nil {
		t.Fatal(err)
	}
	if a := parseApplied(openReport(t, path)); a.complete || a.execFilter != "" {
		t.Errorf("a report the host could not scan was read as claiming something: %+v", a)
	}
}

// A capped argv says so, and the flag reaches the caller: an argv missing its tail that
// did not report the cut would be a record that lies about what ran.
func TestTruncatedArgvIsReportedAsTruncated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "applied")
	written := "exec-filter none\nlandlock yes\nAPPLIED\nexec-recorder yes\n" +
		`exec-ran 7 "/usr/bin/cc" "cc\x00-c" ` + launcher.AppliedExecArgvTruncated + "\n" +
		`exec-ran 8 "/bin/true" "true"` + "\nEXEC-RECORD\n"
	if err := os.WriteFile(path, []byte(written), 0o600); err != nil {
		t.Fatal(err)
	}
	a := parseApplied(openReport(t, path))
	if !a.execRecordComplete {
		t.Fatal("a record carrying a marked truncation was read as broken")
	}
	rec := a.execRecord(true)
	if len(rec.Runs) != 2 {
		t.Fatalf("runs = %+v, want both records", rec.Runs)
	}
	if !rec.Runs[0].ArgvTruncated {
		t.Error("a cut argv reached the caller claiming to be whole")
	}
	if rec.Runs[1].ArgvTruncated {
		t.Error("an untouched argv was reported as cut")
	}
	// The trailer is a fixed word, not free text: anything else is a line the stage did
	// not write, and the record is the one section that reads variable-length input.
	if _, ok := parseExecRun(`9 "/bin/true" "true" something-else`); ok {
		t.Error("an unrecognized trailer was accepted on an exec-ran record")
	}
}

// The stage writes the record section in one call after the run, so a short write - a
// full run directory, the launcher killed mid-write - can end a line inside its own key.
// "exec-ra" is not a record the stage writes, but treating it as tampering would void an
// attestation the first marker already made, which is the diagnostic deciding what is
// enforced.
func TestATornRecordLineDoesNotVoidTheAttestation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "applied")
	written := "exec-filter none\nlandlock yes\nAPPLIED\nexec-recorder yes\n" +
		`exec-ran 7 "/usr/bin/cc" "cc"` + "\nexec-ra"
	if err := os.WriteFile(path, []byte(written), 0o600); err != nil {
		t.Fatal(err)
	}
	a := parseApplied(openReport(t, path))
	if !a.complete {
		t.Fatal("a record line torn inside its key discarded the whole report")
	}
	if a.execRecordComplete {
		t.Error("a torn record section was reported as whole")
	}
	var r enforce.Report
	r.Set(enforce.LayerFilesystem, enforce.Enforced, "")
	if got := a.reconcile(&r, false, false, true, 0); got != enforce.SetupAttested {
		t.Errorf("setup state = %v, want SetupAttested", got)
	}

	// The tolerance is scoped to the record section: an unknown line after the marker but
	// BEFORE any exec-recorder line is still the tampering it always was.
	other := filepath.Join(t.TempDir(), "applied")
	if err := os.WriteFile(other, []byte("exec-filter none\nlandlock yes\nAPPLIED\nnot-a-record yes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b := parseApplied(openReport(t, other)); b.complete {
		t.Error("a line the stage never writes was accepted after the marker")
	}
}
