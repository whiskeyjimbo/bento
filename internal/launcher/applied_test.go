//go:build linux

package launcher

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// reportOf runs fn against a report written to a fresh file and returns its bytes
// alongside whatever fn returned. The descriptor is a dup so the report owns it: two
// *os.File wrappers on one descriptor would each close it at finalization.
func reportOf(t *testing.T, fn func(*appliedReport) error) (string, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "applied")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	a, err := newAppliedReport(fd)
	if err != nil {
		t.Fatal(err)
	}
	fnErr := fn(a)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b), fnErr
}

// The Landlock branch is the only fail-open decision in the launcher, and on a kernel
// that has Landlock none of its three outcomes but "yes" can happen. What the host does
// with the run rests entirely on which one is recorded - a backstop that failed and one
// that was never there are different facts, and both differ from one that landed - so
// each is driven through the seams here.
func TestApplyLayersRecordsTheLandlockOutcome(t *testing.T) {
	restrict, available := landlockRestrict, landlockAvailable
	t.Cleanup(func() { landlockRestrict, landlockAvailable = restrict, available })

	cases := []struct {
		name      string
		restrict  func([]string) error
		available func() bool
		want      string
	}{
		{"applied", func([]string) error { return nil }, func() bool { return true }, "landlock " + AppliedYes},
		{
			"failed", func([]string) error { return errors.New("ruleset refused") }, func() bool { return true },
			"landlock " + AppliedNo + " \"ruleset refused\"",
		},
		// Restrict is best-effort: below the usable ABI it installs nothing and still
		// returns nil, so a report keyed on the error alone would claim a backstop that
		// does not exist.
		{"no usable ABI", func([]string) error { return nil }, func() bool { return false }, "landlock " + AppliedAbsent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			landlockRestrict, landlockAvailable = tc.restrict, tc.available
			got, err := reportOf(t, func(a *appliedReport) error {
				if err := applyLayers(Config{}, a); err != nil {
					return err
				}
				return a.write()
			})
			if err != nil {
				t.Fatalf("applyLayers refused a best-effort Landlock outcome: %v", err)
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("report %q does not record %q", got, tc.want)
			}
			if !strings.Contains(got, AppliedMarker) {
				t.Errorf("report %q has no completion marker; the host will read the run as never having reported", got)
			}
		})
	}
}

// A filter that will not install must abort before anything is recorded: the report is
// what the host trusts over its own probe, so a stage that got no filter must leave it
// without a marker rather than describe the layers it never reached.
func TestApplyLayersRefusesWhenTheFilterWillNotInstall(t *testing.T) {
	install := installExecBlock
	t.Cleanup(func() { installExecBlock = install })
	installExecBlock = func() error { return errors.New("this kernel refuses the filter") }

	got, err := reportOf(t, func(a *appliedReport) error { return applyLayers(Config{Block: true}, a) })
	if err == nil {
		t.Fatal("applyLayers proceeded with no exec filter installed")
	}
	if got != "" {
		t.Errorf("a refused run still wrote to the report: %q", got)
	}
}

// The report descriptor is named on the launch invocation, so a wrong one is reachable
// from argv. By the time the report is written the filter is installed and the target is
// a syscall away, and fd 1 is the target's own stdout - which the report would be written
// into and then closed out from under.
func TestNewAppliedReportValidatesTheDescriptor(t *testing.T) {
	if _, err := newAppliedReport(1); err == nil {
		t.Error("accepted the target's stdout as the applied-report descriptor")
	}
	closed, err := unix.Dup(0)
	if err != nil {
		t.Fatal(err)
	}
	unix.Close(closed)
	if _, err := newAppliedReport(closed); err == nil {
		t.Error("accepted a descriptor naming nothing as the applied-report descriptor")
	}
	// Zero is how a caller says it wants no report at all, and stays a no-op.
	a, err := newAppliedReport(0)
	if err != nil {
		t.Fatalf("refused the no-report descriptor: %v", err)
	}
	a.record(AppliedLandlock, AppliedYes, nil)
	if err := a.write(); err != nil {
		t.Errorf("writing a no-report report: %v", err)
	}
}

// The record must not fire the other way either. reapUntil runs with the target already
// executing, so a wait that fails there - ECHILD, where an inherited SIGCHLD=SIG_IGN has
// the kernel auto-reaping - is not a target that was never reached, and reporting one
// would be the same untruth this channel exists to stop, pointing the other way.
func TestRunTargetKeepsTheRecordOffARunThatHappened(t *testing.T) {
	reap := reapChildren
	t.Cleanup(func() { reapChildren = reap })
	waitFailed := errors.New("launcher: reaping children: no child processes")
	reapChildren = func(int) (int, error) { return 0, waitFailed }

	got, err := reportOf(t, func(a *appliedReport) error {
		if err := a.write(); err != nil {
			return err
		}
		_, runErr := runTarget(false, []string{"/bin/true"}, nil, a, nil)
		return runErr
	})
	if err == nil {
		t.Fatal("runTarget swallowed a failed wait instead of returning it")
	}
	if strings.Contains(got, AppliedTargetUnreached) {
		t.Errorf("a wait that failed with the target already running was reported as a target that never ran: %q", got)
	}
	if !strings.Contains(got, AppliedMarker) {
		t.Errorf("report %q lost its completion marker", got)
	}
	// errTargetRan is a marker wrapper, not a replacement: the cause must stay
	// inspectable through it, or the caller that decides what to tell the user about a
	// failed wait sees only the marker type.
	if !errors.Is(err, waitFailed) {
		t.Errorf("the cause did not survive the errTargetRan wrapper: %v", err)
	}
}

// The cause of a failed run is an arbitrary error string, and it is appended to a
// line-oriented report the host parses. Quoting is what stops a newline in it from
// forging a record the stage never wrote - "landlock yes" being the one that matters,
// since it would claim a backstop on a run where none was applied.
func TestTargetUnreachedQuotesTheCause(t *testing.T) {
	got, err := reportOf(t, func(a *appliedReport) error {
		return a.targetUnreached(errors.New("no such file\n" + AppliedLandlock + " " + AppliedYes))
	})
	if err != nil {
		t.Fatalf("targetUnreached: %v", err)
	}
	if strings.Contains(got, "\n"+AppliedLandlock+" ") {
		t.Errorf("a newline in the cause forged a layer record: %q", got)
	}
	if !strings.Contains(got, AppliedTargetUnreached+` "no such file\n`) {
		t.Errorf("report %q does not carry the quoted cause", got)
	}
}

// This append is all that stands between the host and a complete report for a run that
// never happened, so a write that fails must not leave the marker readable as a clean
// run. The report is discarded instead - and when the discard fails too, both failures
// have to surface, since the caller is the only thing left that can tell the operator
// the report cannot be trusted.
//
// A read-only descriptor fails both operations, which is the reachable half. The other
// - a write that fails where a shrinking ftruncate still succeeds - is the full
// filesystem the code was written for, and nothing in a test can provoke it without a
// seam in the report itself.
func TestTargetUnreachedSurfacesADiscardThatAlsoFailed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "applied")
	if err := os.WriteFile(path, []byte(AppliedMarker+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fd, err := unix.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	a, err := newAppliedReport(fd)
	if err != nil {
		t.Fatal(err)
	}

	err = a.targetUnreached(errors.New("no such file"))
	if err == nil {
		t.Fatal("targetUnreached reported success on a descriptor it could not write")
	}
	for _, want := range []string{"writing the unreached-target record", "discarding the applied-layer report"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %v does not name %q", err, want)
		}
	}
}

// sentinelRunReport makes the test binary re-exec itself as the sacrificial child that
// runs a whole launcher stage.
const sentinelRunReport = "BENTO_TEST_RUN_REPORT"

// Run's tail - the report write and the terminal dispatch - runs in no test but this
// one, and it is where the report stops describing the run: the marker is written before
// the target is reached, because on the exec-block path this process is replaced by the
// target and there is no later moment to write from. So a target that cannot be reached
// at all leaves a COMPLETE report behind, and the host's missing-marker branch - written
// for exactly "a stage that died before setup finished" - never fires. An entrypoint that
// does not exist inside the sandbox is the most common setup failure there is.
//
// It runs in a child process: Run makes the process permanently non-dumpable and applies
// Landlock to it, both of which would leak into every other test in the package.
func TestRunReportsWhetherTheTargetWasReached(t *testing.T) {
	if mode := os.Getenv(sentinelRunReport); mode != "" {
		runReportChild(mode)
		return
	}

	cases := []struct {
		name string
		mode string
		// wantUnreached is whether the report must carry the record saying the layers were
		// applied to a run that never happened.
		wantUnreached bool
	}{
		{"the target ran", "reached", false},
		{"the entrypoint does not exist", "missing", true},
		{"the target is not an absolute path", "relative", true},
		// The exec-block path is the one the design rests on, and its failure semantics are
		// seccomp.Exec's rather than os/exec's: a reached target replaces this process, so
		// nothing must have appended to the report by the time the host reads it.
		{"the target ran under the exec block", "block-reached", false},
		{"the entrypoint does not exist under the exec block", "block-missing", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "applied")
			f, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			cmd := exec.Command(os.Args[0], "-test.run", "^"+t.Name()[:strings.Index(t.Name(), "/")]+"$")
			cmd.Env = append(os.Environ(), sentinelRunReport+"="+tc.mode)
			cmd.ExtraFiles = []*os.File{f}
			out, err := cmd.CombinedOutput()
			if (err != nil) != tc.wantUnreached {
				t.Fatalf("the stage exited with %v on a target it should%s have reached\n%s",
					err, map[bool]string{true: " not", false: ""}[tc.wantUnreached], out)
			}
			report, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			// The marker must land either way: the layers really were applied, and this is
			// what separates that from a stage that died before applying them.
			if !strings.Contains(string(report), AppliedMarker) {
				t.Fatalf("the stage wrote no completion marker: %q (child said %q)", report, out)
			}
			if got := strings.Contains(string(report), AppliedTargetUnreached); got != tc.wantUnreached {
				t.Errorf("unreached-target record present = %v, want %v; report %q (child said %q)",
					got, tc.wantUnreached, report, out)
			}
		})
	}
}

// runReportChild runs one whole launcher stage against the report on fd 3 and reports
// what Run returned. Under the exec block a reached target replaces this process, so the
// child says nothing at all - which is itself the thing being checked, since the report
// must have ended at the marker when the descriptor closed at the exec.
func runReportChild(mode string) {
	target := "/bin/true"
	switch mode {
	case "missing", "block-missing":
		target = "/nonexistent-bento-run-report-target"
	case "relative":
		target = "true"
	}
	code, err := Run(Config{Block: strings.HasPrefix(mode, "block-"), AppliedFD: 3, Target: []string{target}})
	if err != nil {
		os.Stdout.WriteString("RUN_ERR " + err.Error() + "\n")
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "RUN_OK %d\n", code)
	// Exit before testing's teardown: the layers Run applied are still in force, so a
	// -cover build's data emit fails on the temp dir and turns a clean stage into a
	// nonzero exit. The child's own counters are unrecoverable either way - Landlock is
	// the blocker, and the only way past it would be to widen the grant under test.
	os.Exit(0)
}
