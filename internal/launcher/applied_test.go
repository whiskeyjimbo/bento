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
		{"failed", func([]string) error { return errors.New("ruleset refused") }, func() bool { return true },
			"landlock " + AppliedNo + " \"ruleset refused\""},
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
			if !tc.wantUnreached && err != nil {
				t.Fatalf("the stage failed on a target that exists: %v\n%s", err, out)
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
// what Run returned. Block is off throughout: the exec-block path replaces this process,
// and the reporting question is the same on either dispatch.
func runReportChild(mode string) {
	target := "/bin/true"
	switch mode {
	case "missing":
		target = "/nonexistent-bento-run-report-target"
	case "relative":
		target = "true"
	}
	code, err := Run(Config{AppliedFD: 3, Target: []string{target}})
	if err != nil {
		os.Stdout.WriteString("RUN_ERR " + err.Error() + "\n")
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "RUN_OK %d\n", code)
}
