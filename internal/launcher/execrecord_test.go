//go:build linux

package launcher

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
)

// The record's whole claim is that the target cannot hide an exec from it: the
// clone/fork options attach a descendant before it runs an instruction, so a grandchild
// is recorded exactly like a child. A shell running two commands is the smallest shape
// that exercises both - the shell forks, and each command execs in its own process.
func TestRecorderSeesTheWholeExecTree(t *testing.T) {
	rec := &execRecorder{runs: []execRun{{exe: "/bin/sh", argv: []string{"/bin/sh", "-c", "..."}}}}
	code, err := superviseTraced([]string{"/bin/sh", "-c", "/bin/true; /bin/echo recorded >/dev/null"}, os.Environ(), rec)
	if err != nil {
		t.Fatalf("traced supervision failed: %v", err)
	}
	if rec.failed != nil {
		t.Skipf("this host refuses the attach (%v); yama ptrace_scope 2 and 3 both do", rec.failed)
	}
	if code != 0 {
		t.Errorf("exit code %d, want 0", code)
	}
	var images []string
	for _, r := range rec.runs {
		images = append(images, r.exe)
	}
	// The seed is the target itself, which no stop reports - its exec retires before the
	// options are set.
	if len(images) == 0 || images[0] != "/bin/sh" {
		t.Fatalf("the record was not seeded with the target: %q", images)
	}
	for _, want := range []string{"true", "echo"} {
		if !containsSuffix(images, want) {
			t.Errorf("the record is missing the %s exec: %q", want, images)
		}
	}
}

// /proc/<pid>/exe is the kernel's own answer, so a PATH search cannot be misattributed
// and a symlinked interpreter reads back as the file that actually ran.
func TestRecorderRecordsTheResolvedImageAndArgv(t *testing.T) {
	rec := &execRecorder{}
	if _, err := superviseTraced([]string{"/bin/sh", "-c", "/bin/echo one two >/dev/null"}, os.Environ(), rec); err != nil {
		t.Fatalf("traced supervision failed: %v", err)
	}
	if rec.failed != nil {
		t.Skipf("this host refuses the attach: %v", rec.failed)
	}
	for _, r := range rec.runs {
		if strings.HasSuffix(r.exe, "/echo") {
			if strings.Join(r.argv, " ") != "/bin/echo one two" {
				t.Errorf("argv %q lost its arguments", r.argv)
			}
			if !strings.HasPrefix(r.exe, "/") {
				t.Errorf("image %q is not an absolute resolved path", r.exe)
			}
			return
		}
	}
	t.Errorf("no echo exec was recorded: %+v", rec.runs)
}

// The recorder may not change what the run reports. superviseTarget renders a signalled
// target as 128+signal, and the traced path has its own wait loop that must render it
// identically - a diagnostic that shifted the exit code would be changing the answer.
func TestRecorderPreservesTheSignalledExitCode(t *testing.T) {
	rec := &execRecorder{}
	code, err := superviseTraced([]string{"/bin/sh", "-c", "kill -TERM $$"}, os.Environ(), rec)
	if err != nil {
		t.Fatalf("traced supervision failed: %v", err)
	}
	if rec.failed != nil {
		t.Skipf("this host refuses the attach: %v", rec.failed)
	}
	if code != 143 {
		t.Errorf("exit code %d, want 143 (128+SIGTERM), the code superviseTarget reports", code)
	}
}

// An attach the host refuses is reported, not fatal: the record is a diagnostic and a
// host that will not permit it still gets its run. The child calls PTRACE_TRACEME before
// its exec, so the refusal surfaces at Start and the retry below is what degrades.
func TestRefusedAttachStillRunsTheTarget(t *testing.T) {
	rec := &execRecorder{}
	code, err := superviseTraced([]string{"/bin/true"}, os.Environ(), rec)
	if err != nil {
		t.Fatalf("a run whose recorder could not attach was failed outright: %v", err)
	}
	if code != 0 {
		t.Errorf("exit code %d, want 0", code)
	}
	if rec.failed != nil && len(rec.runs) != 0 {
		t.Errorf("a recorder that never attached reported %d execs", len(rec.runs))
	}
}

// A target that does not exist is a target that was never reached, and it must stay one
// with the recorder on: runTarget writes the unreached record from this error, and the
// recorder's own retry must not turn it into something else.
func TestRecorderKeepsAMissingTargetUnreached(t *testing.T) {
	rec := &execRecorder{}
	_, err := superviseTraced([]string{"/nonexistent/bento-test-target"}, os.Environ(), rec)
	if err == nil {
		t.Fatal("a nonexistent target was reported as run")
	}
	var ran errTargetRan
	if errors.As(err, &ran) {
		t.Errorf("a target that never started was reported as one that ran: %v", err)
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

// The cap exists because the host reads the report a line at a time and refuses one it
// cannot buffer: an uncapped argv does not make a long line, it costs the rest of the
// section. It cuts on an argument boundary so no entry reports half a path as a whole
// one, and it marks the cut so the entry cannot read as faithful.
func TestCappedArgv(t *testing.T) {
	long := strings.Repeat("x", 3000)

	if got, truncated := cappedArgv([]string{"cc", "-c", "a.c"}); truncated || got != "cc\x00-c\x00a.c" {
		t.Errorf("an ordinary argv was altered: %q truncated=%v", got, truncated)
	}

	got, truncated := cappedArgv([]string{"cc", long, long, "late.c"})
	if !truncated {
		t.Fatal("an argv past the cap was reported as whole")
	}
	if got != "cc\x00"+long {
		t.Errorf("the cut did not land on an argument boundary: %q", got)
	}
	if len(got) > maxRecordedArgv {
		t.Errorf("the cut argv is %d bytes, over the %d cap", len(got), maxRecordedArgv)
	}

	// One argument over the cap has no boundary to cut on, so the entry keeps its image
	// and reports no argv rather than a prefix of a single argument.
	if got, truncated := cappedArgv([]string{strings.Repeat("y", maxRecordedArgv+1)}); got != "" || !truncated {
		t.Errorf("a single oversized argument: got %q truncated=%v, want an empty marked argv", got, truncated)
	}
}

// A target killed between the fork and its own exec never reaches the tracer's stop. The
// wait consumes its death instead, and that status is the run's outcome: superviseTarget
// reports 128+signal for it, and the recorder may not turn the same run into a failure.
func TestATargetThatDiesBeforeAttachKeepsItsExitCode(t *testing.T) {
	// The child is stopped at its initial exec and killed from outside, which is the shape
	// an OOM kill or an external SIGKILL takes.
	cmd, err := startTarget([]string{"/bin/true"}, os.Environ(), true)
	if err != nil {
		t.Skipf("this host refuses the attach: %v", err)
	}
	root := cmd.Process.Pid
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(root, &ws, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := syscall.PtraceDetach(root); err != nil {
		t.Skipf("could not stage the race: %v", err)
	}
	_ = cmd.Process.Kill()

	code, done, err := attachRecorder(root)
	if !done {
		t.Skipf("the target reached its stop after all (code %d, err %v)", code, err)
	}
	if code != 128+int(syscall.SIGKILL) {
		t.Errorf("exit code %d, want %d (128+SIGKILL), the code superviseTarget reports", code, 128+int(syscall.SIGKILL))
	}
	if err == nil {
		t.Error("a recorder that never attached did not say so")
	}
	_ = cmd.Wait()
}
