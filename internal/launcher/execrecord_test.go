//go:build linux

package launcher

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
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

// A trace that dies mid-run is the case the section's marker exists for, and the marker
// alone cannot carry it: a truncated record ends with a marker exactly like a complete
// one, because the launcher writes the section after the target finishes either way. Only
// the recorder's own failure marker separates them, so a loop that returns an error
// without setting it produces a record the host reads as watched and complete when the
// tracer saw nothing at all.
//
// The first resume answering ESRCH is the cheapest shape and a real one - a root SIGKILLed
// between the attach and the resume, which is what an OOM kill looks like from here. A
// reaped pid stands in for it.
func TestALostTraceMarksTheRecordFailed(t *testing.T) {
	cmd, err := startTarget([]string{"/bin/true"}, os.Environ(), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cmd.Process.Wait(); err != nil {
		t.Fatal(err)
	}
	dead := cmd.Process.Pid

	rec := &execRecorder{runs: []execRun{{exe: "/bin/true", argv: []string{"/bin/true"}}}}
	if _, err := traceExecs(dead, rec); !errors.Is(err, syscall.ESRCH) {
		t.Skipf("pid %d does not answer ESRCH (%v), so it cannot stand in for a dead root", dead, err)
	}
	if rec.failed == nil {
		t.Fatal("a trace that lost its target left the record claiming it was watching")
	}

	// The record still gets written - the target ran - so what the host sees is asserted
	// rather than only the field.
	f, err := os.CreateTemp(t.TempDir(), "applied")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	applied := &appliedReport{f: f}
	if err := applied.writeExecRecord(rec); err != nil {
		t.Fatal(err)
	}
	report, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	want := AppliedExecRecorder + " " + AppliedNo
	if !strings.Contains(string(report), want) {
		t.Errorf("exec record = %q, want a %q line; %q is the record that reads as complete when it is not", report, want, AppliedExecRecorder+" "+AppliedYes)
	}
}

// The record's claim that the target cannot hide an exec from it covers the entry's CONTENT
// as well as the event, and that half rests on a kernel detail worth pinning: execve resets
// the dumpable flag. prctl(PR_SET_DUMPABLE, 0) needs no privilege, refuses a same-uid reader
// of /proc/<pid>/exe with EPERM, and exempts no tracer - so a target that sets it once
// before forking its build would blank the image of every exec in the tree, while the
// section's marker went on attesting the record was whole. What stops it is that the read
// happens at the exec event, after the reset the exec itself performs.
//
// So the assertion is on a non-empty image, which fails both if the kernel stops resetting
// the flag and if the read is moved anywhere BEFORE the exec, which is the direction that
// matters: a read at the entry stop sees the flag the target set, and one at a later stop sees
// the reset like this one does.
func TestANonDumpableTargetStillRecordsItsImage(t *testing.T) {
	rec := &execRecorder{}
	if _, err := superviseTraced([]string{"/bin/sh", "-c", "exec /bin/true"}, os.Environ(), rec); err != nil {
		t.Fatal(err)
	}
	// The control: the same shape without the prctl has to record an image, or a blank one
	// below would prove nothing about dumpable.
	if len(rec.runs) == 0 || rec.runs[len(rec.runs)-1].exe == "" {
		t.Fatalf("a plain exec recorded no image, so this host cannot stand up the comparison: %+v", rec.runs)
	}

	// A process of its own, because prctl is per-process and the test binary itself has to
	// stay readable: the helper sets the flag and then execs, so it is live going into the
	// exec whose event the recorder reads.
	rec = &execRecorder{}
	code, err := superviseTraced([]string{"/proc/self/exe", "-test.run", "TestNonDumpableExecHelper"},
		append(os.Environ(), "BENTO_LAUNCHER_NONDUMPABLE=1"), rec)
	if err != nil {
		t.Fatalf("non-dumpable target: %v", err)
	}
	// The helper fails the run if its prctl was refused, so a clean exit is what says the
	// tracee really was undumpable when it exec'd.
	if code != 0 {
		t.Fatalf("the non-dumpable helper exited %d, so it never staged the prctl", code)
	}
	var got []string
	for _, r := range rec.runs {
		got = append(got, r.exe)
	}
	if !containsSuffix(got, "true") {
		t.Errorf("a non-dumpable target's exec recorded images %q, want one ending in /true; a blank entry is a record attesting to an exec whose image it lost", got)
	}
}

// The non-dumpable tracee for the test above: it makes itself undumpable and then execs, in
// its own process because prctl is per-process and the test binary must stay readable.
func TestNonDumpableExecHelper(t *testing.T) {
	if os.Getenv("BENTO_LAUNCHER_NONDUMPABLE") == "" {
		t.Skip("child tracee for the non-dumpable exec test")
	}
	if _, _, errno := syscall.RawSyscall(unix.SYS_PRCTL, unix.PR_SET_DUMPABLE, 0, 0); errno != 0 {
		t.Fatalf("prctl(PR_SET_DUMPABLE, 0): %v", errno)
	}
	if err := syscall.Exec("/bin/true", []string{"/bin/true"}, nil); err != nil {
		t.Fatalf("exec: %v", err)
	}
}
