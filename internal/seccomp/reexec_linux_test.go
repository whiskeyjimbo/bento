//go:build linux

package seccomp

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

// helperCommand builds the child half of a re-exec test: this same test binary, run
// with only the named helper selected and the trigger env var the helper checks for.
//
// The coverage flag is threaded only when the caller (make cover) set the directory,
// because a test binary built without instrumentation refuses -test.gocoverdir and
// exits 2 - which every parent here would report as a helper failure. Passing a
// directory is what lets the child's counters survive: it is a separate process, so
// its profile has nowhere to go otherwise.
func helperCommand(t *testing.T, run, trigger string) *exec.Cmd {
	t.Helper()
	args := []string{"-test.run=" + run, "-test.v"}
	if dir := os.Getenv("BENTO_TEST_COVERDIR"); dir != "" {
		args = append(args, "-test.gocoverdir="+dir)
	}
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), trigger)
	return cmd
}

// runKilledHelper runs a helper whose filter is expected to KILL it, and reports how it
// died: the signal if it was killed, or 0 if it exited on its own. Every filter in this
// package that returns a kill verdict is asserted through here, because a kill is only
// observable from the parent's wait status - the child never reaches a print.
//
// It skips the calling test on a kernel with no ia32 entry point, where `int 0x80` raises
// SIGSEGV and reaches no filter at all. That skip reads the child's OUTPUT, not its wait
// status, because the fault lands inside Go code: the runtime catches SIGSEGV, prints a
// fatal-error dump and exits 2 UNSIGNALED, so a wait-status check for SIGSEGV never fires
// and the test would fail on every such host instead of skipping. A seccomp kill is not
// interceptable that way - SECCOMP_RET_KILL_PROCESS is not deliverable - so SIGSYS still
// arrives as a signal. The check is inert for a helper that issues no compat syscall.
//
// A child killed this way is the one shape in this package whose coverage is structurally
// unrecoverable: it dies without running testing's teardown and never writes its counters.
func runKilledHelper(t *testing.T, run, trigger string) (syscall.Signal, string) {
	t.Helper()
	out, err := helperCommand(t, run, trigger).CombinedOutput()
	if strings.Contains(string(out), "signal SIGSEGV") {
		t.Skip("kernel has no ia32 compat entry point (CONFIG_IA32_EMULATION off or ia32_emulation=0), so no foreign-arch syscall can be issued")
	}
	if err == nil {
		return 0, string(out)
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("%s helper: %v\n%s", run, err, out)
	}
	ws, ok := ee.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() {
		t.Fatalf("%s helper exited %d rather than dying on a signal:\n%s", run, ee.ExitCode(), out)
	}
	return ws.Signal(), string(out)
}
