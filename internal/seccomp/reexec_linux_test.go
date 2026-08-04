//go:build linux

package seccomp

import (
	"os"
	"os/exec"
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
