//go:build linux

package linux

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/whiskeyjimbo/bento/policy"
)

// The degraded tier wraps its launcher in systemd-run --scope to apply resource
// limits, while its leaked-process cleanup relies on the process-group sweep
// (killProcessGroup). This proves --scope does NOT break that sweep - it puts the
// command in a new cgroup, not a new process group - so a backgrounded descendant of
// the scoped command is still killed.
func TestScopeDoesNotBreakProcessGroupSweep(t *testing.T) {
	if ok, reason := canCreateScope(t.Context()); !ok {
		t.Skip("no usable systemd user scope: " + reason)
	}
	pidFile := filepath.Join(t.TempDir(), "sleeper.pid")
	// A shell that backgrounds a long sleep (a leaked descendant) and records its pid.
	exe, args := wrapWithLimits("sh", []string{
		"-c",
		"sleep 300 & echo $! > " + pidFile + "; sleep 1",
	}, policy.Limits{Memory: "64M"}, "")

	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	// Wait for the sleeper pid to be recorded.
	var sleeper int
	for i := 0; i < 100 && sleeper == 0; i++ {
		if b, err := os.ReadFile(pidFile); err == nil {
			if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				sleeper = n
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if sleeper == 0 {
		_ = killProcessGroup(cmd.Process)
		t.Fatal("sleeper pid never recorded")
	}

	if err := killProcessGroup(cmd.Process); err != nil {
		t.Fatalf("killProcessGroup: %v", err)
	}
	_, _ = cmd.Process.Wait()

	// Give the SIGKILL a moment, then confirm the backgrounded sleeper is gone.
	time.Sleep(200 * time.Millisecond)
	if err := syscall.Kill(sleeper, 0); err == nil {
		_ = syscall.Kill(sleeper, syscall.SIGKILL) // cleanup
		t.Fatalf("BROKEN: backgrounded process %d survived the pgroup sweep under systemd-run --scope", sleeper)
	}
}

// A zero pid must not reach Kill: -0 addresses the caller's own process group, so an
// unguarded sweep SIGKILLs the launcher (here, this test binary) instead of the
// target. The assertion is that this test survives to make it.
func TestProcessGroupSweepIgnoresZeroPid(t *testing.T) {
	if err := killProcessGroup(&os.Process{}); err != nil {
		t.Fatalf("killProcessGroup: %v", err)
	}
}

// The pgroup sweep only runs while bento is alive to run it. A SIGKILLed bento runs
// nothing, so the launcher carries Pdeathsig as well, and what that is worth is a
// runtime/kernel fact rather than bento logic - measured here, not assumed.
func TestLauncherDiesWithSIGKILLedParent(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestPdeathsigParentHelper")
	cmd.Env = append(os.Environ(), "BENTO_TEST_PDEATHSIG=plain")
	assertChildDiesWithParent(t, cmd)
}

// The scoped shape of the same property. A limited degraded run sets launcherProcAttr on
// systemd-run, not on the launcher, so the teardown depends on PDEATHSIG surviving the
// scope's execve into its command. prctl(2) says it does (cleared on fork, and on a
// setuid/setgid exec); this measures it, for the same reason its process-group twin above
// measures the scope's effect on the group.
func TestPdeathsigSurvivesTheScopeExec(t *testing.T) {
	if ok, reason := canCreateScope(t.Context()); !ok {
		t.Skip("no usable systemd user scope: " + reason)
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestPdeathsigParentHelper")
	cmd.Env = append(os.Environ(), "BENTO_TEST_PDEATHSIG=scoped")
	assertChildDiesWithParent(t, cmd)
}

// assertChildDiesWithParent runs a helper that reports one pid and waits, then asserts the
// pid outlives nothing but its parent: alive while the parent is (Go's Pdeathsig is armed
// against the forking OS THREAD, so a runtime that retired that thread would kill a
// healthy run mid-flight) and gone once the parent is SIGKILLed.
func assertChildDiesWithParent(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	var child int
	if _, err := fmt.Fscanf(out, "CHILD %d\n", &child); err != nil {
		t.Fatalf("child pid never reported: %v", err)
	}

	// Long enough for the runtime to have retired the forking thread if it were going to.
	time.Sleep(2 * time.Second)
	if err := syscall.Kill(child, 0); err != nil {
		t.Fatalf("BROKEN: Pdeathsig killed %d while its parent was still alive: %v", child, err)
	}

	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("sigkill parent: %v", err)
	}
	_, _ = cmd.Process.Wait()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(child, 0); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = syscall.Kill(child, syscall.SIGKILL) // cleanup
	t.Fatalf("BROKEN: %d survived its SIGKILLed parent; a killed bento leaves the whole degraded run orphaned", child)
}

// TestPdeathsigParentHelper is the child half: it starts a sleeper under the SysProcAttr
// runDegraded gives its launcher, reports the pid and waits to be killed. Inert unless
// the parent set the trigger.
func TestPdeathsigParentHelper(t *testing.T) {
	// exec, so the reported pid IS the sleeper: a forking shell would leave the sleep
	// behind as a descendant and the test would be measuring the wrong process. Under the
	// scope the same holds one link further out - systemd-run execs the shell in place.
	exe, args := shBinary(), []string{"-c", "exec sleep 300"}
	switch os.Getenv("BENTO_TEST_PDEATHSIG") {
	case "plain":
	case "scoped":
		exe, args = wrapWithLimits(exe, args, policy.Limits{Memory: "64M"}, "")
	default:
		t.Skip("child helper for the Pdeathsig tests")
	}
	sleeper := exec.Command(exe, args...)
	attr := launcherProcAttr // the production value, so dropping Pdeathsig there goes red
	sleeper.SysProcAttr = &attr
	if err := sleeper.Start(); err != nil {
		t.Fatalf("start sleeper: %v", err)
	}
	fmt.Printf("CHILD %d\n", sleeper.Process.Pid)
	time.Sleep(60 * time.Second)
}
