//go:build linux

package linux

import (
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
	if ok, reason := canCreateScope(); !ok {
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
