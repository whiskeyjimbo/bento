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

	"github.com/whiskeyjimbo/bento-v2/policy"
)

// bv2-bbq gate: enforcing limits in the degraded tier would wrap the launcher in
// systemd-run --scope, but the degraded tier's leaked-process cleanup relies on the
// process-group sweep (killProcessGroup). This proves --scope does NOT break that
// sweep: a backgrounded process under the scoped command must still be killed.
func TestScopeDoesNotBreakProcessGroupSweep(t *testing.T) {
	if ok, reason := canCreateScope(); !ok {
		t.Skip("no usable systemd user scope: " + reason)
	}
	pidFile := filepath.Join(t.TempDir(), "sleeper.pid")
	// A shell that backgrounds a long sleep (a leaked descendant) and records its pid.
	exe, args := wrapWithLimits("sh", []string{"-c",
		"sleep 300 & echo $! > " + pidFile + "; sleep 1"}, policy.Limits{Memory: "64M"})

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
		syscall.Kill(sleeper, syscall.SIGKILL) // cleanup
		t.Fatalf("BROKEN: backgrounded process %d survived the pgroup sweep under systemd-run --scope", sleeper)
	}
}
