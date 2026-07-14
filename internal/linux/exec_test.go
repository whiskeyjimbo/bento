package linux

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whiskeyjimbo/bento-v2/internal/enforce"
	"github.com/whiskeyjimbo/bento-v2/internal/policy"
)

// These prove the exec-block filter actually stops subprocesses inside a real
// sandbox, not merely that it loaded. They use the built bento binary because the
// in-sandbox launcher is bento re-exec'd, and the test process is not bento.

// spawnScript tries to run a subprocess and reports whether it succeeded. The
// inner `sh -c` forks and execve's a new shell, which is the exec path the filter
// denies.
const spawnScript = "echo START; sh -c 'echo SUBPROCESS-RAN' 2>/dev/null || echo SUBPROCESS-BLOCKED; echo END"

func TestExecBlockedByDefault(t *testing.T) {
	requireSandbox(t)
	out := runShell(t, sandboxEnforcer(t), &policy.Policy{}, spawnScript)
	if !strings.Contains(out, "START") || !strings.Contains(out, "END") {
		t.Fatalf("the script itself did not run to completion, so the transition is broken: %q", out)
	}
	if strings.Contains(out, "SUBPROCESS-RAN") {
		t.Fatalf("a subprocess ran despite exec: none: %q", out)
	}
	if !strings.Contains(out, "SUBPROCESS-BLOCKED") {
		t.Fatalf("expected the subprocess to be refused: %q", out)
	}
}

func TestExecAllowedWhenPolicyPermits(t *testing.T) {
	requireSandbox(t)
	out := runShell(t, sandboxEnforcer(t), &policy.Policy{Exec: policy.ExecAll}, spawnScript)
	if !strings.Contains(out, "SUBPROCESS-RAN") {
		t.Fatalf("exec: all should permit subprocesses: %q", out)
	}
}

// exec-blocking and egress must both hold at once: the bridge child is started
// before the filter (so its own execve succeeds), then the filter blocks the
// target's subprocesses, while the target still reaches allowlisted hosts.
func TestExecBlockAndEgressTogether(t *testing.T) {
	requireSandbox(t)
	p := &policy.Policy{Network: []policy.NetworkRule{{Host: "127.0.0.1", Port: "1"}}}
	out := runShell(t, sandboxEnforcer(t), p, spawnScript)

	// The filter still blocks subprocesses even with the egress bridge running.
	if strings.Contains(out, "SUBPROCESS-RAN") {
		t.Fatalf("a subprocess ran despite exec: none while egress was enabled: %q", out)
	}
	if !strings.Contains(out, "SUBPROCESS-BLOCKED") {
		t.Fatalf("expected the subprocess to be refused: %q", out)
	}
}

// When the launcher supervises a subprocess-spawning target (exec: all + egress),
// it is PID 1 and must act as an init: return the target's exit code as soon as
// the target exits, reaping — not waiting on — an orphaned background grandchild.
// If reaping waited for every child, this run would hang on the long sleep.
func TestSuperviseReapsOrphanAndReturnsPromptly(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	script := filepath.Join(dir, "orphan.sh")
	// Background a long sleep (orphaned when the shell exits), then exit 7.
	if err := os.WriteFile(script, []byte("sleep 30 &\nexit 7\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{
		Entrypoint:  script,
		Interpreter: "sh",
		Read:        []string{dir},
		Exec:        policy.ExecAll,
		Network:     []policy.NetworkRule{{Host: "127.0.0.2", Port: "1"}}, // forces the launcher/supervise path
	}

	start := time.Now()
	res, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 7 {
		t.Errorf("exit code = %d, want 7 (the target's code, returned via the reaper)", res.ExitCode)
	}
	if elapsed > 10*time.Second {
		t.Errorf("run took %s — the reaper waited on the orphaned sleep instead of returning on target exit", elapsed)
	}
}
