package linux

import (
	"strings"
	"testing"

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
