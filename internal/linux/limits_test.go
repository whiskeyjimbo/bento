package linux

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/internal/enforce"
	"github.com/whiskeyjimbo/bento-v2/internal/policy"
)

func TestWrapWithLimitsNoLimitsIsPassthrough(t *testing.T) {
	exe, args := wrapWithLimits("bwrap", []string{"--die-with-parent"}, policy.Limits{})
	if exe != "bwrap" || len(args) != 1 || args[0] != "--die-with-parent" {
		t.Errorf("no limits should pass the command through unchanged; got %s %v", exe, args)
	}
}

func TestWrapWithLimitsBuildsScope(t *testing.T) {
	exe, args := wrapWithLimits("bwrap", []string{"--proc", "/proc"}, policy.Limits{
		Memory: "128M", CPU: "100%", PIDs: 32,
	})
	if exe != "systemd-run" {
		t.Fatalf("exe = %q, want systemd-run", exe)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--user --scope --quiet",
		"MemoryMax=128M", "MemorySwapMax=0", // swap must be pinned so memory can't escape
		"CPUQuota=100%",
		"TasksMax=32",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("scope args missing %q; got %q", want, joined)
		}
	}
	// The wrapped command must follow the -- separator, intact.
	found := strings.Contains(joined, " -- ")
	if !found || !strings.HasSuffix(joined, "-- bwrap --proc /proc") {
		t.Errorf("wrapped command not appended after --: %q", joined)
	}
}

func TestWrapWithLimitsOnlySetsWhatIsAsked(t *testing.T) {
	_, args := wrapWithLimits("bwrap", nil, policy.Limits{PIDs: 8})
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "MemoryMax") || strings.Contains(joined, "CPUQuota") {
		t.Errorf("only TasksMax was requested; got %q", joined)
	}
	if !strings.Contains(joined, "TasksMax=8") {
		t.Errorf("TasksMax not set; got %q", joined)
	}
}

// A memory-limited target that tries to allocate far past its cap must be killed,
// not allowed to allocate. The control (no limit) proves the allocation itself
// succeeds when unbounded, so the kill is the limit and not a broken script.
func TestMemoryLimitEnforced(t *testing.T) {
	requireSandbox(t)
	if ok, reason := limitsAvailable(); !ok {
		t.Skip("resource limits unavailable on this host: " + reason)
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}

	dir := t.TempDir()
	bomb := filepath.Join(dir, "bomb.py")
	src := "buf=[]\n" +
		"for _ in range(400):\n" +
		"    buf.append(bytearray(1024*1024))\n" +
		"print('ALLOCATED')\n"
	if err := os.WriteFile(bomb, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	run := func(l policy.Limits) string {
		p := &policy.Policy{Entrypoint: bomb, Interpreter: "python3", Read: []string{dir}, Exec: policy.ExecAll, Limits: l}
		var out strings.Builder
		// A non-zero exit is expected under the limit, so the error is not fatal
		// here — the assertion is on whether the allocation completed.
		sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out})
		return out.String()
	}

	if got := run(policy.Limits{}); !strings.Contains(got, "ALLOCATED") {
		t.Fatalf("control run without a limit should allocate; got %q", got)
	}
	if got := run(policy.Limits{Memory: "24M"}); strings.Contains(got, "ALLOCATED") {
		t.Fatalf("a 24M memory limit should have killed a 400M allocation; got %q", got)
	}
}
