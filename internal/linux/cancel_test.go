//go:build linux

package linux

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// A caller that cancels the run must not get back a clean Result. The kill a cancel
// produces is byte-identical to the one a memory cap produces, so the only thing that
// separates "the operator aborted" from "the policy held and killed the target" is
// this error.
func TestRunReportsACancelledContextAsAnError(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	script := filepath.Join(dir, "sleep.sh")
	if err := os.WriteFile(script, []byte("sleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir}, Exec: policy.ExecAll}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(500 * time.Millisecond)
		cancel()
	}()
	defer cancel()

	res, err := sandboxEnforcer(t).Run(ctx, p, enforce.Process{}, enforce.RunOptions{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run on a cancelled context = (%+v, %v), want an error wrapping context.Canceled", res, err)
	}
	if res.Signaled || res.ExitCode != 0 {
		t.Errorf("cancelled run also reported a target outcome: ExitCode=%d Signaled=%v", res.ExitCode, res.Signaled)
	}
}

func TestRunDegradedReportsACancelledContextAsAnError(t *testing.T) {
	requireDegraded(t)

	sleep, err := exec.LookPath("sleep")
	if err != nil {
		skipMissingDep(t, "sleep not available")
	}
	p := &policy.Policy{Entrypoint: sleep, Args: []string{"30"}, Exec: policy.ExecNone}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(500 * time.Millisecond)
		cancel()
	}()
	defer cancel()

	res, err := enforcerUsing(testBento(t)).runDegraded(ctx, p, enforce.Process{}, "", nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runDegraded on a cancelled context = (%+v, %v), want an error wrapping context.Canceled", res, err)
	}
}
