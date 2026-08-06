//go:build linux

package linux

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// cancelOnceRunning cancels ctx as soon as the target has signalled it is up, by
// creating the returned path. Cancelling on a timer instead would cancel during the
// enforcer's cold probe on a slow host, which returns an error through the pre-existing
// setup path and passes these tests without ever reaching the branch they exist for.
func cancelOnceRunning(t *testing.T, cancel context.CancelFunc) string {
	t.Helper()
	ready := filepath.Join(t.TempDir(), "running")
	go func() {
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(ready); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		cancel()
	}()
	return ready
}

// cancelOnFirstWrite is the same readiness signal as cancelOnceRunning for a tier that
// cannot create the file: the target's first byte of output means it is up.
func cancelOnFirstWrite(cancel context.CancelFunc) io.Writer {
	var once sync.Once
	return writerFunc(func(b []byte) (int, error) {
		once.Do(func() { go cancel() })
		return len(b), nil
	})
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }

// A caller that cancels the run must not get back a clean Result. The kill a cancel
// produces is byte-identical to the one a memory cap produces, so the only thing that
// separates "the operator aborted" from "the policy held and killed the target" is
// this error.
func TestRunReportsACancelledContextAsAnError(t *testing.T) {
	requireSandbox(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := cancelOnceRunning(t, cancel)

	dir := t.TempDir()
	script := filepath.Join(dir, "sleep.sh")
	if err := os.WriteFile(script, []byte("touch "+ready+"\nsleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{
		Entrypoint:  script,
		Interpreter: "sh",
		Read:        []string{dir},
		Write:       []string{filepath.Dir(ready)},
		Exec:        policy.ExecAll,
	}

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

	sh, err := exec.LookPath("sh")
	if err != nil {
		skipMissingDep(t, "sh not available")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Shell builtins only, and a read that blocks on a pipe nothing ever writes: this
	// tier is exercised under exec: none, where a real sleep(1) would be refused before
	// the target ever got to run. The write on stdout is what says the target is up.
	// An *os.File, not io.Pipe: exec hands a file straight to the child, where a plain
	// reader gets a copying goroutine that Wait then blocks on forever.
	stdin, holdOpen, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer holdOpen.Close()
	defer stdin.Close()
	p := &policy.Policy{
		Entrypoint: sh,
		Args:       []string{"-c", "echo up; read x"},
		Exec:       policy.ExecNone,
	}

	res, err := enforcerUsing(testBento(t)).runDegraded(ctx, p,
		enforce.Process{Stdin: stdin, Stdout: cancelOnFirstWrite(cancel)}, "", nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runDegraded on a cancelled context = (%+v, %v), want an error wrapping context.Canceled", res, err)
	}
}
