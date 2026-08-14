//go:build linux

package linux

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

// Everything the cancel arm computed before the cancel is still true of the run, and it
// was being thrown away: the arm returned a Result carrying only the report and the
// auto-exec fields, so every egress, shield and alias field came back zero. A supervisor
// that timed out a run then read GateAdmitted got the empty value whose documented
// meaning is "no destination was admitted beyond the manifest" - a wrong-and-quiet answer
// about a run that did reach the proxy. stopProxy has to be called before the collector is
// read, the way the two completing arms do it, or the drain is only partial.
func TestCancelledRunStillReportsWhatItObserved(t *testing.T) {
	requireSandbox(t)
	if _, err := exec.LookPath("curl"); err != nil {
		skipMissingDep(t, "curl not available")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := cancelOnceRunning(t, cancel)

	// Link-local, so the upstream guard refuses it on every host and the observation is
	// deterministic without touching the network. The connection is made and recorded
	// BEFORE the target signals it is up, so the cancel lands after the proxy has seen it.
	const target = "169.254.254.254:1"
	dir := t.TempDir()
	script := filepath.Join(dir, "probe.sh")
	body := "curl -sS --proxytunnel -o /dev/null --max-time 5 http://" + target + "/ >/dev/null 2>&1\n" +
		"touch " + ready + "\nsleep 30\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{
		Entrypoint:  script,
		Interpreter: "sh",
		Read:        []string{dir},
		Write:       []string{filepath.Dir(ready)},
		Exec:        policy.ExecAll,
	}

	gate := func(context.Context, string, string) bool { return true }
	res, err := sandboxEnforcer(t).Run(ctx, p, enforce.Process{}, enforce.RunOptions{Gate: gate, RecordExec: true})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run on a cancelled context = %v, want an error wrapping context.Canceled", err)
	}
	if res.EgressConnections == 0 {
		t.Error("EgressConnections = 0: the connection the proxy handled before the cancel is part of this run")
	}
	want := []enforce.HostPort{{Host: "169.254.254.254", Port: "1"}}
	if !slices.Equal(res.GuardBlocked, want) {
		t.Errorf("GuardBlocked = %v, want %v: the guard's refusal is what the run did, cancelled or not", res.GuardBlocked, want)
	}
	// The other half of the arm: what the sandboxed stage itself reported. A nil record
	// for a caller that asked to record execs reads as a run nobody watched.
	if res.ExecRecord == nil {
		t.Error("ExecRecord is nil though the run asked for one; the cancel arm dropped what the launcher reported")
	}
	// The cancel arm still withholds the target's own outcome, which is the one thing a
	// SIGKILLed target cannot be said to have produced.
	if res.Signaled || res.ExitCode != 0 {
		t.Errorf("cancelled run also reported a target outcome: ExitCode=%d Signaled=%v", res.ExitCode, res.Signaled)
	}
}

// A context already cancelled when Run is called never starts the wrapper at all, so
// cmd.ProcessState is nil - and killedByCancel deliberately reads that as the cancel
// ("the command never started"), which puts the nil straight into the cancel arm. The
// arm must still come back with the cancellation error rather than crashing on it.
func TestRunOnAnAlreadyCancelledContextDoesNotCrash(t *testing.T) {
	requireSandbox(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	dir := t.TempDir()
	script := filepath.Join(dir, "noop.sh")
	if err := os.WriteFile(script, []byte("true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir}, Exec: policy.ExecAll}

	_, err := sandboxEnforcer(t).Run(ctx, p, enforce.Process{}, enforce.RunOptions{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want an error wrapping context.Canceled", err)
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
