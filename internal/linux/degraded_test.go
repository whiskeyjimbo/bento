package linux

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/whiskeyjimbo/bento-v2/enforce"
	"github.com/whiskeyjimbo/bento-v2/internal/landlock"
	"github.com/whiskeyjimbo/bento-v2/internal/seccomp"
	"github.com/whiskeyjimbo/bento-v2/policy"
)

// A signal-killed target must surface as 128+signal, matching the bwrap and supervise
// paths: the degraded exec:none path reads cmd.ProcessState.ExitCode() directly, which
// is -1 for a signal and would otherwise reach the caller as 255. exitCodeOf does the
// mapping; verify it against a real signaled process.
func TestExitCodeOfMapsSignalToConvention(t *testing.T) {
	cmd := exec.Command("sh", "-c", "kill -TERM $$")
	_ = cmd.Run() // exits via SIGTERM; ProcessState is set regardless of the error
	if got := exitCodeOf(cmd.ProcessState); got != 128+int(syscall.SIGTERM) {
		t.Errorf("signaled target: exitCodeOf = %d, want %d", got, 128+int(syscall.SIGTERM))
	}

	ok := exec.Command("sh", "-c", "exit 42")
	_ = ok.Run()
	if got := exitCodeOf(ok.ProcessState); got != 42 {
		t.Errorf("normal exit: exitCodeOf = %d, want 42", got)
	}
}

// The degraded (no-bwrap) tier must actually confine: a granted read works, an
// ungranted read is denied by Landlock, and an IP socket is refused by the seccomp
// egress block. The probe is a static (CGO-free) Go binary run as its own entrypoint
// under exec: none, so no interpreter or subprocess is involved.
func TestDegradedConfinesFilesystemAndEgress(t *testing.T) {
	requireDegraded(t)
	bin := buildDegradedProbe(t)

	grantedDir := t.TempDir()
	grantedFile := filepath.Join(grantedDir, "ok.txt")
	if err := os.WriteFile(grantedFile, []byte("granted-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	ungrantedFile := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(ungrantedFile, []byte("do-not-read"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{Entrypoint: bin, Read: []string{grantedDir}, Exec: policy.ExecNone}
	var out strings.Builder
	proc := enforce.Process{
		Stdout: &out, Stderr: &out,
		Env: map[string]string{"GRANTED": grantedFile, "UNGRANTED": ungrantedFile},
	}
	res, err := enforcerUsing(testBento(t)).runDegraded(context.Background(), p, proc)
	if err != nil {
		t.Fatalf("runDegraded: %v\noutput:\n%s", err, out.String())
	}
	got := out.String()
	for _, want := range []string{"GRANTED_READ_OK", "UNGRANTED_READ_DENIED", "SOCKET_BLOCKED", "EXEC_BLOCKED"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q; exit=%d output:\n%s", want, res.ExitCode, got)
		}
	}
}

// An interpreter run works under the degraded tier when its runtime is in a system
// location the read set covers (bash is in systemReadPaths on an FHS host, and under
// /nix on NixOS - both granted). The script reads a granted file with a shell
// redirect (no subprocess), so exec: none does not interfere.
func TestDegradedRunsInterpreterOnGrantedRead(t *testing.T) {
	requireDegraded(t)
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	data := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(data, []byte("degraded-file-content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "s.sh")
	if err := os.WriteFile(script, []byte(`read x < "$DATA"; echo "got=$x"`), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "bash", Read: []string{dir}, Exec: policy.ExecNone}
	var out strings.Builder
	proc := enforce.Process{Stdout: &out, Stderr: &out, Env: map[string]string{"DATA": data}}
	res, err := enforcerUsing(testBento(t)).runDegraded(context.Background(), p, proc)
	if err != nil {
		t.Fatalf("runDegraded: %v\noutput:\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "got=degraded-file-content") {
		t.Errorf("interpreter did not read the granted file; exit=%d output:\n%s", res.ExitCode, out.String())
	}
}

// An exec:all degraded run exercises the launcher's superviseTarget path (fork the
// target, reap it) with the cross-process seccomp block installed. It is the guard
// that the block refuses only pidfd_getfd, not the whole pidfd family - Go's child
// management uses pidfd_open/pidfd_send_signal, so over-blocking would break the
// launcher here and the exec:none tests (which execveat) would not catch it.
func TestDegradedExecAllSupervisesChild(t *testing.T) {
	requireDegraded(t)
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "s.sh")
	if err := os.WriteFile(script, []byte("echo parent-ran; exit 0"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "bash", Read: []string{dir}, Exec: policy.ExecAll}
	var out strings.Builder
	res, err := enforcerUsing(testBento(t)).runDegraded(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out})
	if err != nil {
		t.Fatalf("exec:all degraded run failed (cross-process block may over-restrict pidfd): %v\noutput:\n%s", err, out.String())
	}
	if res.ExitCode != 0 || !strings.Contains(out.String(), "parent-ran") {
		t.Errorf("supervised child did not run cleanly: exit=%d output:\n%s", res.ExitCode, out.String())
	}
}

// A process the target backgrounds and leaves running must be swept when the run
// ends: with no PID namespace to tear down, the enforcer runs the launcher in its
// own process group and SIGKILLs the group on teardown. The target records the
// background pid; after the run it must be dead.
func TestDegradedSweepsLeakedProcessGroup(t *testing.T) {
	requireDegraded(t)
	sleepBin, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep not available")
	}
	if resolved, err := filepath.EvalSymlinks(sleepBin); err == nil {
		sleepBin = resolved // the real binary, which the read set (systemReadPaths / /nix) covers
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")
	script := filepath.Join(dir, "s.sh")
	// Background a long sleep, record its pid, and exit - the sleep outlives the script.
	if err := os.WriteFile(script, []byte(`"$SLEEP" 300 & echo $! > "$PIDFILE"; echo backgrounded`), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "bash", Read: []string{dir}, Write: []string{dir}, Exec: policy.ExecAll}
	var out strings.Builder
	proc := enforce.Process{Stdout: &out, Stderr: &out, Env: map[string]string{"SLEEP": sleepBin, "PIDFILE": pidFile}}
	if _, err := enforcerUsing(testBento(t)).runDegraded(context.Background(), p, proc); err != nil {
		t.Fatalf("runDegraded: %v\noutput:\n%s", err, out.String())
	}

	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("no background pid recorded (did the run reach the script?): %v\noutput:\n%s", err, out.String())
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("bad pid %q: %v", data, err)
	}
	// The sweep SIGKILLs the group; the leaked sleep should die and be reaped shortly.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
			return // gone
		}
		if time.Now().After(deadline) {
			t.Fatalf("backgrounded pid %d survived the run; the process-group sweep did not reach it", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The degraded tier must apply the same grant-safety checks as the full tier: a write
// grant that contains the ~/.ssh credential shield is refused, not silently accepted.
// Without a mount namespace or deny-list here, accepting it would hand the whole home -
// including ~/.ssh - to Landlock read-write, an escape the full tier hard-refuses via
// checkWriteNotAboveShield. The check fires before any exec, so no real kernel is
// needed and no host directory is created for the refused grant.
func TestDegradedRefusesWriteAboveShield(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(t.TempDir(), "entry.sh")
	if err := os.WriteFile(entry, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: entry, Write: []string{home}, Exec: policy.ExecNone}
	_, err := enforcerUsing("/bin/true").runDegraded(context.Background(), p, enforce.Process{})
	if err == nil || !strings.Contains(err.Error(), "always-shielded") {
		t.Fatalf("degraded tier must refuse a write grant above the ~/.ssh shield; got err=%v", err)
	}
}

// A grant onto a whole managed pseudo-filesystem is refused in the degraded tier too.
// With no pid namespace and no fresh /proc, a read: /proc grant would serve the host's
// process table (environ of same-uid processes: tokens, DB passwords), so the full
// tier's checkGrantNotManagedMount refusal must hold here as well.
func TestDegradedRefusesManagedMountGrant(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	entry := filepath.Join(t.TempDir(), "entry.sh")
	if err := os.WriteFile(entry, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: entry, Read: []string{"/proc"}, Exec: policy.ExecNone}
	_, err := enforcerUsing("/bin/true").runDegraded(context.Background(), p, enforce.Process{})
	if err == nil || !strings.Contains(err.Error(), "pseudo-filesystem") {
		t.Fatalf("degraded tier must refuse a whole-/proc grant; got err=%v", err)
	}
}

func requireDegraded(t *testing.T) {
	t.Helper()
	if !landlock.Available() {
		t.Skip("Landlock not available on this kernel")
	}
	if !seccomp.EgressSupported() {
		t.Skip("seccomp egress block not implemented for this architecture")
	}
}

// buildDegradedProbe compiles a static Go binary that reports whether a granted read
// succeeds, an ungranted read is denied, and an IP socket is refused. Static (CGO
// off) so it needs no libc in the read set.
func buildDegradedProbe(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available to build the probe")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "probe.go")
	const prog = `package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func main() {
	if _, err := os.ReadFile(os.Getenv("GRANTED")); err == nil {
		fmt.Println("GRANTED_READ_OK")
	} else {
		fmt.Println("GRANTED_READ_FAIL", err)
	}
	if _, err := os.ReadFile(os.Getenv("UNGRANTED")); err != nil {
		fmt.Println("UNGRANTED_READ_DENIED")
	} else {
		fmt.Println("UNGRANTED_READ_LEAK")
	}
	if fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0); err == syscall.EPERM {
		fmt.Println("SOCKET_BLOCKED")
	} else if err == nil {
		syscall.Close(fd)
		fmt.Println("SOCKET_NOT_BLOCKED")
	} else {
		fmt.Println("SOCKET_ERR", err)
	}
	if err := exec.Command("/bin/true").Run(); err != nil {
		fmt.Println("EXEC_BLOCKED")
	} else {
		fmt.Println("EXEC_NOT_BLOCKED")
	}
}
`
	if err := os.WriteFile(src, []byte(prog), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "probe")
	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0", "HOME="+toolchainHome)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building degraded probe: %v\n%s", err, out)
	}
	return bin
}
