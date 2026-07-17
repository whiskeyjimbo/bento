package linux

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/enforce"
	"github.com/whiskeyjimbo/bento-v2/policy"
	"github.com/whiskeyjimbo/bento-v2/internal/seccomp"
)

// exec: none-strict must block a new process (fork) while still allowing threads.
// The discriminator against plain none - which blocks only execve - is a fork
// WITHOUT exec: it succeeds under none and must fail under none-strict. The probe
// is a static (CGO-free) Go binary so it needs no interpreter or libc in the
// sandbox, and it issues the raw clone itself so the result does not depend on a
// shell's fork-failure handling.
func TestNoneStrictBlocksForkAllowsThreads(t *testing.T) {
	requireSandbox(t)
	if !seccomp.StrictExecSupported() {
		t.Skip("the none-strict filter is not implemented for this architecture")
	}
	bin := buildForkProbe(t)

	strict := runForkProbe(t, &policy.Policy{Exec: policy.ExecNoneStrict}, bin)
	if !strings.Contains(strict, "THREAD_OK") {
		t.Errorf("none-strict must still allow thread creation; got %q", strict)
	}
	if !strings.Contains(strict, "FORK_BLOCKED") {
		t.Errorf("none-strict must block fork; got %q", strict)
	}

	// Control: under plain none the same fork succeeds (only execve is blocked), so
	// the test proves the fork block is specific to none-strict, not an artifact.
	plain := runForkProbe(t, &policy.Policy{Exec: policy.ExecNone}, bin)
	if !strings.Contains(plain, "FORK_OK") {
		t.Errorf("plain none must allow fork (it blocks only execve); got %q", plain)
	}
}

func buildForkProbe(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available to build the probe")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "fork.go")
	const prog = `package main

import (
	"fmt"
	"runtime"
	"syscall"
)

func main() {
	// Reaching main at all proves thread creation works: the Go runtime needs
	// clone(CLONE_THREAD) to start. Force one more locked thread to be sure.
	done := make(chan struct{})
	go func() { runtime.LockOSThread(); close(done) }()
	<-done
	fmt.Println("THREAD_OK")

	// A process-creating clone (SIGCHLD, no CLONE_THREAD) is fork. RawSyscall
	// avoids the scheduler hooks that are unsafe in a forked child.
	r, _, errno := syscall.RawSyscall(syscall.SYS_CLONE, uintptr(syscall.SIGCHLD), 0, 0)
	if errno != 0 {
		fmt.Println("FORK_BLOCKED")
		return
	}
	if r == 0 {
		syscall.RawSyscall(syscall.SYS_EXIT, 0, 0, 0)
	}
	syscall.Wait4(int(r), nil, 0, nil)
	fmt.Println("FORK_OK")
}
`
	if err := os.WriteFile(src, []byte(prog), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "fork")
	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building fork probe: %v\n%s", err, out)
	}
	return bin
}

func runForkProbe(t *testing.T, p *policy.Policy, bin string) string {
	t.Helper()
	p.Entrypoint = bin
	p.Read = append(p.Read, filepath.Dir(bin))
	var out strings.Builder
	if _, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out}, nil); err != nil {
		t.Fatalf("Run: %v (output: %s)", err, out.String())
	}
	return out.String()
}
