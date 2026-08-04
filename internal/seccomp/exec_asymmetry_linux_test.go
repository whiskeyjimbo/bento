//go:build linux

package seccomp

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The exec-block filter is a SOFT block by construction: it denies execve(2) but
// leaves execveat(2) open, because the in-sandbox launcher enters the target through
// execveat. That asymmetry is documented (seccomp_linux.go) and stops the ~100% of
// real-world exec paths that go through execve, but a target that calls execveat
// directly is not blocked. This pins the boundary so a filter change that either
// starts blocking execveat (breaking the launcher transition) or stops blocking
// execve (a real regression) fails loudly. The filter is process-wide and permanent,
// so it runs in a re-exec'd child rather than poisoning the test process.
func TestExecBlockIsSoftAllowsExecveat(t *testing.T) {
	cmd := helperCommand(t, "TestExecBlockIsSoftAllowsExecveatHelper", "BENTO_TEST_EXEC_ASYMMETRY=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("exec-asymmetry helper exited with error: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "ASYMMETRY_OK") {
		t.Errorf("helper did not confirm the exec:none soft-block boundary:\n%s", out)
	}
}

// TestExecBlockIsSoftAllowsExecveatHelper is the child half: it installs the filter
// and probes both exec syscalls, exiting nonzero (with a tag) on any mismatch. Inert
// unless the parent set the trigger env var.
func TestExecBlockIsSoftAllowsExecveatHelper(t *testing.T) {
	if os.Getenv("BENTO_TEST_EXEC_ASYMMETRY") != "1" {
		t.Skip("child helper for TestExecBlockIsSoftAllowsExecveat")
	}
	if err := BlockExec(); err != nil {
		fmt.Println("BLOCKEXEC_ERR", err)
		os.Exit(3)
	}
	// A path that does not exist: the kernel would resolve it to ENOENT, so any errno
	// other than that came from the filter, not path resolution.
	path, err := unix.BytePtrFromString("/nonexistent-bento-exec-probe")
	if err != nil {
		fmt.Println("PATH_ERR", err)
		os.Exit(3)
	}

	// execve is denied with the filter's own errno (EPERM), before the kernel ever
	// resolves the path.
	if _, _, errno := unix.Syscall(unix.SYS_EXECVE, uintptr(unsafe.Pointer(path)), 0, 0); errno != unix.EPERM {
		fmt.Println("EXECVE_NOT_EPERM", errno)
		os.Exit(4)
	}

	// execveat stays open by construction, so the kernel dispatches it and fails path
	// resolution with ENOENT. Anything other than EPERM proves the filter let it
	// through - ENOENT specifically proves the kernel got as far as resolving the path.
	atFDCWD := unix.AT_FDCWD // -100; route through a typed int so the negative value wraps to uintptr at runtime
	_, _, errno := unix.Syscall6(unix.SYS_EXECVEAT, uintptr(atFDCWD), uintptr(unsafe.Pointer(path)), 0, 0, 0, 0)
	if errno == unix.EPERM {
		fmt.Println("EXECVEAT_EPERM_UNEXPECTED")
		os.Exit(5)
	}
	if errno != unix.ENOENT {
		fmt.Println("EXECVEAT_UNEXPECTED_ERRNO", errno)
		os.Exit(6)
	}
	fmt.Println("ASYMMETRY_OK")
}

// execveat(AT_FDCWD, path, ..., 0) resolves a relative path against the working
// directory exactly as execve does, so an absolute argv[0] is a checked precondition
// here, not something the syscall gives for free. Exec must refuse a relative one, or
// it diverges from the supervising path (superviseTarget), which refuses it to avoid a
// $PATH lookup - and the target that runs is not the one the manifest named.
func TestExecRejectsRelativeArgv0(t *testing.T) {
	if err := Exec([]string{"true"}, nil); err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Errorf("Exec with a relative argv[0] = %v, want a refusal naming the absolute-path requirement", err)
	}
	if err := Exec(nil, nil); err == nil {
		t.Error("Exec with an empty argv must refuse")
	}
}
