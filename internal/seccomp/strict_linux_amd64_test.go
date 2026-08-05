//go:build linux && amd64

package seccomp

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// x32SyscallTag is __X32_SYSCALL_BIT, spelled out here rather than taken from the
// filter's own x32SyscallBit - as with the syscall numbers and clone flags below, which
// come from x/sys/unix. Sourcing a value from the filter would let a wrong one agree with
// itself and pass while real x32 syscalls slipped through.
const x32SyscallTag = 0x40000000

// The none-strict filter is the most intricate hand-rolled BPF program in this package -
// a jump table over clone flags read out of seccomp_data at a hardcoded offset - and
// until now no test installed it: every caller reaches it through a package var the
// launcher's tests replace with a fake. A wrong jump offset or a wrong struct offset in
// it fails OPEN, silently, while `exec: none-strict` still reports enforced.
//
// This drives every branch through a re-exec'd child, because the filter is process-wide
// and permanent. The x32 branch kills, so it gets its own child below.
func TestStrictFilterBlocksProcessCreation(t *testing.T) {
	if !Supported() {
		t.Skip("seccomp not supported on this kernel")
	}
	if !StrictExecSupported() {
		t.Skip("no none-strict filter on this architecture")
	}
	cmd := helperCommand(t, "TestStrictFilterBlocksProcessCreationHelper", "BENTO_TEST_STRICT=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("none-strict helper exited with error: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "STRICT_OK") {
		t.Errorf("helper did not confirm the none-strict filter's branches:\n%s", out)
	}
}

// TestStrictFilterBlocksProcessCreationHelper is the child half: it probes each branch
// before and after installing the filter and exits nonzero (with a tag) on any mismatch.
// Inert unless the parent set the trigger env var.
//
// Nothing here ever creates a process or a thread, by construction. The clone probes ask
// for flag combinations the kernel itself refuses with EINVAL (CLONE_THREAD requires
// CLONE_SIGHAND, CLONE_SIGHAND requires CLONE_VM), so a permitted clone is distinguishable
// from a filtered one by errno alone - EINVAL is the kernel's answer, EPERM is the
// filter's - and neither outcome leaves anything running. That is also what pins
// offArg0Lo: a wrong offset makes the AND read the wrong word, and the CLONE_THREAD probe
// comes back EPERM instead of EINVAL.
func TestStrictFilterBlocksProcessCreationHelper(t *testing.T) {
	if os.Getenv("BENTO_TEST_STRICT") != "1" {
		t.Skip("child helper for TestStrictFilterBlocksProcessCreation")
	}

	// The controls: each probe reaches the kernel and gets the kernel's own errno before
	// the filter exists, so every verdict below is attributable to the filter rather than
	// to the probe being malformed. fork and vfork have no control - they take no
	// arguments and cannot return EPERM from the kernel, so their EPERM is already
	// unambiguous, and running them unfiltered would be running the thing under test.
	if errno := execveErrno(); errno != unix.ENOENT {
		fmt.Println("CONTROL_EXECVE", errno)
		os.Exit(3)
	}
	if errno := cloneErrno(unix.CLONE_THREAD | unix.CLONE_SIGHAND); errno != unix.EINVAL {
		fmt.Println("CONTROL_CLONE_THREAD", errno)
		os.Exit(3)
	}
	if errno := cloneErrno(unix.CLONE_SIGHAND); errno != unix.EINVAL {
		fmt.Println("CONTROL_CLONE_PROCESS", errno)
		os.Exit(3)
	}
	if errno := clone3Errno(); errno != unix.EINVAL {
		fmt.Println("CONTROL_CLONE3", errno)
		os.Exit(3)
	}

	if err := BlockExecStrict(); err != nil {
		fmt.Println("BLOCKEXECSTRICT_ERR", err)
		os.Exit(4)
	}

	for _, probe := range []struct {
		name string
		got  unix.Errno
		want unix.Errno
	}{
		{"execve", execveErrno(), unix.EPERM},
		// Still open by construction, the same soft block BlockExec carries: the
		// in-sandbox launcher enters the target through execveat. ENOENT is the kernel
		// resolving the path, so the filter did not intercept it.
		{"execveat", execveatErrno(), unix.ENOENT},
		{"fork", forkErrno(unix.SYS_FORK), unix.EPERM},
		{"vfork", forkErrno(unix.SYS_VFORK), unix.EPERM},
		// Forced to ENOSYS so glibc falls back to clone, which BPF can inspect. If this
		// branch regressed the kernel would answer EINVAL again and clone3 would sail
		// past the whole filter.
		{"clone3", clone3Errno(), unix.ENOSYS},
		// Permitted: the filter lets it through and the kernel refuses the flags, which
		// is the only way to observe "allowed" without actually creating a thread.
		{"clone with CLONE_THREAD", cloneErrno(unix.CLONE_THREAD | unix.CLONE_SIGHAND), unix.EINVAL},
		{"clone without CLONE_THREAD", cloneErrno(unix.CLONE_SIGHAND), unix.EPERM},
	} {
		if probe.got != probe.want {
			fmt.Printf("PROBE_MISMATCH %s got %v want %v\n", probe.name, probe.got, probe.want)
			os.Exit(5)
		}
	}
	fmt.Println("STRICT_OK")
}

// x32 shares the amd64 audit arch but tags its syscall numbers, so a tagged number misses
// every equality check in the filter and would reach the trailing allow - which for
// execve or clone is the whole block bypassed. The filter kills on the tag itself, before
// any per-syscall check, so the probe uses a harmless getpid: what is under test is the
// tag branch, and if it regressed the fallthrough is a bogus getpid rather than a real
// exec attempt.
//
// Like the foreign-arch guard this asserts SIGSYS, which a kill-thread and a kill-process
// verdict both produce in a single-threaded child; TestKillProcessActionIsAvailable
// covers the scope separately.
func TestStrictFilterKillsX32Syscalls(t *testing.T) {
	if !Supported() {
		t.Skip("seccomp not supported on this kernel")
	}
	if !StrictExecSupported() {
		t.Skip("no none-strict filter on this architecture")
	}
	cmd := helperCommand(t, "TestStrictFilterKillsX32SyscallsHelper", "BENTO_TEST_STRICT_X32=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("the helper survived an x32-tagged syscall under the none-strict filter:\n%s", out)
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("x32 helper: %v\n%s", err, out)
	}
	ws, ok := ee.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() {
		t.Fatalf("x32 helper exited %d rather than dying on a signal:\n%s", ee.ExitCode(), out)
	}
	if sig := ws.Signal(); sig != syscall.SIGSYS {
		t.Fatalf("an x32-tagged syscall under the none-strict filter died on %v, want SIGSYS:\n%s", sig, out)
	}
}

// TestStrictFilterKillsX32SyscallsHelper is the child half: it installs the filter and
// issues one x32-tagged syscall, which must not return. Its coverage counters are
// structurally unrecoverable - SECCOMP_RET_KILL_PROCESS is not deliverable, so testing's
// teardown never runs - the same as the foreign-arch guard helper.
func TestStrictFilterKillsX32SyscallsHelper(t *testing.T) {
	if os.Getenv("BENTO_TEST_STRICT_X32") != "1" {
		t.Skip("child helper for TestStrictFilterKillsX32Syscalls")
	}
	// The control is the parent's own liveness: an untagged getpid runs constantly in
	// every other test here, so a tagged one being fatal is attributable to the tag.
	if err := BlockExecStrict(); err != nil {
		fmt.Println("BLOCKEXECSTRICT_ERR", err)
		os.Exit(3)
	}
	_, _, _ = unix.RawSyscall(x32SyscallTag|unix.SYS_GETPID, 0, 0, 0)
	fmt.Println("X32_SURVIVED")
	os.Exit(4)
}

// execveatErrno attempts execveat on a path that does not exist and reports the errno,
// the counterpart to execveErrno. AT_FDCWD routes through a typed int so the negative
// value wraps to uintptr at runtime.
func execveatErrno() unix.Errno {
	path, err := unix.BytePtrFromString("/nonexistent-bento-strict-probe")
	if err != nil {
		return 0
	}
	atFDCWD := unix.AT_FDCWD
	_, _, errno := unix.Syscall6(unix.SYS_EXECVEAT, uintptr(atFDCWD), uintptr(unsafe.Pointer(path)), 0, 0, 0, 0)
	return errno
}

// cloneErrno issues clone(2) with the given flags and reports the errno. The caller picks
// flags the kernel rejects, so this never returns in a child - see forkErrno for what
// happens if the filter let one through anyway.
func cloneErrno(flags uintptr) unix.Errno {
	return rawErrno(unix.SYS_CLONE, flags, 0, 0)
}

// clone3Errno issues clone3(2) with a null argument struct and a zero size, which the
// kernel rejects with EINVAL before reading anything. That makes the filter's forced
// ENOSYS distinguishable from the kernel's own answer.
func clone3Errno() unix.Errno {
	return rawErrno(unix.SYS_CLONE3, 0, 0, 0)
}

// forkErrno issues fork(2) or vfork(2) and reports the errno.
func forkErrno(nr uintptr) unix.Errno {
	return rawErrno(nr, 0, 0, 0)
}

// rawErrno issues a syscall the caller expects to fail, and leaves immediately if it
// turns out to have succeeded in a child. That branch is only reachable when the filter
// regressed, and it has to return to the kernel without touching the Go runtime: under
// vfork this child is running on the parent's stack, which stays suspended until it goes.
func rawErrno(nr, a1, a2, a3 uintptr) unix.Errno {
	r1, _, errno := unix.RawSyscall(nr, a1, a2, a3)
	if errno == 0 && r1 == 0 {
		_, _, _ = unix.RawSyscall(unix.SYS_EXIT, 0, 0, 0)
	}
	return errno
}
