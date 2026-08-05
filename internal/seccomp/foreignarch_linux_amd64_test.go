//go:build linux && amd64

package seccomp

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	seccomp "github.com/elastic/go-seccomp-bpf"
	"golang.org/x/sys/unix"

	"github.com/whiskeyjimbo/bento/internal/i386"
)

// runForeignArchHelper runs one of the helpers below in a child (the filters are
// process-wide and permanent) and reports how it died. The shared harness carries the
// wait-status reading and the no-ia32-entry-point skip.
func runForeignArchHelper(t *testing.T, which string) (syscall.Signal, string) {
	t.Helper()
	return runKilledHelper(t, "TestForeignArchHelper", "BENTO_TEST_FOREIGN_ARCH="+which)
}

// The library-backed filters (BlockIoUring, BlockExec, BlockProcessReach) match
// syscalls by their amd64 numbers and default-allow everything else, so a syscall
// issued through the i386 compat ABI reaches the allow path - that is the bypass
// blockForeignArch closes, and until now nothing exercised it. The guard must kill
// the process on `int 0x80`, and the control below must show the same instruction
// surviving the library filter alone, or this test would only be proving that a
// kill filter kills.
//
// Together the pair also pins the multi-filter action precedence the guard depends on:
// two filters are installed and the most severe verdict wins, so the guard's kill must
// outrank the library filter's trailing SECCOMP_RET_ALLOW. The control arm is what shows
// that, since it is the same library filter without the companion.
//
// What the pair does NOT pin is the kill SCOPE. It asserts SIGSYS, which a kill-thread
// and a kill-process verdict both produce in a single-threaded child, and no kernel this
// project runs on is old enough for the two to diverge. TestKillProcessActionIsAvailable
// covers that separately by asking the kernel rather than by observing a death.
func TestForeignArchGuardKillsCompatSyscall(t *testing.T) {
	if !Supported() {
		t.Skip("seccomp not supported on this kernel")
	}
	sig, out := runForeignArchHelper(t, "guard")
	if sig != syscall.SIGSYS {
		t.Fatalf("an i386 syscall under BlockIoUring died on %v, want SIGSYS from the foreign-arch filter:\n%s", sig, out)
	}
}

// The control: with only the library-assembled policy installed - the same filter
// BlockIoUring installs, minus the foreign-arch companion - the i386 syscall must
// go through. A failure here means the compat ABI stopped reaching the default-allow
// on its own, and the guard above is no longer the thing being tested.
func TestForeignArchBypassExistsWithoutTheGuard(t *testing.T) {
	if !Supported() {
		t.Skip("seccomp not supported on this kernel")
	}
	sig, out := runForeignArchHelper(t, "control")
	if sig != 0 {
		t.Fatalf("the control helper died on %v; the library filter alone should let an i386 syscall through:\n%s", sig, out)
	}
	if !strings.Contains(out, "CONTROL_SURVIVED") {
		t.Errorf("control helper did not reach the syscall:\n%s", out)
	}
}

// TestForeignArchHelper is the child half of both tests above. It issues an i386
// getpid and, if it is still running afterwards, says so - the guard case reads that
// as a failure and the control case as the expected bypass. Inert unless the parent
// selected a mode.
func TestForeignArchHelper(t *testing.T) {
	switch os.Getenv("BENTO_TEST_FOREIGN_ARCH") {
	case "guard":
		// BlockIoUring rather than blockForeignArch directly: it is the call the
		// profiling path makes, so this pins the guard where a caller actually gets it.
		if err := BlockIoUring(); err != nil {
			fmt.Println("BLOCKIOURING_ERR", err)
			os.Exit(3)
		}
		i386.Getpid()
		fmt.Println("GUARD_SURVIVED")
		os.Exit(4)
	case "control":
		if err := installPolicy(seccomp.Policy{
			DefaultAction: seccomp.ActionAllow,
			Syscalls: []seccomp.SyscallGroup{
				{Action: seccomp.ActionErrno, Names: []string{"io_uring_setup", "io_uring_enter", "io_uring_register"}},
			},
		}, "io_uring block"); err != nil {
			fmt.Println("INSTALLPOLICY_ERR", err)
			os.Exit(3)
		}
		i386.Getpid()
		fmt.Println("CONTROL_SURVIVED")
	default:
		t.Skip("child helper for the foreign-arch tests")
	}
}

// TestKillProcessActionIsAvailable asks the kernel whether the action every filter in
// this package returns for a foreign arch is the one it claims to return. Below kernel
// 4.14 SECCOMP_RET_KILL_PROCESS does not exist and 0x80000000 masks down to
// SECCOMP_RET_KILL_THREAD, so the block still holds but only the offending thread dies.
//
// The tests above cannot tell those apart: a single-threaded child dies either way, and
// no kernel this project's CI runs is old enough to diverge. SECCOMP_GET_ACTION_AVAIL
// answers it directly and without parsing a version, which backports make unreliable.
// A pre-4.14 kernel does not have the operation at all, so it fails there too - which is
// the same answer.
func TestKillProcessActionIsAvailable(t *testing.T) {
	action := uint32(seccompRetKillProcess)
	_, _, e := unix.Syscall(unix.SYS_SECCOMP, seccompGetActionAvail, 0, uintptr(unsafe.Pointer(&action)))
	switch e {
	case 0:
	case unix.EINVAL:
		// The operation itself is missing, which dates the kernel below 4.14. Skipping is
		// the honest answer: an old kernel is supported, and the degradation is a narrowing
		// of the kill's scope rather than a defect.
		t.Skipf("this kernel has no SECCOMP_GET_ACTION_AVAIL, so it predates SECCOMP_RET_KILL_PROCESS and the foreign-arch guard kills the offending thread rather than the process; the block holds, its scope does not")
	default:
		// The operation exists and rejected the value, so the kernel is new enough and the
		// constant is not an action it recognizes. Skipping that would hide a typo in a
		// filter's kill verdict behind a message about old kernels.
		t.Fatalf("the kernel has SECCOMP_GET_ACTION_AVAIL but does not recognize %#x as an action (%v); the value every filter here returns for a foreign arch is wrong", seccompRetKillProcess, e)
	}
}
