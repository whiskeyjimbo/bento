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

	seccomp "github.com/elastic/go-seccomp-bpf"

	"github.com/whiskeyjimbo/bento/internal/i386"
)

// runForeignArchHelper runs one of the helpers below in a child (the filters are
// process-wide and permanent) and reports how it died: the signal if it was killed,
// or 0 if it exited on its own. It skips the calling test on a kernel with no ia32
// entry point, where `int 0x80` raises SIGSEGV and reaches no filter at all.
//
// That skip reads the child's OUTPUT, not its wait status, because the fault lands
// inside Go code: the runtime catches SIGSEGV, prints a fatal-error dump and exits 2
// UNSIGNALED, so a wait-status check for SIGSEGV never fires and the test would fail
// on every such host instead of skipping. A seccomp kill is not interceptable that
// way - SECCOMP_RET_KILL_PROCESS is not deliverable - so SIGSYS still arrives as a
// signal.
func runForeignArchHelper(t *testing.T, which string) (syscall.Signal, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestForeignArchHelper", "-test.v")
	cmd.Env = append(os.Environ(), "BENTO_TEST_FOREIGN_ARCH="+which)
	out, err := cmd.CombinedOutput()
	if strings.Contains(string(out), "signal SIGSEGV") {
		t.Skip("kernel has no ia32 compat entry point (CONFIG_IA32_EMULATION off or ia32_emulation=0), so no foreign-arch syscall can be issued")
	}
	if err == nil {
		return 0, string(out)
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("%s helper: %v\n%s", which, err, out)
	}
	ws, ok := ee.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() {
		t.Fatalf("%s helper exited %d rather than dying on a signal:\n%s", which, ee.ExitCode(), out)
	}
	return ws.Signal(), string(out)
}

// The library-backed filters (BlockIoUring, BlockExec, BlockProcessReach) match
// syscalls by their amd64 numbers and default-allow everything else, so a syscall
// issued through the i386 compat ABI reaches the allow path - that is the bypass
// blockForeignArch closes, and until now nothing exercised it. The guard must kill
// the process on `int 0x80`, and the control below must show the same instruction
// surviving the library filter alone, or this test would only be proving that a
// kill filter kills.
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
