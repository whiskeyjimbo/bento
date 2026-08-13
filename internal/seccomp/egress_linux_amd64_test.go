//go:build linux && amd64

package seccomp

import (
	"fmt"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/whiskeyjimbo/bento/internal/i386"
)

// egressFilter repeats the none-strict filter's arch-and-x32 preamble as its own
// hand-counted jump table, so the strict filter's tests do not cover it. It matters more
// here than there: in the degraded tier this filter is the ONLY egress fence, and an
// off-by-one in either kill arm turns an i386 int 0x80 socket() into a default-allow that
// nothing else reports.
//
// Like the strict pair, both assert SIGSYS without pinning the kill's scope;
// TestKillProcessActionIsAvailable is what checks the host is on the KILL_PROCESS side.
func TestEgressFilterKillsForeignArchSyscall(t *testing.T) {
	if !Supported() {
		t.Skip("seccomp not supported on this kernel")
	}
	if !EgressSupported() {
		t.Skip("egress filter not implemented for this architecture")
	}
	sig, out := runKilledHelper(t, "TestEgressFilterKillsForeignArchSyscallHelper", "BENTO_TEST_EGRESS_ARCH=1")
	if sig != syscall.SIGSYS {
		t.Fatalf("an i386 syscall under the egress filter died on %v, want SIGSYS from the arch check:\n%s", sig, out)
	}
}

// TestEgressFilterKillsForeignArchSyscallHelper is the child half: it installs the filter
// and issues one i386 getpid, which must not return.
func TestEgressFilterKillsForeignArchSyscallHelper(t *testing.T) {
	if os.Getenv("BENTO_TEST_EGRESS_ARCH") != "1" {
		t.Skip("child helper for TestEgressFilterKillsForeignArchSyscall")
	}
	if err := BlockEgress(); err != nil {
		fmt.Println("BLOCKEGRESS_ERR", err)
		os.Exit(3)
	}
	i386.Getpid()
	fmt.Println("ARCH_SURVIVED")
	os.Exit(4)
}

// x32 shares the amd64 audit arch but tags its syscall numbers, so a tagged socket()
// would miss nrSocket's equality check and reach the trailing allow - the domain
// allowlist bypassed entirely. The filter kills on the tag before any per-syscall check,
// so the probe uses a harmless getpid: the tag branch is what is under test.
func TestEgressFilterKillsX32Syscalls(t *testing.T) {
	if !Supported() {
		t.Skip("seccomp not supported on this kernel")
	}
	if !EgressSupported() {
		t.Skip("egress filter not implemented for this architecture")
	}
	sig, out := runKilledHelper(t, "TestEgressFilterKillsX32SyscallsHelper", "BENTO_TEST_EGRESS_X32=1")
	if sig != syscall.SIGSYS {
		t.Fatalf("an x32-tagged syscall under the egress filter died on %v, want SIGSYS:\n%s", sig, out)
	}
}

// TestEgressFilterKillsX32SyscallsHelper is the child half: it installs the filter and
// issues one x32-tagged syscall, which must not return.
func TestEgressFilterKillsX32SyscallsHelper(t *testing.T) {
	if os.Getenv("BENTO_TEST_EGRESS_X32") != "1" {
		t.Skip("child helper for TestEgressFilterKillsX32Syscalls")
	}
	if err := BlockEgress(); err != nil {
		fmt.Println("BLOCKEGRESS_ERR", err)
		os.Exit(3)
	}
	_, _, _ = unix.RawSyscall(x32SyscallTag|unix.SYS_GETPID, 0, 0, 0)
	fmt.Println("X32_SURVIVED")
	os.Exit(4)
}
