//go:build linux && amd64

package seccomp

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/whiskeyjimbo/bento/internal/i386"
)

// TestBlockTerminalInjection proves the filter refuses the terminal-injection ioctls
// at the kernel: TIOCSTI and TIOCLINUX return EPERM (the filter's own errno, distinct
// from the ENOTTY/EIO a non-tty fd or a legacy-disabled kernel would give, so the test
// has teeth regardless of the host's dev.tty.legacy_tiocsti setting) while an ordinary
// ioctl still works. The filter is process-wide and permanent, so it runs in a
// re-exec'd child rather than poisoning the test process.
func TestBlockTerminalInjection(t *testing.T) {
	cmd := helperCommand(t, "TestBlockTerminalInjectionHelper", "BENTO_TEST_BLOCK_TIOCSTI=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("terminal-injection helper exited with error: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "TIOCSTI_OK") {
		t.Errorf("terminal-injection helper did not confirm enforcement:\n%s", out)
	}
}

// TestBlockTerminalInjectionHelper is the child half: it installs the filter and
// probes the blocked and allowed ioctls, exiting nonzero (with a tag) on any mismatch.
// It is inert unless the parent set the trigger env var.
func TestBlockTerminalInjectionHelper(t *testing.T) {
	if os.Getenv("BENTO_TEST_BLOCK_TIOCSTI") != "1" {
		t.Skip("child helper for TestBlockTerminalInjection")
	}
	if err := BlockTerminalInjection(); err != nil {
		fmt.Println("BLOCKTIOCSTI_ERR", err)
		os.Exit(3)
	}
	// A byte the target would want to inject. The syscall must be refused before the
	// kernel ever reads it, so its value does not matter.
	var b byte = 'x'
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, 0, tiocsti, uintptr(unsafe.Pointer(&b))); errno != unix.EPERM {
		fmt.Println("TIOCSTI_NOT_EPERM", errno)
		os.Exit(4)
	}
	var arg byte = 2 // TIOCL_PASTESEL: paste the console selection as input
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, 0, tioclinux, uintptr(unsafe.Pointer(&arg))); errno != unix.EPERM {
		fmt.Println("TIOCLINUX_NOT_EPERM", errno)
		os.Exit(5)
	}
	// An unrelated ioctl must still reach the kernel (not be EPERM'd by the filter).
	// TIOCGWINSZ (0x5413) sits right next to TIOCSTI (0x5412), so a not-EPERM here also
	// proves the filter matches the exact request rather than a range. On the invalid
	// fd 500 the kernel returns EBADF, which is proof it dispatched the ioctl.
	var ws unix.Winsize
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, 500, unix.TIOCGWINSZ, uintptr(unsafe.Pointer(&ws))); errno == unix.EPERM {
		fmt.Println("TIOCGWINSZ_WRONGLY_BLOCKED", errno)
		os.Exit(6)
	}
	fmt.Println("TIOCSTI_OK")
}

// terminalInjectionFilter carries its own copy of the arch-and-x32 preamble - the same
// hand-counted jump table as the egress and none-strict filters, tested separately
// because an off-by-one in one copy says nothing about the others. Here the bypass is a
// TIOCSTI issued through the i386 compat ABI or with an x32-tagged ioctl number, either
// of which would miss nrIoctl and reach the trailing allow.
//
// As with those, SIGSYS is asserted without pinning the kill's scope;
// TestKillProcessActionIsAvailable checks the host is on the KILL_PROCESS side.
func TestTerminalFilterKillsForeignArchSyscall(t *testing.T) {
	if !Supported() {
		t.Skip("seccomp not supported on this kernel")
	}
	sig, out := runKilledHelper(t, "TestTerminalFilterKillsForeignArchSyscallHelper", "BENTO_TEST_TIOCSTI_ARCH=1")
	if sig != syscall.SIGSYS {
		t.Fatalf("an i386 syscall under the terminal filter died on %v, want SIGSYS from the arch check:\n%s", sig, out)
	}
}

// TestTerminalFilterKillsForeignArchSyscallHelper is the child half: it installs the
// filter and issues one i386 getpid, which must not return.
func TestTerminalFilterKillsForeignArchSyscallHelper(t *testing.T) {
	if os.Getenv("BENTO_TEST_TIOCSTI_ARCH") != "1" {
		t.Skip("child helper for TestTerminalFilterKillsForeignArchSyscall")
	}
	if err := BlockTerminalInjection(); err != nil {
		fmt.Println("BLOCKTIOCSTI_ERR", err)
		os.Exit(3)
	}
	i386.Getpid()
	fmt.Println("ARCH_SURVIVED")
	os.Exit(4)
}

// The x32 arm, tested with a harmless getpid for the reason the egress and strict pairs
// use one: the kill happens on the tag itself, before any per-syscall check, so a
// regression shows as a surviving getpid rather than needing a real injection attempt.
func TestTerminalFilterKillsX32Syscalls(t *testing.T) {
	if !Supported() {
		t.Skip("seccomp not supported on this kernel")
	}
	sig, out := runKilledHelper(t, "TestTerminalFilterKillsX32SyscallsHelper", "BENTO_TEST_TIOCSTI_X32=1")
	if sig != syscall.SIGSYS {
		t.Fatalf("an x32-tagged syscall under the terminal filter died on %v, want SIGSYS:\n%s", sig, out)
	}
}

// TestTerminalFilterKillsX32SyscallsHelper is the child half: it installs the filter and
// issues one x32-tagged syscall, which must not return.
func TestTerminalFilterKillsX32SyscallsHelper(t *testing.T) {
	if os.Getenv("BENTO_TEST_TIOCSTI_X32") != "1" {
		t.Skip("child helper for TestTerminalFilterKillsX32Syscalls")
	}
	if err := BlockTerminalInjection(); err != nil {
		fmt.Println("BLOCKTIOCSTI_ERR", err)
		os.Exit(3)
	}
	_, _, _ = unix.RawSyscall(x32SyscallTag|unix.SYS_GETPID, 0, 0, 0)
	fmt.Println("X32_SURVIVED")
	os.Exit(4)
}
