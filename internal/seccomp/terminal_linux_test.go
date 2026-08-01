//go:build linux && amd64

package seccomp

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestBlockTerminalInjection proves the filter refuses the terminal-injection ioctls
// at the kernel: TIOCSTI and TIOCLINUX return EPERM (the filter's own errno, distinct
// from the ENOTTY/EIO a non-tty fd or a legacy-disabled kernel would give, so the test
// has teeth regardless of the host's dev.tty.legacy_tiocsti setting) while an ordinary
// ioctl still works. The filter is process-wide and permanent, so it runs in a
// re-exec'd child rather than poisoning the test process.
func TestBlockTerminalInjection(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestBlockTerminalInjectionHelper", "-test.v")
	cmd.Env = append(os.Environ(), "BENTO_TEST_BLOCK_TIOCSTI=1")
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
	os.Exit(0)
}
