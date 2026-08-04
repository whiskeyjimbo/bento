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

// TestBlockIoUring proves the filter refuses io_uring_setup at the kernel with EPERM,
// so a target cannot create a ring whose file operations would escape the ptrace
// observer. The filter is process-wide and permanent, so it runs in a re-exec'd child.
func TestBlockIoUring(t *testing.T) {
	cmd := helperCommand(t, "TestBlockIoUringHelper", "BENTO_TEST_BLOCK_IOURING=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("io_uring helper exited with error: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "IOURING_OK") {
		t.Errorf("io_uring helper did not confirm enforcement:\n%s", out)
	}
}

// TestBlockIoUringHelper is the child half: it installs the filter and confirms
// io_uring_setup is refused with EPERM. Inert unless the parent set the trigger.
func TestBlockIoUringHelper(t *testing.T) {
	if os.Getenv("BENTO_TEST_BLOCK_IOURING") != "1" {
		t.Skip("child helper for TestBlockIoUring")
	}
	if err := BlockIoUring(); err != nil {
		fmt.Println("BLOCKIOURING_ERR", err)
		os.Exit(3)
	}
	// The filter EPERMs io_uring_setup before the kernel reads params, so a zeroed
	// buffer suffices. EPERM is the filter's errno; without it the kernel returns 0 (a
	// ring fd) or ENOSYS on a kernel lacking io_uring - never EPERM - so the check has
	// teeth regardless of host support.
	var params [128]byte
	if _, _, errno := unix.Syscall(unix.SYS_IO_URING_SETUP, 1, uintptr(unsafe.Pointer(&params[0])), 0); errno != unix.EPERM {
		fmt.Println("IOURING_SETUP_NOT_EPERM", errno)
		os.Exit(4)
	}
	fmt.Println("IOURING_OK")
}
