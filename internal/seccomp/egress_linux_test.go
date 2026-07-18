//go:build linux

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

// TestBlockEgress proves the filter actually enforces at the kernel: an INET/INET6
// socket is refused with EPERM while AF_UNIX and AF_NETLINK still work. Because the
// filter is process-wide and permanent, it runs in a re-exec'd child (the helper
// below) rather than poisoning the test process.
func TestBlockEgress(t *testing.T) {
	if !EgressSupported() {
		t.Skip("egress filter not implemented for this architecture")
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestBlockEgressHelper", "-test.v")
	cmd.Env = append(os.Environ(), "BENTO_TEST_BLOCK_EGRESS=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("egress helper exited with error: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "EGRESS_OK") {
		t.Errorf("egress helper did not confirm enforcement:\n%s", out)
	}
}

// TestBlockEgressHelper is the child half of TestBlockEgress: it installs the filter
// and probes each address family, exiting nonzero (with a tag) on any mismatch. It is
// inert unless the parent set the trigger env var.
func TestBlockEgressHelper(t *testing.T) {
	if os.Getenv("BENTO_TEST_BLOCK_EGRESS") != "1" {
		t.Skip("child helper for TestBlockEgress")
	}
	if err := BlockEgress(); err != nil {
		fmt.Println("BLOCKEGRESS_ERR", err)
		os.Exit(3)
	}
	// AF_UNIX (local IPC) and AF_NETLINK (kernel IPC, NETLINK_ROUTE) must still work.
	if fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0); err != nil {
		fmt.Println("AF_UNIX_BLOCKED", err)
		os.Exit(4)
	} else {
		unix.Close(fd)
	}
	if fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE); err != nil {
		fmt.Println("AF_NETLINK_BLOCKED", err)
		os.Exit(4)
	} else {
		unix.Close(fd)
	}
	// The wire families must be refused with EPERM, not merely fail for another reason.
	if _, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0); err != unix.EPERM {
		fmt.Println("AF_INET_NOT_EPERM", err)
		os.Exit(5)
	}
	if _, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0); err != unix.EPERM {
		fmt.Println("AF_INET6_NOT_EPERM", err)
		os.Exit(5)
	}
	// io_uring_setup must be refused: io_uring can dispatch socket/connect past a
	// socket()-only filter, so leaving it open would be an egress bypass. The filter
	// EPERMs it before the kernel reads params, so a zeroed buffer pointer suffices.
	var params [128]byte
	if _, _, errno := unix.Syscall(unix.SYS_IO_URING_SETUP, 1, uintptr(unsafe.Pointer(&params[0])), 0); errno != unix.EPERM {
		fmt.Println("IO_URING_NOT_EPERM", errno)
		os.Exit(6)
	}
	fmt.Println("EGRESS_OK")
	os.Exit(0)
}
