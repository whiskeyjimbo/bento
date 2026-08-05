//go:build linux

package seccomp

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestBlockProcessReach proves the cross-process block EPERMs the reach syscalls
// (ptrace, pidfd_getfd) while leaving pidfd_open working - Go's os/exec uses
// pidfd_open + pidfd_send_signal to manage a child, so over-blocking the pidfd family
// would break the launcher's own exec:all supervise path. It runs in a re-exec'd
// child because the filter is process-wide and permanent.
func TestBlockProcessReach(t *testing.T) {
	cmd := helperCommand(t, "TestBlockProcessReachHelper", "BENTO_TEST_BLOCK_PROCESS_REACH=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("process-reach helper exited with error: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PROCESS_REACH_OK") {
		t.Errorf("helper did not confirm the block:\n%s", out)
	}
}

func TestBlockProcessReachHelper(t *testing.T) {
	if os.Getenv("BENTO_TEST_BLOCK_PROCESS_REACH") != "1" {
		t.Skip("child helper for TestBlockProcessReach")
	}
	if err := BlockProcessReach(); err != nil {
		fmt.Println("BLOCKPROCESSREACH_ERR", err)
		os.Exit(3)
	}
	// ptrace must be refused with EPERM: PTRACE_TRACEME normally returns 0 on self.
	if _, _, errno := unix.Syscall(unix.SYS_PTRACE, uintptr(unix.PTRACE_TRACEME), 0, 0); errno != unix.EPERM {
		fmt.Println("PTRACE_NOT_EPERM", errno)
		os.Exit(4)
	}
	// pidfd_getfd (fd theft) must be EPERM, not the EBADF an unfiltered bad-arg call
	// would give - proving the filter fired, not the kernel's arg check.
	if _, _, errno := unix.Syscall(unix.SYS_PIDFD_GETFD, 0, 0, 0); errno != unix.EPERM {
		fmt.Println("PIDFD_GETFD_NOT_EPERM", errno)
		os.Exit(5)
	}
	// process_madvise (cross-process page eviction) must be EPERM too.
	if _, _, errno := unix.Syscall6(unix.SYS_PROCESS_MADVISE, 0, 0, 0, 0, 0, 0); errno != unix.EPERM {
		fmt.Println("PROCESS_MADVISE_NOT_EPERM", errno)
		os.Exit(7)
	}
	// move_pages (a NULL-nodes page-residency oracle) must be EPERM, not the EFAULT/
	// EINVAL an unfiltered zero-arg call would give - proving the filter fired.
	if _, _, errno := unix.Syscall6(unix.SYS_MOVE_PAGES, 0, 0, 0, 0, 0, 0); errno != unix.EPERM {
		fmt.Println("MOVE_PAGES_NOT_EPERM", errno)
		os.Exit(8)
	}
	// get_robust_list (robust-futex head-pointer disclosure) must be EPERM, not the
	// EFAULT an unfiltered null-pointer call would give.
	if _, _, errno := unix.Syscall(unix.SYS_GET_ROBUST_LIST, 0, 0, 0); errno != unix.EPERM {
		fmt.Println("GET_ROBUST_LIST_NOT_EPERM", errno)
		os.Exit(9)
	}
	// process_vm_readv / process_vm_writev (cross-process memory read/write) must be
	// EPERM, not the ESRCH/EFAULT an unfiltered zero-arg call would give.
	if _, _, errno := unix.Syscall6(unix.SYS_PROCESS_VM_READV, 0, 0, 0, 0, 0, 0); errno != unix.EPERM {
		fmt.Println("PROCESS_VM_READV_NOT_EPERM", errno)
		os.Exit(10)
	}
	if _, _, errno := unix.Syscall6(unix.SYS_PROCESS_VM_WRITEV, 0, 0, 0, 0, 0, 0); errno != unix.EPERM {
		fmt.Println("PROCESS_VM_WRITEV_NOT_EPERM", errno)
		os.Exit(11)
	}
	// kcmp (a same-process/same-fd comparison oracle) must be EPERM.
	if _, _, errno := unix.Syscall6(unix.SYS_KCMP, 0, 0, 0, 0, 0, 0); errno != unix.EPERM {
		fmt.Println("KCMP_NOT_EPERM", errno)
		os.Exit(12)
	}
	// perf_event_open (samples another process's instruction pointers) must be EPERM,
	// not the EFAULT an unfiltered null-attr call would give.
	if _, _, errno := unix.Syscall6(unix.SYS_PERF_EVENT_OPEN, 0, 0, 0, 0, 0, 0); errno != unix.EPERM {
		fmt.Println("PERF_EVENT_OPEN_NOT_EPERM", errno)
		os.Exit(13)
	}
	// pidfd_open must STILL work: Go's child management depends on it, so it must not
	// be caught by the block.
	fd, _, errno := unix.Syscall(unix.SYS_PIDFD_OPEN, uintptr(os.Getpid()), 0, 0)
	if errno != 0 {
		fmt.Println("PIDFD_OPEN_BLOCKED", errno)
		os.Exit(6)
	}
	unix.Close(int(fd))
	fmt.Println("PROCESS_REACH_OK")
}
