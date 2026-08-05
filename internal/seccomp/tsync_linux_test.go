//go:build linux

package seccomp

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// A seccomp filter is installed per THREAD. The Go runtime schedules the target's
// launch across whatever OS threads it already has, so a filter that reached only the
// installing thread would leave every sibling able to execve - the exec-block would be
// a hole, silently, on a host where it reports Enforced. TSYNC is what makes the
// filter cover them, and its failure mode is quiet: without the ESRCH flag a partial
// sync returns the offending TID with errno 0, which the library reads as success.
//
// This drives a sibling thread that exists BEFORE the install and is not the
// installing thread, so nothing but a working TSYNC can produce the denial. The
// filter is process-wide and permanent, so it runs in a re-exec'd child.
func TestExecBlockCoversPreexistingThreads(t *testing.T) {
	cmd := helperCommand(t, "TestExecBlockCoversPreexistingThreadsHelper", "BENTO_TEST_TSYNC=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("tsync helper exited with error: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "TSYNC_OK") {
		t.Errorf("helper did not confirm the filter reached a pre-existing sibling thread:\n%s", out)
	}
}

// TestExecBlockCoversPreexistingThreadsHelper is the child half: it pins a sibling
// thread, probes execve there before and after installing the filter, and exits
// nonzero (with a tag) on any mismatch. Inert unless the parent set the trigger env
// var.
func TestExecBlockCoversPreexistingThreadsHelper(t *testing.T) {
	if os.Getenv("BENTO_TEST_TSYNC") != "1" {
		t.Skip("child helper for TestExecBlockCoversPreexistingThreads")
	}
	// Pin this goroutine too, so the installing thread's identity is stable and the
	// sibling below is provably a different one.
	runtime.LockOSThread()
	installer := unix.Gettid()

	probe, result, ready := make(chan struct{}), make(chan unix.Errno), make(chan int)
	go func() {
		runtime.LockOSThread()
		ready <- unix.Gettid()
		for range probe {
			result <- execveErrno()
		}
	}()
	sibling := <-ready
	if sibling == installer {
		fmt.Println("SAME_THREAD", sibling)
		os.Exit(3)
	}

	// The positive control, on the very thread the assertion below uses: before the
	// filter exists this thread CAN reach execve, so the later denial is caused by the
	// filter rather than by anything intrinsic to a locked sibling thread.
	probe <- struct{}{}
	if errno := <-result; errno != unix.ENOENT {
		fmt.Println("CONTROL_NOT_ENOENT", errno)
		os.Exit(4)
	}

	if err := BlockExec(); err != nil {
		fmt.Println("BLOCKEXEC_ERR", err)
		os.Exit(5)
	}

	probe <- struct{}{}
	if errno := <-result; errno != unix.EPERM {
		fmt.Println("SIBLING_NOT_EPERM", errno)
		os.Exit(6)
	}
	fmt.Println("TSYNC_OK")
}

// execveErrno attempts execve on a path that does not exist and reports the errno.
// The kernel would resolve that path to ENOENT, so EPERM can only have come from the
// filter, and ENOENT proves the calling thread reached the kernel unfiltered.
func execveErrno() unix.Errno {
	path, err := unix.BytePtrFromString("/nonexistent-bento-tsync-probe")
	if err != nil {
		return 0
	}
	_, _, errno := unix.Syscall(unix.SYS_EXECVE, uintptr(unsafe.Pointer(path)), 0, 0)
	return errno
}
