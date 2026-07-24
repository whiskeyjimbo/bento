//go:build linux

package launcher

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/whiskeyjimbo/bento-v2/internal/seccomp"
)

// sentinelInstallFilter re-execs the test binary as the sacrificial child that
// installs a real, permanent seccomp filter and probes it.
const sentinelInstallFilter = "BENTO_TEST_INSTALL_FILTER"

// installExecFilter installs the STRONGEST block the policy asks for and the arch
// provides: none-strict gets the fork-blocking filter where StrictExecSupported, and
// falls back to the execve-only block elsewhere. On amd64 the fallback branch is
// unreachable, so a regression there - refusing, or installing nothing - would be
// invisible. This forces the strictExecSupported seam off to reach it and proves the
// fallback still installs a working block (execve denied) and that it is the non-strict
// one (fork allowed), with the real strict path as the positive control.
//
// It runs in child processes because the filter is process-wide and permanent. A
// process-creating clone is the only behavioral difference between the two filters, so
// nothing but running one can tell them apart.
func TestInstallExecFilterFallsBackWhenStrictUnsupported(t *testing.T) {
	if mode := os.Getenv(sentinelInstallFilter); mode != "" {
		installFilterChild(mode)
		return
	}

	t.Run("fallback installs the execve-only block", func(t *testing.T) {
		out := runInstallFilterChild(t, "fallback")
		if !strings.Contains(out, "EXECVE_BLOCKED") {
			t.Errorf("the fallback installed no exec block (execve was not denied): %q", out)
		}
		if !strings.Contains(out, "FORK_OK") {
			t.Errorf("the fallback installed the STRICT filter (fork was blocked) instead of the execve-only block: %q", out)
		}
	})

	t.Run("strict control blocks fork", func(t *testing.T) {
		if !seccomp.StrictExecSupported() {
			t.Skip("no strict filter on this arch, so the fork-blocking control cannot run")
		}
		out := runInstallFilterChild(t, "strict")
		if !strings.Contains(out, "FORK_BLOCKED") {
			t.Errorf("with strict supported installExecFilter did not install the fork-blocking filter: %q", out)
		}
	})
}

func runInstallFilterChild(t *testing.T, mode string) string {
	t.Helper()
	parent := t.Name()[:strings.Index(t.Name(), "/")]
	cmd := exec.Command(os.Args[0], "-test.run", "^"+parent+"$")
	cmd.Env = append(os.Environ(), sentinelInstallFilter+"="+mode)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s child failed: %v\n%s", mode, err, out)
	}
	return string(out)
}

// installFilterChild installs the filter installExecFilter(strict=true) chooses and
// reports how it behaves. In "fallback" mode it forces strictExecSupported off first,
// so installExecFilter must take the execve-only path even though this arch has the
// strict filter. It prints nothing on the paths that must not happen (a filter that
// installs nothing lets execve reach ENOENT; the parent's assertion then fails).
func installFilterChild(mode string) {
	if mode == "fallback" {
		strictExecSupported = func() bool { return false }
	}
	if err := installExecFilter(true); err != nil {
		os.Stdout.WriteString("INSTALL_ERR " + err.Error() + "\n")
		return
	}

	// execve a path that does not exist: EPERM proves the filter denied it before the
	// kernel resolved the path; ENOENT proves execve reached resolution, so no block was
	// installed at all.
	if path, err := unix.BytePtrFromString("/nonexistent-bento-installfilter-probe"); err == nil {
		_, _, errno := unix.Syscall(unix.SYS_EXECVE, uintptr(unsafe.Pointer(path)), 0, 0)
		switch errno {
		case unix.EPERM:
			os.Stdout.WriteString("EXECVE_BLOCKED\n")
		case unix.ENOENT:
			os.Stdout.WriteString("EXECVE_OPEN\n")
		default:
			os.Stdout.WriteString("EXECVE_ERRNO " + errno.Error() + "\n")
		}
	}

	// A process-creating clone (SIGCHLD, no CLONE_THREAD) is fork: the strict filter
	// blocks it, the execve-only block allows it. RawSyscall avoids the scheduler hooks
	// that are unsafe in a forked child, which exits immediately without touching the Go
	// runtime.
	r, _, errno := syscall.RawSyscall(syscall.SYS_CLONE, uintptr(syscall.SIGCHLD), 0, 0)
	if errno != 0 {
		os.Stdout.WriteString("FORK_BLOCKED\n")
		return
	}
	if r == 0 {
		syscall.RawSyscall(syscall.SYS_EXIT, 0, 0, 0)
	}
	syscall.Wait4(int(r), nil, 0, nil)
	os.Stdout.WriteString("FORK_OK\n")
}
