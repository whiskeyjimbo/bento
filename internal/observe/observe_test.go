package observe

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func find(res Result, path string) (Access, bool) {
	for _, a := range res.Accesses {
		if a.Path == path {
			return a, true
		}
	}
	return Access{}, false
}

// The observer must see the files a program opens (distinguishing read from
// write) and notice when it spawns a subprocess. It runs a real shell script and
// checks the observations against what the script did.
func TestTraceObservesOpensAndExec(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}

	dir := t.TempDir()
	readable := filepath.Join(dir, "input.txt")
	if err := os.WriteFile(readable, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	written := filepath.Join(dir, "output.txt")

	// Read one file, write another, and spawn a subprocess (the `true` binary).
	script := "cat " + readable + " > /dev/null; echo hi > " + written + "; true\n"
	sh, _ := exec.LookPath("sh")

	res, err := Trace([]string{sh, "-c", script}, os.Environ(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}

	if a, ok := find(res, readable); !ok {
		t.Errorf("did not observe the read of %s", readable)
	} else if a.Write {
		t.Errorf("%s was read, but observed as a write", readable)
	}

	if a, ok := find(res, written); !ok {
		t.Errorf("did not observe the write of %s", written)
	} else if !a.Write {
		t.Errorf("%s was written, but observed as read-only", written)
	}

	if !res.Execed {
		t.Error("the script spawned `true` but no exec was observed")
	}
}

// A path opened relative to a real directory descriptor (openat with a dirfd,
// not AT_FDCWD) must be anchored at that directory, not left bare - otherwise the
// profiler would anchor it at the working directory and grant the wrong path.
func TestTraceResolvesOpenatDirfd(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "viadir.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Open the directory, then open the file relative to that descriptor.
	script := fmt.Sprintf("import os\nd=os.open(%q,os.O_RDONLY)\nos.close(os.open('viadir.txt',os.O_RDONLY,dir_fd=d))\n", dir)

	res, err := Trace([]string{py, "-c", script}, os.Environ(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}

	var anchored bool
	for _, a := range res.Accesses {
		if a.Path == "viadir.txt" {
			t.Errorf("dirfd-relative open recorded bare-relative, not anchored: %q", a.Path)
		}
		if strings.HasPrefix(a.Path, "/") && strings.HasSuffix(a.Path, "/viadir.txt") {
			anchored = true
		}
	}
	if !anchored {
		t.Errorf("dirfd-relative open was not anchored to an absolute path; accesses: %v", res.Accesses)
	}
}

// openat2 (syscall 437) must be decoded like openat, or a program that uses it
// (Rust std, systemd tools) profiles as touching nothing.
func TestTraceDecodesOpenat2(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "via_openat2.txt")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf(`import ctypes, struct, os
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
how = struct.pack("QQQ", os.O_RDONLY, 0, 0)  # struct open_how {flags, mode, resolve}
buf = ctypes.create_string_buffer(how, len(how))
fd = libc.syscall(ctypes.c_long(437), ctypes.c_long(-100), %q.encode(), buf, ctypes.c_size_t(len(how)))
if fd < 0:
    raise SystemExit("openat2 unsupported")
os.close(fd)
`, target)

	res, err := Trace([]string{py, "-c", script}, os.Environ(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}
	if res.ExitCode != 0 {
		t.Skipf("openat2 not usable on this host (exit %d)", res.ExitCode)
	}
	if _, ok := find(res, target); !ok {
		t.Errorf("openat2 open was not observed; accesses: %v", res.Accesses)
	}
}

func TestResolveAtPassthroughAndDrop(t *testing.T) {
	// An absolute path, a working-directory-relative path, and an empty path are
	// returned unchanged; the profiler anchors the AT_FDCWD case itself.
	if got := resolveAt(0, atFdCwd, "rel/x"); got != "rel/x" {
		t.Errorf("AT_FDCWD: got %q, want the path unchanged", got)
	}
	if got := resolveAt(0, 5, "/abs/x"); got != "/abs/x" {
		t.Errorf("absolute: got %q, want it unchanged", got)
	}
	// A descriptor that is not a live directory (here, a nonexistent fd) must drop
	// to empty rather than pass the bare relative path through to be mis-anchored.
	if got := resolveAt(os.Getpid(), 0x7fffffff, "rel/x"); got != "" {
		t.Errorf("unresolvable dirfd: got %q, want dropped to empty", got)
	}
}

func TestTracePropagatesExitCode(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	res, err := Trace([]string{sh, "-c", "exit 5"}, os.Environ(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}
	if res.ExitCode != 5 {
		t.Errorf("exit code = %d, want 5", res.ExitCode)
	}
}

// A signal delivered to the tracee must reach it, not be swallowed by the tracer.
// The target signals itself with SIGTERM; if the tracer suppresses the delivered
// signal (the bug), the target instead runs to the `exit 0` and this fails. With
// the signal forwarded, the target dies by SIGTERM and reports 128+SIGTERM. This
// also stands in for the crash case: a suppressed synchronous SIGSEGV would re-run
// the faulting instruction forever and spin the profiler.
func TestTraceForwardsDeliveredSignal(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	res, err := Trace([]string{sh, "-c", "kill -TERM $$; sleep 5; exit 0"}, os.Environ(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}
	if want := 128 + int(syscall.SIGTERM); res.ExitCode != want {
		t.Errorf("exit code = %d, want %d (SIGTERM must be delivered, not eaten)", res.ExitCode, want)
	}
}

// The SIGTRAP exclusion in the signal-forwarding path is load-bearing: with
// PTRACE_O_TRACEEXEC unset, a forked child's execve reports as a SIGTRAP
// signal-delivery-stop, and forwarding SIGTRAP (default action: core dump) would
// kill the exec'ing subprocess. The target's exit status is that of an exec'd
// child, so if SIGTRAP were forwarded the child would die and the status be
// non-zero. It must exit 0 and the exec must be observed.
func TestTraceForkExecSurvivesSignalForwarding(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	res, err := Trace([]string{sh, "-c", "cat /dev/null; exit $?"}, os.Environ(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}
	if !res.Execed {
		t.Skip("`cat` did not exec on this system; SIGTRAP-forwarding is not exercised")
	}
	if res.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0 (an exec'ing subprocess must not be SIGTRAP-killed)", res.ExitCode)
	}
}

// A healthy, signal-driven target must have its signal delivered to its own
// handler, not eaten. The target installs a SIGTERM handler that exits 7; if the
// tracer suppresses the signal (the bug), the handler never runs and it falls
// through to `exit 0`. This covers the class of ordinary scripts that rely on
// signals (timeouts, SIGCHLD, self-pipe) rather than only a target killed by the
// signal's default action.
func TestTraceDeliversSignalToHandler(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	res, err := Trace([]string{sh, "-c", "trap 'exit 7' TERM; kill -TERM $$; sleep 3; exit 0"}, os.Environ(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}
	if res.ExitCode != 7 {
		t.Errorf("exit code = %d, want 7 (the target's SIGTERM handler must run)", res.ExitCode)
	}
}
