package observe

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

// killAndReap is the cleanup Trace defers on an early error; it must fully remove
// a ptrace-stopped child rather than leave a TASK_TRACED process (or an unreaped
// zombie) behind. This exercises the helper directly against a real child driven
// into that suspended state - Trace has no seam to inject a mid-setup failure, so
// the wiring of the deferred guard itself is covered by review, not this test.
func TestKillAndReapRemovesStoppedTracee(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	// ptrace is per-thread: the tracer must start, wait on, and reap the child from
	// the same OS thread, as Trace does.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cmd := exec.Command(sh, "-c", "sleep 30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting tracee: %v", err)
	}
	pid := cmd.Process.Pid
	// If an assertion below fails before killAndReap runs (or it misbehaves), do not
	// leave the stopped child pinned for its whole sleep.
	defer func() {
		syscall.Kill(pid, syscall.SIGKILL)
		var ws syscall.WaitStatus
		syscall.Wait4(pid, &ws, 0, nil)
	}()

	// Consume the initial execve stop; the child is now suspended in TASK_TRACED,
	// the state every early return in Trace would abandon it in.
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		t.Fatalf("initial wait: %v", err)
	}

	killAndReap(pid)

	// A signal-0 probe to a reaped pid reports ESRCH; anything else means the child
	// (or an unreaped zombie) is still around.
	if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
		t.Fatalf("tracee still present after killAndReap: kill(pid, 0) = %v, want ESRCH", err)
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

func TestResolveAtAnchorsAndDrops(t *testing.T) {
	// An absolute path and an empty path are returned unchanged.
	if got := resolveAt(0, 5, "/abs/x"); got != "/abs/x" {
		t.Errorf("absolute: got %q, want it unchanged", got)
	}
	if got := resolveAt(0, atFdCwd, ""); got != "" {
		t.Errorf("empty: got %q, want it unchanged", got)
	}
	// An AT_FDCWD relative path is anchored at the process's working directory, read
	// from /proc/<pid>/cwd. Using this test process's own pid, the anchor is the
	// test's cwd - so the result is that cwd joined with the relative path, never the
	// bare relative path (which downstream would mis-anchor).
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if got := resolveAt(os.Getpid(), atFdCwd, "rel/x"); got != filepath.Join(cwd, "rel/x") {
		t.Errorf("AT_FDCWD: got %q, want it anchored at %q", got, filepath.Join(cwd, "rel/x"))
	}
	// A pid whose /proc/<pid>/cwd cannot be read, and a descriptor that is not a live
	// directory, both drop to empty rather than pass the bare relative path through.
	if got := resolveAt(0, atFdCwd, "rel/x"); got != "" {
		t.Errorf("unreadable cwd: got %q, want dropped to empty", got)
	}
	if got := resolveAt(os.Getpid(), 0x7fffffff, "rel/x"); got != "" {
		t.Errorf("unresolvable dirfd: got %q, want dropped to empty", got)
	}
}

// A relative path opened after a chdir must be anchored at the directory the run
// was in when it opened the file, not at the run's starting directory. Before the
// fix the observer returned the bare relative name and the profiler anchored it at
// the entrypoint's directory, naming a file the script never touched.
func TestTraceAnchorsRelativeOpenAfterChdir(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	sub := filepath.Join(t.TempDir(), "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "after_cd.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// chdir into sub, then open a relative path - it must be anchored at sub.
	script := fmt.Sprintf("import os\nos.chdir(%q)\nos.close(os.open('after_cd.txt', os.O_RDONLY))\n", sub)

	res, err := Trace([]string{py, "-c", script}, os.Environ(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}
	want := filepath.Join(sub, "after_cd.txt")
	if _, ok := find(res, want); !ok {
		t.Errorf("relative open after chdir was not anchored at the new cwd (want %q); accesses: %v", want, res.Accesses)
	}
	for _, a := range res.Accesses {
		if a.Path == "after_cd.txt" {
			t.Errorf("relative open recorded bare-relative, not anchored: %q", a.Path)
		}
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
	if res.Signaled {
		t.Errorf("a plain nonzero exit must not be reported as signaled")
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
	// The run must be reported as signaled (a crash/OOM/timeout), so the profiler can
	// warn the observations may be partial - distinct from a plain nonzero exit.
	if !res.Signaled || res.Signal != int(syscall.SIGTERM) {
		t.Errorf("got Signaled=%v Signal=%d, want signaled by SIGTERM (%d)", res.Signaled, res.Signal, syscall.SIGTERM)
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
