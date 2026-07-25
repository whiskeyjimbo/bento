package observe

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
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
// connect(2) to an AF_UNIX pathname socket must be recorded as a READ on the socket
// path, so a host service the target reaches (an agent, a session bus, docker.sock)
// shows up on the consent surface. Recording is at syscall entry, so a connect to a
// nonexistent socket is still captured.
func TestTraceRecordsUnixConnect(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "svc.sock")
	script := fmt.Sprintf(`
import socket
c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    c.connect(%q)
except OSError:
    pass
c.close()
`, target)
	res, err := Trace([]string{py, "-c", script}, os.Environ(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}
	found := false
	for _, a := range res.Accesses {
		if a.Path == target {
			found = true
			if a.Write {
				t.Errorf("connect target recorded as a write, want a read: %+v", a)
			}
		}
	}
	if !found {
		t.Errorf("no access recorded for connect target %q; accesses: %v", target, res.Accesses)
	}
}

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

// reapTracees is the cleanup Trace runs on an early error and on clean exit; it must
// fully remove a ptrace-stopped tracee rather than leave a TASK_TRACED process (or an
// unreaped zombie) behind. This exercises it directly against a real child driven
// into that suspended state. The pre-resume setup paths (initial wait, set-options,
// resume) still have no failure seam and are covered by review; the loop-wait path,
// which the guard's descendant handling depends on, is driven end-to-end via the
// waitTracee seam in TestTraceReapsDescendantOnLoopWaitError.
func TestReapTraceesRemovesStoppedTracee(t *testing.T) {
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
	// If an assertion below fails before reapTracees runs (or it misbehaves), do not
	// leave the stopped child pinned for its whole sleep.
	defer func() {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		var ws syscall.WaitStatus
		_, _ = syscall.Wait4(pid, &ws, 0, nil)
	}()

	// Consume the initial execve stop; the child is now suspended in TASK_TRACED,
	// the state every early return in Trace would abandon it in.
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		t.Fatalf("initial wait: %v", err)
	}

	reapTracees(map[int]bool{pid: true})

	// A signal-0 probe to a reaped pid reports ESRCH; anything else means the child
	// (or an unreaped zombie) is still around.
	if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
		t.Fatalf("tracee still present after reapTracees: kill(pid, 0) = %v, want ESRCH", err)
	}
}

// On the loop's defensive wait-error return, a descendant tracee already attached
// (via the trace-fork options) must be killed and reaped, not left behind under a
// tracer that may never exit. That return is effectively unreachable in normal
// operation, so the wait is forced to error here - right after a descendant's stop
// is seen - and the descendant is asserted gone (not a live tracee, not a zombie).
func TestTraceReapsDescendantOnLoopWaitError(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}

	var root, descendant int
	armed := false
	orig := waitTracee
	waitTracee = func(pid int, ws *syscall.WaitStatus, flags int, ru *syscall.Rusage) (int, error) {
		if armed {
			return 0, syscall.EIO
		}
		w, werr := syscall.Wait4(pid, ws, flags, ru)
		if werr != nil {
			return w, werr
		}
		switch {
		case root == 0:
			root = w // the first stop is the root; its child does not exist yet
		case w != root && ws.Stopped():
			descendant = w // a live descendant is now attached
			armed = true   // ...error on the next wait, with it still tracked
		}
		return w, werr
	}
	defer func() { waitTracee = orig }()

	// Fork one long-lived child so exactly one descendant is attached and stays alive
	// (30s) past the forced error - its pid is stable and cannot be recycled into a
	// false "still present". `wait` keeps root blocked rather than exiting first.
	script := "sleep 30 &\nwait\n"
	if _, err := Trace([]string{sh, "-c", script}, os.Environ(), nil, nil, nil); err == nil {
		t.Fatal("Trace should have returned the forced wait error")
	}
	if descendant == 0 {
		t.Skip("no descendant was attached before the forced error; nothing to assert")
	}
	// The descendant must not survive as a live tracee. It was SIGKILL'd, so it is
	// dead; whether this tracer or init reaps the corpse is a race, so poll until the
	// pid is fully gone (ESRCH) rather than catch a transient zombie. Before the fix
	// the descendant is never killed, stays TASK_TRACED, and this never reaches ESRCH.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if err := syscall.Kill(descendant, 0); err == syscall.ESRCH {
			break
		} else if !traceeAliveStopped(descendant) {
			// Killed and reaped-pending (zombie): dead, not leaked.
			break
		}
		if time.Now().After(deadline) {
			t.Errorf("descendant %d still alive and TASK_TRACED after the failed trace; it was not killed", descendant)
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// traceeAliveStopped reports whether pid is a live process in a stopped/traced or
// runnable state (the leak), as opposed to a zombie ('Z') or gone. The process
// state is the third space-separated field of /proc/<pid>/stat, after the
// parenthesized comm (which can itself contain spaces/parens).
func traceeAliveStopped(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false // gone
	}
	s := string(b)
	close := strings.LastIndexByte(s, ')')
	if close < 0 || close+2 >= len(s) {
		return false
	}
	switch s[close+2] {
	case 'Z', 'X', 'x':
		return false // dead
	default:
		return true // R, S, D, t, T: still alive
	}
}

// When root exits cleanly, a descendant it left running (a backgrounded process)
// must not stay attached and TASK_TRACED under a tracer that may never exit. The
// trace returns normally, and the descendant must be gone - the same guarantee the
// error path gives, on the more common clean-exit path.
func TestTraceReapsBackgroundedDescendantOnCleanExit(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	// Fork a long-lived child, print its pid, then exit 0 - root completes while the
	// child is still alive. The 30s sleep keeps the pid stable (no recycling) so a
	// leak is observable, and lets the trace's own kill be what ends it.
	dir := t.TempDir()
	script := filepath.Join(dir, "bg.sh")
	if err := os.WriteFile(script, []byte("sleep 30 &\necho CHILD=$!\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Capture stdout via a real file, not an in-memory writer: Trace does not call
	// cmd.Wait (it does its own ptrace waiting), so os/exec's copy goroutine for a
	// non-file writer is never joined and reading it after Trace returns would race it.
	// An *os.File is passed to the child directly, with no such goroutine.
	outPath := filepath.Join(dir, "out.txt")
	outFile, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer outFile.Close()
	res, err := Trace([]string{sh, script}, os.Environ(), nil, outFile, outFile)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("root should have exited 0; got %d", res.ExitCode)
	}
	outBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}

	child := parseChildPID(t, string(outBytes))
	// The child was SIGKILL'd on the clean exit, so it is dead; whether this tracer or
	// init reaps the corpse is a race, so poll until the pid is fully gone or a zombie
	// (dead), never a live tracee. Before the fix it stays alive+TASK_TRACED for the
	// full sleep and this never reaches "dead".
	deadline := time.Now().Add(3 * time.Second)
	for {
		if err := syscall.Kill(child, 0); err == syscall.ESRCH {
			break // gone
		} else if !traceeAliveStopped(child) {
			break // zombie: dead, not leaked
		}
		if time.Now().After(deadline) {
			t.Errorf("backgrounded child %d survived root's clean exit as a live tracee; it was not reaped", child)
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func parseChildPID(t *testing.T, out string) int {
	t.Helper()
	for line := range strings.SplitSeq(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "CHILD="); ok {
			pid, err := strconv.Atoi(v)
			if err != nil {
				t.Fatalf("parsing child pid from %q: %v", v, err)
			}
			return pid
		}
	}
	t.Fatalf("did not find CHILD=<pid> in trace output: %q", out)
	return 0
}

// A backgrounded MULTITHREADED descendant left alive at root's clean exit is the
// deadlock case: reaping it means SIGKILLing a thread group whose zombie leader
// cannot be collected until its sibling threads are (delay_group_leader). A per-pid
// wait on the leader would block forever whenever it is reaped before its threads;
// reapTracees drains -1 so the threads are collected first. root (sh) exits while the
// threaded python child runs, so its leader and thread tids are all live in the
// tracee set at cleanup - Trace must still return promptly.
func TestTraceReapsBackgroundedMultithreadedDescendant(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	// Background a multithreaded child, then keep root alive briefly (a short sleep,
	// itself a transient child) so the loop tracks the child's thread tids before root
	// exits. At root's exit the leader-plus-threads group is live in the tracee set -
	// the state that deadlocks a per-pid reap of a delayed group leader.
	child := py + " -c 'import threading,time; [threading.Thread(target=lambda: time.sleep(30), daemon=True).start() for _ in range(6)]; time.sleep(30)'"
	script := child + " &\nsleep 0.5\nexit 0\n"

	done := make(chan struct{})
	go func() {
		_, _ = Trace([]string{sh, "-c", script}, os.Environ(), nil, nil, nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("Trace hung reaping a backgrounded multithreaded descendant (per-pid Wait4 on a delayed group leader?)")
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

// The legacy open(2) syscall (no dirfd) must be anchored at the working directory
// too, or a relative open after a chdir is mis-anchored - and a musl/static binary
// on x86_64 issues raw open(2), not openat, so this is a real path, not a museum
// piece. python normally uses openat, so the raw syscall is issued via ctypes.
func TestTraceAnchorsRawOpenAfterChdir(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("raw SYS_open probe is amd64-specific")
	}
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	sub := filepath.Join(t.TempDir(), "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "raw.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// chdir into sub, then issue a raw open(2) (SYS_open = 2 on x86_64) for a
	// relative name. It must be anchored at sub, not left bare.
	script := fmt.Sprintf(`import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
os.chdir(%q)
fd = libc.syscall(ctypes.c_long(2), b"raw.txt", ctypes.c_int(os.O_RDONLY))
if fd < 0:
    raise SystemExit("raw open unsupported")
os.close(fd)
`, sub)

	res, err := Trace([]string{py, "-c", script}, os.Environ(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}
	if res.ExitCode != 0 {
		t.Skipf("raw SYS_open not usable on this host (exit %d)", res.ExitCode)
	}
	want := filepath.Join(sub, "raw.txt")
	if _, ok := find(res, want); !ok {
		t.Errorf("raw open(2) after chdir was not anchored at the new cwd (want %q); accesses: %v", want, res.Accesses)
	}
	for _, a := range res.Accesses {
		if a.Path == "raw.txt" {
			t.Errorf("raw open(2) recorded bare-relative, not anchored: %q", a.Path)
		}
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
	if got, ok := resolveAt(0, 5, "/abs/x"); got != "/abs/x" || !ok {
		t.Errorf("absolute: got %q, %v, want it unchanged and not a drop", got, ok)
	}
	if got, ok := resolveAt(0, atFdCwd, ""); got != "" || !ok {
		t.Errorf("empty: got %q, %v, want it unchanged and not a drop", got, ok)
	}
	// An AT_FDCWD relative path is anchored at the process's working directory, read
	// from /proc/<pid>/cwd. Using this test process's own pid, the anchor is the
	// test's cwd - so the result is that cwd joined with the relative path, never the
	// bare relative path (which downstream would mis-anchor).
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := resolveAt(os.Getpid(), atFdCwd, "rel/x"); got != filepath.Join(cwd, "rel/x") || !ok {
		t.Errorf("AT_FDCWD: got %q, %v, want it anchored at %q", got, ok, filepath.Join(cwd, "rel/x"))
	}
	// A pid whose /proc/<pid>/cwd cannot be read, and a descriptor that is not a live
	// directory, both drop rather than pass the bare relative path through - and they
	// report the drop, so the count reaches the report instead of reading as "no access".
	if got, ok := resolveAt(0, atFdCwd, "rel/x"); got != "" || ok {
		t.Errorf("unreadable cwd: got %q, %v, want a reported drop", got, ok)
	}
	if got, ok := resolveAt(os.Getpid(), 0x7fffffff, "rel/x"); got != "" || ok {
		t.Errorf("unresolvable dirfd: got %q, %v, want a reported drop", got, ok)
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

// The profiler must record the path-modifying syscalls (bv2-n73): a target that
// saves via atomic write-temp-then-rename, truncates, mkdir/unlinks, or symlinks
// needs write access to the affected directories, and the old profiler saw none of
// it. Drives the real ptrace observer over a target doing each and asserts the
// destinations now appear as writes.
func TestTraceRecordsMutatingSyscalls(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	dir := t.TempDir()
	// The ctypes renameat2 call exercises the newdirfd/newpath registers (Rdx, R10)
	// directly, which glibc's plain os.rename does not reach.
	// The mknod/mknodat/bind syscalls are driven raw (libc.syscall by number, and a real
	// AF_UNIX bind) so each directory-writing case fires distinctly: glibc's mknod wrapper
	// routes through mknodat on modern versions, which would leave SYS_MKNOD untested. A
	// FIFO node (S_IFIFO) and a pathname socket are unprivileged, unlike a device node.
	script := fmt.Sprintf(`
import os, ctypes, socket
d = %q
open(d+'/tmp','w').close()
os.rename(d+'/tmp', d+'/out')
open(d+'/trunc','w').close()
os.truncate(d+'/trunc', 0)
os.mkdir(d+'/newdir')
open(d+'/gone','w').close()
os.unlink(d+'/gone')
os.symlink('/nowhere', d+'/link')
libc = ctypes.CDLL(None, use_errno=True)
open(d+'/rat_src','w').close()
libc.renameat2(-100, (d+'/rat_src').encode(), -100, (d+'/rat_dst').encode(), 0)
S_IFIFO = 0o010000
if libc.syscall(133, (d+'/fifo').encode(), S_IFIFO | 0o644, 0) != 0:
    raise SystemExit('mknod failed')
if libc.syscall(259, -100, (d+'/fifoat').encode(), S_IFIFO | 0o644, 0) != 0:
    raise SystemExit('mknodat failed')
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(d+'/sock')
s.close()
# Metadata writes, driven raw by syscall number so glibc routing does not send them
# through a different case (os.chmod routes via fchmodat/fchmodat2 on modern glibc,
# which is why SYS_CHMOD would otherwise stay untested). The target files are created
# by the test BEFORE tracing, so the only write these paths can record comes from the
# metadata syscall itself, not a write-open. Recording is at syscall-entry, so a no-op
# (-1,-1 chown) still records.
libc.syscall(90, (d+'/m_chmod').encode(), 0o600)               # chmod: AT_FDCWD/Rdi group
libc.syscall(92, (d+'/m_chown').encode(), -1, -1)             # chown: AT_FDCWD/Rdi group
libc.syscall(280, -100, (d+'/m_utime').encode(), 0, 0)       # utimensat: dirfd/Rsi group
`, dir)

	// Pre-create the metadata targets outside the traced process so their only recorded
	// write is the metadata syscall, not the file creation.
	for _, name := range []string{"/m_chmod", "/m_chown", "/m_utime"} {
		if err := os.WriteFile(dir+name, nil, 0o644); err != nil {
			t.Fatalf("pre-create %s: %v", name, err)
		}
	}

	res, err := Trace([]string{py, "-c", script}, os.Environ(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}
	isWrite := func(path string) bool {
		for _, a := range res.Accesses {
			if a.Path == path && a.Write {
				return true
			}
		}
		return false
	}
	for _, want := range []string{dir + "/out", dir + "/trunc", dir + "/newdir", dir + "/gone", dir + "/link", dir + "/rat_dst", dir + "/fifo", dir + "/fifoat", dir + "/sock", dir + "/m_chmod", dir + "/m_chown", dir + "/m_utime"} {
		if !isWrite(want) {
			t.Errorf("no write access recorded for %q (mutating syscall missed); accesses: %v", want, res.Accesses)
		}
	}
}

// openat2 with RESOLVE_IN_ROOT resolves an absolute path relative to the dirfd, not
// the real root, so the profiler must record it anchored at the dirfd - recording
// the bare "/etc/hosts" would name a host path the run never opened (bv2-2yi).
func TestTraceOpenat2ResolveInRoot(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "etc", "hosts"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// openat2(dirfd=<dir>, "/etc/hosts", {resolve: RESOLVE_IN_ROOT}) -> <dir>/etc/hosts.
	script := fmt.Sprintf(`
import ctypes, os
class how(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64), ("resolve", ctypes.c_uint64)]
d = %q
dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
h = how(0, 0, 0x10)  # RESOLVE_IN_ROOT
libc = ctypes.CDLL(None, use_errno=True)
rc = libc.syscall(437, dfd, b"/etc/hosts", ctypes.byref(h), ctypes.sizeof(h))
if rc < 0:
    raise SystemExit("openat2 failed")
`, dir)

	res, err := Trace([]string{py, "-c", script}, os.Environ(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}
	want := filepath.Join(dir, "etc", "hosts")
	var anchored, misattributed bool
	for _, a := range res.Accesses {
		if a.Path == want {
			anchored = true
		}
		if a.Path == "/etc/hosts" {
			misattributed = true
		}
	}
	if misattributed {
		t.Errorf("recorded /etc/hosts (real-root mis-attribution); accesses: %v", res.Accesses)
	}
	if !anchored {
		t.Errorf("RESOLVE_IN_ROOT open not anchored at the dirfd; want %q; accesses: %v", want, res.Accesses)
	}
}

// One access the observer cannot name must count as ONE drop. inspect runs on both the
// entry and the exit stop of the same syscall, and every drop cause is deterministic
// across the pair - the tracee is frozen in between - so an undeduplicated counter
// reports every loss twice. A count that is wrong by construction is worse than none:
// it teaches the reader to discount the warning.
//
// The lost access here is an openat whose pathname pointer is unmapped, so the path
// cannot be read out of the tracee at either stop.
func TestTraceCountsOneDropPerLostAccess(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	// ctypes calls openat directly with a pointer the process never mapped. The kernel
	// answers EFAULT and the script carries on; what matters is the observer's count.
	script := `
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall(257, -100, ctypes.c_void_p(0x1), 0, 0)
`
	res, err := Trace([]string{py, "-c", script}, os.Environ(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}
	// Measured against the same interpreter doing nothing, so an interpreter startup
	// that ever drops something of its own is subtracted rather than mistaken for this.
	base, err := Trace([]string{py, "-c", "pass"}, os.Environ(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Trace (baseline): %v", err)
	}
	if got := res.Dropped - base.Dropped; got != 1 {
		t.Errorf("Dropped = %d (baseline %d), want exactly 1 for the one unreadable pathname; 2 is the signature of counting the entry and exit stop of the same syscall separately", res.Dropped, base.Dropped)
	}
}
