// Package observe records what a program does - the files it opens and whether
// it spawns subprocesses - by running it under ptrace. It is the profiler's
// observation backend: run a script permissively under observe, then synthesize
// a tight manifest from what it actually touched.
//
// This is a profiling tool, not an enforcement layer. It decodes syscalls by
// their amd64 numbers and register layout; other architectures get a stub.
package observe

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
)

// Access is one file the program opened.
type Access struct {
	Path  string
	Write bool // the open requested write access
}

// Result is what a traced run observed.
type Result struct {
	Accesses []Access
	Execed   bool // the program exec'd at least one subprocess
	ExitCode int
	// Signaled reports the root died from a signal (crash, OOM-kill, timeout);
	// Signal is that signal number. A signaled or nonzero run may have stopped
	// partway, so its accesses - and any manifest synthesized from them - are
	// incomplete.
	Signaled bool
	Signal   int
}

// amd64 syscall numbers.
const (
	sysOpen    = 2
	sysOpenat  = 257
	sysOpenat2 = 437
	sysCreat   = 85
	sysExecve  = 59
)

// atFdCwd is openat's dirfd value meaning "relative to the working directory".
// A real dirfd instead anchors a relative path at that descriptor's directory.
const atFdCwd = -100

// Open flags that mean the open requested write access.
const writeFlags = syscall.O_WRONLY | syscall.O_RDWR | syscall.O_CREAT | syscall.O_TRUNC | syscall.O_APPEND

// Trace runs argv under ptrace and reports the files it opened and whether it
// spawned subprocesses. The target runs with the given environment and standard
// streams; a non-zero exit is returned in Result, not as an error.
func Trace(argv, env []string, stdin io.Reader, stdout, stderr io.Writer) (Result, error) {
	if len(argv) == 0 {
		return Result{}, fmt.Errorf("observe: empty argv")
	}

	// ptrace requires every call to come from the thread that started the tracee,
	// so the whole trace runs pinned to one OS thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	if err := cmd.Start(); err != nil {
		return Result{}, fmt.Errorf("observe: starting target: %w", err)
	}
	root := cmd.Process.Pid

	// The child comes up ptrace-stopped and every error path below returns while it
	// is still suspended. Kill and reap it on any such early return, so a failed
	// trace leaks no TASK_TRACED process: PTRACE_O_EXITKILL only fires when this
	// tracer exits, which for a library embedder's process may be never. Reaping
	// stays on the locked thread (this defer runs before UnlockOSThread), as ptrace
	// requires. The happy path clears this after the loop has already reaped root.
	succeeded := false
	defer func() {
		if !succeeded {
			killAndReap(root)
		}
	}()

	// The child stops at its initial execve; set options to follow subprocesses
	// and to tag syscall stops distinctly, then let it run.
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(root, &ws, 0, nil); err != nil {
		return Result{}, fmt.Errorf("observe: initial wait: %w", err)
	}
	const opts = syscall.PTRACE_O_TRACESYSGOOD |
		syscall.PTRACE_O_TRACECLONE | syscall.PTRACE_O_TRACEFORK | syscall.PTRACE_O_TRACEVFORK |
		unixPtraceExitKill
	if err := syscall.PtraceSetOptions(root, opts); err != nil {
		return Result{}, fmt.Errorf("observe: set options: %w", err)
	}

	seen := map[string]bool{}
	var res Result
	record := func(path string, write bool) {
		if path == "" {
			return
		}
		key := path + boolKey(write)
		if seen[key] {
			return
		}
		seen[key] = true
		res.Accesses = append(res.Accesses, Access{Path: path, Write: write})
	}

	if err := syscall.PtraceSyscall(root, 0); err != nil {
		return Result{}, fmt.Errorf("observe: resume: %w", err)
	}

	for {
		wpid, err := syscall.Wait4(-1, &ws, 0, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			// This wait almost never errors (EINTR is retried above; ECHILD cannot
			// happen while root is unreaped), so it is effectively a defensive exit.
			// The cleanup guard reaps root; any descendant tracees already attached
			// here are left to PTRACE_O_EXITKILL rather than individually reaped.
			return Result{}, fmt.Errorf("observe: wait: %w", err)
		}

		switch {
		case wpid == root && (ws.Exited() || ws.Signaled()):
			// The wait above already reaped root, so the cleanup guard must not also
			// wait on it; mark success before touching res so nothing between here
			// and the return can leave the guard waiting on a freed pid.
			succeeded = true
			res.ExitCode = exitCode(ws)
			if ws.Signaled() {
				res.Signaled = true
				res.Signal = int(ws.Signal())
			}
			sort.Slice(res.Accesses, func(i, j int) bool { return res.Accesses[i].Path < res.Accesses[j].Path })
			return res, nil
		case ws.Exited() || ws.Signaled():
			// A subprocess ended; nothing to resume.
			continue
		case ws.Stopped() && ws.StopSignal() == syscall.SIGTRAP|0x80:
			// A syscall stop. Decode the file-opening ones; recording on both
			// entry and exit is deduplicated, so no enter/exit bookkeeping.
			inspect(wpid, record, &res)
			syscall.PtraceSyscall(wpid, 0)
		default:
			// A group-stop, a ptrace event (a new child), or a genuine
			// signal-delivery-stop. Forward a real signal so the tracee actually
			// receives it: suppressing a synchronous fault (SIGSEGV/SIGILL/...) would
			// re-run the faulting instruction forever and spin the profiler, and
			// eating SIGINT/SIGTERM/SIGALRM/SIGCHLD would hang or misbehave an
			// otherwise healthy target. SIGTRAP is the exception - ptrace event stops
			// and a forked child's exec (PTRACE_O_TRACEEXEC is not set) report SIGTRAP,
			// and forwarding it (default action: core dump) would kill them.
			sig := 0
			if ws.Stopped() {
				if s := ws.StopSignal(); s != syscall.SIGTRAP && s != syscall.SIGTRAP|0x80 {
					sig = int(s)
				}
			}
			syscall.PtraceSyscall(wpid, sig)
		}
	}
}

// killAndReap SIGKILLs a tracee and waits for its death, so a trace that returns
// before the target completes leaves no suspended TASK_TRACED process behind. A
// ptrace-stopped tracee is not exempt from SIGKILL, so this does not hang. The
// wait loops to retry EINTR and to step past a pending ptrace-stop notification
// that may be reported before the death.
func killAndReap(pid int) {
	_ = syscall.Kill(pid, syscall.SIGKILL)
	for {
		var ws syscall.WaitStatus
		_, err := syscall.Wait4(pid, &ws, 0, nil)
		if err == syscall.EINTR {
			continue
		}
		// ECHILD (already reaped) or a terminal status means the tracee is gone; a
		// non-terminal stop status means the SIGKILL has not landed yet, so wait on.
		if err != nil || ws.Exited() || ws.Signaled() {
			return
		}
	}
}

// inspect decodes a syscall stop and records file opens / subprocess execs.
func inspect(pid int, record func(string, bool), res *Result) {
	var regs syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
		return
	}
	switch regs.Orig_rax {
	case sysOpenat:
		path := resolveAt(pid, int32(regs.Rdi), readString(pid, uintptr(regs.Rsi)))
		record(path, regs.Rdx&writeFlags != 0)
	case sysOpenat2:
		// openat2(dirfd, path, struct open_how *how, size): the flags are the first
		// u64 of *how, not a register. Increasingly used (Rust std, systemd tools),
		// so a program using it must not profile as touching nothing.
		path := resolveAt(pid, int32(regs.Rdi), readString(pid, uintptr(regs.Rsi)))
		record(path, openHowWrite(pid, uintptr(regs.Rdx)))
	case sysOpen:
		// open/creat take no dirfd; a relative path is anchored at the working
		// directory, exactly the AT_FDCWD case, so route them through resolveAt too or
		// a relative open after a chdir would be mis-anchored.
		path := resolveAt(pid, atFdCwd, readString(pid, uintptr(regs.Rdi)))
		record(path, regs.Rsi&writeFlags != 0)
	case sysCreat:
		path := resolveAt(pid, atFdCwd, readString(pid, uintptr(regs.Rdi)))
		record(path, true)
	case sysExecve:
		// Only execve is counted: the enforcement exec-block filter blocks execve
		// but allows execveat, so a program that spawns via execveat runs fine under
		// exec: none and does not need exec: all.
		res.Execed = true
	}
}

// resolveAt anchors a relative openat/open pathname at the directory it was opened
// against, so the observation names the file the run actually touched. An absolute
// path is returned unchanged. A relative path is joined onto the directory the
// syscall resolves it against: the process's working directory for AT_FDCWD, or the
// directory a real descriptor names otherwise. Both are read from /proc at the
// syscall-entry stop, so a chdir the run has already done is reflected - anchoring a
// path opened after `cd /etc` at /etc, not at the run's starting directory (which
// would name a file the script never opened).
//
// The anchor is dropped rather than guessed when /proc gives no live directory: a
// descriptor that is not one readlinks to a non-path ("socket:[N]", "anon_inode:…")
// or a deleted directory ("… (deleted)"). Passing the bare relative path through
// would wrongly anchor it at the profiler's own cwd downstream - the bug being fixed.
func resolveAt(pid int, dirfd int32, path string) string {
	if path == "" || strings.HasPrefix(path, "/") {
		return path
	}
	link := fmt.Sprintf("/proc/%d/cwd", pid)
	if dirfd != atFdCwd {
		link = fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd)
	}
	dir, err := os.Readlink(link)
	if err != nil || !strings.HasPrefix(dir, "/") || strings.HasSuffix(dir, " (deleted)") {
		return ""
	}
	return filepath.Join(dir, path)
}

// openHowWrite reads open_how.flags - the first u64 of the struct openat2 points
// at - and reports whether the open requested write access.
func openHowWrite(pid int, addr uintptr) bool {
	mem, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return false
	}
	defer mem.Close()

	var buf [8]byte
	if n, _ := mem.ReadAt(buf[:], int64(addr)); n < 8 {
		return false
	}
	return binary.LittleEndian.Uint64(buf[:])&uint64(writeFlags) != 0
}

// readString reads a NUL-terminated string from the traced process's memory.
func readString(pid int, addr uintptr) string {
	mem, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return ""
	}
	defer mem.Close()

	var buf [4096]byte
	n, _ := mem.ReadAt(buf[:], int64(addr))
	for i := 0; i < n; i++ {
		if buf[i] == 0 {
			return string(buf[:i])
		}
	}
	return ""
}

func exitCode(ws syscall.WaitStatus) int {
	if ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ws.ExitStatus()
}

func boolKey(b bool) string {
	if b {
		return "\x01"
	}
	return "\x00"
}

// PTRACE_O_EXITKILL is not exported by the syscall package on all versions.
const unixPtraceExitKill = 0x00100000
