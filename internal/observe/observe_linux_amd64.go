// Package observe records what a program does — the files it opens and whether
// it spawns subprocesses — by running it under ptrace. It is the profiler's
// observation backend: run a script permissively under observe, then synthesize
// a tight manifest from what it actually touched.
//
// This is a profiling tool, not an enforcement layer. It decodes syscalls by
// their amd64 numbers and register layout; other architectures get a stub.
package observe

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sort"
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
}

// amd64 syscall numbers.
const (
	sysOpen     = 2
	sysOpenat   = 257
	sysCreat    = 85
	sysExecve   = 59
	sysExecveat = 322
)

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
			return Result{}, fmt.Errorf("observe: wait: %w", err)
		}

		switch {
		case wpid == root && (ws.Exited() || ws.Signaled()):
			res.ExitCode = exitCode(ws)
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
			// A group-stop, a ptrace event (a new child, already being traced), or
			// a delivered signal. Resume; a new child stops on its own next syscall.
			syscall.PtraceSyscall(wpid, 0)
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
		record(readString(pid, uintptr(regs.Rsi)), regs.Rdx&writeFlags != 0)
	case sysOpen:
		record(readString(pid, uintptr(regs.Rdi)), regs.Rsi&writeFlags != 0)
	case sysCreat:
		record(readString(pid, uintptr(regs.Rdi)), true)
	case sysExecve, sysExecveat:
		res.Execed = true
	}
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
