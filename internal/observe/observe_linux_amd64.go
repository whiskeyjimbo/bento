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

	"golang.org/x/sys/unix"
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

// sysFchmodat2 is the fchmodat2(2) syscall number (Linux 6.6+), not yet in x/sys/unix.
// It is the dirfd-relative chmod glibc's fchmodat routes through, so a target changing
// mode via it must have its path recorded as a write like the other metadata writes.
const sysFchmodat2 = 452

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

	// Every tracee the loop has seen and not yet reaped: root, plus any descendant
	// auto-attached via PTRACE_O_TRACECLONE/FORK/VFORK. The cleanup guard reaps all of
	// them, because a descendant attached mid-trace is left TASK_TRACED-forever on an
	// early error return - killing root does not reach it (there is no shared process
	// group, and PTRACE_O_EXITKILL fires only when this tracer exits, which for a
	// library embedder may be never).
	tracees := map[int]bool{root: true}

	// The child comes up ptrace-stopped and every error path below returns while it
	// is still suspended. Kill and reap every live tracee on any such early return, so
	// a failed trace leaks no TASK_TRACED process. Reaping stays on the locked thread
	// (this defer runs before UnlockOSThread), as ptrace requires. The happy path
	// clears this after the loop has already reaped root.
	succeeded := false
	defer func() {
		if !succeeded {
			reapTracees(tracees)
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
		wpid, err := waitTracee(-1, &ws, 0, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			// This wait almost never errors (EINTR is retried above; ECHILD cannot
			// happen while root is unreaped), so it is effectively a defensive exit.
			// The cleanup guard reaps root and every descendant tracked below.
			return Result{}, fmt.Errorf("observe: wait: %w", err)
		}

		// Any pid the tracer waits on is an attached tracee: root, or a descendant
		// auto-attached by the trace-clone/fork options. Track it so it is reaped when
		// the trace ends - on the error guard or on the clean exit below; drop it again
		// when it ends on its own.
		tracees[wpid] = true

		switch {
		case wpid == root && (ws.Exited() || ws.Signaled()):
			// Root has exited and the wait above already reaped it. Mark success so the
			// cleanup guard does not run (and does not wait on the freed root pid), then
			// reap any descendant still attached: a process the script backgrounded and
			// left running would otherwise stay TASK_TRACED under a tracer that may never
			// exit - the same leak the error guard prevents. A normal script's children
			// have already exited and been dropped, so this reaps an empty remainder.
			succeeded = true
			delete(tracees, root)
			reapTracees(tracees)
			res.ExitCode = exitCode(ws)
			if ws.Signaled() {
				res.Signaled = true
				res.Signal = int(ws.Signal())
			}
			sort.Slice(res.Accesses, func(i, j int) bool { return res.Accesses[i].Path < res.Accesses[j].Path })
			return res, nil
		case ws.Exited() || ws.Signaled():
			// A subprocess ended and is reaped; drop it so the guard does not wait on a
			// freed pid, and nothing to resume.
			delete(tracees, wpid)
			continue
		case ws.Stopped() && ws.StopSignal() == syscall.SIGTRAP|0x80:
			// A syscall stop. Decode the file-opening ones; recording on both
			// entry and exit is deduplicated, so no enter/exit bookkeeping.
			inspect(wpid, record, &res)
			syscall.PtraceSyscall(wpid, 0)
		default:
			// A fork/clone/vfork event reports the new child's pid here, before that
			// child's own first stop is dequeued - and the parent stays stopped at this
			// event until resumed below. Track the child now so it is reaped even if the
			// parent runs on and exits before its stop is seen; otherwise a child forked
			// just before root exits would slip past the cleanup untracked.
			switch ws.TrapCause() {
			case syscall.PTRACE_EVENT_FORK, syscall.PTRACE_EVENT_VFORK, syscall.PTRACE_EVENT_CLONE:
				if child, err := syscall.PtraceGetEventMsg(wpid); err == nil {
					tracees[int(child)] = true
				}
			}

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

// waitTracee is the loop's wait syscall, indirected through a var so a test can
// force the loop's defensive error return - otherwise effectively unreachable (EINTR
// is retried, ECHILD cannot occur while root is unreaped) - and check that a
// descendant attached by then is reaped, not leaked.
var waitTracee = syscall.Wait4

// reapTracees SIGKILLs every tracee and drains waits until all of them are gone, so
// a trace that returns before the target completes leaves no suspended TASK_TRACED
// process behind. A ptrace-stopped tracee is not exempt from SIGKILL, so each one
// dies.
//
// It waits on -1 rather than each pid in turn. A multithreaded descendant's zombie
// thread-group leader cannot be reaped until its sibling threads are (the kernel's
// delay_group_leader), so a per-pid Wait4(leader) would block forever whenever the
// leader is killed before its threads - which map iteration order makes a coin flip.
// Draining -1 dequeues whichever tracee is ready (threads first), so groups empty and
// leaders become reapable. It stops once the tracked set is empty rather than at
// ECHILD, so it never blocks on an embedding process's own unrelated live children;
// an ECHILD before then means the rest reparented to init (which reaps their corpses)
// and is a clean stop.
func reapTracees(tracees map[int]bool) {
	remaining := make(map[int]bool, len(tracees))
	for pid := range tracees {
		remaining[pid] = true
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
	for len(remaining) > 0 {
		var ws syscall.WaitStatus
		wpid, err := syscall.Wait4(-1, &ws, 0, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return // ECHILD: no waitable tracee remains; any survivor reparented to init
		}
		if ws.Exited() || ws.Signaled() {
			delete(remaining, wpid)
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
		// openat2(dirfd, path, struct open_how *how, size): flags and resolve are fields
		// of *how, not registers. Increasingly used (Rust std, systemd tools), so a
		// program using it must not profile as touching nothing.
		flags, resolve, ok := openHow(pid, uintptr(regs.Rdx))
		path := readString(pid, uintptr(regs.Rsi))
		if anchored, rec := openat2Path(openat2Resolve(resolve, ok), path); rec {
			record(resolveAt(pid, int32(regs.Rdi), anchored), ok && flags&uint64(writeFlags) != 0)
		}
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
	default:
		inspectMutating(pid, &regs, record)
	}
}

// inspectMutating decodes the path-modifying syscalls - the ones that create,
// remove, rename, or truncate a directory entry and so need write access to the
// containing directory. Each is recorded as a write on the affected path(s); the
// synthesizer collapses that to a directory grant, exactly like an O_WRONLY open.
// Without these, a target that saves via the atomic write-temp-then-rename pattern
// profiles as touching only the random temp name (missing the real output), and a
// truncate profiles as touching nothing (a read-only-granted file can be zeroed).
//
// amd64 arg registers are Rdi, Rsi, Rdx, R10, R8. Read at the syscall stop, so a
// failed attempt is still recorded (matching the open cases) - the script's intent
// is what the manifest must grant.
func inspectMutating(pid int, regs *syscall.PtraceRegs, record func(string, bool)) {
	at := func(dirfd int32, pathReg uint64, write bool) {
		record(resolveAt(pid, dirfd, readString(pid, uintptr(pathReg))), write)
	}
	switch regs.Orig_rax {
	// rename removes the source and creates the destination: both directories need
	// write. renameat/renameat2 carry a dirfd for each (dest path is the 4th arg).
	case unix.SYS_RENAME:
		at(atFdCwd, regs.Rdi, true)
		at(atFdCwd, regs.Rsi, true)
	case unix.SYS_RENAMEAT, unix.SYS_RENAMEAT2:
		at(int32(regs.Rdi), regs.Rsi, true)
		at(int32(regs.Rdx), regs.R10, true)
	// Single-path creates/removes/truncates/metadata-writes. mknod/mknodat create a
	// FIFO, socket, or device node - a directory write like mkdir, so the manifest must
	// grant it or enforcement fails the run closed. The metadata writes (chmod/chown/
	// utime/xattr) all fail EROFS on a read-only bind, so each needs its path recorded
	// as a write; recording chmod but not its siblings would leave a silent under-grant.
	case unix.SYS_MKDIR, unix.SYS_RMDIR, unix.SYS_UNLINK, unix.SYS_TRUNCATE, unix.SYS_MKNOD,
		unix.SYS_CHMOD, unix.SYS_CHOWN, unix.SYS_LCHOWN, unix.SYS_UTIME, unix.SYS_UTIMES,
		unix.SYS_SETXATTR, unix.SYS_LSETXATTR, unix.SYS_REMOVEXATTR, unix.SYS_LREMOVEXATTR:
		at(atFdCwd, regs.Rdi, true)
	case unix.SYS_MKDIRAT, unix.SYS_UNLINKAT, unix.SYS_MKNODAT,
		unix.SYS_FCHMODAT, sysFchmodat2, unix.SYS_FCHOWNAT, unix.SYS_UTIMENSAT, unix.SYS_FUTIMESAT:
		at(int32(regs.Rdi), regs.Rsi, true)
	// A hardlink reads the existing source and creates a new name (a write).
	case unix.SYS_LINK:
		at(atFdCwd, regs.Rdi, false)
		at(atFdCwd, regs.Rsi, true)
	case unix.SYS_LINKAT:
		at(int32(regs.Rdi), regs.Rsi, false)
		at(int32(regs.Rdx), regs.R10, true)
	// A symlink only creates the link; its target is an uninterpreted string, not a
	// path the syscall touches, so only the link path is recorded.
	case unix.SYS_SYMLINK:
		at(atFdCwd, regs.Rsi, true)
	case unix.SYS_SYMLINKAT: // symlinkat(target, newdirfd, linkpath)
		at(int32(regs.Rsi), regs.Rdx, true)
	// bind(2) on an AF_UNIX pathname socket creates a socket file - a directory write.
	// The path is inside the sockaddr, not a register, and is bounded by addrlen rather
	// than NUL-terminated, so it needs its own read. Abstract and unnamed sockets make
	// no filesystem entry and are skipped by sockaddrUnixPath.
	case unix.SYS_BIND:
		if path := sockaddrUnixPath(pid, uintptr(regs.Rsi), regs.Rdx); path != "" {
			record(resolveAt(pid, atFdCwd, path), true)
		}
	// connect(2) to an AF_UNIX pathname socket needs that socket present in the sandbox;
	// a read-only bind is enough (connect succeeds through it - netns does not fence a
	// path socket), so record it as a READ on the socket path. This surfaces a host
	// service the target reaches - the SSH/gpg agent, a session bus, docker.sock - on the
	// profiling consent surface, where the user grants (or refuses) that specific socket.
	// It is discovery only: a missed connect leaves the socket ungranted, so the run
	// denies it. connect and bind share the (sockfd, addr, addrlen) shape. Abstract
	// sockets make no filesystem entry and are netns-fenced in this tier, so they are
	// skipped - nothing to grant.
	case unix.SYS_CONNECT:
		if path := sockaddrUnixPath(pid, uintptr(regs.Rsi), regs.Rdx); path != "" {
			record(resolveAt(pid, atFdCwd, path), false)
		}
	}
}

// sockaddrUnixPath returns the filesystem path an AF_UNIX bind(2) or connect(2) names,
// or "" when the address makes no filesystem entry. It reads addrlen bytes of the
// sockaddr from the traced process and hands them to unixSockaddrPath for the parse.
func sockaddrUnixPath(pid int, addr uintptr, addrlen uint64) string {
	// sockaddr_un is a 2-byte family plus up to 108 bytes of sun_path; a larger addrlen
	// is rejected by the kernel (EINVAL), so it names no file.
	if addrlen <= 2 || addrlen > 110 {
		return ""
	}
	mem, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return ""
	}
	defer mem.Close()

	buf := make([]byte, addrlen)
	n, _ := mem.ReadAt(buf, int64(addr))
	return unixSockaddrPath(buf[:max(n, 0)])
}

// unixSockaddrPath extracts the bound filesystem path from a raw sockaddr, or "" when
// the address makes no directory entry: a non-AF_UNIX family, an abstract socket
// (sun_path[0] == 0, which lives in an abstract namespace rather than the filesystem),
// or an unnamed/autobind address (no path bytes). sun_path is bounded by the buffer
// length, not a NUL, because the kernel accepts an unterminated address; the scan stops
// at the first NUL or the end.
func unixSockaddrPath(buf []byte) string {
	if len(buf) <= 2 || binary.LittleEndian.Uint16(buf[0:2]) != unix.AF_UNIX {
		return ""
	}
	path := buf[2:]
	if path[0] == 0 { // abstract namespace: no filesystem entry
		return ""
	}
	for i, b := range path {
		if b == 0 {
			return string(path[:i])
		}
	}
	return string(path)
}

// openat2Path maps an openat2 pathname and its RESOLVE_* flags to the path that must
// be anchored at the dirfd, and whether the open touches anything worth recording.
//
// Under RESOLVE_IN_ROOT the dirfd is the root: an absolute path is re-rooted there and
// a ".." that would climb above it is clamped, exactly as the kernel resolves it.
// Clean("/"+path) reproduces that clamp - it collapses extra leading slashes
// ("//etc/x") and drops any ".." above the root ("/../../etc/x") - before the result is
// made relative for the dirfd anchor. A bare TrimPrefix does neither and would leak the
// real host path the run never opened.
//
// Under RESOLVE_BENEATH an absolute path is rejected by the kernel with EXDEV, so the
// open touches nothing and recording it would fabricate an access; a relative path
// resolves within the dirfd like an ordinary relative open.
func openat2Path(resolve uint64, path string) (anchored string, record bool) {
	switch {
	case resolve&unix.RESOLVE_IN_ROOT != 0:
		return strings.TrimPrefix(filepath.Clean("/"+path), "/"), true
	case resolve&unix.RESOLVE_BENEATH != 0 && strings.HasPrefix(path, "/"):
		return "", false
	default:
		return path, true
	}
}

// openat2Resolve picks the RESOLVE_* flags an openat2 is attributed by. When the open_how
// read failed (ok is false) the real flags are unknown, so it falls back to RESOLVE_IN_ROOT
// rather than the zero value: that anchors an absolute path at the dirfd (the run's root)
// instead of recording it as a real-root host path the run may never have opened. The two
// errors are not symmetric - under-attribution fails the run closed and is fixed by adding
// a grant, over-attribution silently widens the manifest - so the conservative anchor wins.
func openat2Resolve(resolve uint64, ok bool) uint64 {
	if !ok {
		return unix.RESOLVE_IN_ROOT
	}
	return resolve
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

// openHow reads the openat2 open_how struct at addr: flags at offset 0 and resolve
// at offset 16 (mode, at offset 8, is not needed). ok is false if the read fails, in
// which case the caller (via openat2Resolve) treats the open as a non-write anchored
// at the dirfd - the fail-safe for an unreadable /proc/<pid>/mem.
func openHow(pid int, addr uintptr) (flags, resolve uint64, ok bool) {
	mem, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return 0, 0, false
	}
	defer mem.Close()

	var buf [24]byte
	if n, _ := mem.ReadAt(buf[:], int64(addr)); n < 24 {
		return 0, 0, false
	}
	return binary.LittleEndian.Uint64(buf[0:8]), binary.LittleEndian.Uint64(buf[16:24]), true
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
	for i := range n {
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
