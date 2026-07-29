// Package observe records what a program does - the files it opens and whether
// it spawns subprocesses - by running it under ptrace. It is the profiler's
// observation backend: run a script under observe (default-deny, enforcement off),
// then synthesize a tight manifest from what it actually touched.
//
// This is a profiling tool, not an enforcement layer. It decodes syscalls by
// their amd64 numbers and register layout; other architectures get a stub.
package observe

import (
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Access is one path the program reached: opened, modified, or - via a successful
// stat/access/readlink - established the existence of. An existence probe is a read
// because the sandbox has no narrower grant: a path is bound in or it is not there.
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
	// Dropped counts observations the observer could not read: a syscall stop whose
	// registers would not load, a pathname or sockaddr it could not fetch from the
	// tracee's memory, a relative path whose anchor directory /proc would not name.
	// Each one is a file access that happened and is absent from Accesses, so a
	// nonzero count means the manifest below is incomplete - indistinguishable, without
	// it, from a target that simply touched nothing there.
	Dropped int
	// SeccompKilled reports that a tracee - root or any descendant - died on SIGSYS,
	// i.e. a kill-mode seccomp filter refused one of its syscalls. Everything that
	// process would have touched after the refused syscall is absent from Accesses, so a
	// caller must treat this run's observation as incomplete. Tracked separately from
	// Signaled because a script that tolerates its helper dying still exits zero, and
	// that run's observation is missing everything the helper did with nothing else to
	// say so. Which filter killed it is the caller's to interpret: for bento's profiling
	// run the only kill-mode filter installed is the foreign-arch guard, but a target
	// that sandboxes itself dies the same way.
	SeccompKilled bool
}

// amd64 syscall numbers.
const (
	sysOpen    = 2
	sysOpenat  = 257
	sysOpenat2 = 437
	sysCreat   = 85
	sysExecve  = 59
	// sysExecveat is the dirfd-relative spawn. It does not set Execed (see the
	// sysExecve case), but the binary it names is still a file the run must be able
	// to read, so its path is recorded like any other access.
	sysExecveat = 322
)

// auditArchX8664 is the AUDIT_ARCH_ value the kernel reports for a syscall dispatched
// through the 64-bit entry point. internal/seccomp gates its filters on the same value;
// it is repeated here rather than shared because this package decodes syscalls and
// installs nothing, and a decoder that imported the enforcement layer for a number would
// be the wrong dependency.
const auditArchX8664 = 0xC000003E

// x32SyscallBit tags a syscall number issued through the x32 ABI, which shares the
// amd64 audit arch - so the arch check alone does not tell the two apart, and an x32
// number means something else in the amd64 table it would be decoded against.
const x32SyscallBit = 0x40000000

// atFdCwd is openat's dirfd value meaning "relative to the working directory".
// A real dirfd instead anchors a relative path at that descriptor's directory.
const atFdCwd = -100

// sysFchmodat2 is the fchmodat2(2) syscall number (Linux 6.6+), not yet in x/sys/unix.
// It is the dirfd-relative chmod glibc's fchmodat routes through, so a target changing
// mode via it must have its path recorded as a write like the other metadata writes.
const sysFchmodat2 = 452

// Open flags that mean the open requested write access.
const writeFlags = syscall.O_WRONLY | syscall.O_RDWR | syscall.O_CREAT | syscall.O_TRUNC | syscall.O_APPEND

// Supported reports whether this build has the ptrace observation backend. It is
// a build-time fact, not a kernel capability: the decoder reads syscall numbers
// and the register layout for amd64, so every other architecture links the stub.
// Callers must consult it before launching a profiling sandbox, so a host that
// cannot observe says so instead of running the target and reporting an empty
// observation as a failed one.
func Supported() bool { return true }

// traceCalls serializes Trace within a process. The loop dequeues stops with
// Wait4(-1) because there is no wait-for-this-set syscall, and a -1 wait CONSUMES
// another concurrent trace's stops rather than merely seeing them: the thief would
// record a foreign tracee's file accesses into its own Result - a misattributed audit
// record, the one failure this package must not have - while the robbed call died on
// ECHILD. Serializing is what makes the -1 wait safe; the residual is that a -1 wait
// still reaps an unrelated child of the CALLING process, which is why Trace documents
// that it owns the process's child reaping for its duration.
var traceCalls sync.Mutex

// Trace runs argv under ptrace and reports the files it opened and whether it
// spawned subprocesses. The target runs with the given environment and standard
// streams; a non-zero exit is returned in Result, not as an error.
//
// Trace is single-flight and takes over child reaping for its duration: it dequeues
// wait statuses with Wait4(-1) (ptrace offers no way to wait on one tracee set), so
// concurrent calls are serialized, and a caller must not have its own children whose
// exit status it needs while a trace runs - this consumes it. bento's profiling path
// satisfies both: the trace runs in the dedicated in-sandbox launcher stage.
func Trace(argv, env []string, stdin io.Reader, stdout, stderr io.Writer) (Result, error) {
	if len(argv) == 0 {
		return Result{}, fmt.Errorf("observe: empty argv")
	}
	traceCalls.Lock()
	defer traceCalls.Unlock()

	// ptrace requires every call to come from the thread that started the tracee,
	// so the whole trace runs pinned to one OS thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	// When a stream is not an *os.File, Start pipes it through a copier goroutine, and
	// only Wait joins those goroutines and closes the parent ends of the pipes. This
	// loop reaps the tracee itself (ptrace requires it), so Wait's own wait fails - but
	// it still joins the copiers and closes the pipes, which is why it is called anyway
	// below. WaitDelay bounds that join: without it a descendant still holding the pipe
	// would block the join forever, where the old code merely abandoned the goroutine.
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Start(); err != nil {
		return Result{}, fmt.Errorf("observe: starting target: %w", err)
	}
	root := cmd.Process.Pid

	// Registered before the reap guard below so it runs AFTER it (defers are LIFO):
	// the copiers finish when the last holder of the pipe is gone, so the tracees must
	// be killed first. The error is dropped deliberately - it reports this loop's own
	// reaping as a failed wait, and the exit status comes from that reaping, not here.
	// Without this call an embedder passing a bytes.Buffer gets truncated output and a
	// leaked goroutine writing into it after Trace returned.
	defer func() { _ = cmd.Wait() }()

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
	if err := requireSyscallInfo(root); err != nil {
		return Result{}, err
	}
	const opts = syscall.PTRACE_O_TRACESYSGOOD |
		syscall.PTRACE_O_TRACECLONE | syscall.PTRACE_O_TRACEFORK | syscall.PTRACE_O_TRACEVFORK |
		unixPtraceExitKill
	if err := syscall.PtraceSetOptions(root, opts); err != nil {
		return Result{}, fmt.Errorf("observe: set options: %w", err)
	}

	seen := map[string]bool{}
	// The in-flight entry/exit pairs dropOnce is deduplicating, kept apart from the
	// recorded-path set above: entries here are released as each pair completes, and
	// mixing the two lifetimes in one map is how a stale key goes unnoticed.
	drops := map[string]bool{}
	// Pathnames the entry stop of an existence syscall resolved, waiting for the exit
	// stop's return value to say whether the call succeeded. Keyed and released per
	// entry/exit pair like the drop counter, so a stop that is not this pair's - an
	// rt_sigreturn landing between the two, say - cannot be mistaken for it.
	held := map[string]heldPath{}
	// The op of each pid's last syscall stop that was read successfully - the parity a
	// failed read has no op of its own to supply. See lastStopWasExit.
	lastOp := map[int]byte{}
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
		if errors.Is(err, syscall.EINTR) {
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

		// SIGSYS means a kill-mode seccomp filter refused a syscall. For the profiled
		// run that is the launcher's foreign-arch guard - but a target that installs its
		// OWN kill filter (bwrap, a browser or language runtime sandbox) dies the same
		// way, so this records only that the process was seccomp-killed and could not be
		// observed. Naming the ABI as the cause is left to the caller, which knows which
		// filters it installed. Recorded for every tracee, not just root, so a helper the
		// script shrugs off is still reported.
		if ws.Signaled() && ws.Signal() == syscall.SIGSYS {
			res.SeccompKilled = true
		}

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
			// Sort on the same path+write key the dedup uses. One path can legitimately
			// appear twice, once read and once written, and sorting on path alone leaves
			// that pair's order to an unstable sort - changing the observation report's
			// bytes run to run.
			slices.SortFunc(res.Accesses, func(a, b Access) int {
				return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(boolKey(a.Write), boolKey(b.Write)))
			})
			return res, nil
		case ws.Exited() || ws.Signaled():
			// A subprocess ended and is reaped; drop it so the guard does not wait on a
			// freed pid, and nothing to resume.
			delete(tracees, wpid)
			delete(lastOp, wpid)
			continue
		case ws.Stopped() && ws.StopSignal() == syscall.SIGTRAP|0x80:
			// A syscall stop. Decode the file-opening ones, unless it came through a
			// foreign ABI and the amd64 table would misread it. Recording on both entry
			// and exit is deduplicated, so no enter/exit bookkeeping beyond the drop
			// counter's own.
			if op, native := nativeSyscall(wpid, lastOp, held, &res.Dropped); native {
				count, release := dropOnce(drops, wpid, &res.Dropped)
				inspect(wpid, op, record, count, release, held, &res)
			}
			_ = syscall.PtraceSyscall(wpid, 0)
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
			_ = syscall.PtraceSyscall(wpid, sig)
		}
	}
}

// nativeSyscall reports whether the syscall this stop is reporting was dispatched
// through the amd64 entry point, counting a dropped observation when it was not.
//
// inspect decodes syscall numbers and argument registers against the amd64 table, so a
// syscall issued through the i386 compat entry (`int 0x80`) is decoded as an unrelated
// amd64 one, against registers the compat ABI never set - the kernel takes compat args
// from ebx/ecx/edx, not rdi/rsi/rdx. i386 readlink(85) reads as amd64 creat and
// fabricates a write on whatever rdi holds; the collision is not confined to 85, and the
// rest land on syscalls decoded at the entry stop, where no success filter could catch
// them: i386 mmap(90) is amd64 chmod, i386 oldselect(82) is rename, i386 symlink(83) is
// mkdir. A foreign syscall is therefore not decoded at all.
//
// It is counted as a drop rather than ignored because the decoder cannot tell what it
// was, and a file access it could not read is exactly what Dropped exists to report.
// Counted once per call, at the entry stop, which is what the op field distinguishes -
// no dedup needed. A failed read is counted for the same reason: it says nothing about
// what the stop was. That one is counted per stop rather than per call, because a
// failure leaves no op field to tell them apart; with the request's availability already
// established at the initial stop, the only failure left is a tracee that died mid-pair,
// which has no second stop to count. Which stop it died at decides whether that is a real
// loss, and lastOp is what answers it here - unlike inspect, which has this stop's own op
// in hand.
//
// This settles the audit arch, not the whole ABI question: x32 shares AUDIT_ARCH_X86_64
// and passes here, and inspect drops it on the tag its syscall numbers carry.
func nativeSyscall(pid int, lastOp map[int]byte, held map[string]heldPath, dropped *int) (op byte, native bool) {
	op, arch, err := syscallInfo(pid)
	if err != nil {
		// A read that failed says nothing about which stop this was, so the parity it
		// would have recorded is gone and every later inference off this pid's stale one
		// would be off by a stop.
		prev := lastOp[pid]
		delete(lastOp, pid)
		if !errors.Is(err, syscall.ESRCH) || !deadThreadLostNothing(nextStop(prev), held, pid) {
			*dropped++
		}
		return 0, false
	}
	lastOp[pid] = op
	if arch == auditArchX8664 {
		return op, true
	}
	if op == unix.PTRACE_SYSCALL_INFO_ENTRY {
		*dropped++
	}
	return op, false
}

// deadThreadLostNothing reports whether an ESRCH at a stop of this op means no observation
// was actually lost. It is the one judgement both reads that can fail on a dying thread
// share - PTRACE_GET_SYSCALL_INFO in nativeSyscall and PtraceGetRegs in inspect - because
// which of the two loses the race is a coin flip on the same event.
//
// At an ENTRY stop nothing ran: a ptrace-stopped thread executes nothing until the observer
// resumes it, so a thread already gone died holding the stop and never issued the syscall.
//
// At an EXIT stop the syscall did complete, but the only thing decoded there is the
// existence syscalls' success filter, replayed against a pathname the entry stop already
// resolved and held - every other syscall reads its pathname at the entry stop and is done.
// So a pid holding nothing had nothing this stop could lose; a dying thread's nanosleep or
// futex exit stop is the case that showed up in practice. With a pathname held the loss is
// real: the probe completed and its result is what decides whether the path needs a grant.
//
// Any other op - the initial exec stop's NONE, a seccomp stop, or a parity that was never
// established - is unknown rather than safe, and counts. An uncounted lost access is the
// failure this channel exists to prevent, so unknown must never mean "suppress".
func deadThreadLostNothing(op byte, held map[string]heldPath, pid int) bool {
	switch op {
	case unix.PTRACE_SYSCALL_INFO_ENTRY:
		return true
	case unix.PTRACE_SYSCALL_INFO_EXIT:
		return !holdsPath(held, pid)
	}
	return false
}

// nextStop reports the op of the stop that follows one of op, which is what a stop whose
// own read failed has to be judged on. A thread's syscall stops strictly alternate and
// every one of them passes through nativeSyscall, so the stop after an entry is an exit and
// the stop after an exit is an entry.
//
// prev is a pid's last op only when one was read successfully, so anything else - a cloned
// child's first stop, a stop after a failed read, the initial exec stop's NONE, a seccomp
// stop - carries no parity and yields NONE, which deadThreadLostNothing counts. Inferring
// where nothing was observed is what would turn this into a silent suppressor.
//
// A wrong answer costs at most one drop: it is consulted only where the thread is already
// dead, so the pid is reaped and its parity forgotten immediately after.
func nextStop(prev byte) byte {
	switch prev {
	case unix.PTRACE_SYSCALL_INFO_ENTRY:
		return unix.PTRACE_SYSCALL_INFO_EXIT
	case unix.PTRACE_SYSCALL_INFO_EXIT:
		return unix.PTRACE_SYSCALL_INFO_ENTRY
	}
	return unix.PTRACE_SYSCALL_INFO_NONE
}

// syscallInfo reads the op and dispatch arch of the stop the tracee is in, via
// PTRACE_GET_SYSCALL_INFO. Both live in the first eight bytes of struct
// ptrace_syscall_info (u8 op, u8 pad[3], u32 arch), but the whole struct's size is
// passed: the kernel writes min(the given size, its own) and returns its own, so asking
// for eight would be a silent partial read on a layout that grows rather than an error.
func syscallInfo(pid int) (op byte, arch uint32, err error) {
	var info [88]byte
	n, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_GET_SYSCALL_INFO,
		uintptr(pid), uintptr(len(info)), uintptr(unsafe.Pointer(&info[0])), 0, 0)
	if errno != 0 {
		return 0, 0, errno
	}
	if n < 8 {
		return 0, 0, fmt.Errorf("kernel returned %d bytes, too few to read the dispatch arch", n)
	}
	return info[0], binary.LittleEndian.Uint32(info[4:8]), nil
}

// requireSyscallInfo checks that the kernel implements PTRACE_GET_SYSCALL_INFO, which
// nativeSyscall needs and which arrived in Linux 5.3. The tracee is at its initial
// exec stop here rather than a syscall stop; the request answers there too, reporting
// op = NONE with arch filled in, which is all this probe needs.
//
// Trace refuses the run rather than falling back to decoding without the check. Bento
// degrades enforcement on an old kernel, but profiling is where a manifest is written:
// a run that can fabricate a write grant is worse than no profile, and refusing matches
// what the profile command already does with an unobservable run.
func requireSyscallInfo(pid int) error {
	if _, _, err := syscallInfo(pid); err != nil {
		return fmt.Errorf("observe: PTRACE_GET_SYSCALL_INFO (Linux 5.3+) is needed to tell a foreign-ABI syscall from an amd64 one: %w", err)
	}
	return nil
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

// dropSlots is how many pathname arguments one syscall can lose separately. rename, link
// and their *at forms name a source AND a destination, so one call can lose two distinct
// accesses; keying the counter on the call alone reported those two as one, which is the
// undercount this channel exists to prevent. Two is the most any decoded syscall takes.
const dropSlots = 2

// dropOnce returns the drop counter for one syscall stop, and the release that ends its
// deduplication. inspect runs on both the entry and the exit stop of the same syscall,
// and every drop cause is deterministic across the pair - the tracee is frozen between
// them, so an unreadable pathname is unreadable both times. Counting each stop would
// report every lost access twice, and a count that is wrong by construction is worse than
// none: it trains a reader to discount the warning.
//
// The key is the tracee plus the syscall's number, instruction pointer and argument slot.
// All but the slot are identical on entry and exit. They are NOT unique across calls: a libc call site issuing
// the same syscall in a loop has the same Rip every iteration. So the dedup is scoped to
// the pair it needs to span - inspect releases the key once the exit stop is decoded, and
// the next iteration counts again. Held for the whole trace instead, a target whose
// pathnames are unreadable from a loop reports one drop for N lost accesses, which is the
// undercount this channel exists to prevent.
//
// A key outlives its pair whenever the exit stop never reaches the release: a failed
// register read (which has no registers to key on, and so keys on the zero regs), a
// syscall the kernel does not implement, whose real -ENOSYS makes both its stops read as
// entries, and a tracee that dies mid-pair. Each collapses its repeats into one drop, and
// the last cannot repeat at all - the process is gone.
func dropOnce(inFlight map[string]bool, pid int, n *int) (count func(*syscall.PtraceRegs, int), release func(*syscall.PtraceRegs)) {
	key := func(regs *syscall.PtraceRegs, slot int) string {
		return fmt.Sprintf("%s\x00%d", stopKey(pid, regs), slot)
	}
	count = func(regs *syscall.PtraceRegs, slot int) {
		k := key(regs, slot)
		if inFlight[k] {
			return
		}
		inFlight[k] = true
		*n++
	}
	release = func(regs *syscall.PtraceRegs) {
		for slot := range dropSlots {
			delete(inFlight, key(regs, slot))
		}
	}
	return count, release
}

// stopKey identifies one syscall's entry/exit pair: the tracee, plus the syscall's number
// and instruction pointer, which are identical at both stops. It is NOT unique across
// calls - a libc call site issuing the same syscall in a loop repeats it every iteration -
// so everything keyed on it must release the entry as the pair completes.
func stopKey(pid int, regs *syscall.PtraceRegs) string {
	return fmt.Sprintf("%d\x00%d\x00%d", pid, regs.Orig_rax, regs.Rip)
}

// holdsPath reports whether any of this pid's entry stops resolved a pathname that is
// still waiting on its exit stop. It reads the held set rather than tracking a count
// alongside it, so it cannot disagree with what is actually held - and it is asked only
// where a thread has already died, once per thread, so the scan is not on any hot path.
//
// A thread runs one syscall at a time, but a signal delivered mid-call runs a handler
// whose own calls stop under the same pid, so more than one of its pairs can be open at
// once. That is why this answers per pid rather than for one pair: without registers
// there is no key to ask about, and the pid-wide answer errs toward counting.
func holdsPath(held map[string]heldPath, pid int) bool {
	prefix := fmt.Sprintf("%d\x00", pid)
	for key := range held {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

// heldPath is a pathname the entry stop resolved, kept until the exit stop can say
// whether the call succeeded. readOK is false when the pathname could not be read at all;
// the drop is deferred with it, because a failed existence probe needs no grant and so
// must not be reported as a lost access.
type heldPath struct {
	path   string
	readOK bool
}

// inspect decodes a syscall stop and records file opens / subprocess execs. The numbers
// below are amd64's, and three checks stand between a stop and that table: the caller has
// established the stop carries the amd64 audit arch (see nativeSyscall), the x32 check
// below rules out the one ABI that shares it, and the negative-number check rules out the
// stops that carry no syscall number at all. Past those three the numbers mean what they
// say.
func inspect(pid int, op byte, record func(string, bool), countDrop func(*syscall.PtraceRegs, int), releaseDrop func(*syscall.PtraceRegs), held map[string]heldPath, res *Result) {
	var regs syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
		// No registers means no syscall number either, so this may not have been a file
		// access at all - a tracee killed between the stop and this read fails here on
		// whatever it was running.
		//
		// ESRCH means the thread died holding this stop, which deadThreadLostNothing can
		// often resolve rather than count. The op comes from the caller's own read at this
		// same stop, before any resume, so it describes this stop and not a later one.
		//
		// Every other failure is counted: an uncounted lost access is what this channel
		// exists to prevent. An EIO or EFAULT says nothing about whether the thread is
		// alive.
		if errors.Is(err, syscall.ESRCH) && deadThreadLostNothing(op, held, pid) {
			return
		}
		countDrop(&regs, 0)
		return
	}
	// This syscall's entry/exit pair ends here, so its dedup key goes with it - see
	// dropOnce. Deferred so it runs after the decode below has had its chance to count.
	if !atSyscallEntry(&regs) {
		defer releaseDrop(&regs)
	}
	drop := func() { countDrop(&regs, 0) }
	dropSlot := func(slot int) { countDrop(&regs, slot) }
	// A negative orig_rax is the kernel saying this stop reports no syscall number, not a
	// syscall this decoder failed to read - so it is skipped silently rather than dropped.
	// It arrives from rt_sigreturn, whose exit stop reports the RESTORED pre-signal
	// registers: orig_rax is -1 (the marker that suppresses syscall restart) and rax is the
	// interrupted call's own return value. Nothing is lost by skipping it. Every syscall
	// recorded at the entry stop was already recorded before these registers appeared, and
	// no path-existence syscall - the only ones read at the exit stop - can present here,
	// because the value is rt_sigreturn's restored context and not their own.
	//
	// This must precede the x32 test: -1 has every bit set, so it matches x32SyscallBit and
	// counted as a lost access once per handled signal. Go's async preemption signals a
	// busy tracee constantly, which put the count in the hundreds for a run that lost
	// nothing - in the one channel that tells the user their manifest is incomplete.
	if int64(regs.Orig_rax) < 0 {
		return
	}
	// The other half of the ABI question nativeSyscall could not answer: x32 shares the
	// amd64 audit arch, so it arrives here, but its numbers are tagged and mean something
	// else untagged - x32 openat is 0x40000101. Untagged they would misdecode; tagged they
	// match no case below and would fall through as an access that silently never happened.
	// Dropped instead, which says the observation is short by one. A real x32 number stays
	// positive as an int64 (the tag is bit 30), so the guard above does not screen it out.
	if regs.Orig_rax&x32SyscallBit != 0 {
		drop()
		return
	}
	// Every pathname this decoder reads is read HERE, at the entry stop, while the tracee
	// is frozen before the kernel has copied its arguments. Reading one at the exit stop
	// instead lets a sibling sharing the address space (a thread, or any CLONE_VM child)
	// overwrite the buffer after the syscall ran, so the observer records a path the call
	// never touched - and over-attribution silently widens the manifest the user consents
	// to. The exit stop is still needed for one thing, the existence syscalls' success
	// filter, and that replays what was captured here rather than reading again.
	if !atSyscallEntry(&regs) {
		recordHeldExistence(pid, &regs, record, drop, held)
		return
	}
	switch regs.Orig_rax {
	case sysOpenat:
		if path, ok := readPathAt(pid, int32(regs.Rdi), uintptr(regs.Rsi)); ok {
			record(path, regs.Rdx&writeFlags != 0)
		} else {
			drop()
		}
	case sysOpenat2:
		// openat2(dirfd, path, struct open_how *how, size): flags and resolve are fields
		// of *how, not registers. Increasingly used (Rust std, systemd tools), so a
		// program using it must not profile as touching nothing.
		// An unreadable open_how is a dropped observation, not a guess. The resolve
		// flags decide whether the pathname is re-rooted at the dirfd, clamped, or
		// rejected outright, so without them there is no path that can honestly be
		// recorded - the old fallback anchored it at the dirfd and so named a file the
		// kernel, which refused the call with EFAULT, never opened.
		flags, resolve, ok := openHow(pid, uintptr(regs.Rdx))
		path, pathOK := readString(pid, uintptr(regs.Rsi))
		if !pathOK || !ok {
			drop()
			break
		}
		if anchored, rec := openat2Path(resolve, path); rec {
			anchoredPath, anchorOK := resolveAt(pid, int32(regs.Rdi), anchored)
			if !anchorOK {
				drop()
				break
			}
			record(anchoredPath, flags&uint64(writeFlags) != 0)
		}
	case sysOpen:
		// open/creat take no dirfd; a relative path is anchored at the working
		// directory, exactly the AT_FDCWD case, so route them through resolveAt too or
		// a relative open after a chdir would be mis-anchored.
		if path, ok := readPathAt(pid, atFdCwd, uintptr(regs.Rdi)); ok {
			record(path, regs.Rsi&writeFlags != 0)
		} else {
			drop()
		}
	case sysCreat:
		if path, ok := readPathAt(pid, atFdCwd, uintptr(regs.Rdi)); ok {
			record(path, true)
		} else {
			drop()
		}
	case sysExecve:
		// Tested at the ENTRY stop because that is the only stop where the number still
		// tells execve from execveat: after a successful execveat the kernel reports the
		// EXIT stop as 59, so an ungated test here counts every execveat as an execve.
		//
		// Only execve is counted, and the reason is not that execveat is harmless. The
		// exec-block filter denies execve and permits execveat by construction - the
		// launcher's own transition into the sandbox is an execveat - so a target that
		// spawns that way runs identically under exec: none and exec: all, and reporting
		// it buys the user nothing. What it costs is the point: Execed grants ExecAll,
		// and on ExecAll the launcher installs no exec-block filter at all, so a single
		// execveat would turn into blanket execve permission for the whole run.
		res.Execed = true
		recordExecTarget(pid, atFdCwd, uintptr(regs.Rdi), record, drop)
	case sysExecveat:
		recordExecTarget(pid, int32(regs.Rdi), uintptr(regs.Rsi), record, drop)
	default:
		inspectMutating(pid, &regs, record, dropSlot)
		inspectExistence(pid, &regs, record, drop, held)
	}
}

// atSyscallEntry reports whether this stop is the syscall's entry rather than its
// exit. The kernel leaves -ENOSYS in rax across the entry stop and overwrites it with
// the return value before the exit stop, so the pair is told apart without any
// per-tracee bookkeeping. A syscall the running kernel does not implement returns
// -ENOSYS for real and so reads as an entry stop twice; callers that only act on the
// exit therefore skip it, which is right - it touched nothing.
func atSyscallEntry(regs *syscall.PtraceRegs) bool {
	return int64(regs.Rax) == -int64(syscall.ENOSYS)
}

// inspectExistence decodes the path-EXISTENCE syscalls - the ones that ask whether a
// path is there without opening it. Under enforcement an ungranted path is not merely
// unreadable but absent, so a target that stats a config it never opens sees it during
// the permissive profiling run, gets ENOENT on the enforced run, and takes a different
// branch. Existence and read are the same grant here - making a stat succeed means
// binding the path into the sandbox - so each is recorded as a plain read.
//
// Unlike every other case in this decoder these are read at the syscall EXIT stop and
// recorded only when the call SUCCEEDED. A failed open still needs a grant, because the
// script meant to open that file; a stat that already returned ENOENT needs none,
// because enforcement reproduces that exact answer. The filter is what keeps manifests
// tight: a shell's PATH search misses hundreds of times per command, and recording those
// probes would bury the paths the run actually needs.
//
// A successful access(W_OK) is recorded as a read, not a write. It reports that a write
// would be permitted, which a read-only bind makes false - but over-attribution silently
// widens the manifest while under-attribution fails the run closed and is fixed by
// adding a grant, the same asymmetry openat2Resolve turns on.
//
// getdents64 and fchdir carry no pathname, and the descriptor they act on came from an
// openat this decoder already recorded. getcwd names the run's own working directory,
// which the sandbox must have bound for the process to be running in it.
// It runs at the ENTRY stop and only captures: the pathname is read and resolved here,
// while the tracee is frozen and the buffer still holds what the kernel is about to read,
// then held under this stop's key until recordHeldExistence can apply the success filter.
// Reading it at the exit stop instead - where the return value lives - is what let a
// sibling sharing the address space plant a path the call never touched.
func inspectExistence(pid int, regs *syscall.PtraceRegs, record func(string, bool), drop func(), held map[string]heldPath) {
	// chdir is recorded outright rather than held, because it moves the very anchor
	// resolveAt reads back out of /proc: waiting for its exit stop would join a later
	// relative pathname onto the directory the call just entered. That costs it the
	// success filter, so a chdir to a path that is not there is recorded like a failed
	// open.
	if regs.Orig_rax == unix.SYS_CHDIR {
		if path, ok := readPathAt(pid, atFdCwd, uintptr(regs.Rdi)); ok {
			record(path, false)
		} else {
			drop()
		}
		return
	}
	var dirfd int32
	var pathReg uint64
	switch regs.Orig_rax {
	case unix.SYS_STAT, unix.SYS_LSTAT, unix.SYS_ACCESS, unix.SYS_READLINK:
		dirfd, pathReg = atFdCwd, regs.Rdi
	// The *at forms take (dirfd, path, ...). AT_EMPTY_PATH with an empty pathname makes
	// them operate on the descriptor itself, naming no path; record's empty-path skip
	// covers that without a separate flag test.
	// statfs asks about the filesystem a path is on, the xattr readers about its
	// attributes, and each answers ENOENT for a path the sandbox did not bind - so a run
	// that only ever probes a path this way (df /data) profiled as not needing it.
	case unix.SYS_STATFS, unix.SYS_GETXATTR, unix.SYS_LGETXATTR, unix.SYS_LISTXATTR, unix.SYS_LLISTXATTR:
		dirfd, pathReg = atFdCwd, regs.Rdi
	case unix.SYS_NEWFSTATAT, unix.SYS_STATX, unix.SYS_FACCESSAT, unix.SYS_FACCESSAT2, unix.SYS_READLINKAT,
		unix.SYS_NAME_TO_HANDLE_AT:
		dirfd, pathReg = int32(regs.Rdi), regs.Rsi
	// inotify_add_watch(fd, path, mask) takes a watch descriptor, not a dirfd, so its
	// pathname is anchored at the working directory like the non-at forms.
	case unix.SYS_INOTIFY_ADD_WATCH:
		dirfd, pathReg = atFdCwd, regs.Rsi
	default:
		return
	}
	// An unreadable pathname is not dropped here: the drop travels with the held entry, so
	// that a probe the kernel goes on to refuse costs nothing - the same success filter the
	// recorded path itself gets.
	path, ok := readPathAt(pid, dirfd, uintptr(pathReg))
	held[stopKey(pid, regs)] = heldPath{path: path, readOK: ok}
}

// recordHeldExistence applies the existence syscalls' success filter at the exit stop, to
// the pathname the entry stop resolved, and releases the held entry either way.
//
// Only a call that SUCCEEDED is recorded. A failed open still needs a grant, because the
// script meant to open that file; a stat that already returned ENOENT needs none, because
// enforcement reproduces that exact answer. The filter is what keeps manifests tight: a
// shell's PATH search misses hundreds of times per command, and recording those probes
// would bury the paths the run actually needs.
func recordHeldExistence(pid int, regs *syscall.PtraceRegs, record func(string, bool), drop func(), held map[string]heldPath) {
	key := stopKey(pid, regs)
	h, ok := held[key]
	if !ok {
		return
	}
	delete(held, key)
	if int64(regs.Rax) < 0 {
		return
	}
	if !h.readOK {
		drop()
		return
	}
	record(h.path, false)
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
func inspectMutating(pid int, regs *syscall.PtraceRegs, record func(string, bool), dropSlot func(int)) {
	// slot distinguishes the source pathname from the destination one, so a rename that
	// loses both reports two drops rather than collapsing them into one.
	at := func(slot int, dirfd int32, pathReg uint64, write bool) {
		if path, ok := readPathAt(pid, dirfd, uintptr(pathReg)); ok {
			record(path, write)
			return
		}
		dropSlot(slot)
	}
	switch regs.Orig_rax {
	// rename removes the source and creates the destination: both directories need
	// write. renameat/renameat2 carry a dirfd for each (dest path is the 4th arg).
	case unix.SYS_RENAME:
		at(0, atFdCwd, regs.Rdi, true)
		at(1, atFdCwd, regs.Rsi, true)
	case unix.SYS_RENAMEAT, unix.SYS_RENAMEAT2:
		at(0, int32(regs.Rdi), regs.Rsi, true)
		at(1, int32(regs.Rdx), regs.R10, true)
	// Single-path creates/removes/truncates/metadata-writes. mknod/mknodat create a
	// FIFO, socket, or device node - a directory write like mkdir, so the manifest must
	// grant it or enforcement fails the run closed. The metadata writes (chmod/chown/
	// utime/xattr) all fail EROFS on a read-only bind, so each needs its path recorded
	// as a write; recording chmod but not its siblings would leave a silent under-grant.
	case unix.SYS_MKDIR, unix.SYS_RMDIR, unix.SYS_UNLINK, unix.SYS_TRUNCATE, unix.SYS_MKNOD,
		unix.SYS_CHMOD, unix.SYS_CHOWN, unix.SYS_LCHOWN, unix.SYS_UTIME, unix.SYS_UTIMES,
		unix.SYS_SETXATTR, unix.SYS_LSETXATTR, unix.SYS_REMOVEXATTR, unix.SYS_LREMOVEXATTR:
		at(0, atFdCwd, regs.Rdi, true)
	case unix.SYS_MKDIRAT, unix.SYS_UNLINKAT, unix.SYS_MKNODAT,
		unix.SYS_FCHMODAT, sysFchmodat2, unix.SYS_FCHOWNAT, unix.SYS_UTIMENSAT, unix.SYS_FUTIMESAT:
		// utimensat and futimesat accept a NULL pathname, and then act on the descriptor
		// itself rather than naming a file - the kernel forms of futimens(3) and futimes(3).
		// Reading address zero fails, so decoding one as a pathname reported a lost access
		// for a call that lost nothing: cp -p, tar -x, install and rsync all use utimensat,
		// so extracting an archive alone put hundreds of phantom losses on the channel that
		// tells the user their manifest is short. The exemption names the two rather than
		// skipping every zero pathname register because they are the only two: the other
		// *at forms in this case list (mkdirat, unlinkat, mknodat, fchmodat, fchmodat2,
		// fchownat) all refuse a NULL pathname with EFAULT.
		if regs.Rsi == 0 && (regs.Orig_rax == unix.SYS_UTIMENSAT || regs.Orig_rax == unix.SYS_FUTIMESAT) {
			return
		}
		at(0, int32(regs.Rdi), regs.Rsi, true)
	// A hardlink reads the existing source and creates a new name (a write).
	case unix.SYS_LINK:
		at(0, atFdCwd, regs.Rdi, false)
		at(1, atFdCwd, regs.Rsi, true)
	case unix.SYS_LINKAT:
		at(0, int32(regs.Rdi), regs.Rsi, false)
		at(1, int32(regs.Rdx), regs.R10, true)
	// A symlink only creates the link; its target is an uninterpreted string, not a
	// path the syscall touches, so only the link path is recorded.
	case unix.SYS_SYMLINK:
		at(0, atFdCwd, regs.Rsi, true)
	case unix.SYS_SYMLINKAT: // symlinkat(target, newdirfd, linkpath)
		at(0, int32(regs.Rsi), regs.Rdx, true)
	// bind(2) on an AF_UNIX pathname socket creates a socket file - a directory write.
	// The path is inside the sockaddr, not a register, and is bounded by addrlen rather
	// than NUL-terminated, so it needs its own read. Abstract and unnamed sockets make
	// no filesystem entry and are skipped by sockaddrUnixPath.
	case unix.SYS_BIND:
		if path, ok := sockaddrUnixPath(pid, uintptr(regs.Rsi), regs.Rdx); !ok {
			dropSlot(0)
		} else if path != "" {
			if anchored, anchorOK := resolveAt(pid, atFdCwd, path); anchorOK {
				record(anchored, true)
			} else {
				dropSlot(0)
			}
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
		if path, ok := sockaddrUnixPath(pid, uintptr(regs.Rsi), regs.Rdx); !ok {
			dropSlot(0)
		} else if path != "" {
			if anchored, anchorOK := resolveAt(pid, atFdCwd, path); anchorOK {
				record(anchored, false)
			} else {
				dropSlot(0)
			}
		}
	}
}

// sockaddrUnixPath returns the filesystem path an AF_UNIX bind(2) or connect(2) names,
// or "" when the address makes no filesystem entry. It reads addrlen bytes of the
// sockaddr from the traced process and hands them to unixSockaddrPath for the parse.
func sockaddrUnixPath(pid int, addr uintptr, addrlen uint64) (string, bool) {
	// sockaddr_un is a 2-byte family plus up to 108 bytes of sun_path; a larger addrlen
	// is rejected by the kernel (EINVAL), so it names no file. That is an answer, not a
	// failure, so it is not a drop.
	if addrlen <= 2 || addrlen > 110 {
		return "", true
	}
	mem, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return "", false
	}
	defer mem.Close()

	buf := make([]byte, addrlen)
	// A short read is not a shorter address: sun_path need not be NUL-terminated, so
	// parsing the truncated bytes would record a real-looking path that is a prefix of
	// the one the target used - a misattributed access, worse than a counted loss.
	if n, err := mem.ReadAt(buf, int64(addr)); err != nil && n < len(buf) {
		return "", false
	}
	return unixSockaddrPath(buf), true
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
func resolveAt(pid int, dirfd int32, path string) (string, bool) {
	if path == "" || strings.HasPrefix(path, "/") {
		return path, true
	}
	link := fmt.Sprintf("/proc/%d/cwd", pid)
	if dirfd != atFdCwd {
		link = fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd)
	}
	dir, err := os.Readlink(link)
	if err != nil || !strings.HasPrefix(dir, "/") || strings.HasSuffix(dir, " (deleted)") {
		return "", false
	}
	return filepath.Join(dir, path), true
}

// readPathAt reads a pathname argument from the tracee and anchors it. ok is false if
// either step failed, which is a dropped observation rather than an access to nothing.
func readPathAt(pid int, dirfd int32, addr uintptr) (string, bool) {
	path, ok := readString(pid, addr)
	if !ok {
		return "", false
	}
	return resolveAt(pid, dirfd, path)
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
func readString(pid int, addr uintptr) (string, bool) {
	mem, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return "", false
	}
	defer mem.Close()

	var buf [4096]byte
	n, _ := mem.ReadAt(buf[:], int64(addr))
	for i := range n {
		if buf[i] == 0 {
			return string(buf[:i]), true
		}
	}
	// No NUL in the window: either the read failed outright or the pathname is longer
	// than any the kernel would accept. Either way the path is unknown, not empty.
	return "", false
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

// recordExecTarget records the binary a spawn syscall names. The sandbox must be able to
// read and execute it, so it is an access like any other - and a spawn by absolute path
// (os/exec with a full path, or a bare syscall.Exec) reaches the kernel without the PATH
// search whose stats would otherwise have recorded it incidentally.
func recordExecTarget(pid int, dirfd int32, addr uintptr, record func(string, bool), drop func()) {
	if path, ok := readPathAt(pid, dirfd, addr); ok {
		record(path, false)
		return
	}
	drop()
}
