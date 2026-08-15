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
	// Absent reports that every open of this path whose return the observer saw came
	// back ENOENT, with nothing at the path at all. An open that failed for any other
	// reason answers nothing: a file can exist and still refuse to open. The access is recorded either way - the program
	// meant to open that file, and enforcement must reproduce the same answer - but a
	// path nothing was ever found at cannot have been read, which is what lets a
	// reporting layer tell a probe apart from a resolved file. It is keyed on the path
	// alone, so a probe that misses and a create that succeeds do not disagree.
	Absent bool
	// Probed reports that every syscall naming this path only asked whether it was
	// there - stat, access, readlink, chdir - and none of them opened it. Both need the
	// same grant, so this says nothing about what the run requires; it lets a consumer
	// tell an access the program reached for from one the kernel's own path resolution
	// provoked on its behalf. Keyed on the path alone for the reason Absent is: a
	// directory that is stat'ed once and opened once is not probe-only.
	Probed bool
}

// Result is what a traced run observed.
type Result struct {
	Accesses []Access
	Execed   bool // an execve(2) ran and replaced an image, so a subprocess exists
	// ExecAttempted reports that an execve(2) was ISSUED, whether or not it ran. It is
	// the weaker fact and the two have different jobs: a grant hangs off Execed, because
	// a spawn that never happened must not widen policy, while the reporting layer needs
	// this one to tell a target that named a path the sandbox did not hold from one that
	// never named a path at all.
	//
	// execve(2) only. Its one reader asks whether a SHELL that exited 127 named the tool
	// it could not find, and a shell spawns with execve - so counting execveat here could
	// only suppress that report on a run where it was the right one.
	ExecAttempted bool
	ExitCode      int
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
	// sysExecveat is the dirfd-relative spawn. It never sets Execed (see the sysExecve
	// case), but the binary it names is still a file the run must be able to read, so
	// its path is recorded like any other access.
	sysExecveat = 322
)

// The kernel's internal restart signals, which have no names in syscall or x/sys/unix
// because no userspace program can see one: the signal machinery rewrites them to EINTR or
// re-issues the call before the return reaches userspace. A ptracer at the syscall-exit
// stop reads the raw value and so sees all four, and ptrace(2) documents exactly that.
const (
	errRestartSys          syscall.Errno = 512
	errRestartNoIntr       syscall.Errno = 513
	errRestartNoHand       syscall.Errno = 514
	errRestartRestartBlock syscall.Errno = 516
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
	// exec.Command below does a $PATH lookup when argv[0] has no slash, resolving against
	// the target's own policy-supplied PATH - a different binary than the one named, and
	// profiled as if it were that one. The launcher's other two exec paths refuse a
	// relative argv[0] for the same reason, and the guarantee they state is only true if
	// this one refuses it too.
	if !filepath.IsAbs(argv[0]) {
		return Result{}, fmt.Errorf("observe: target command must be an absolute path, got %q", argv[0])
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
			// The SIGSYS answer is dropped: every path reaching here returns Result{}, so
			// there is no observation for it to qualify.
			_ = reapTracees(tracees)
		}
	}()

	// The child stops at its initial execve; set options to follow subprocesses, to tag
	// syscall stops distinctly, and to report each exec - the one event that names the tid
	// an execve retires (see the PTRACE_EVENT_EXEC case) - then let it run.
	var ws syscall.WaitStatus
	if _, err := waitTracee(root, &ws, 0, nil); err != nil {
		return Result{}, fmt.Errorf("observe: initial wait: %w", err)
	}
	if ws.Exited() || ws.Signaled() {
		// Root died between its PTRACE_TRACEME and the exec stop - an external signal, or
		// the cgroup OOM killer whose limits this run's own profiling sets - and the wait
		// above reaped it. Everything below assumes it is alive and stopped, and leaving
		// it in the set would have the cleanup guard SIGKILL a freed pid that by now may
		// belong to an unrelated host process, which is the hazard the root-exit branch
		// deletes it for.
		delete(tracees, root)
		return Result{}, fmt.Errorf("observe: the target ended before the trace attached")
	}
	if err := requireSyscallInfo(root); err != nil {
		return Result{}, err
	}
	const opts = syscall.PTRACE_O_TRACESYSGOOD |
		syscall.PTRACE_O_TRACECLONE | syscall.PTRACE_O_TRACEFORK | syscall.PTRACE_O_TRACEVFORK |
		syscall.PTRACE_O_TRACEEXEC |
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
	// failed read has no op of its own to supply. See nextStop.
	lastOp := map[int]byte{}
	// Whether each tid's most recent spawn attempt was an execve rather than an execveat,
	// parked at the entry stop for the exec event to read. Keyed on the tid because the
	// event carries the new image's registers and so no stop key can be rebuilt from it,
	// the same reason releaseHeldOf sweeps by tid.
	execSpawn := map[int]bool{}
	// Whether an open of each path was ever seen to return a file. Keyed on the path
	// alone rather than on seen's path+write key: a program that probes a path read-only,
	// gets ENOENT, then creates it has opened one file, and letting the two entries carry
	// opposite answers would report a file that demonstrably exists as absent.
	resolved := map[string]bool{}
	missed := map[string]bool{}
	// Which of the two decoders named each path, keyed on the path alone like resolved
	// and missed above and for the same reason: one path reached both ways must not
	// carry two answers. Probe-only is the weaker claim, so opened wins when both hold.
	opened := map[string]bool{}
	probed := map[string]bool{}
	var res Result
	add := func(path string, write bool) {
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
	record := func(path string, write bool) {
		if path != "" {
			opened[path] = true
		}
		add(path, write)
	}
	// recordProbe is record for the existence decoder alone - the syscalls that ask
	// whether a path is there without opening it. The access itself is recorded exactly
	// as record's is; only the attribution differs.
	recordProbe := func(path string, write bool) {
		if path != "" {
			probed[path] = true
		}
		add(path, write)
	}
	openResult := func(path string, found bool) {
		if found {
			resolved[path] = true
			return
		}
		missed[path] = true
	}

	// The root's own execve retired before the loop attached - the child comes up stopped
	// AT it - so no syscall stop names it, and the images the kernel opened for it are
	// missing for the same reason a descendant's were. The binary itself is the entrypoint
	// the caller already knows about; its #! interpreter and its loader are not, and a
	// script run this way profiled without the shell that ran it. cmd.Path is argv[0] after
	// the PATH search, which is the file the kernel actually opened.
	rootImages, rootComplete := execImageChain(cmd.Path)
	for _, image := range rootImages {
		record(image, false)
	}
	if !rootComplete {
		res.Dropped++
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
			// Every pathname still held is an existence probe whose entry stop resolved a
			// pathname and whose exit stop can never arrive: the loop returns here and the
			// descendants that would have delivered it are SIGKILLed just below. Reachable
			// two ways - a descendant the script backgrounded, still mid-probe, and root
			// itself killed mid-syscall, the crash/OOM/timeout shape Signaled reports. No
			// per-pid sweep is needed because at this point they are all lost, and no
			// phantom is counted on a clean run: each descendant's held is swept at its own
			// exit, so a script whose children have finished leaves this empty.
			res.Dropped += existenceHeld(held)
			// A descendant SIGSYS'd before root exited may still have its status queued
			// here, and this drain is the only thing that sees it.
			if reapTracees(tracees) {
				res.SeccompKilled = true
			}
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
			for i, a := range res.Accesses {
				res.Accesses[i].Absent = missed[a.Path] && !resolved[a.Path]
				res.Accesses[i].Probed = probed[a.Path] && !opened[a.Path]
			}
			return res, nil
		case ws.Exited() || ws.Signaled():
			// A subprocess ended and is reaped; forget it so the guard does not wait on a
			// freed pid, and nothing to resume.
			res.Dropped += forgetExitedTid(wpid, tracees, lastOp, held, drops, execSpawn)
			continue
		case ws.Stopped() && ws.StopSignal() == syscall.SIGTRAP|0x80:
			// A syscall stop. Decode the file-opening ones, unless it came through a
			// foreign ABI and the amd64 table would misread it. Recording on both entry
			// and exit is deduplicated, so no enter/exit bookkeeping beyond the drop
			// counter's own.
			count, release, forget := dropOnce(drops, wpid, &res.Dropped)
			if op, native := nativeSyscall(wpid, lastOp, held, forget, &res.Dropped); native {
				inspect(wpid, op, record, recordProbe, openResult, count, release, forget, held, execSpawn, &res)
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
			// An exec event reports the tid the execve retired, which is the one
			// disappearance ptrace does not otherwise announce - see forgetRetiredTid.
			//
			// Nothing is swept when the message will not load, and nothing can be: the
			// retired tid is unrecoverable afterwards, since the post-exec thread group
			// holds only the stopping pid. A tracee at an event stop answers this request,
			// so the one way to get here is the tracee dying between the wait and the
			// call - and then the retirement is the smaller half of the loss, because the
			// execed image is going with it.
			//
			// This is also where Execed is set, because this event is the only report that
			// a spawn actually happened - the syscall that fired it has no exit stop to
			// return through. WHICH spawn syscall it was is the entry stop's answer, parked
			// under the calling tid; that tid is this event's message, so a thread's execve
			// is credited to the thread that issued it and not to the leader whose pid it
			// has just taken over. An unloadable message falls back to the stopping pid,
			// which is the same tid whenever the execing thread was the leader.
			case syscall.PTRACE_EVENT_EXEC:
				spawner := wpid
				if old, err := syscall.PtraceGetEventMsg(wpid); err == nil {
					spawner = int(old)
					// Before the sweep below, which would count the exec this event is
					// reporting as an observation lost with the retired tid.
					res.Dropped += recordExecOf(held, spawner, record)
					res.Dropped += forgetRetiredTid(wpid, spawner, tracees, lastOp, held, drops)
				}
				res.Dropped += recordExecOf(held, wpid, record)
				if execSpawn[spawner] {
					res.Execed = true
				}
				delete(execSpawn, spawner)
				// The tid this event retired took the leader's pid, and a leader parked
				// mid-execve of its own leaves that answer under the surviving pid with
				// nothing left to retire it. The next spawn's entry stop normally overwrites
				// it, but one this decoder could not read does not - and the stale true then
				// credits an execveat with an execve, which is the ExecAll over-grant a
				// single misattribution buys. The same sweep forgetExitedTid makes for the
				// same reason.
				if spawner != wpid {
					delete(execSpawn, wpid)
				}
			}

			// A group-stop, a ptrace event (a new child), or a genuine
			// signal-delivery-stop. Forward a real signal so the tracee actually
			// receives it: suppressing a synchronous fault (SIGSEGV/SIGILL/...) would
			// re-run the faulting instruction forever and spin the profiler, and
			// eating SIGINT/SIGTERM/SIGALRM/SIGCHLD would hang or misbehave an
			// otherwise healthy target. SIGTRAP is the exception - every ptrace event
			// stop reports it, including the fork/clone and exec events handled above,
			// and forwarding it (default action: core dump) would kill the tracee.
			//
			// One policy covers all three, and the reason is what group-stop does with a
			// forwarded stop signal: a target that stops ITSELF - kill -STOP, a shell's
			// job control, SIGTTIN on a background process group reading the controlling
			// terminal - reports the stop twice, once as the delivery and once as the
			// group-stop it caused, and the second resume LIFTS the group-stop rather
			// than re-arming it. If it re-armed instead, the loop would dequeue and
			// forward the same SIGSTOP forever - nothing here sends SIGCONT - and a
			// profile would hang with no diagnostic. ptrace(2) recommends passing 0 when
			// restarting from any stop that is not a signal-delivery-stop, which would
			// say the same thing more directly; the forwarding here predates that reading
			// and is pinned by test rather than by the recommendation.
			//
			// It is also why a self-stop does not pause a profiled run the way it would
			// an untraced one.
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
// failure leaves no op field to tell them apart. With the request's availability already
// established at the initial stop, the failure that actually happens is a tracee that died
// mid-pair, and it has no second stop to count; which stop it died at decides whether that
// is a real loss, and lastOp is what answers it here - unlike inspect, which has this stop's
// own op in hand. Any other errno leaves a live tracee whose second stop is still coming, so
// it is counted flatly and judged on nothing (see unreadableStopLoss).
//
// This settles the audit arch, not the whole ABI question: x32 shares AUDIT_ARCH_X86_64
// and passes here, and inspect drops it on the tag its syscall numbers carry.
func nativeSyscall(pid int, lastOp map[int]byte, held map[string]heldPath, forgetDrops func(), dropped *int) (op byte, native bool) {
	op, arch, err := syscallInfo(pid)
	if err != nil {
		// A read that failed says nothing about which stop this was, so the parity it
		// would have recorded is gone and every later inference off this pid's stale one
		// would be off by a stop.
		prev := lastOp[pid]
		delete(lastOp, pid)
		if errors.Is(err, syscall.ESRCH) {
			*dropped += deadThreadLoss(nextStop(prev), held, pid)
		} else {
			*dropped += unreadableStopLoss(held, pid, forgetDrops)
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

// deadThreadLoss reports how many observations an ESRCH at a stop of this op actually lost.
// It is the one judgement both reads that can fail on a dying thread share -
// PTRACE_GET_SYSCALL_INFO in nativeSyscall and PtraceGetRegs in inspect - because which of
// the two loses the race is a coin flip on the same event.
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
// Those pathnames are released as they are counted, because this thread's wait status is
// still coming and the sweep it triggers would otherwise count every one of them a second
// time - one lost probe reported as two, which is the miscount dropOnce exists to prevent.
//
// Any other op - the initial exec stop's NONE, a seccomp stop, or a parity that was never
// established - is unknown rather than safe, and counts one. An uncounted lost access is the
// failure this channel exists to prevent, so unknown must never mean "suppress". Nothing is
// released there: what was lost is a stop of unknown kind, not the held pathnames, and those
// are still the exit sweep's to count.
func deadThreadLoss(op byte, held map[string]heldPath, pid int) int {
	switch op {
	case unix.PTRACE_SYSCALL_INFO_ENTRY:
		return 0
	case unix.PTRACE_SYSCALL_INFO_EXIT:
		return releaseHeldOf(held, pid)
	}
	return 1
}

// unreadableStopLoss reports how many observations a read that failed for a reason other
// than ESRCH lost, and releases the pathname the stop's pair was holding as it counts. The
// other sibling of deadThreadLoss: both reads that can fail - PTRACE_GET_SYSCALL_INFO in
// nativeSyscall and PtraceGetRegs in inspect - take this branch on an EIO or EFAULT.
//
// One, always, and not judged on the op the way deadThreadLoss judges its own. The
// asymmetry is the tracee's state, not an oversight: a dead thread at an entry stop never
// ran the syscall, so there was nothing to lose, while here the thread is alive and the
// syscall does run - the stop just cannot be decoded. At an entry stop that costs the
// pathname, which is read there and nowhere else; at an exit stop it costs the success
// filter. Either way this stop is one lost observation, and returning what the release
// below found instead would report an entry-stop failure as no loss at all.
//
// The release is what keeps that one from being counted twice. Any pathname held for this
// pid is this pair's - a tid has at most one pair open (see releaseHeldOf) - so it is the
// same loss, and left in place it would be counted again by the sweep at this tracee's exit
// (releaseHeldOf) or at root's (len(held)).
//
// forgetDrops ends the pair's dedup for the same reason, and it is the half with a cost
// that outlives this stop. This count goes straight to the total rather than through
// dropOnce, so the sweep loses nothing here - but the thread is ALIVE, unlike every other
// caller of forgetDropsOf, and its next iteration of the same libc call site rebuilds the
// identical key. Left in place, that key suppresses every later drop at that site for the
// life of the tracee.
func unreadableStopLoss(held map[string]heldPath, pid int, forgetDrops func()) int {
	releaseHeldOf(held, pid)
	forgetDrops()
	return 1
}

// nextStop reports the op of the stop that follows one of op, which is what a stop whose
// own read failed has to be judged on. A thread's syscall stops strictly alternate and
// every one of them passes through nativeSyscall, so the stop after an entry is an exit and
// the stop after an exit is an entry.
//
// prev is a pid's last op only when one was read successfully, so anything else - a cloned
// child's first stop, a stop after a failed read, the initial exec stop's NONE, a seccomp
// stop - carries no parity and yields NONE, which deadThreadLoss counts. Inferring
// where nothing was observed is what would turn this into a silent suppressor.
//
// One stop stream is spliced rather than alternating: a non-leader thread that execve's
// adopts the leader's pid, so the execve exit stop arrives under the leader's pid carrying
// the leader's own parity rather than the execing thread's. Neither answer loses an
// observation: a stale ENTRY infers an exit stop, whose only decode is a success filter
// execve never registered, and a stale EXIT infers an entry stop and suppresses - which is
// right, because forgetRetiredTid has already released and counted everything that pid was
// holding across the exec. The retired tid's own parity is not left behind to be read at all;
// the exec event names it and the loop forgets it there.
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

// waitTracee is both waits Trace makes - the initial one and the loop's - indirected
// through a var so a test
// can force the defensive error returns - otherwise effectively unreachable (EINTR is
// retried, ECHILD cannot occur while root is unreaped) - and check that the tracees live at
// that point are reaped, not leaked.
//
// The INITIAL wait goes through it as well as the loop's, and is the return with the most
// to leak: it fires before PtraceSetOptions, so no PTRACE_O_EXITKILL is set and a child
// left TASK_TRACED there survives the tracer entirely.
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
//
// It reports whether any status it drained was a SIGSYS death, because those statuses
// never reach the main loop's own SIGSYS test: Wait4(-1) returns whichever child is ready
// in task-list order, so a helper killed by a kill-mode filter is drained here whenever
// root's status is dequeued first. Losing it lets Synthesize build a manifest from an
// observation it would otherwise refuse, with everything that process touched missing and
// Dropped at 0.
//
// It is indirected through a var so a test can see the remainder the loop hands it: a tid
// left in the set that no longer exists is a pid this would SIGKILL blind, and nothing else
// about the trace shows it.
var reapTracees = reapTraceesImpl

func reapTraceesImpl(tracees map[int]bool) (seccompKilled bool) {
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
			return seccompKilled // ECHILD: no waitable tracee remains; any survivor reparented to init
		}
		if ws.Signaled() && ws.Signal() == syscall.SIGSYS {
			seccompKilled = true
		}
		if ws.Exited() || ws.Signaled() {
			delete(remaining, wpid)
		}
	}
	return seccompKilled
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
// A key outlives its pair whenever the exit stop never reaches the release: a stop this
// tracer could not read at all, and a tracee that dies mid-pair. The second would strand a
// key on a tid the kernel is free to reuse, so forgetDropsOf sweeps it as the wait status
// arrives. The first leaves it on a tid that is still very much alive and still looping
// through the same call site, where every later iteration dedups against a key whose pair
// ended - the undercount this channel exists to prevent, and why forget is returned
// alongside: unreadableStopLoss sweeps the pid there, the same way it releases the
// pathname the pair was holding.
func dropOnce(inFlight map[string]bool, pid int, n *int) (count func(*syscall.PtraceRegs, int), release func(*syscall.PtraceRegs), forget func()) {
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
	forget = func() { forgetDropsOf(inFlight, pid) }
	return count, release, forget
}

// stopKey identifies one syscall's entry/exit pair: the tracee, plus the syscall's number
// and instruction pointer, which are identical at both stops. It is NOT unique across
// calls - a libc call site issuing the same syscall in a loop repeats it every iteration -
// so everything keyed on it must release the entry as the pair completes.
func stopKey(pid int, regs *syscall.PtraceRegs) string {
	return fmt.Sprintf("%d\x00%d\x00%d", pid, regs.Orig_rax, regs.Rip)
}

// forgetRetiredTid drops every trace of the tid an execve retired, and reports how many
// observations went with it. A thread that execve's takes over the thread-group leader's pid
// and its own tid ceases to exist with no wait status, so every map keyed on that tid would
// strand its entry - the exec event, whose message is that former tid, is the only report of
// the disappearance.
//
// tracees is the entry with a consequence: reapTracees SIGKILLs whatever the set names, and
// by reap time the retired tid may belong to an unrelated host process. It also keeps the
// set from ever emptying, which drops the drain onto its ECHILD stop and forfeits the "never
// blocks on the embedder's own children" property reapTracees documents.
//
// The ordinary exec - by a single-threaded process or by the leader itself - reports the
// stopping pid as the retired tid, because that pid is exactly what the execing thread kept.
// It is still very much alive, so nothing is forgotten there: dropping a live tracee from the
// reap set leaves it TASK_TRACED under a tracer that, for a library embedder, may never exit,
// which is a worse leak than the strand being swept. The pid is re-tracked at its next stop,
// so only a descendant that exits the window between the two would leak - which is a race,
// not a certainty, and reason enough not to open it.
//
// The retired tid is not the only casualty. The execve also destroys the thread-group leader
// whose pid the execer took, and that death is announced even less than the retirement - the
// pid it happened under is still stopped right here. So everything held under the stopping pid
// is swept too: it belongs to a thread that no longer exists, the image now under that pid has
// issued no syscall of its own yet, and the exit stop those pathnames are waiting on can never
// arrive. Only in the non-leader case, where the pid demonstrably changed hands; an ordinary
// exec's pathnames belong to the thread that is still running and still owes them an exit stop.
//
// That leader sweep is the half with reachable losses to count - a leader mid-probe when a
// sibling execs is the observed case. The retired tid's own sweep is symmetry: a thread's
// syscall stops alternate, so every pair the execer opened closed before its execve entry stop,
// and there should be nothing left to release. It is swept rather than assumed empty because
// the cost of being wrong is an uncounted access, which is what Dropped exists to prevent.
func forgetRetiredTid(wpid, old int, tracees map[int]bool, lastOp map[int]byte, held map[string]heldPath, drops map[string]bool) int {
	if old == wpid {
		return 0
	}
	delete(tracees, old)
	delete(lastOp, old)
	forgetDropsOf(drops, old)
	forgetDropsOf(drops, wpid)
	return releaseHeldOf(held, old) + releaseHeldOf(held, wpid)
}

// forgetExitedTid drops every trace of a tid whose wait status has arrived, and reports how
// many observations went with it. The sibling of forgetRetiredTid for the disappearance the
// kernel does announce.
//
// A thread killed between the entry and exit stop of an existence probe leaves that pathname
// held with no stop left to resolve it, and no ptrace request fails to say so - deadThreadLoss
// only speaks for a thread that dies AT a stop. A non-leader execve makes this routine:
// de_thread kills every sibling and each one arrives here.
//
// The release is load-bearing for what gets recorded, not only for the count. held is keyed on
// stopKey, whose tid the kernel is free to hand to a new tracee once this one is reaped; a
// stale entry left behind then matches the new thread's exit stop at the same call site, and
// recordHeldExistence records the dead thread's pathname gated on the live call's return
// value - a path the run never touched, in the manifest the user consents to. Dropping it here
// is what keeps that key from ever being reachable by another thread. A parked spawn answer is
// swept for the same reason and reports no loss: a tid that exited without reaching its exec
// event ran no exec, and left behind it would answer for whatever thread the kernel hands the
// tid to next - with exec: all as the price of being wrong.
func forgetExitedTid(wpid int, tracees map[int]bool, lastOp map[int]byte, held map[string]heldPath, drops map[string]bool, execSpawn map[int]bool) int {
	delete(tracees, wpid)
	delete(lastOp, wpid)
	delete(execSpawn, wpid)
	forgetDropsOf(drops, wpid)
	return releaseHeldOf(held, wpid)
}

// forgetDropsOf clears the in-flight drop keys a vanished tid left behind. It reports no
// loss and must not: every one of these keys was counted the moment the drop happened, and
// what a stale key costs is the NEXT count, not this one. dropOnce keys on the tid, so a
// pair whose exit stop never reached its release - inspect returning early on an
// unreadable stop, or nativeSyscall failing there - leaves a key the kernel can hand to a
// new tracee along with the tid. The next thread's drop at the same call site then dedups
// against a dead thread's and is never counted, which is the undercount this channel
// exists to prevent. The sibling of releaseHeldOf, and keyed the same way.
func forgetDropsOf(drops map[string]bool, pid int) {
	prefix := fmt.Sprintf("%d\x00", pid)
	for key := range drops {
		if strings.HasPrefix(key, prefix) {
			delete(drops, key)
		}
	}
}

// releaseHeldOf drops every pathname a vanished tid was still holding and reports how many
// were lost. Each is an existence probe whose entry stop resolved a pathname and whose exit
// stop can never arrive, so whether the call succeeded - the thing that decides if the path
// needs a grant - is unknowable. That is the same loss deadThreadLoss counts for a
// thread that dies at an exit stop holding one, and it is counted here for the same reason:
// an access the observer could not read must reach Dropped or the manifest is silently short.
//
// A held OPEN is released the same way and counted at none: its pathname reached Accesses
// at the entry stop, so what the missing exit stop costs is only the answer to whether the
// open found a file. Counting it would report a recorded access as lost.
//
// It takes a tid rather than a stop key because a vanished thread leaves no registers to
// form one. A tid has at most one pair open - its syscall stops alternate, and a signal
// handler's own stops cannot fall between one pair's two, because the exit stop is reported
// as the syscall returns and the handler runs only after the tracer has resumed past it -
// so this sweep normally finds a single entry. It is a sweep rather than a lookup because
// the key cannot be rebuilt, not because several can be held.
func releaseHeldOf(held map[string]heldPath, pid int) int {
	prefix := fmt.Sprintf("%d\x00", pid)
	lost := 0
	for key, h := range held {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		delete(held, key)
		if !h.open {
			lost++
		}
	}
	return lost
}

// heldPath is a pathname the entry stop resolved, kept until the exit stop can say
// whether the call succeeded. readOK is false when the pathname could not be read at all;
// the drop is deferred with it, because a failed existence probe needs no grant and so
// must not be reported as a lost access.
// An open holds for a different reason: its pathname was already recorded at the entry
// stop, and the exit stop only says whether the open found a file. Losing that answer
// costs a reporting nuance rather than an access, which is why the sweeps below count
// existence probes and not opens.
// An exec holds for a third reason: the image it names is only worth recording if the
// call did not answer that nothing is there. execvp and dash's tryexec issue a real
// execve per PATH element and read the ENOENT, so without the filter every miss enters
// the manifest as a resolved read of a path no file was ever found at. images and
// complete are the kernel's own opens for that image, resolved at the entry stop with the
// rest of it, and recorded with it or not at all.
type heldPath struct {
	path     string
	readOK   bool
	open     bool
	exec     bool
	images   []string
	complete bool
}

// existenceHeld counts the held pathnames whose loss is a lost access. See heldPath.
func existenceHeld(held map[string]heldPath) int {
	n := 0
	for _, h := range held {
		if !h.open {
			n++
		}
	}
	return n
}

// inspect decodes a syscall stop and records file opens / subprocess execs. The numbers
// below are amd64's, and three checks stand between a stop and that table: the caller has
// established the stop carries the amd64 audit arch (see nativeSyscall), the x32 check
// below rules out the one ABI that shares it, and the negative-number check rules out the
// stops that carry no syscall number at all. Past those three the numbers mean what they
// say.
func inspect(pid int, op byte, record, recordProbe func(string, bool), openResult func(string, bool), countDrop func(*syscall.PtraceRegs, int), releaseDrop func(*syscall.PtraceRegs), forgetDrops func(), held map[string]heldPath, execSpawn map[int]bool, res *Result) {
	var regs syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
		// No registers means no syscall number either, so this may not have been a file
		// access at all - a tracee killed between the stop and this read fails here on
		// whatever it was running.
		//
		// ESRCH means the thread died holding this stop, which deadThreadLoss can often
		// resolve to nothing rather than count. The op comes from the caller's own read at
		// this same stop, before any resume, so it describes this stop and not a later one.
		//
		// Every other failure is counted: an uncounted lost access is what this channel
		// exists to prevent. An EIO or EFAULT says nothing about whether the thread is
		// alive. It is counted per stop rather than through the pair's dedup, whose key
		// would be built from registers this read never returned - one key for every such
		// failure on this pid, so a second lost stop would dedup to nothing.
		if errors.Is(err, syscall.ESRCH) {
			res.Dropped += deadThreadLoss(op, held, pid)
			return
		}
		res.Dropped += unreadableStopLoss(held, pid, forgetDrops)
		return
	}
	// This syscall's entry/exit pair ends here, so its dedup key goes with it - see
	// dropOnce. Deferred so it runs after the decode below has had its chance to count.
	atExit := op == unix.PTRACE_SYSCALL_INFO_EXIT
	if atExit {
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
	// no path-existence syscall - the only ones decoded at the exit stop - can present here,
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
	// Every pathname this decoder reads is read HERE, at the entry stop, before the kernel
	// has copied the tracee's arguments. Reading one at the exit stop instead lets a
	// sibling sharing the address space (a thread, or any CLONE_VM child) overwrite the
	// buffer after the syscall ran, so the observer records a path the call never touched -
	// and over-attribution silently widens the manifest the user consents to. The exit stop
	// is still needed for one thing, the existence syscalls' success filter, and that
	// replays what was captured here rather than reading again.
	//
	// This narrows the window rather than closing it. ptrace freezes the stopped THREAD,
	// not the address space, so a CLONE_VM sibling still runs between this read and the
	// kernel's copyin after the resume. What is left is a race the sibling has to win
	// inside that window instead of across the whole syscall, and one a planted path only
	// converts into a recorded access when the call the kernel then ran also found a file.
	if atExit {
		// The exec release runs first and on its own: an exec is an open of the image, so
		// it is attributed like one rather than like an existence probe, and recordProbe
		// below is the existence decoder's alone.
		if !releaseHeldExec(pid, &regs, record, openResult, drop, held) {
			recordHeldExistence(pid, &regs, recordProbe, openResult, drop, held)
		}
		return
	}
	switch regs.Orig_rax {
	case sysOpenat:
		if path, ok := readPathAt(pid, int32(regs.Rdi), uintptr(regs.Rsi)); ok {
			record(path, regs.Rdx&writeFlags != 0)
			holdOpen(pid, &regs, held, path)
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
			holdOpen(pid, &regs, held, anchoredPath)
		}
	case sysOpen:
		// open/creat take no dirfd; a relative path is anchored at the working
		// directory, exactly the AT_FDCWD case, so route them through resolveAt too or
		// a relative open after a chdir would be mis-anchored.
		if path, ok := readPathAt(pid, atFdCwd, uintptr(regs.Rdi)); ok {
			record(path, regs.Rsi&writeFlags != 0)
			holdOpen(pid, &regs, held, path)
		} else {
			drop()
		}
	case sysCreat:
		if path, ok := readPathAt(pid, atFdCwd, uintptr(regs.Rdi)); ok {
			record(path, true)
			holdOpen(pid, &regs, held, path)
		} else {
			drop()
		}
	case sysExecve:
		// Which spawn syscall this is can only be read HERE: after a successful execveat
		// the kernel reports the exit stop as 59, so a number tested at any later stop
		// counts every execveat as an execve. Whether the call ran can only be read at the
		// exec EVENT, which is where the flag is set - so the answer to the first question
		// is parked under this tid for the second to pick up (see execSpawned).
		//
		// Both halves are load-bearing, in the same direction. Execed grants ExecAll, and
		// on ExecAll the launcher installs no exec-block filter at all, so a single
		// mis-attributed spawn turns into blanket execve permission for the whole run. An
		// execveat is not attributed because the filter denies execve and permits execveat
		// by construction - the launcher's own transition into the sandbox is an execveat -
		// so a target spawning that way runs identically under exec: none and exec: all,
		// and reporting it costs the user the filter and buys nothing. An execve that
		// FAILED spawns nothing, so it buys nothing either, at the same price: a script
		// reaching for a helper that is absent inside the profiling sandbox issues one
		// execve, gets ENOENT, and would take the whole run's exec block with it. That
		// attempt is still worth reporting - just not as a grant - which is what the
		// weaker flag set here carries.
		execSpawn[pid] = true
		res.ExecAttempted = true
		holdExecTarget(pid, &regs, atFdCwd, uintptr(regs.Rdi), false, held, drop)
	case sysExecveat:
		// Recorded as not-an-execve rather than left alone: a failed execve on this tid
		// parked a true above, and the exec event this execveat may be about to fire has no
		// way of its own to tell whose answer it is reading.
		execSpawn[pid] = false
		holdExecTarget(pid, &regs, int32(regs.Rdi), uintptr(regs.Rsi), regs.R8&unix.AT_EMPTY_PATH != 0, held, drop)
	default:
		if undecodedPathSyscalls[regs.Orig_rax] {
			drop()
			return
		}
		inspectMutating(pid, &regs, record, dropSlot)
		inspectExistence(pid, &regs, recordProbe, drop, held)
	}
}

// undecodedPathSyscalls are the syscalls that name a path, are reachable from inside the
// profiling sandbox, and that this decoder does not read. Each is COUNTED rather than
// decoded: without it a target that named a path this way leaves the access out of
// Accesses AND leaves Dropped at 0, which is the one direction that channel's invariant
// forbids - the caller reads the run as having touched nothing there and synthesizes a
// short manifest. Counting says the observation is incomplete without claiming to know
// what was lost, which is what Dropped exists to pay for.
//
// Enumerated rather than "any number that matched no case". A blanket counter fires on
// every syscall this decoder deliberately ignores - and phantom drops in the hundreds, in
// the one channel that tells a user their manifest is short, is a defect this package has
// already been fixed for once (see the rt_sigreturn and utimensat notes above).
//
// Reachable means reachable from a profiling run, not merely defined. The mount family
// and chroot need capabilities the run does not start with, but nothing stops the target
// calling unshare(2) - runObserve installs only BlockIoUring, which refuses the three
// io_uring calls and permits everything else - and a fresh user namespace hands back
// CAP_FULL_SET over it. open_tree without OPEN_TREE_CLONE and fanotify_mark since 5.13
// need no privilege at all; fanotify_mark is the sharpest of them, because its sibling
// inotify_add_watch is decoded a few lines below.
//
// Deliberately absent: swapon/swapoff/acct/quotactl want capabilities in the INITIAL
// namespace, mq_open/mq_unlink want an mqueue mount the sandbox does not provide, and
// io_uring is refused before the fork. Add a number here when it becomes reachable, and
// prefer moving one out into a decode when the path it names is worth recording.
var undecodedPathSyscalls = map[uint64]bool{
	unix.SYS_CHROOT:        true,
	unix.SYS_PIVOT_ROOT:    true,
	unix.SYS_MOUNT:         true,
	unix.SYS_UMOUNT2:       true,
	unix.SYS_OPEN_TREE:     true,
	unix.SYS_MOVE_MOUNT:    true,
	unix.SYS_FSPICK:        true,
	unix.SYS_FANOTIFY_MARK: true,
}

// inspectExistence decodes the path-EXISTENCE syscalls - the ones that ask whether a
// path is there without opening it. Under enforcement an ungranted path is not merely
// unreadable but absent, so a target that stats a config it never opens sees it during
// the permissive profiling run, gets ENOENT on the enforced run, and takes a different
// branch. Existence and read are the same grant here - making a stat succeed means
// binding the path into the sandbox - so each is recorded as a plain read.
//
// Unlike every other case in this decoder these are dropped when the call answered that
// the path is not there. A failed open still needs a grant, because the script meant to
// open that file; a stat that already returned ENOENT needs none, because enforcement
// reproduces that exact answer. The filter is what keeps manifests tight: a shell's PATH
// search misses hundreds of times per command, and recording those probes would bury the
// paths the run actually needs. It turns on the errno rather than on failure alone - see
// recordHeldExistence, where a probe refused on an existing path is still an access. chdir
// is the one case here that skips the filter, for the reason its own branch below gives.
//
// A successful access(W_OK) is recorded as a read, not a write. It reports that a write
// would be permitted, which a read-only bind makes false - but over-attribution silently
// widens the manifest while under-attribution fails the run closed and is fixed by
// adding a grant, the same asymmetry the openat2 decode turns on.
//
// getdents64 and fchdir carry no pathname, and the descriptor they act on came from an
// openat this decoder already recorded. getcwd names the run's own working directory,
// which the sandbox must have bound for the process to be running in it.
//
// It runs at the ENTRY stop and only captures: the pathname is read and resolved here,
// before the kernel has copied it, then held under this stop's key until
// recordHeldExistence can apply the filter against the return value at the exit stop.
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
	// getxattrat/listxattrat are the Linux 6.13 *at forms of the xattr readers above,
	// taking (dirfd, path, at_flags, ...). They answer ENOENT for a path the sandbox did
	// not bind exactly as their non-at siblings do, so leaving them out would let a run
	// that probes only this way profile as not needing the path.
	case unix.SYS_NEWFSTATAT, unix.SYS_STATX, unix.SYS_FACCESSAT, unix.SYS_FACCESSAT2, unix.SYS_READLINKAT,
		unix.SYS_NAME_TO_HANDLE_AT, unix.SYS_GETXATTRAT, unix.SYS_LISTXATTRAT:
		dirfd, pathReg = int32(regs.Rdi), regs.Rsi
	// inotify_add_watch(fd, path, mask) takes a watch descriptor, not a dirfd, so its
	// pathname is anchored at the working directory like the non-at forms.
	case unix.SYS_INOTIFY_ADD_WATCH:
		dirfd, pathReg = atFdCwd, regs.Rsi
	default:
		return
	}
	// An unreadable pathname is not dropped here: the drop travels with the held entry, so
	// that a probe the kernel goes on to answer "not there" costs nothing - the same filter
	// the recorded path itself gets.
	path, ok := readPathAt(pid, dirfd, uintptr(pathReg))
	held[stopKey(pid, regs)] = heldPath{path: path, readOK: ok}
}

// holdOpen keeps an open's pathname until its exit stop can say whether it found a file.
// The access itself is already recorded by the time this is called and stays recorded
// whatever the return value says - a failed open still needs a grant, because the program
// meant to open that file. What the exit stop adds is the difference between a path that
// resolved to something and one that was only probed, which is a distinction the reporting
// layer needs and the grant does not. Replaying the entry stop's pathname rather than
// reading it again at the exit stop is what keeps a sibling sharing the address space from
// swapping in a path the call never touched.
func holdOpen(pid int, regs *syscall.PtraceRegs, held map[string]heldPath, path string) {
	held[stopKey(pid, regs)] = heldPath{path: path, readOK: true, open: true}
}

// recordHeldExistence applies the existence syscalls' success filter at the exit stop, to
// the pathname the entry stop resolved, and releases the held entry either way. A held
// open takes the same exit stop to report what its return value found; see holdOpen.
//
// Only a call that found the path is recorded. A failed open still needs a grant, because
// the script meant to open that file; a stat that already returned ENOENT needs none,
// because enforcement reproduces that exact answer. The filter is what keeps manifests
// tight: a shell's PATH search misses hundreds of times per command, and recording those
// probes would bury the paths the run actually needs.
func recordHeldExistence(pid int, regs *syscall.PtraceRegs, record func(string, bool), openResult func(string, bool), drop func(), held map[string]heldPath) {
	key := stopKey(pid, regs)
	h, ok := held[key]
	if !ok {
		return
	}
	delete(held, key)
	if h.open {
		// Only the two errnos that mean nothing is there answer the question, and every
		// other outcome leaves it unanswered rather than answering it no. A failure with
		// EACCES, EISDIR, ELOOP or a process out of descriptors is a file that exists and
		// refused the open for its own reason, and calling that absence would soften the
		// warning about a deceptive name on the file most worth warning about: one that is
		// present but unreadable.
		ret := int64(regs.Rax)
		if ret >= 0 {
			openResult(h.path, true)
		} else if errno := syscall.Errno(-ret); errno == syscall.ENOENT || errno == syscall.ENOTDIR {
			openResult(h.path, false)
		}
		return
	}
	// A probe that failed for any reason OTHER than the path not being there still names a
	// file the sandbox has to bind. ENOENT is the one answer enforcement reproduces
	// unchanged; the open branch's other errno, ENOTDIR, does not belong here and is
	// handled below. Everything else is a path that demonstrably exists and
	// refused the probe on its own terms: access(W_OK) answering EACCES on a file that is
	// present but not writable, a stat whose EACCES is a search permission missing on a
	// component that exists, ELOOP on a symlink chain that is very much there, getxattr's
	// ENODATA (the normal answer for a file carrying no such attribute), or
	// name_to_handle_at's EOVERFLOW, which is the documented first call of its two-call
	// protocol. Treating those as absence left the path out of the manifest entirely, and
	// the enforced run then answers ENOENT where the profiling run answered EACCES - a
	// different branch in the target, off a manifest that reported no loss.
	//
	// The rest of the skip set is the answers the kernel gives without looking at the path
	// at all, which say nothing either way and so must not widen the manifest. EFAULT and
	// ENAMETOOLONG mean the pathname itself never got taken. ENOSYS is a seccomp policy
	// (or a kernel too old) refusing the call before it runs, which is exactly how glibc
	// probes faccessat2 before falling back - and the fallback call gets a real answer of
	// its own. EBADF is a dirfd that names nothing, so no path was resolved against it;
	// an absolute pathname ignores the dirfd and cannot answer EBADF, so skipping it
	// hides no real file. ENOMEM is the same shape, rarer: the kernel gave up before it
	// resolved anything.
	//
	// EINVAL is NOT in that set, though it looks like it - statx with a bad mask and
	// faccessat2 with bad flags are both refused before the walk. It stays out because it
	// is not always pre-resolution: readlink and readlinkat answer EINVAL for a file that
	// is very much there and simply is not a symlink, and skipping that would drop a real
	// access.
	//
	// The four restart pseudo-errnos are in that category too, and only a TRACER sees
	// them: the signal machinery converts them before userspace ever does, but the
	// syscall-exit stop happens first, so this decoder reads the raw value. They say the
	// call is about to be re-issued and nothing about the path, and the re-issue rebuilds
	// an identical stop key and arrives with the real answer of its own. Reachable wherever
	// a probe can block and a signal can land: a stat on a FUSE or NFS mount under a Go
	// target, whose runtime preempts with a handled signal constantly.
	//
	// Literal EINTR is NOT one of them, though the kernel emits it at the same stop. It is
	// the syscall's own terminal answer - the aborted call that will not be re-issued, which
	// is what SA_RESTART's absence and FUSE's own aborted-request path both produce - so
	// there is no later stop carrying anything about this path. Skipping it put the
	// observation in neither Accesses nor Dropped, which is the manifest reading as complete
	// while the enforced run answers ENOENT where the profiling run got a real answer. It is
	// counted rather than skipped, the same as ENOTDIR below and for the same reason: the
	// answer is missing either way, and only Dropped says so.
	if ret := int64(regs.Rax); ret < 0 {
		switch syscall.Errno(-ret) {
		case syscall.ENOENT, syscall.EFAULT, syscall.ENAMETOOLONG,
			syscall.ENOSYS, syscall.EBADF, syscall.ENOMEM,
			errRestartSys, errRestartNoIntr, errRestartNoHand, errRestartRestartBlock:
			return
		case syscall.EINTR:
			drop()
			return
		case syscall.ENOTDIR:
			// Not the answer ENOENT is, though both mean the probed path is not there.
			// ENOTDIR is the kernel reporting a component that IS there and is not a
			// directory - stat("/etc/passwd/x") answers it only because /etc/passwd exists
			// and is a regular file - so an unbound sandbox answers ENOENT instead, and a
			// target branching on the two (which is the whole reason this decoder exists)
			// takes a different branch under enforcement.
			//
			// What would settle it is the file that made the difference, and this pathname
			// is not it: for stat("/etc/passwd/x/y") the offending component is two levels
			// up, so naming any fixed ancestor would put a path the sandbox cannot bind in
			// the manifest. That makes it an observation this decoder cannot make, counted
			// rather than skipped - the answer is missing either way, and only Dropped
			// says so.
			drop()
			return
		default:
			// Errno is not an enum with a fixed set; every other failure is a real
			// refusal of a path that resolved, which is what the caller records.
		}
	} else {
		// Only a probe that SUCCEEDED settles the question an open's return value settles -
		// so a file that a stat reached but an open missed is not reported as absent. A
		// refused probe proves the path is worth granting, not that the final component
		// resolved: a stat refused for search permission never reached it.
		openResult(h.path, true)
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
	// setxattrat/removexattrat are the Linux 6.13 *at forms of the xattr writers above,
	// taking (dirfd, path, at_flags, ...) - the same reason the case above gives for
	// fchmodat2, applied to the row it stopped short of. AT_EMPTY_PATH makes them act on
	// the descriptor and name no path, which arrives here as an empty pathname rather
	// than the NULL utimensat's exemption is about, and record already skips that.
	case unix.SYS_MKDIRAT, unix.SYS_UNLINKAT, unix.SYS_MKNODAT,
		unix.SYS_FCHMODAT, sysFchmodat2, unix.SYS_FCHOWNAT, unix.SYS_UTIMENSAT, unix.SYS_FUTIMESAT,
		unix.SYS_SETXATTRAT, unix.SYS_REMOVEXATTRAT:
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
		if path, ok := sockaddrUnixPath(pid, uintptr(regs.Rsi), uint32(regs.Rdx)); !ok {
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
		if path, ok := sockaddrUnixPath(pid, uintptr(regs.Rsi), uint32(regs.Rdx)); !ok {
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
//
// addrlen is uint32 because socklen_t is: the kernel reads only the low half of the
// register, so a target that sets the high half - hand-written asm, or a syscall(2) call
// whose long argument has an uncleared top half - connects successfully to a host socket
// while a 64-bit read here sees an over-long address and reports no filesystem entry.
// Narrowed in the signature rather than at each call site so bind and connect cannot drift.
func sockaddrUnixPath(pid int, addr uintptr, addrlen uint32) (string, bool) {
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
// which case the caller drops the observation rather than recording anything: without
// the resolve flags there is no honest path, and guessing one named a file the kernel
// never opened.
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

// recordExecTarget records the binary a spawn syscall names, and the images the kernel
// then opens for it without a syscall - see execImageChain. The sandbox must be able to
// read and execute all of them, so each is an access like any other - and a spawn by absolute path
// (os/exec with a full path, or a bare syscall.Exec) reaches the kernel without the PATH
// search whose stats would otherwise have recorded it incidentally.
// An empty pathname is execveat's AT_EMPTY_PATH form, where the descriptor names the
// binary and nothing else does - fexecve(3) and every memfd or O_PATH exec route reaches
// the kernel this way. Recording nothing there left the spawned binary out of the manifest
// AND out of Dropped, so the enforced run fails closed on a file the profiling run said
// was never touched. The elsewhere-correct "an empty path names no file" rule (see the
// AT_EMPTY_PATH note in inspectExistence, where naming nothing is right) does not hold for
// an exec. The descriptor is resolved through /proc exactly as a relative path's anchor
// is, which also settles the memfd case honestly: its link reads "… (deleted)", resolveAt
// refuses it, and a drop says the observation is short rather than naming a pseudo-path
// the sandbox could never bind.
func holdExecTarget(pid int, regs *syscall.PtraceRegs, dirfd int32, addr uintptr, emptyPath bool, held map[string]heldPath, drop func()) {
	path, ok := readPathAt(pid, dirfd, addr)
	if !ok {
		drop()
		return
	}
	if path == "" {
		// Without AT_EMPTY_PATH there is no file: execve(""), execveat(AT_FDCWD, "")
		// and execveat(fd, "", 0) all name nothing and the kernel answers ENOENT, so
		// this is not a lost observation to count. Resolving the descriptor anyway would
		// record a binary the call never ran. Anchoring "." at the descriptor is what
		// turns the flagged form into the file's own path - /proc/<pid>/fd/<n> links
		// straight to it.
		if !emptyPath || dirfd == atFdCwd {
			return
		}
		if path, ok = resolveAt(pid, dirfd, "."); !ok {
			drop()
			return
		}
	}
	images, complete := execImageChain(path)
	held[stopKey(pid, regs)] = heldPath{path: path, readOK: true, exec: true, images: images, complete: complete}
}

// recordExecHeld records an exec target and the images the kernel opens for it, and
// reports whether the chain was short. The pair is recorded together or not at all: the
// images are the kernel's opens for THIS image, so naming them off a call that resolved
// nothing would put a loader in the manifest for an exec that never happened.
func recordExecHeld(h heldPath, record func(string, bool)) int {
	record(h.path, false)
	for _, image := range h.images {
		record(image, false)
	}
	if !h.complete {
		return 1
	}
	return 0
}

// releaseHeldExec answers the exit stop of an exec that FAILED - a successful one was
// recorded at its exec event, which arrives before this stop - and reports whether this
// stop was one.
//
// The access is recorded either way, exactly as a failed open's is: the target meant to
// run that file, and a grant is what makes it reachable. What the return value settles is
// the same thing it settles for an open - whether anything was found there - and it is
// answered on the open branch's three-valued rule, because it is the same question. Only
// ENOENT and ENOTDIR say the path is not there, only a spawn that ran says it is, and
// every other outcome leaves the question open rather than answering it either way. The
// restart pseudo-errnos are why that third case has to exist here and not just for opens:
// execve returns ERESTARTNOINTR raw at this stop when a signal lands during de_thread, and
// calling that "found" would let a PATH-search miss claim the path resolved - resolved
// beats missed, so the re-issue's real ENOENT could not correct it afterwards.
//
// Without the answer at all, every exec target read back as resolved, including the ones
// nothing was ever found at: glibc's execvp and dash's tryexec search PATH with a real
// execve per element rather than a stat, so the existence decoder's own filter never sees
// those misses, and each entered the manifest as a positive claim that the path was there.
//
// Whether such a path is worth PROPOSING is not decidable here. The observer runs inside
// the sandbox, where a tool the host has and the run did not bind answers the same ENOENT
// a search miss does; only the host can tell the two apart, and the read that gets it
// mounted next round is the whole point of profiling it.
func releaseHeldExec(pid int, regs *syscall.PtraceRegs, record func(string, bool), openResult func(string, bool), drop func(), held map[string]heldPath) bool {
	key := stopKey(pid, regs)
	h, ok := held[key]
	if !ok || !h.exec {
		return false
	}
	delete(held, key)
	ret := int64(regs.Rax)
	switch {
	case ret >= 0:
		openResult(h.path, true)
	case syscall.Errno(-ret) == syscall.ENOENT || syscall.Errno(-ret) == syscall.ENOTDIR:
		openResult(h.path, false)
	}
	if lost := recordExecHeld(h, record); lost > 0 {
		drop()
	}
	return true
}

// recordExecOf records the exec a tid was holding, because the exec EVENT says it ran.
// That event is the only report a successful execve gets - its exit stop carries the new
// image's registers, so the key the entry stop parked under cannot be rebuilt there - and
// it arrives before that exit stop, which is what leaves the exit stop to the calls that
// failed. It sweeps by tid for the same reason releaseHeldOf does, and every other way a
// held exec can end (the tid dying, an unreadable stop) still counts it as the lost
// observation it is.
func recordExecOf(held map[string]heldPath, pid int, record func(string, bool)) int {
	prefix := fmt.Sprintf("%d\x00", pid)
	lost := 0
	for key, h := range held {
		if !strings.HasPrefix(key, prefix) || !h.exec {
			continue
		}
		delete(held, key)
		lost += recordExecHeld(h, record)
	}
	return lost
}
