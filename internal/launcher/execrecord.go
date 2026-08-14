//go:build linux

package launcher

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
)

// execRun is one exec the recorder observed: the image the kernel actually ran and the
// argv it ran with. Both are read from /proc at the stop, after the exec retired, so
// there is no pathname to fetch out of tracee memory and nothing to resolve against a
// dirfd - and /proc/<pid>/exe is the kernel's own answer, so a symlinked interpreter
// (/bin/sh reading back as /usr/bin/dash) and a PATH search are already resolved.
type execRun struct {
	pid  int
	exe  string
	argv []string
}

// execRecorder accumulates what an enforced run executed. It is exec-only ptrace: the
// tracer sets PTRACE_O_TRACEEXEC with the clone/fork options and resumes with
// PTRACE_CONT, so the cost is one stop per exec plus the fork and exit events rather
// than one per syscall.
//
// The target cannot hide an exec from it. The clone/fork options attach a descendant
// before it runs an instruction, and a tracee has exactly one tracer - which is also the
// price the recorder charges, and why it is opt-in: with it on, nothing inside the
// sandbox can ptrace anything, so strace, gdb and a harness attaching to its own child
// meet EPERM they do not meet otherwise.
type execRecorder struct {
	// runs is seeded with the target itself. The root exec retires before the tracer can
	// set its options - the child comes up stopped AT it - so no event names it, and the
	// launcher knows it by construction rather than leaving the record short.
	runs []execRun
	// failed is why the recorder could not watch, when it could not. The record is a
	// diagnostic: an attach the host refuses (Yama ptrace_scope 2 and 3 both do, and the
	// capability that would answer them is not available inside a --cap-drop ALL user
	// namespace) is reported and the run proceeds untraced.
	failed error
	// unavailable is why this mode cannot have a recorder at all, as opposed to failed,
	// which is a recorder this mode could have had and did not get. The distinction is
	// the host's: a mode that structurally cannot be watched is not a shortfall to
	// report, and a run that asked for a record on one should be told so plainly.
	unavailable error
}

// record appends one observed exec.
func (r *execRecorder) record(pid int, exe string, argv []string) {
	r.runs = append(r.runs, execRun{pid: pid, exe: exe, argv: argv})
}

// superviseTraced is superviseTarget with the exec recorder attached. It is a separate
// path rather than a flag through the existing one so a run that did not ask for a
// record is byte-for-byte the run it is today: the wait loop, the resume calls and the
// tracee bookkeeping below exist only here.
//
// It preserves superviseTarget's contract exactly - an absolute argv[0], a start failure
// reported as a target that was never reached, and the exit code (128+signal for a
// signalled target) that waitExitCode renders - because the applied report's meaning
// rests on those and a diagnostic may not disturb them.
func superviseTraced(target, env []string, rec *execRecorder) (int, error) {
	// ptrace requires every call to come from the thread that started the tracee, so the
	// whole supervision runs pinned to one OS thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cmd, err := startTarget(target, env, true)
	if err != nil {
		// The child calls PTRACE_TRACEME before its exec, so a host that refuses the attach
		// fails here rather than at any call below - Yama ptrace_scope 2 and 3 are the whole
		// of that case. Retry untraced: the record is a diagnostic and a host that will not
		// permit it still gets its run. A start failure with a cause of its own fails the
		// retry too, and is reported as the unreached target it is.
		rec.failed = err
		return superviseTarget(target, env)
	}
	root := cmd.Process.Pid

	// Past Start the target exists, so nothing below may report it as never reached.
	code, done, err := attachRecorder(root)
	if done {
		// The target died before it ever stopped for the tracer - killed between the fork
		// and its own exec, which is the OOM or external-SIGKILL shape. The wait above
		// reaped it, so its status is the run's outcome and there is nothing left to trace.
		// superviseTarget reports exactly this code, and the recorder may not turn it into
		// a failed run.
		rec.failed = err
		// The seed goes with it, for the reason the exec-block path drops its own: the
		// target died before it reached the exec the seed stands for, so keeping the entry
		// would report an exec that provably never retired - the record lying about what
		// ran, behind a marker saying only that nothing watched.
		rec.runs = nil
		return code, nil
	}
	if err != nil {
		rec.failed = err
		// Detaching resumes the tracee, which is still stopped at its own initial exec, and
		// leaves this process its plain parent. Reaping is then reapChildren's again.
		if detachErr := syscall.PtraceDetach(root); detachErr != nil {
			// Nothing can resume it now, and a tracee left stopped forever is a hung run
			// rather than a missing diagnostic - so this one is fatal, with the target
			// already started.
			return 0, errTargetRan{errors.Join(err, fmt.Errorf("launcher: detaching the exec recorder: %w", detachErr))}
		}
		code, err := reapChildren(root)
		if err != nil {
			return 0, errTargetRan{err}
		}
		return code, nil
	}

	code, err = traceExecs(root, rec)
	if err != nil {
		return 0, errTargetRan{err}
	}
	return code, nil
}

// attachRecorder sets the recorder's options on the stopped root and lets it run.
//
// Deliberately NOT PTRACE_O_EXITKILL, unlike internal/observe: it would make a bug in
// the wait loop SIGKILL the whole enforced run, a diagnostic killing a run that would
// otherwise have succeeded. The observer sets it because a profiling run IS the trace, so
// an abandoned tracee is a leak with nothing left to reap it; here the point is the
// target. A tracer that dies detaches instead and the record ends where it ended, which
// is what the record section's own marker exists to make legible.
// done reports that the target ended instead of stopping, in which case code is its
// outcome and the caller has nothing left to trace or detach.
//
// Indirected through a var so a test can stage that death: it is a race against the
// target's own exec, and the caller's handling of it decides what the record claims ran.
var attachRecorder = attachRecorderImpl

func attachRecorderImpl(root int) (code int, done bool, err error) {
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(root, &ws, 0, nil); err != nil {
		return 0, false, fmt.Errorf("launcher: waiting for the target's initial stop: %w", err)
	}
	if ws.Exited() || ws.Signaled() {
		return waitExitCode(ws), true, fmt.Errorf("launcher: the target ended before the exec recorder could attach")
	}
	const opts = syscall.PTRACE_O_TRACEEXEC |
		syscall.PTRACE_O_TRACECLONE | syscall.PTRACE_O_TRACEFORK | syscall.PTRACE_O_TRACEVFORK
	if err := syscall.PtraceSetOptions(root, opts); err != nil {
		return 0, false, fmt.Errorf("launcher: installing the exec recorder: %w", err)
	}
	return 0, false, nil
}

// traceExecs is the wait loop. It resumes the stopped root, records an exec at each
// PTRACE_EVENT_EXEC stop, and returns the target's exit code when the root ends.
// Losing the loop is what makes a record incomplete, so the failure is marked on the
// recorder before it is returned: the record is written either way (the target ran), and
// without the marker a trace that ended after two of a hundred execs reads as a run that
// simply stopped exec'ing - the silently-incomplete record the section's marker exists to
// prevent. The likeliest shape is the very first resume answering ESRCH, a root SIGKILLed
// between the attach and here, which leaves nothing recorded but the seed entry.
func traceExecs(root int, rec *execRecorder) (int, error) {
	// Every tracee seen and not yet reaped: root, plus each descendant auto-attached at
	// its fork. They are tracked so a descendant the target backgrounded is resumed when
	// the loop ends rather than left stopped under a tracer that has stopped listening.
	//
	// Released on a defer so the two error returns below - a lost trace, which is
	// precisely when a descendant is likeliest to be mid-stop - hold the same invariant
	// as the clean exit. The kernel detaches every tracee when the tracer exits, so for
	// the launcher's own process this is belt-and-braces; it is load-bearing only for a
	// tracer that keeps running, which is what an embedder driving Run in-process is.
	tracees := map[int]bool{root: true}
	defer func() { releaseTracees(tracees) }()

	if err := syscall.PtraceCont(root, 0); err != nil {
		rec.failed = fmt.Errorf("launcher: resuming the target: %w", err)
		return 0, rec.failed
	}

	var ws syscall.WaitStatus
	for {
		wpid, err := syscall.Wait4(-1, &ws, 0, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			rec.failed = fmt.Errorf("launcher: supervising the target: %w", err)
			return 0, rec.failed
		}
		tracees[wpid] = true

		switch {
		case wpid == root && (ws.Exited() || ws.Signaled()):
			delete(tracees, root)
			return waitExitCode(ws), nil
		case ws.Exited() || ws.Signaled():
			// A descendant ended and this wait reaped it; nothing to resume.
			delete(tracees, wpid)
			continue
		}

		switch ws.TrapCause() {
		case syscall.PTRACE_EVENT_FORK, syscall.PTRACE_EVENT_VFORK, syscall.PTRACE_EVENT_CLONE:
			// The event names the new child before that child's own first stop is dequeued,
			// and the parent stays stopped here until resumed below. Tracking it now is what
			// keeps a descendant forked just before the root exits from slipping past the
			// release.
			if child, err := syscall.PtraceGetEventMsg(wpid); err == nil {
				tracees[int(child)] = true
			}
		case syscall.PTRACE_EVENT_EXEC:
			recordExec(wpid, rec)
			// The event message is the tid the execve retired. An execve by a NON-leader
			// thread reports under the thread-group leader's pid and the non-leader's pid
			// disappears with no exit event of its own, so this is the only announcement of
			// that disappearance; without it the release below waits on a freed pid.
			if old, err := syscall.PtraceGetEventMsg(wpid); err == nil && int(old) != wpid {
				delete(tracees, int(old))
			}
		}

		// Forward a real signal so the tracee actually receives it: suppressing a
		// synchronous fault would re-run the faulting instruction forever, and eating
		// SIGINT/SIGTERM/SIGCHLD would hang or misbehave an otherwise healthy target.
		// SIGTRAP is the exception - every ptrace event stop above reports it, and
		// forwarding it (default action: core dump) would kill the tracee.
		sig := 0
		if ws.Stopped() {
			if s := ws.StopSignal(); s != syscall.SIGTRAP && s != syscall.SIGTRAP|0x80 {
				sig = int(s)
			}
		}
		_ = syscall.PtraceCont(wpid, sig)
	}
}

// recordExec reads the image and argv of the exec that just retired. A tracee at an
// event stop is alive and its /proc entry readable - the launcher is non-dumpable, not
// the target - so the one way to fail here is the tracee dying between the wait and the
// read, and then the exec is going with it. It is recorded with whatever was readable
// rather than dropped, so the record does not silently lose an entry.
//
// That the target cannot blank its own entry rests on WHERE this is called from, which is
// the exec event and nowhere else. prctl(PR_SET_DUMPABLE, 0) needs no privilege and does
// refuse a same-uid reader - being the tracer is no exemption - but execve resets the
// dumpable flag, so the very exec being recorded here clears it. A read moved to any other
// stop loses that and a target could blank every image and argv in the tree while the
// section's marker went on attesting the record was whole.
func recordExec(pid int, rec *execRecorder) {
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		exe = ""
	}
	var argv []string
	if raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		if trimmed := strings.TrimRight(string(raw), "\x00"); trimmed != "" {
			argv = strings.Split(trimmed, "\x00")
		}
	}
	rec.record(pid, exe, argv)
}

// releaseTracees detaches every descendant still attached when the root has ended. A
// process the target backgrounded would otherwise stay stopped under a tracer that is no
// longer waiting on it, and the recorder installs no PTRACE_O_EXITKILL to collect it.
//
// Detach rather than kill: these are the target's own processes, and the recorder is a
// diagnostic that may not end anything the run would have left running. Under bwrap they
// are inside the run's pid namespace, which is torn down with it either way.
//
// Indirected through a var so a test can see that the loop's error returns release too:
// a detach the loop skips leaves nothing else about the trace showing it.
var releaseTracees = releaseTraceesImpl

func releaseTraceesImpl(tracees map[int]bool) {
	for pid := range tracees {
		_ = syscall.PtraceDetach(pid)
	}
}
