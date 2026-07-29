package observe

import (
	"bytes"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The tracee half of this file's tests: a re-exec of the test binary that issues raw
// syscalls on demand, so the decoder is driven by a known call sequence rather than by
// whatever an interpreter happens to do on the host. Inert unless the parent set the
// mode - it is invoked by name through -test.run, the same shape the seccomp and
// launcher packages use for a child that must be its own process.
//
// The modes:
//
//	threads    T locked OS threads each open a file of their own, concurrently.
//	lostpaths  N openat calls whose pathname pointer is unmapped, from one call site.
//	sigreturn  N handled signals, so the tracer sees N rt_sigreturn exit stops.
//	nullpath   N utimensat/futimesat calls with a NULL pathname.
//	lostrename N renames with BOTH pathnames unmapped, from one call site.
//	badhow     openat2 with a readable pathname but an unmapped open_how.
//	plantpath  a sibling overwrites the victim thread's pathname buffer mid-syscall.
//	execve     spawns via execve(2), the path the exec-block filter denies.
//	execveat   spawns via execveat(2), the path it permits by construction.
func TestObserveTraceeHelper(t *testing.T) {
	mode := os.Getenv("BENTO_OBSERVE_TRACEE")
	if mode == "" {
		t.Skip("child tracee for this package's decoder tests")
	}
	n, err := strconv.Atoi(os.Getenv("BENTO_OBSERVE_TRACEE_N"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "TRACEE_BAD_N", err)
		os.Exit(3)
	}
	switch mode {
	case "threads":
		dir := os.Getenv("BENTO_OBSERVE_TRACEE_DIR")
		// Released once every opener is on a thread of its own, so the opens overlap by
		// construction. Without it a host with few cores can run them one after another,
		// and the trace no longer exercises the interleaving it exists to test.
		var ready, start sync.WaitGroup
		ready.Add(n)
		start.Add(1)
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Locked so the opener is a thread the tracer sees as its own tid rather
				// than one the scheduler may swap under it mid-syscall.
				runtime.LockOSThread()
				ready.Done()
				start.Wait()
				f, err := os.Open(threadFile(dir, i))
				if err != nil {
					fmt.Fprintln(os.Stderr, "TRACEE_OPEN_ERR", err)
					os.Exit(4)
				}
				f.Close()
			}()
		}
		ready.Wait()
		start.Done()
		wg.Wait()
	case "lostpaths":
		// One call site, so every iteration stops at the same instruction pointer -
		// the case a dedup key held for longer than its entry/exit pair cannot tell
		// from a repeated stop. The pointer is never mapped, so the kernel answers
		// EFAULT and the decoder cannot read the pathname at either stop.
		for range n {
			_, _, _ = syscall.Syscall6(syscall.SYS_OPENAT, ^uintptr(99), 0x1, 0, 0, 0, 0)
		}
	case "sigreturn":
		// Every handled signal ends in rt_sigreturn, whose exit stop reports the
		// RESTORED pre-signal registers: orig_rax is -1 (the kernel's "do not restart
		// this syscall" marker) and rax is the interrupted call's own return value. No
		// file access happens here at all, which is what makes it the pure case.
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGUSR1)
		defer signal.Stop(ch)
		for range n {
			if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
				fmt.Fprintln(os.Stderr, "TRACEE_KILL_ERR", err)
				os.Exit(6)
			}
			<-ch
		}
	case "lostrename":
		// Both pathnames unmapped, from one call site. rename needs write on the source
		// AND the destination directory, so one call loses two distinct accesses - and a
		// drop key that does not distinguish the two arguments reports it as one.
		for range n {
			_, _, _ = syscall.Syscall(syscall.SYS_RENAME, 0x1, 0x2, 0)
		}
	case "nullpath":
		// utimensat(fd, NULL, ...) and futimesat(fd, NULL, ...) - the kernel forms of
		// futimens(3) and futimes(3). Both act on the descriptor and name no file. The
		// calls must actually SUCCEED, or they would prove nothing about a decoder that
		// only mishandles the pathname.
		f, err := os.CreateTemp(os.Getenv("BENTO_OBSERVE_TRACEE_DIR"), "nullpath")
		if err != nil {
			fmt.Fprintln(os.Stderr, "TRACEE_TMP_ERR", err)
			os.Exit(10)
		}
		var ts [2]syscall.Timespec
		var tv [2]syscall.Timeval
		for range n {
			if _, _, errno := syscall.Syscall6(unix.SYS_UTIMENSAT, f.Fd(), 0,
				uintptr(unsafe.Pointer(&ts[0])), 0, 0, 0); errno != 0 {
				fmt.Fprintln(os.Stderr, "TRACEE_UTIMENSAT_ERRNO", errno)
				os.Exit(10)
			}
			if _, _, errno := syscall.Syscall(unix.SYS_FUTIMESAT, f.Fd(), 0,
				uintptr(unsafe.Pointer(&tv[0]))); errno != 0 {
				fmt.Fprintln(os.Stderr, "TRACEE_FUTIMESAT_ERRNO", errno)
				os.Exit(10)
			}
		}
	case "badhow":
		// A real pathname the decoder can read, with an open_how pointer that is not
		// mapped - so the kernel refuses the call with EFAULT and opens nothing, while a
		// decoder guessing the resolve flags would still record the path.
		path, err := syscall.BytePtrFromString(filepath.Join(os.Getenv("BENTO_OBSERVE_TRACEE_DIR"), badHowName))
		if err != nil {
			fmt.Fprintln(os.Stderr, "TRACEE_PATH_ERR", err)
			os.Exit(9)
		}
		_, _, _ = syscall.Syscall6(sysOpenat2, ^uintptr(99),
			uintptr(unsafe.Pointer(path)), 0x1, 24, 0, 0)
	case "plantpath":
		plantPathTracee(os.Getenv("BENTO_OBSERVE_TRACEE_DIR"), n)
	case "execve":
		// The ordinary spawn, which must still be detected. Exec is execve(2).
		if err := syscall.Exec(traceeExecTarget, []string{traceeExecTarget}, nil); err != nil {
			fmt.Fprintln(os.Stderr, "TRACEE_EXECVE_ERR", err)
			os.Exit(7)
		}
	case "execveat":
		// Spawns via execveat(2) rather than execve(2). The image is replaced, so
		// nothing below this runs.
		argv, err := syscall.SlicePtrFromStrings([]string{traceeExecTarget})
		if err != nil {
			fmt.Fprintln(os.Stderr, "TRACEE_ARGV_ERR", err)
			os.Exit(7)
		}
		envp, err := syscall.SlicePtrFromStrings([]string{})
		if err != nil {
			fmt.Fprintln(os.Stderr, "TRACEE_ENVP_ERR", err)
			os.Exit(7)
		}
		path, err := syscall.BytePtrFromString(traceeExecTarget)
		if err != nil {
			fmt.Fprintln(os.Stderr, "TRACEE_PATH_ERR", err)
			os.Exit(7)
		}
		// ^uintptr(99) is AT_FDCWD (-100) as an unsigned word; the constant itself does
		// not convert, the same spelling lostpaths uses for its bad dirfd.
		_, _, errno := syscall.Syscall6(unix.SYS_EXECVEAT, ^uintptr(99),
			uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(&argv[0])),
			uintptr(unsafe.Pointer(&envp[0])), 0, 0)
		fmt.Fprintln(os.Stderr, "TRACEE_EXECVEAT_ERR", errno)
		os.Exit(7)
	default:
		fmt.Fprintln(os.Stderr, "TRACEE_BAD_MODE", mode)
		os.Exit(5)
	}
	os.Exit(0)
}

// badHowName is the pathname the badhow mode passes to openat2. Distinctive, so its
// presence in a Result can only have come from that one call.
const badHowName = "openat2-how-unreadable"

// The two names the plantpath mode swaps between, equal in length so a write lands
// wholly on one or the other and cannot splice a third path out of the two.
//
// plantDecoyName must never exist on disk. That is the whole assertion: the existence
// syscalls are recorded only when the call SUCCEEDED, so a stat naming the decoy always
// fails and can never legitimately be recorded. Seeing it in a Result means the observer
// read the pathname at a moment other than the one the kernel read it.
const (
	plantRealName  = "present-file"
	plantDecoyName = "DECOY-absent"
)

// plantPathTracee is a victim thread issuing newfstatat on a shared pathname buffer while
// a sibling thread overwrites that buffer with a path that does not exist. Threads share
// an address space, which is what a CLONE_VM sibling is.
//
// The sibling only ever writes the DECOY, and the victim rewrites the real name before
// each call, so within one iteration the buffer only ever goes real -> decoy, never back.
// That asymmetry is what makes the test decisive rather than racy: an observer reading the
// pathname at the entry stop either sees the real name (and the kernel, reading later,
// sees the decoy or the real name - a decoy read fails and is filtered out) or sees the
// decoy (and the kernel cannot then see the real name). Either way the decoy is never
// recorded against a successful call. An observer reading at the EXIT stop instead reads
// after the sibling has had the whole syscall to overwrite the buffer, so it records the
// decoy against a call that succeeded on the real file.
//
// The sibling writes through /proc/self/mem rather than assigning to the slice: it is the
// same memory either way, but a syscall keeps the deliberate data race out of reach of the
// race detector, which would otherwise abort this tracee instead of letting it prove the
// point.
func plantPathTracee(dir string, n int) {
	real := filepath.Join(dir, plantRealName)
	buf := make([]byte, len(real)+1)
	copy(buf, real)
	nameAt := uintptr(unsafe.Pointer(&buf[0])) + uintptr(len(real)-len(plantRealName))

	mem, err := os.OpenFile("/proc/self/mem", os.O_WRONLY, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "TRACEE_MEM_ERR", err)
		os.Exit(8)
	}
	defer mem.Close()

	done := make(chan struct{})
	var sibling sync.WaitGroup
	sibling.Add(1)
	go func() {
		defer sibling.Done()
		runtime.LockOSThread()
		for {
			select {
			case <-done:
				return
			default:
			}
			if _, err := mem.WriteAt([]byte(plantDecoyName), int64(nameAt)); err != nil {
				fmt.Fprintln(os.Stderr, "TRACEE_PLANT_ERR", err)
				os.Exit(8)
			}
		}
	}()

	runtime.LockOSThread()
	var st unix.Stat_t
	for range n {
		copy(buf[len(real)-len(plantRealName):len(real)], plantRealName)
		_, _, _ = syscall.Syscall6(unix.SYS_NEWFSTATAT, ^uintptr(99),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&st)), 0, 0, 0)
	}
	close(done)
	sibling.Wait()
	runtime.KeepAlive(buf)
}

// traceeExecTarget is what the exec modes spawn: absolute, so no PATH search
// stats it first, and present on every host this package builds for.
const traceeExecTarget = "/bin/true"

func threadFile(dir string, i int) string {
	return filepath.Join(dir, fmt.Sprintf("thread-%d", i))
}

// traceHelper runs the tracee above under the real observer.
func traceHelper(t *testing.T, mode, dir string, n int) Result {
	t.Helper()
	env := append(os.Environ(),
		"BENTO_OBSERVE_TRACEE="+mode,
		"BENTO_OBSERVE_TRACEE_N="+strconv.Itoa(n),
		"BENTO_OBSERVE_TRACEE_DIR="+dir,
	)
	// The tracee reports its own setup failures on stderr before exiting non-zero, so
	// keep them: an exit code alone leaves a broken helper indistinguishable from a
	// decoder that recorded nothing.
	var diag bytes.Buffer
	res, err := Trace([]string{os.Args[0], "-test.run=^TestObserveTraceeHelper$"}, env, nil, nil, &diag)
	if err != nil {
		t.Fatalf("Trace(%s): %v\n%s", mode, err, diag.String())
	}
	if res.ExitCode != 0 {
		t.Fatalf("tracee %s exited %d\n%s", mode, res.ExitCode, diag.String())
	}
	return res
}

// Concurrent openers must each be attributed their own pathname. The decoder reads the
// pathname out of tracee memory at the syscall EXIT stop, by which point every sibling
// thread has been resumed and stopped again in turn, so a decoder that keys the read on
// anything but the tid that stopped - or that re-reads a buffer a sibling has since
// reused - reports one thread's file against another's open. Siblings share an address
// space, so reading the memory through the wrong tid is not the failure mode here;
// reading the wrong tid's registers is, and so is a stale buffer.
//
// Both directions are checked: every opened file present, and nothing under the
// directory that no thread ever named. Over-attribution is the one that matters, because
// the manifest is what the user consents to.
func TestTraceAttributesConcurrentOpensPerThread(t *testing.T) {
	const threads = 6
	dir := t.TempDir()
	want := make(map[string]bool, threads)
	for i := range threads {
		path := threadFile(dir, i)
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		want[path] = true
	}
	// A file that exists and is never opened. A path the decoder attributes to the
	// wrong thread would still be one of the six; this catches the coarser failure of
	// a pathname read back from a buffer some other syscall left behind.
	decoy := filepath.Join(dir, "never-opened")
	if err := os.WriteFile(decoy, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	res := traceHelper(t, "threads", dir, threads)

	got := make(map[string]bool, threads)
	for _, a := range res.Accesses {
		if filepath.Dir(a.Path) == dir {
			got[a.Path] = true
		}
	}
	for path := range want {
		if !got[path] {
			t.Errorf("no access recorded for %q; recorded under the dir: %v", path, got)
		}
	}
	for path := range got {
		if !want[path] {
			t.Errorf("recorded %q, which no thread opened; recorded under the dir: %v", path, got)
		}
	}
}

// Dropped is the channel that tells the host its manifest is short. Two ways to get it
// wrong meet in one trace of N lost accesses issued from a single call site:
//
//   - counting the entry and the exit stop of each syscall separately doubles it, and a
//     count that is wrong by construction teaches the reader to discount the warning;
//   - a dedup key held for longer than its entry/exit pair collapses the whole loop into
//     one drop, which reads as a stray probe for a file the target needs every iteration.
//
// The count is one trace, with no baseline subtracted from a second one: the tracee loses
// exactly this many accesses, so the true count is the floor and the observer's own
// miscounts only ever add.
//
// observerSlack is the one addition that is not a miscount. A tracee thread that exits
// between its syscall stop and the observer's read of it answers ESRCH. Where inspect's
// register read fails that way at an entry stop, the observer now knows nothing ran and
// does not count it; where PTRACE_GET_SYSCALL_INFO is the read that failed there is no op
// to say which stop it was, so that one is still counted deliberately - an uncounted loss
// is the failure the channel exists to prevent. A Go tracee retires a thread or two on its
// way out, so a run carries at most a couple. The band is wide enough to absorb them and
// far too tight for either counting bug.
const observerSlack = 3

func TestTraceCountsEveryLostAccessOnce(t *testing.T) {
	const lost = 500
	res := traceHelper(t, "lostpaths", t.TempDir(), lost)
	if res.Dropped < lost || res.Dropped > lost+observerSlack {
		t.Errorf("Dropped = %d, want %d..%d - one per lost access; fewer is the signature of a dedup key outliving its entry/exit pair, and ~%d of counting the entry and exit stop of the same syscall separately", res.Dropped, lost, lost+observerSlack, 2*lost)
	}
}

// A handled signal must not read as a lost file access. rt_sigreturn's exit stop reports
// the restored pre-signal registers, in which orig_rax is -1 - and -1 has every bit set,
// so a test for the x32 tag bit matches it. That made every handled signal count as an
// observation the profiler could not read, in the one channel that tells the user their
// manifest is incomplete; Go's async preemption signals a busy tracee constantly, so a
// run that lost nothing reported drops in the hundreds.
//
// Nothing here touches the filesystem, so the count should be nothing but observerSlack -
// two orders of magnitude below what one drop per handled signal would give.
func TestTraceDoesNotCountHandledSignalsAsLostAccesses(t *testing.T) {
	const signals = 300
	res := traceHelper(t, "sigreturn", t.TempDir(), signals)
	if res.Dropped > observerSlack {
		t.Errorf("Dropped = %d after %d handled signals and no file access, want at most %d; ~%d is the signature of rt_sigreturn's restored orig_rax of -1 matching the x32 tag test", res.Dropped, signals, observerSlack, signals)
	}
}

// Execed is what grants ExecAll, and ExecAll makes the launcher install no exec-block
// filter at all - so which spawn syscall sets it decides whether a run keeps its
// exec-block filter or loses it entirely.
//
// execve must set it and execveat must not. The filter denies execve and permits
// execveat by construction (the launcher's own transition into the sandbox is an
// execveat), so an execveat-spawning target behaves the same under exec: none as under
// exec: all - reporting it would widen the manifest to nothing but the user's cost.
//
// The two are told apart only at the syscall ENTRY stop: after a successful execveat the
// kernel reports the EXIT stop as execve's own number, so a decoder that tests at either
// stop counts every execveat as an execve. Both directions are pinned because a fix that
// stopped detecting exec altogether would satisfy the execveat half on its own.
func TestTraceCountsExecveButNotExecveat(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want bool
	}{
		{"execve", true},
		{"execveat", false},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			res := traceHelper(t, tc.mode, t.TempDir(), 0)
			if res.Execed != tc.want {
				t.Errorf("Execed = %v after a %s spawn, want %v", res.Execed, tc.mode, tc.want)
			}
			// The spawned binary is a file the sandbox must be able to read, and this
			// path is absolute, so no PATH search stats it into the record incidentally.
			if !slices.Contains(res.Accesses, Access{Path: traceeExecTarget}) {
				t.Errorf("%s spawned %s and it is absent from the recorded accesses: %v", tc.mode, traceeExecTarget, res.Accesses)
			}
		})
	}
}

// A sibling sharing the address space must not be able to plant a path in the observation.
// The pathname argument lives in the tracee's memory, so when the observer reads it decides
// what it records: read at the syscall EXIT stop, the sibling has had the whole syscall to
// overwrite the buffer, and the observer attributes the planted path to a call that
// succeeded on a different file. The manifest is the user's consent surface, so a path the
// run never touched appearing in it is the failure that matters.
//
// plantDecoyName is what makes the assertion airtight rather than statistical: it does not
// exist, the existence syscalls are recorded only when the call succeeded, and a stat of a
// path that is not there cannot succeed. There is no legitimate route by which it can be
// recorded.
//
// The real path is asserted present in the same run, because an observer that stopped
// recording existence syscalls altogether would satisfy the decoy half perfectly.
func TestTraceDoesNotRecordAPathPlantedBySibling(t *testing.T) {
	const stats = 3000
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, plantRealName), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	decoy := filepath.Join(dir, plantDecoyName)

	res := traceHelper(t, "plantpath", dir, stats)

	var sawReal bool
	for _, a := range res.Accesses {
		if a.Path == decoy {
			t.Fatalf("recorded %q, a path that does not exist and so cannot have been established by any successful call; the observer read the pathname after the sibling overwrote it", decoy)
		}
		if a.Path == filepath.Join(dir, plantRealName) {
			sawReal = true
		}
	}
	if !sawReal {
		t.Errorf("the real path was never recorded, so the decoy's absence proves nothing; recorded: %v", res.Accesses)
	}
}

// rename needs write access to the source AND the destination directory, so one failed
// call loses two distinct accesses. The drop counter is keyed per entry/exit pair, and a
// key that does not also distinguish the two pathname arguments reported them as one - an
// undercount on the channel whose whole job is to say how much the manifest is missing.
func TestTraceCountsBothLostPathsOfARename(t *testing.T) {
	const calls = 200
	const lost = calls * 2
	res := traceHelper(t, "lostrename", t.TempDir(), calls)
	if res.Dropped < lost || res.Dropped > lost+observerSlack {
		t.Errorf("Dropped = %d after %d renames losing both pathnames each, want %d..%d; ~%d is the signature of one drop key serving both arguments", res.Dropped, calls, lost, lost+observerSlack, calls)
	}
}

// A syscall that names no file must not report a lost one. utimensat and futimesat both
// take a NULL pathname and then act on the descriptor itself; decoding that as a pathname
// reads address zero, fails, and counts a drop - inflating the one channel that tells the
// user their manifest is incomplete, for a run that lost nothing. cp -p, tar -x, install
// and rsync all reach utimensat this way, so extracting an archive alone did it hundreds
// of times.
func TestTraceDoesNotCountANullPathnameAsALostAccess(t *testing.T) {
	const calls = 100
	res := traceHelper(t, "nullpath", t.TempDir(), calls)
	if res.Dropped > observerSlack {
		t.Errorf("Dropped = %d after %d utimensat+futimesat calls that name no file, want at most %d; ~%d is the signature of decoding a NULL pathname as one", res.Dropped, 2*calls, observerSlack, 2*calls)
	}
}
