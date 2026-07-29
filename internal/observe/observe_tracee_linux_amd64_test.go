package observe

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
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
//	execthread execve's from a non-leader thread, which retires that thread's tid;
//	           N sibling threads probe a path in a loop until de_thread kills them.
//	outliveroot backgrounds a probeforever child and exits while it is still probing.
//	probeforever N threads probe a path in a loop and never stop; started by outliveroot.
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
	case "execthread":
		// execve from a thread that is NOT the thread-group leader: the kernel kills the
		// other threads and hands the execing one the leader's pid, so its own tid
		// disappears with no wait status for the tracer to see. An exec from the leader
		// retires no tid at all and would prove nothing, and which thread a goroutine gets
		// is the runtime's business - a test function does not run on the main one - so the
		// tid is checked rather than assumed. A goroutine that finds itself on the leader
		// hands off and parks WITHOUT unlocking, so that thread stays occupied and the next
		// attempt is given another; there is one leader, so it hands off at most once.
		//
		// n sibling threads probing a real path in a tight loop, so that when de_thread
		// kills them some are mid-probe: their entry stop consumed and its pathname
		// resolved, their exit stop never coming.
		var probing sync.WaitGroup
		probing.Add(n)
		for range n {
			go func() {
				runtime.LockOSThread()
				path, err := syscall.BytePtrFromString(filepath.Join(os.Getenv("BENTO_OBSERVE_TRACEE_DIR"), probeName))
				if err != nil {
					fmt.Fprintln(os.Stderr, "TRACEE_PATH_ERR", err)
					os.Exit(9)
				}
				probing.Done()
				for {
					_, _, _ = syscall.Syscall(unix.SYS_ACCESS, uintptr(unsafe.Pointer(path)), unix.F_OK, 0)
				}
			}()
		}
		probing.Wait()

		var execFromNonLeader func()
		execFromNonLeader = func() {
			runtime.LockOSThread()
			if unix.Gettid() == os.Getpid() {
				go execFromNonLeader()
				time.Sleep(time.Minute)
				return
			}
			if err := syscall.Exec(traceeExecTarget, []string{traceeExecTarget}, nil); err != nil {
				fmt.Fprintln(os.Stderr, "TRACEE_EXECTHREAD_ERR", err)
				os.Exit(11)
			}
		}
		go execFromNonLeader()
		// The exec replaces the image, so the sleep never finishes; it is a sleep rather
		// than a bare block so the runtime's deadlock detector has no claim on it.
		time.Sleep(time.Minute)
	case "outliveroot":
		// A backgrounded descendant that is still probing when root exits. Root starts it,
		// waits on the pipe until every prober is in its loop - otherwise root can exit
		// before the first entry stop and the tracer has nothing held to lose - then exits
		// clean and leaves the whole process behind.
		ready, signal, err := os.Pipe()
		if err != nil {
			fmt.Fprintln(os.Stderr, "TRACEE_PIPE_ERR", err)
			os.Exit(12)
		}
		child := exec.Command(os.Args[0], "-test.run=^TestObserveTraceeHelper$")
		child.Env = append(os.Environ(), "BENTO_OBSERVE_TRACEE=probeforever")
		child.ExtraFiles = []*os.File{signal}
		if err := child.Start(); err != nil {
			fmt.Fprintln(os.Stderr, "TRACEE_START_ERR", err)
			os.Exit(12)
		}
		signal.Close()
		if _, err := ready.Read(make([]byte, 1)); err != nil {
			fmt.Fprintln(os.Stderr, "TRACEE_READY_ERR", err)
			os.Exit(12)
		}
	case "probeforever":
		// n threads probing a real path in a tight loop and never stopping, so that
		// whenever the trace ends some of them are mid-probe: the entry stop consumed and
		// its pathname resolved, the exit stop not yet dequeued. Reaped by the observer's
		// own cleanup, which SIGKILLs what is left attached.
		var probing sync.WaitGroup
		probing.Add(n)
		for range n {
			go func() {
				runtime.LockOSThread()
				path, err := syscall.BytePtrFromString(filepath.Join(os.Getenv("BENTO_OBSERVE_TRACEE_DIR"), probeName))
				if err != nil {
					fmt.Fprintln(os.Stderr, "TRACEE_PATH_ERR", err)
					os.Exit(9)
				}
				probing.Done()
				for {
					_, _, _ = syscall.Syscall(unix.SYS_ACCESS, uintptr(unsafe.Pointer(path)), unix.F_OK, 0)
				}
			}()
		}
		probing.Wait()
		// fd 3 is the pipe the parent is blocked on; the write is what releases it.
		if _, err := os.NewFile(3, "ready").Write([]byte{'r'}); err != nil {
			fmt.Fprintln(os.Stderr, "TRACEE_READY_WRITE_ERR", err)
			os.Exit(12)
		}
		// A sleep rather than a bare block, so the runtime's deadlock detector has no
		// claim on it. The observer's cleanup arrives long before it elapses.
		time.Sleep(time.Hour)
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

// probeName is the path execthread's sibling threads probe while they wait to be killed.
const probeName = "sibling-probe-target"

// heldBy counts the pathnames a pid is still waiting on an exit stop to resolve. The
// observer only ever releases them in bulk, so nothing in the package answers this.
func heldBy(held map[string]heldPath, pid int) int {
	n := 0
	prefix := fmt.Sprintf("%d\x00", pid)
	for key := range held {
		if strings.HasPrefix(key, prefix) {
			n++
		}
	}
	return n
}

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

// A thread that dies holding a syscall stop is the observer's own race, not a loss the
// tracee had: a ptrace-stopped thread runs nothing until it is resumed, so one that is
// already gone at the entry stop never executed the syscall. Counting it reports a lost
// access on a call that never happened, which is what made a multithreaded Go tracee
// report a drop or two on a run that lost nothing.
//
// The exit stop turns on what the stop had left to do rather than on the stop itself. Its
// only decode is the existence syscalls' success filter, replayed against a pathname the
// entry stop held, so a pid holding nothing had nothing to lose - a dying thread's
// nanosleep exit stop is the one that showed up in practice. A pid with a pathname held is
// the real loss: the probe completed and its result is what decides the grant.
func TestInspectDoesNotCountADeadThreadsPhantomStops(t *testing.T) {
	// A reaped pid answers every ptrace request with ESRCH, which is exactly the state a
	// thread that exited between its stop and the register read leaves behind.
	dead := reapedPid(t)
	if err := syscall.PtraceGetRegs(dead, &syscall.PtraceRegs{}); !errors.Is(err, syscall.ESRCH) {
		t.Skipf("pid %d does not answer ESRCH (%v), so this cannot stand in for a dead thread", dead, err)
	}

	for _, tc := range []struct {
		name string
		op   byte
		held map[string]heldPath
		want int
	}{
		{"entry", unix.PTRACE_SYSCALL_INFO_ENTRY, map[string]heldPath{}, 0},
		{"exit holding nothing", unix.PTRACE_SYSCALL_INFO_EXIT, map[string]heldPath{}, 0},
		{
			"exit holding a pathname",
			unix.PTRACE_SYSCALL_INFO_EXIT,
			map[string]heldPath{stopKey(dead, &syscall.PtraceRegs{Orig_rax: unix.SYS_STAT}): {path: "/etc/hosts", readOK: true}},
			1,
		},
		{
			// Another pid's pending probe says nothing about this one's stop.
			"exit while a sibling holds a pathname",
			unix.PTRACE_SYSCALL_INFO_EXIT,
			map[string]heldPath{stopKey(dead+1, &syscall.PtraceRegs{Orig_rax: unix.SYS_STAT}): {path: "/etc/hosts", readOK: true}},
			0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var res Result
			count, release := dropOnce(map[string]bool{}, dead, &res.Dropped)
			inspect(dead, tc.op, func(string, bool) {}, count, release, tc.held, &res)
			if res.Dropped != tc.want {
				t.Errorf("Dropped = %d after an ESRCH register read at the %s stop, want %d", res.Dropped, tc.name, tc.want)
			}
		})
	}
}

// A thread that dies holding a probe is reported by two channels in turn, and the loss is
// one. The ptrace read at its stop fails ESRCH and counts it; then its wait status arrives
// and the loop's exit branch sweeps everything the tid still held. Both consult the same
// held entry, so the count is right only if whichever runs first takes it away - otherwise
// one lost probe tells the user the manifest is short by two.
func TestADeadThreadsHeldProbeIsCountedOnce(t *testing.T) {
	dead := reapedPid(t)
	if err := syscall.PtraceGetRegs(dead, &syscall.PtraceRegs{}); !errors.Is(err, syscall.ESRCH) {
		t.Skipf("pid %d does not answer ESRCH (%v), so this cannot stand in for a dead thread", dead, err)
	}
	held := map[string]heldPath{
		stopKey(dead, &syscall.PtraceRegs{Orig_rax: unix.SYS_STAT}):   {path: "/etc/hosts", readOK: true},
		stopKey(dead, &syscall.PtraceRegs{Orig_rax: unix.SYS_ACCESS}): {path: "/etc/passwd", readOK: true},
	}

	var res Result
	count, release := dropOnce(map[string]bool{}, dead, &res.Dropped)
	inspect(dead, unix.PTRACE_SYSCALL_INFO_EXIT, func(string, bool) {}, count, release, held, &res)
	res.Dropped += releaseHeldOf(held, dead)

	if res.Dropped != 2 {
		t.Errorf("Dropped = %d after one dead thread's two held probes reached both channels, want 2; 3 is the signature of the stop-read counting a flat one and leaving the sweep to count both again", res.Dropped)
	}
	if n := heldBy(held, dead); n != 0 {
		t.Errorf("%d pathnames are still held for a thread that no longer exists, so a later sweep would count them a third time", n)
	}
}

// A read that fails for a reason other than ESRCH cannot be staged against a live tracer -
// every pid a test could point ptrace at answers ESRCH, and an EIO or EFAULT would have to
// be injected - so the invariant is asserted where the two failure sites now share it. One
// loss per unreadable stop, and the pair's pathname goes with it: leaving it held is what
// let the sweeps report the same lost probe a second time.
func TestAnUnreadableStopCountsItsHeldProbeOnce(t *testing.T) {
	const pid = 4242

	for _, tc := range []struct {
		name string
		held map[string]heldPath
		want int
	}{
		{"holding nothing", map[string]heldPath{}, 0},
		{
			"holding a pathname",
			map[string]heldPath{stopKey(pid, &syscall.PtraceRegs{Orig_rax: unix.SYS_STAT}): {path: "/etc/hosts", readOK: true}},
			0,
		},
		{
			// Another pid's pending probe is still waiting on a stop of its own.
			"while a sibling holds a pathname",
			map[string]heldPath{stopKey(pid+1, &syscall.PtraceRegs{Orig_rax: unix.SYS_STAT}): {path: "/etc/hosts", readOK: true}},
			1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := unreadableStopLoss(tc.held, pid); got != 1 {
				t.Errorf("an unreadable stop %s counted %d, want 1 - the stop itself is the loss whatever it was holding", tc.name, got)
			}
			if n := heldBy(tc.held, pid); n != 0 {
				t.Errorf("%d pathnames are still held for a stop already counted, so a sweep would count them again", n)
			}
			if len(tc.held) != tc.want {
				t.Errorf("held has %d entries, want %d - releasing more than this pid's pair would drop a probe that is still live", len(tc.held), tc.want)
			}
		})
	}
}

// The same race one read earlier: the thread dies before PTRACE_GET_SYSCALL_INFO, so the
// stop has no op of its own and the pid's last recorded one has to supply the parity.
// Stops alternate, so the stop after a known entry stop is an exit stop and the stop after
// a known exit stop is an entry stop; from there the judgement is the same one inspect
// makes. Parity that was never established is unknown rather than safe and still counts.
func TestNativeSyscallResolvesADeadThreadsPhantomStops(t *testing.T) {
	dead := reapedPid(t)
	if _, _, err := syscallInfo(dead); !errors.Is(err, syscall.ESRCH) {
		t.Skipf("pid %d does not answer ESRCH (%v), so this cannot stand in for a dead thread", dead, err)
	}
	holding := map[string]heldPath{
		stopKey(dead, &syscall.PtraceRegs{Orig_rax: unix.SYS_STAT}): {path: "/etc/hosts", readOK: true},
	}

	for _, tc := range []struct {
		name string
		seed []byte
		held map[string]heldPath
		want int
	}{
		{"at the entry stop after an exit stop", []byte{unix.PTRACE_SYSCALL_INFO_EXIT}, map[string]heldPath{}, 0},
		{"at the exit stop after an entry stop, holding nothing", []byte{unix.PTRACE_SYSCALL_INFO_ENTRY}, map[string]heldPath{}, 0},
		{"at the exit stop after an entry stop, holding a pathname", []byte{unix.PTRACE_SYSCALL_INFO_ENTRY}, holding, 1},
		{"after the initial stop", []byte{unix.PTRACE_SYSCALL_INFO_NONE}, map[string]heldPath{}, 1},
		{"after a seccomp stop", []byte{unix.PTRACE_SYSCALL_INFO_SECCOMP}, map[string]heldPath{}, 1},
		{"with no parity recorded", nil, map[string]heldPath{}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lastOp := map[int]byte{}
			for _, op := range tc.seed {
				lastOp[dead] = op
			}
			dropped := 0
			if _, native := nativeSyscall(dead, lastOp, tc.held, &dropped); native {
				t.Fatal("a failed read cannot report the stop as native")
			}
			if dropped != tc.want {
				t.Errorf("Dropped = %d after an ESRCH info read %s, want %d", dropped, tc.name, tc.want)
			}
			// The parity a failed read leaves behind is a stop stale, so every later
			// inference off it would be off by one.
			if _, ok := lastOp[dead]; ok {
				t.Error("a failed read must invalidate the pid's parity, not leave the previous stop's op in place")
			}
		})
	}
}

// reapedPid returns the pid of a process that has run and been waited for, so it names
// nothing live. Pid reuse would need the whole pid space to wrap within the test.
func reapedPid(t *testing.T) int {
	t.Helper()
	// No mode in the environment, so the helper skips immediately and exits clean.
	cmd := exec.Command(os.Args[0], "-test.run=TestObserveTraceeHelper")
	if err := cmd.Run(); err != nil {
		t.Fatalf("run a throwaway child: %v", err)
	}
	return cmd.Process.Pid
}

// Dropped is the channel that tells the host its manifest is short. Two ways to get it
// wrong meet in one trace of N lost accesses issued from a single call site:
//
//   - counting the entry and the exit stop of each syscall separately doubles it, and a
//     count that is wrong by construction teaches the reader to discount the warning;
//   - a dedup key held for longer than its entry/exit pair collapses the whole loop into
//     one drop, which reads as a stray probe for a file the target needs every iteration.
//
// The count is one trace, with no baseline subtracted from a second one, and it is exact:
// the tracee loses exactly this many accesses and the observer's own miscounts only ever
// add. It was a band for a while, to absorb the phantom a tracee thread that exits between
// its syscall stop and the observer's read of it used to leave behind. Both reads that can
// lose that race now resolve it (see deadThreadLoss), so an exact assertion is what
// catches the two bugs above.
//
// One phantom is still counted by construction: a thread that dies at its first-ever
// syscall stop has no parity yet, and unknown parity counts rather than suppresses. A Go
// runtime thread lives well past its first stop before being retired, and 400 runs under
// load produced none - but a single unexplained drop here is that, not a counting bug.
func TestTraceCountsEveryLostAccessOnce(t *testing.T) {
	const lost = 500
	res := traceHelper(t, "lostpaths", t.TempDir(), lost)
	if res.Dropped != lost {
		t.Errorf("Dropped = %d, want %d - one per lost access; fewer is the signature of a dedup key outliving its entry/exit pair, and ~%d of counting the entry and exit stop of the same syscall separately", res.Dropped, lost, 2*lost)
	}
}

// A handled signal must not read as a lost file access. rt_sigreturn's exit stop reports
// the restored pre-signal registers, in which orig_rax is -1 - and -1 has every bit set,
// so a test for the x32 tag bit matches it. That made every handled signal count as an
// observation the profiler could not read, in the one channel that tells the user their
// manifest is incomplete; Go's async preemption signals a busy tracee constantly, so a
// run that lost nothing reported drops in the hundreds.
//
// Nothing here touches the filesystem, so the count should be zero -
// two orders of magnitude below what one drop per handled signal would give.
func TestTraceDoesNotCountHandledSignalsAsLostAccesses(t *testing.T) {
	const signals = 300
	res := traceHelper(t, "sigreturn", t.TempDir(), signals)
	if res.Dropped != 0 {
		t.Errorf("Dropped = %d after %d handled signals and no file access, want 0; ~%d is the signature of rt_sigreturn's restored orig_rax of -1 matching the x32 tag test", res.Dropped, signals, signals)
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

// A thread that execve's takes over the thread-group leader's pid and its own tid ceases to
// exist with no wait status, so the loop's tracee set is never told to forget it. What that
// costs is not memory: reapTracees SIGKILLs every pid the set names, and by reap time the
// retired tid may belong to an unrelated host process. It also keeps the set from emptying,
// which drops the drain onto its ECHILD stop and forfeits the property reapTracees
// documents - that it never blocks on an embedding process's own live children.
//
// The exec event is the only report of the disappearance, and its event message is the
// retired tid. So the assertion is on the remainder handed to reapTracees: it must be empty
// after a run whose exec came from a non-leader thread.
func TestTraceForgetsATidRetiredByAnExecve(t *testing.T) {
	var remainder []int
	orig := reapTracees
	reapTracees = func(tracees map[int]bool) {
		remainder = remainder[:0]
		for pid := range tracees {
			remainder = append(remainder, pid)
		}
		orig(tracees)
	}
	defer func() { reapTracees = orig }()

	res := traceHelper(t, "execthread", t.TempDir(), 0)
	if !res.Execed {
		t.Fatal("the tracee did not exec, so no tid was retired and the sweep is not exercised")
	}
	for _, pid := range remainder {
		// A retired tid is already gone, which is exactly what makes signalling it
		// dangerous: the pid is free for the host to hand to something unrelated.
		t.Errorf("pid %d was left in the tracee set for reapTracees to SIGKILL; kill(pid, 0) = %v",
			pid, syscall.Kill(pid, 0))
	}
}

// A thread killed between the entry and exit stop of an existence probe takes that
// pathname with it: the entry stop resolved it, and whether the call succeeded - the thing
// that decides if the path needs a grant - can no longer be read. No ptrace request fails
// to announce that, because the thread has no stop left to fail at; the only trace of it is
// the wait status, which the loop's exit branch handles.
//
// A non-leader execve makes the case routine rather than exotic: de_thread kills every
// sibling at once, so probers spinning at the moment of the exec are a steady supply of
// threads dying mid-syscall. Which of them is caught between the two stops is the
// scheduler's business, so the assertion is that at least one loss reaches Dropped, not an
// exact count.
func TestTraceCountsAProbeLostWithADyingThread(t *testing.T) {
	const probers = 16
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, probeName), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := traceHelper(t, "execthread", dir, probers)
	if !res.Execed {
		t.Fatal("the tracee did not exec, so no sibling was killed and nothing was lost mid-probe")
	}
	if res.Dropped == 0 {
		t.Errorf("Dropped = 0 after %d threads were killed probing %s; a pathname held by a thread that dies before its exit stop is an access the manifest is short by, and nothing else reports it",
			probers, probeName)
	}
}

// Root's exit ends the trace wherever the descendants happen to be, and a backgrounded
// process still probing is the ordinary way that leaves a pathname resolved with no exit
// stop coming: the loop returns and SIGKILLs what is left, so the stop that would have
// applied the success filter never arrives. Nothing else in this fixture can lose an
// observation - the probed path exists and is read cleanly at every entry stop, and no
// tracee exits during the trace - so a non-zero count here comes from the root-exit sweep
// and from nothing else.
func TestTraceCountsProbesHeldWhenRootExits(t *testing.T) {
	const probers = 16
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, probeName), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := traceHelper(t, "outliveroot", dir, probers)
	if res.Dropped == 0 {
		t.Errorf("Dropped = 0 after root exited while %d backgrounded threads were probing %s; a pathname the entry stop resolved for a tracee that is about to be SIGKILLed is an access the manifest is short by",
			probers, probeName)
	}
}

// The exec event names a retired tid in both the case that needs sweeping and the case that
// must not be swept, and only the event message tells them apart.
//
// A non-leader's exec retires two threads: the execing one, whose tid can never stop again,
// and the leader whose pid it took, which is dead under a pid that is still stopped. Every map
// keyed on either has to forget it, and a pathname held by either is an existence probe whose
// exit stop can never arrive, so each counts as a lost access.
//
// An ordinary exec reports the stopping pid itself, which kept running: forgetting that one
// takes a live tracee out of the reap set - the worse of the two leaks - and its held
// pathnames still have an exit stop coming.
func TestForgetRetiredTidKeepsTheLivePid(t *testing.T) {
	const leader, retired = 100, 101
	for _, tc := range []struct {
		name     string
		old      int
		wantKept bool
		wantLost int
	}{
		{"a non-leader thread's exec retires its own tid and the leader's thread", retired, false, 4},
		{"an ordinary exec reports the pid it kept", leader, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tracees := map[int]bool{leader: true, tc.old: true}
			lastOp := map[int]byte{tc.old: unix.PTRACE_SYSCALL_INFO_ENTRY}
			held := map[string]heldPath{}
			for _, pid := range []int{leader, tc.old} {
				held[stopKey(pid, &syscall.PtraceRegs{Orig_rax: unix.SYS_STAT})] = heldPath{path: "/etc/hosts", readOK: true}
				held[stopKey(pid, &syscall.PtraceRegs{Orig_rax: unix.SYS_ACCESS})] = heldPath{path: "/etc/passwd", readOK: true}
			}

			if lost := forgetRetiredTid(leader, tc.old, tracees, lastOp, held); lost != tc.wantLost {
				t.Errorf("lost = %d, want %d - a pathname held by a thread that can never stop again is an observation no exit stop will ever resolve", lost, tc.wantLost)
			}
			if got := tracees[tc.old]; got != tc.wantKept {
				t.Errorf("tracees[%d] = %v, want %v", tc.old, got, tc.wantKept)
			}
			if _, got := lastOp[tc.old]; got != tc.wantKept {
				t.Errorf("lastOp[%d] present = %v, want %v", tc.old, got, tc.wantKept)
			}
			for _, pid := range []int{leader, tc.old} {
				want := 0
				if tc.wantKept {
					want = 2
				}
				if got := heldBy(held, pid); got != want {
					t.Errorf("pid %d still holds %d pathnames, want %d", pid, got, want)
				}
			}
			if !tracees[leader] {
				t.Errorf("the leader's own pid was dropped from the tracee set; it is alive and must still be reaped")
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
	if res.Dropped != lost {
		t.Errorf("Dropped = %d after %d renames losing both pathnames each, want %d; ~%d is the signature of one drop key serving both arguments", res.Dropped, calls, lost, calls)
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
	if res.Dropped != 0 {
		t.Errorf("Dropped = %d after %d utimensat+futimesat calls that name no file, want 0; ~%d is the signature of decoding a NULL pathname as one", res.Dropped, 2*calls, 2*calls)
	}
}
