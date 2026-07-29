package observe

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"testing"
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
	default:
		fmt.Fprintln(os.Stderr, "TRACEE_BAD_MODE", mode)
		os.Exit(5)
	}
	os.Exit(0)
}

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
// The band is one trace, no baseline subtracted from a second one: every deliberate loss
// is counted, and the observer's own miscounts only ever add. So the true count is the
// floor, and half again as much sits far below the doubling signature.
//
// The slack is for bv2-q7uv, which counts every syscall stop the kernel reports with no
// syscall number as a lost access: measured here at 0..2 per run for this tracee over 25
// runs, but it scales with thread count and is not reproducible run to run, which is why
// an exact count is not assertable through Trace yet. Tighten this to an equality with
// that fix.
func TestTraceCountsEveryLostAccessOnce(t *testing.T) {
	const lost = 500
	res := traceHelper(t, "lostpaths", t.TempDir(), lost)
	if res.Dropped < lost {
		t.Errorf("Dropped = %d, want at least %d - one per lost access; a lower count is the signature of a dedup key that outlives its entry/exit pair", res.Dropped, lost)
	}
	if max := lost * 3 / 2; res.Dropped > max {
		t.Errorf("Dropped = %d, want at most %d for %d lost accesses; ~%d is the signature of counting the entry and exit stop of the same syscall separately", res.Dropped, max, lost, 2*lost)
	}
}
