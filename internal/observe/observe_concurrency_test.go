//go:build linux && amd64

package observe

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// latchedBuffer is a bytes.Buffer that records a write arriving after the caller declared
// Trace returned, and slows each one so there is still copying to do at that moment. Both
// flags are atomic and the buffer is mutex-held: a test whose regression is an unsynchronized
// write must report its own assertion, not a race-detector dump that only -race produces.
type latchedBuffer struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	delay    time.Duration
	returned atomic.Bool
	late     atomic.Bool
}

func (b *latchedBuffer) Write(p []byte) (int, error) {
	if b.returned.Load() {
		b.late.Store(true)
	}
	time.Sleep(b.delay)
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *latchedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *latchedBuffer) len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

// The loop reaps its tracee itself, so exec.Cmd's Wait never ran - and with a stream
// that is not an *os.File, Start pipes it through a copier goroutine that only Wait
// joins. The output was therefore truncated at whatever the goroutine had copied when
// Trace returned, and the goroutine kept writing into the caller's buffer afterwards
// (a real race, and one a plain run reports as a short read). Latent for bento, which
// passes os.Stdout, and live for any embedder.
func TestTraceCapturesOutputThroughANonFileWriter(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		skipMissingDep(t, "sh not available")
	}
	// Enough output to exceed a pipe buffer, so a copier that is not joined cannot
	// have finished by the time Trace returns.
	const lines = 4000
	script := "i=0; while [ $i -lt " + strconv.Itoa(lines) + " ]; do echo LINE$i; i=$((i+1)); done"

	// A short read is the symptom, but it is only probabilistic: the tracee is reaped by
	// the loop, so the copier has usually drained by the time Trace returns and deleting
	// the join fails a plain run about one time in thirteen (measured). The writer makes
	// the property itself observable instead - it records a write ARRIVING after Trace
	// returned, which is the leaked goroutine - and sleeps per write so there is always
	// copier work left to do: the tracee blocks on a full pipe, so at exit up to a pipe
	// buffer plus one chunk is still unwritten, and at 20ms a chunk that is tens of
	// milliseconds of writing an unjoined Trace cannot have waited for.
	out := &latchedBuffer{delay: 20 * time.Millisecond}
	res, err := Trace([]string{sh, "-c", script}, os.Environ(), nil, out, out)
	out.returned.Store(true)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0 (output: %d bytes)", res.ExitCode, out.len())
	}
	// Long enough for a copier still holding the pipe to take its next write, and dead
	// time only on a regression: the joined copier has nothing left to write.
	time.Sleep(200 * time.Millisecond)
	if out.late.Load() {
		t.Error("a write arrived after Trace returned, so the copier goroutine was not joined - it is writing into a caller's buffer the caller now owns")
	}
	// Read the buffer immediately, as a caller would: a still-running copier makes this
	// both short and a data race.
	got := out.String()
	if n := strings.Count(got, "\n"); n != lines {
		t.Errorf("captured %d lines, want %d - the copier goroutine was not joined before Trace returned", n, lines)
	}
	if !strings.Contains(got, "LINE"+strconv.Itoa(lines-1)) {
		t.Errorf("the last line is missing, so the output was truncated: %d bytes", len(got))
	}
}

// Trace dequeues stops with Wait4(-1) - ptrace has no wait-on-this-set - so two
// concurrent traces would consume each other's stops: the thief records a foreign
// tracee's accesses into its own Result (a misattributed audit record) while the
// robbed call dies on "no child processes". Trace is single-flight for exactly this,
// and this asserts the property rather than the mutex: every call must succeed and see
// ONLY its own file.
func TestConcurrentTracesDoNotStealEachOthersStops(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		skipMissingDep(t, "sh not available")
	}
	dir := t.TempDir()

	const traces = 4
	type outcome struct {
		res Result
		err error
		own string
	}
	results := make([]outcome, traces)
	var wg sync.WaitGroup
	for i := range traces {
		own := filepath.Join(dir, "own"+strconv.Itoa(i)+".txt")
		if err := os.WriteFile(own, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		wg.Go(func() {
			var sink bytes.Buffer
			res, err := Trace([]string{sh, "-c", "cat " + own}, os.Environ(), nil, &sink, &sink)
			results[i] = outcome{res: res, err: err, own: own}
		})
	}
	// Bounded, because the failure mode is not a wrong answer: a trace whose stop was
	// consumed elsewhere blocks in its wait loop, so an unbounded Wait would turn a
	// regression into a ten-minute suite timeout and a stack dump instead of a named
	// failure. The passing case takes about a second.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("a trace never returned; its wait status was consumed by a concurrent trace")
	}

	for i, o := range results {
		if o.err != nil {
			t.Errorf("trace %d failed: %v - a concurrent trace consumed its wait status", i, o.err)
			continue
		}
		if _, ok := find(o.res, o.own); !ok {
			t.Errorf("trace %d did not record its own file %s: %+v", i, o.own, o.res.Accesses)
		}
		// The teeth: another trace's file must never appear in this Result.
		for j, other := range results {
			if i == j {
				continue
			}
			if _, ok := find(o.res, other.own); ok {
				t.Errorf("trace %d recorded trace %d's file %s - a foreign tracee's access was misattributed", i, j, other.own)
			}
		}
	}
}
