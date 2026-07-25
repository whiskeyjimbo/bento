package observe

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// The loop reaps its tracee itself, so exec.Cmd's Wait never ran - and with a stream
// that is not an *os.File, Start pipes it through a copier goroutine that only Wait
// joins. The output was therefore truncated at whatever the goroutine had copied when
// Trace returned, and the goroutine kept writing into the caller's buffer afterwards
// (a real race, and one a plain run reports as a short read). Latent for bento, which
// passes os.Stdout, and live for any embedder.
func TestTraceCapturesOutputThroughANonFileWriter(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	// Enough output to exceed a pipe buffer, so a copier that is not joined cannot
	// have finished by the time Trace returns.
	const lines = 4000
	script := "i=0; while [ $i -lt " + strconv.Itoa(lines) + " ]; do echo LINE$i; i=$((i+1)); done"

	var out bytes.Buffer
	res, err := Trace([]string{sh, "-c", script}, os.Environ(), nil, &out, &out)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0 (output: %d bytes)", res.ExitCode, out.Len())
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
		t.Skip("sh not available")
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
		wg.Add(1)
		go func() {
			defer wg.Done()
			var sink bytes.Buffer
			res, err := Trace([]string{sh, "-c", "cat " + own}, os.Environ(), nil, &sink, &sink)
			results[i] = outcome{res: res, err: err, own: own}
		}()
	}
	wg.Wait()

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
