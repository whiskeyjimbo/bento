//go:build linux

package launcher

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/whiskeyjimbo/bento/internal/observe"
)

// sentinelRunObserve re-execs the test binary as a sacrificial child. runObserve blocks
// io_uring with a permanent process-wide seccomp filter and Run makes the process
// non-dumpable, so neither can be called in the test process itself.
const sentinelRunObserve = "BENTO_TEST_RUNOBSERVE"

// The launcher's profiling seam had no unit coverage at all. These are its three
// load-bearing outcomes: a report that survives whatever was already in the file, a
// refusal when the report descriptor names nothing, and a refusal when the trace itself
// fails. Each runs in a child, which reports through the report file or its own exit.
func TestRunObserve(t *testing.T) {
	if mode := os.Getenv(sentinelRunObserve); mode != "" {
		runObserveChild(mode)
		return
	}

	// Truncate(0) does not move the description's offset and Write is write(2), not
	// pwrite, so on a descriptor whose offset has advanced the report lands past a NUL
	// hole and the host's Scanner hits ErrTooLong at 64 KiB instead of parsing it. No
	// path advances the offset today - the launcher does not write to the report before
	// this point, and a descendant reaching the file through /proc/<launcher>/fd gets
	// its own open file description with its own offset - so the child advances it
	// explicitly, which is the only way to exercise what the seek defends.
	t.Run("the report is written from the start of an advanced descriptor", func(t *testing.T) {
		report := filepath.Join(t.TempDir(), "report")
		if err := os.WriteFile(report, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		out, err := runObserveChild_(t, "advanced-offset", report)
		if err != nil {
			t.Fatalf("child failed: %v\n%s", err, out)
		}
		got, err := os.ReadFile(report)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.ContainsRune(got, 0) {
			t.Errorf("the report has a NUL hole, so the write landed past the old offset (%d bytes)", len(got))
		}
		if !bytes.HasPrefix(got, []byte("R ")) && !bytes.HasPrefix(got, []byte("W ")) && !bytes.HasPrefix(got, []byte("EXIT ")) {
			t.Errorf("the report does not start with a record:\n%s", firstBytes(got))
		}
		if !bytes.Contains(got, []byte(observe.ReportEnd)) {
			t.Errorf("the report has no completion marker:\n%s", firstBytes(got))
		}
	})

	// os.NewFile never returns nil for a positive fd, so the old guard was dead and its
	// message described a check that was not performed: --observe-fd 99 ran the whole
	// traced target and only then failed at Truncate with a bare EBADF.
	t.Run("an observation descriptor naming nothing is refused", func(t *testing.T) {
		out, err := runObserveChild_(t, "bad-fd", "")
		if err == nil {
			t.Fatalf("runObserve accepted a descriptor that is not open:\n%s", out)
		}
		if !strings.Contains(out, "is not valid") {
			t.Errorf("wrong refusal for an unopened report descriptor: %q", out)
		}
	})

	// A trace that fails must not leave a report the host would parse: the completion
	// marker is written only when traceErr is nil, so the host reads the run as
	// incomplete rather than proposing an empty manifest.
	t.Run("a failed trace is reported without a completion marker", func(t *testing.T) {
		report := filepath.Join(t.TempDir(), "report")
		if err := os.WriteFile(report, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		out, err := runObserveChild_(t, "trace-fails", report)
		if err == nil {
			t.Fatalf("runObserve returned no error for a target that cannot run:\n%s", out)
		}
		got, err := os.ReadFile(report)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(got, []byte(observe.ReportEnd)) {
			t.Errorf("a failed trace still wrote the completion marker:\n%s", got)
		}
	})
}

func runObserveChild_(t *testing.T, mode, report string) (string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run", "^"+t.Name()[:strings.Index(t.Name(), "/")]+"$")
	cmd.Env = append(os.Environ(), sentinelRunObserve+"="+mode)
	if report != "" {
		f, err := os.OpenFile(report, os.O_RDWR, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		cmd.ExtraFiles = []*os.File{f}
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// runObserveChild drives runObserve directly and exits nonzero on its error, so the
// parent reads the outcome from the child's status and the report file. The report file
// arrives as fd observeChildFD, the first ExtraFiles slot.
func runObserveChild(mode string) {
	const observeChildFD = 3
	cfg := Config{ObserveFD: observeChildFD, Target: []string{"/bin/true"}}
	switch mode {
	case "bad-fd":
		cfg.ObserveFD = 99
	case "trace-fails":
		cfg.Target = []string{"/nonexistent-bento-observe-target"}
	case "advanced-offset":
		// More than the Scanner's 64 KiB token limit, so a report written past the
		// offset is not merely ugly but unparseable by the host.
		if _, err := unix.Write(observeChildFD, bytes.Repeat([]byte("x"), 128<<10)); err != nil {
			fmt.Fprintln(os.Stdout, "advancing the report offset:", err)
			os.Exit(1)
		}
	}
	if _, err := runObserve(cfg, os.Environ()); err != nil {
		fmt.Fprintln(os.Stdout, err)
		os.Exit(1)
	}
}

func firstBytes(b []byte) []byte {
	if len(b) > 256 {
		return b[:256]
	}
	return b
}
