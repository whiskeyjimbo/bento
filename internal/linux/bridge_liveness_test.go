package linux

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// The host reads the bridge's death from a byte on the liveness pipe, never from the
// pipe closing: the sandbox's pid namespace collapses at every exit, so EOF
// arrives on every run and reading death from it would degrade the network layer of
// every clean run that had egress.
func TestBridgeReportedDeath(t *testing.T) {
	t.Run("a written byte is a death report", func(t *testing.T) {
		r, w := livenessPipe(t)
		_, _ = w.Write([]byte{1})
		w.Close()
		if !bridgeReportedDeath(r) {
			t.Fatal("want a death report from a written byte, got none")
		}
	})

	t.Run("EOF with no byte is an ordinary run", func(t *testing.T) {
		r, w := livenessPipe(t)
		w.Close()
		if bridgeReportedDeath(r) {
			t.Fatal("a bridge torn down with the sandbox reported death")
		}
	})

	// A run with no egress wires no pipe at all.
	t.Run("no pipe is no report", func(t *testing.T) {
		if bridgeReportedDeath(nil) {
			t.Fatal("want no report with no liveness pipe, got one")
		}
	})
}

// A bridge that stopped serving must reach the run report: on the exec-block path the
// launcher is gone and the host-side proxy listener stays healthy, so without this the
// report says LayerNetwork Enforced for a run whose egress stopped mid-way.
func TestNoteDeadBridge(t *testing.T) {
	var r enforce.Report
	r.Set(enforce.LayerNetwork, enforce.Enforced, "egress is proxied")
	noteDeadBridge(&r, true)
	if got := r.StateOf(enforce.LayerNetwork); got != enforce.Degraded {
		t.Fatalf("want the network layer degraded, got %v", got)
	}
	if reason := r.Layers[0].Reason; !strings.Contains(reason, "bridge") {
		t.Errorf("the reason does not name the bridge: %q", reason)
	}

	var clean enforce.Report
	clean.Set(enforce.LayerNetwork, enforce.Enforced, "egress is proxied")
	noteDeadBridge(&clean, false)
	if s := clean.StateOf(enforce.LayerNetwork); s != enforce.Enforced {
		t.Fatalf("a live bridge degraded the network layer: %v", s)
	}
}

// The end-to-end half the unit tests cannot cover: the liveness pipe is a second
// extra file, so it only reaches the bridge if bwrap passes fd bridgeLivenessFD
// through as it does the applied report. A clean egress run must also come back with
// the network layer intact - the bridge is killed by the pid-namespace collapse at
// every normal exit, so a design that read death from the pipe closing would degrade
// this run.
func TestCleanEgressRunKeepsTheNetworkLayer(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	script := filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(script, []byte("exit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{
		Entrypoint:  script,
		Interpreter: "sh",
		Read:        []string{dir},
		Network:     []policy.NetworkRule{{Host: "example.com", Port: "443"}},
	}

	var out bytes.Buffer
	res, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out}, enforce.RunOptions{})
	if err != nil {
		t.Fatalf("Run: %v (output: %s)", err, out.String())
	}
	if st := res.Report.StateOf(enforce.LayerNetwork); st == enforce.Degraded {
		t.Errorf("network layer = %v on a clean egress run; the bridge's ordinary teardown was read as its death: %v",
			st, res.Report.Degradations())
	}
}

func livenessPipe(t *testing.T) (r, w *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r, w
}
