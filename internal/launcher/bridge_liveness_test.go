package launcher

import (
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// The bridge outlives every process that could write the applied report, so the one
// byte it puts on the liveness pipe is the whole channel by which its death reaches
// the host. Two halves matter: a failure that has persisted writes it, and an ordinary
// run writes nothing - the pid namespace collapses at every normal exit, so if the
// host had to read death from the pipe closing it would see one on every clean run.
func TestBridgeLivenessReport(t *testing.T) {
	t.Run("writes one byte the host can read", func(t *testing.T) {
		r, w := livenessPipe(t)
		b := &bridgeLiveness{f: w}
		b.reportDeath()
		var buf [8]byte
		n, err := r.Read(buf[:])
		if err != nil {
			t.Fatalf("reading the death report: %v", err)
		}
		if n != 1 {
			t.Fatalf("want exactly one byte on the liveness pipe, got %d", n)
		}
	})

	// The accept loop keeps retrying after reporting, so an unguarded report would put a
	// byte on the pipe per backoff for as long as the failure lasts.
	t.Run("reports at most once", func(t *testing.T) {
		r, w := livenessPipe(t)
		b := &bridgeLiveness{f: w}
		b.reportDeath()
		b.reportDeath()
		b.reportDeath()
		w.Close()
		var buf [8]byte
		if n, _ := r.Read(buf[:]); n != 1 {
			t.Fatalf("want one byte across repeated reports, got %d", n)
		}
	})

	// An embedder driving Run itself wires no liveness pipe, and fd 0 is the target's
	// own stdin - writing a stray byte there would corrupt its input.
	t.Run("writes nothing when no pipe was wired", func(t *testing.T) {
		if f := openBridgeLiveness(0).f; f != nil {
			t.Fatalf("want no liveness file for descriptor 0, got %v", f.Name())
		}
	})
}

// A bridge whose listener wedges never returns: every Accept error short of a closed
// listener is retried forever, deliberately, so egress that might recover is not
// killed. That leaves the host claiming LayerNetwork enforced for a run whose egress
// stopped, which the liveness report exists to correct - so a failure that has
// persisted past the retry budget must reach the pipe even though the loop lives on.
func TestServeBridgeReportsAPersistentAcceptFailure(t *testing.T) {
	shortenAcceptBudget(t)

	r, w := livenessPipe(t)
	l := &failingListener{fail: acceptFailuresBeforeDeath + 2}
	done := make(chan error, 1)
	go func() { done <- serveBridge(l, "/unused.sock", &bridgeLiveness{f: w}) }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveBridge never returned")
	}
	w.Close()

	var buf [8]byte
	n, _ := r.Read(buf[:])
	if n != 1 {
		t.Fatalf("want exactly one death report from a persistently failing listener, got %d bytes", n)
	}
}

// A listener that fails Accept with a transient error the given number of times, then
// reports itself closed so the loop under test terminates.
type failingListener struct {
	fail int
}

func (l *failingListener) Accept() (net.Conn, error) {
	if l.fail > 0 {
		l.fail--
		return nil, syscall.EMFILE
	}
	return nil, net.ErrClosed
}

func (l *failingListener) Close() error   { return nil }
func (l *failingListener) Addr() net.Addr { return &net.TCPAddr{} }

func shortenAcceptBudget(t *testing.T) {
	t.Helper()
	oldCount, oldDelay := acceptFailuresBeforeDeath, acceptRetryDelay
	acceptFailuresBeforeDeath, acceptRetryDelay = 3, time.Millisecond
	t.Cleanup(func() { acceptFailuresBeforeDeath, acceptRetryDelay = oldCount, oldDelay })
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
