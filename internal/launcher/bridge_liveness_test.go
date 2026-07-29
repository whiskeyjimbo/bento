package launcher

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// The bridge outlives every process that could write the applied report, so the one
// byte it puts on the liveness pipe is the whole channel by which its death reaches
// the host. The two halves that matter are that a fatal path writes it and
// that nothing else does: the pid namespace collapses at every normal exit, so if the
// host had to read death from the pipe closing it would see one on every clean run.
func TestNoteBridgeDeath(t *testing.T) {
	t.Run("writes one byte the host can read", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		defer w.Close()
		// noteBridgeDeath owns the descriptor it is given and closes it, so hand it a dup
		// rather than the pipe's own write end.
		fd, err := unix.Dup(int(w.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		noteBridgeDeath(fd)
		var b [8]byte
		n, err := r.Read(b[:])
		if err != nil {
			t.Fatalf("reading the death report: %v", err)
		}
		if n != 1 {
			t.Fatalf("want exactly one byte on the liveness pipe, got %d", n)
		}
	})

	// An embedder driving Run itself wires no liveness pipe, and fd 0 is the target's
	// own stdin - writing a stray byte there would corrupt its input.
	t.Run("writes nothing when no pipe was wired", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		noteBridgeDeath(0)
		w.Close()
		var b [8]byte
		if n, _ := r.Read(b[:]); n != 0 {
			t.Fatalf("want no byte with no liveness pipe, got %d", n)
		}
	})
}
