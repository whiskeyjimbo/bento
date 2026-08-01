//go:build linux

package launcher

import (
	"os"
	"testing"
	"time"
)

// The launcher must not execveat the target until the bridge signals it is
// non-dumpable and listening (bv2-a6t): startBridge blocks on awaitBridgeReady, and
// a bridge that dies before signaling must make it fail closed (refuse the run),
// never proceed to run the target against an attackable or absent bridge.
func TestAwaitBridgeReady(t *testing.T) {
	t.Run("blocks until the ready byte, then returns", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		done := make(chan error, 1)
		go func() { done <- awaitBridgeReady(r) }()
		select {
		case <-done:
			t.Fatal("returned before the ready byte was written")
		case <-time.After(50 * time.Millisecond):
		}
		_, _ = w.Write([]byte{1})
		w.Close()
		if err := <-done; err != nil {
			t.Fatalf("want nil after the ready byte, got %v", err)
		}
	})

	// A bridge that neither signals nor dies would otherwise block the launcher forever,
	// with no output: every other wait in the file is bounded, and an embedder calling
	// launcher.Run directly has nothing else watching it.
	t.Run("gives up on a bridge that never signals", func(t *testing.T) {
		old := bridgeReadyTimeout
		bridgeReadyTimeout = 50 * time.Millisecond
		defer func() { bridgeReadyTimeout = old }()
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		defer w.Close() // the write end stays open, so the read never sees EOF
		done := make(chan error, 1)
		go func() { done <- awaitBridgeReady(r) }()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("want an error from a bridge that never signaled, got nil")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("awaitBridgeReady never returned; the wait is unbounded")
		}
	})

	t.Run("fails closed when the bridge dies before signaling", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		w.Close() // bridge exits without writing -> EOF
		if err := awaitBridgeReady(r); err == nil {
			t.Fatal("want an error on a bridge that died before signaling, got nil")
		}
	})
}
