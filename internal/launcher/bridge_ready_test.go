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
		w.Write([]byte{1})
		w.Close()
		if err := <-done; err != nil {
			t.Fatalf("want nil after the ready byte, got %v", err)
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
