//go:build linux

package launcher

import (
	"net"
	"os"
	"strings"
	"testing"
)

// dropInheritedFDs keeps 0/1/2 unconditionally, and neither egress fence revokes what
// they carry: the netns fences new connections and seccomp.BlockEgress filters socket(2)
// creation, so read/write on an already-open network socket are unfiltered. An embedder
// that hands enforce.Process.Stdin an *os.File wrapping a TCP connection therefore gives
// the target a live network channel under a policy claiming it cannot open one. The run
// must be refused. AF_UNIX stdio reaches no network and is deliberately left working -
// the egress filter allows AF_UNIX, and the bridge and in-sandbox sockets depend on it.
func TestRefuseNetworkFD(t *testing.T) {
	t.Run("a TCP socket is refused", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skipf("no loopback TCP available: %v", err)
		}
		defer ln.Close()
		f := rawFile(t, ln.(*net.TCPListener))
		err = refuseNetworkFD(int(f.Fd()))
		if err == nil {
			t.Fatal("an inherited TCP socket on stdio was accepted")
		}
		if !strings.Contains(err.Error(), "inherited network socket") {
			t.Errorf("wrong refusal for a TCP socket: %v", err)
		}
	})

	t.Run("an AF_UNIX socket is allowed", func(t *testing.T) {
		ln, err := net.Listen("unix", t.TempDir()+"/s.sock")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		f := rawFile(t, ln.(*net.UnixListener))
		if err := refuseNetworkFD(int(f.Fd())); err != nil {
			t.Errorf("an AF_UNIX stdio socket was refused: %v", err)
		}
	})

	t.Run("a regular file is allowed", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "out")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := refuseNetworkFD(int(f.Fd())); err != nil {
			t.Errorf("a regular file on stdio was refused: %v", err)
		}
	})

	t.Run("a closed descriptor is allowed", func(t *testing.T) {
		// Nothing was inherited there, so the target sees the same EBADF the check does.
		if err := refuseNetworkFD(9999); err != nil {
			t.Errorf("an unopened descriptor was refused: %v", err)
		}
	})
}

// rawFile hands back the listener's own descriptor. net.Listener.File dups it, which is
// what the check needs to see: a real socket description, not a pipe.
func rawFile(t *testing.T, ln interface{ File() (*os.File, error) }) *os.File {
	t.Helper()
	f, err := ln.File()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
