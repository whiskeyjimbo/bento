//go:build linux

package launcher

import (
	"net"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
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
		if !strings.Contains(err.Error(), "inherited socket of family") {
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

	// The families are an allowlist, mirroring egressFilter's, so a family nobody
	// enumerated does not slip past. AF_PACKET is the one egress_linux_amd64.go names
	// explicitly: raw frames on the host wire, which an AF_INET/AF_INET6 denylist would
	// wave through. Creating one needs CAP_NET_RAW, so the check runs against a
	// non-IP socket that any user can make instead - it exercises the same branch.
	t.Run("a non-IP, non-AF_UNIX socket is refused", func(t *testing.T) {
		fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
		if err != nil {
			t.Skipf("no AF_VSOCK socket available: %v", err)
		}
		defer unix.Close(fd)
		err = refuseNetworkFD(fd)
		if err == nil {
			t.Fatal("an inherited AF_VSOCK socket on stdio was accepted")
		}
		if !strings.Contains(err.Error(), "inherited socket of family") {
			t.Errorf("wrong refusal for a non-IP socket: %v", err)
		}
	})

	// AF_NETLINK is allowed for the same reason egressFilter allows it: it is kernel
	// IPC and cannot egress, and runtimes enumerate interfaces with it.
	t.Run("an AF_NETLINK socket is allowed", func(t *testing.T) {
		fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
		if err != nil {
			t.Skipf("no AF_NETLINK socket available: %v", err)
		}
		defer unix.Close(fd)
		if err := refuseNetworkFD(fd); err != nil {
			t.Errorf("an AF_NETLINK stdio socket was refused: %v", err)
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
// The opt-in in Run waives a socket but never a descriptor that could not be
// classified, and it can only tell them apart if every standard descriptor is
// examined. Stopping at the first failure would let a waived socket on fd 0 hide an
// unexaminable fd 1, so the collection must not short-circuit. Two sockets stand in
// for the pair: the unclassifiable case needs an errno no test can provoke, and which
// descriptors report is what is actually load-bearing here.
func TestNetworkStdioRefusalsReportsEveryDescriptor(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback TCP available: %v", err)
	}
	defer ln.Close()
	sock := int(rawFile(t, ln.(*net.TCPListener)).Fd())

	for _, fd := range []int{0, 1} {
		saved, err := unix.Dup(fd)
		if err != nil {
			t.Fatalf("saving fd %d: %v", fd, err)
		}
		defer func() {
			// Restoring matters beyond this test: fd 0/1 belong to the whole test binary,
			// so a silent failure here would leave later tests writing into a socket.
			if err := unix.Dup2(saved, fd); err != nil {
				t.Errorf("restoring fd %d: %v", fd, err)
			}
			unix.Close(saved)
		}()
		if err := unix.Dup2(sock, fd); err != nil {
			t.Fatalf("planting a socket on fd %d: %v", fd, err)
		}
	}

	if got := len(networkStdioRefusals()); got != 2 {
		t.Errorf("refusals = %d, want 2: a socket on fd 0 must not hide what fd 1 carries", got)
	}
}

func rawFile(t *testing.T, ln interface{ File() (*os.File, error) }) *os.File {
	t.Helper()
	f, err := ln.File()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
