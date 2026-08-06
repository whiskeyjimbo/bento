//go:build linux

package launcher

import (
	"fmt"
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

	// The families are an allowlist, so a family nobody enumerated does not slip past.
	// AF_PACKET is the one egress_linux_amd64.go names
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

	// A netlink socket binds to a network namespace when it is CREATED, so one inherited
	// on stdio still speaks to the host's however the sandbox is built afterwards - it
	// enumerates host interfaces, addresses and routes. egressFilter permits the family
	// because it governs creation inside the fresh netns, which is the opposite case.
	t.Run("an AF_NETLINK socket is refused", func(t *testing.T) {
		fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
		if err != nil {
			t.Skipf("no AF_NETLINK socket available: %v", err)
		}
		defer unix.Close(fd)
		err = refuseNetworkFD(fd)
		if err == nil {
			t.Fatal("an inherited AF_NETLINK stdio socket was accepted; it reaches the host network namespace")
		}
		// Typed like every other refused family, so an embedder doing socket activation
		// can waive it deliberately and is warned when it does - rather than the silent
		// pass it used to get.
		if !strings.Contains(err.Error(), "inherited socket of family") {
			t.Errorf("wrong refusal for an AF_NETLINK socket: %v", err)
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

	// The reproduction the socket-only check waved through: openat(dirfd, "secret")
	// resolves from the inode, so the target reads a host tree the mount namespace
	// never covers.
	t.Run("a directory is refused", func(t *testing.T) {
		f, err := os.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		err = refuseNetworkFD(int(f.Fd()))
		if err == nil {
			t.Fatal("an inherited directory on stdio was accepted; openat through it leaves the sandbox")
		}
		if !strings.Contains(err.Error(), "inherited directory") {
			t.Errorf("wrong refusal for a directory: %v", err)
		}
	})

	// The interactive case the device rule exists for: refusing it would refuse every
	// run a human types. The pty SLAVE is what a shell actually puts on 0/1/2, so the
	// test opens one rather than settling for the ptmx multiplexer.
	t.Run("a terminal is allowed", func(t *testing.T) {
		slave := ptySlave(t)
		if err := refuseNetworkFD(int(slave.Fd())); err != nil {
			t.Errorf("a terminal on stdio was refused; every interactive run has one: %v", err)
		}
	})

	// The other half of the rule, on the opposite rationale: the sandbox's own /dev
	// provides it, so an inherited one grants nothing openable-by-path did not.
	t.Run("a device the sandbox provides is allowed", func(t *testing.T) {
		f, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := refuseNetworkFD(int(f.Fd())); err != nil {
			t.Errorf("/dev/null on stdio was refused: %v", err)
		}
	})

	// /dev/mem shares major 1 with the harmless nodes and is a direct physical-memory
	// channel, so the minors are enumerated rather than the major allowed wholesale.
	// It is also openable only by root, which is the case this check is written for -
	// a parent with more rights than the target handing a descriptor down.
	t.Run("a memory device is refused", func(t *testing.T) {
		f, err := os.OpenFile("/dev/mem", os.O_RDONLY, 0)
		if err != nil {
			t.Skipf("no /dev/mem available: %v", err)
		}
		defer f.Close()
		err = refuseNetworkFD(int(f.Fd()))
		if err == nil {
			t.Fatal("an inherited /dev/mem on stdio was accepted")
		}
		if !strings.Contains(err.Error(), "character device") {
			t.Errorf("wrong refusal for /dev/mem: %v", err)
		}
	})

	// /dev/kvm and /dev/net/tun are host channels of the exact kind this check exists
	// for, and neither is a socket. Opening either needs privileges or modules the test
	// host may lack, so the classifier is exercised on the device numbers directly -
	// with a descriptor that is not a terminal, which is the other half of the rule.
	t.Run("a device the sandbox does not offer is refused", func(t *testing.T) {
		notATTY, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		defer notATTY.Close()
		for _, d := range []struct {
			name         string
			major, minor uint32
		}{
			{"/dev/kvm", 10, 232},
			{"/dev/net/tun", 10, 200},
			{"/dev/mem", 1, 1},
			{"/dev/kmem", 1, 2},
			{"/dev/port", 1, 4},
			{"an idle host serial port", 4, 64},
			{"a host virtual console", 4, 1},
		} {
			if permittedStdioDevice(int(notATTY.Fd()), unix.Mkdev(d.major, d.minor)) {
				t.Errorf("%s (%d:%d) passed as a permitted stdio device", d.name, d.major, d.minor)
			}
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

// ptySlave opens a pty pair and hands back the slave - the end a shell puts on the
// target's standard streams, and a device number (136-143) the sandbox's own devpts
// does not carry, so it is the terminal rule that has to permit it and not the
// provided-device one.
func ptySlave(t *testing.T) *os.File {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no pty available: %v", err)
	}
	t.Cleanup(func() { master.Close() })
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatalf("unlocking the pty: %v", err)
	}
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatalf("naming the pty slave: %v", err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("opening the pty slave: %v", err)
	}
	t.Cleanup(func() { slave.Close() })
	return slave
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
