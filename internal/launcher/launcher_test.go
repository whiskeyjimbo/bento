package launcher

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// superviseTarget must refuse a relative target[0]: exec.Command would otherwise do a
// $PATH lookup and run a different binary than the manifest named. The Block path
// (seccomp.Exec) refuses one as well - see TestExecRejectsRelativeArgv0 in the seccomp
// package - so the two exec modes agree. Neither is covered by the other: execveat
// resolves a relative path against the working directory perfectly happily, so the
// refusal there is a check, not a property of the syscall.
func TestSuperviseTargetRejectsRelative(t *testing.T) {
	if _, err := superviseTarget([]string{"true"}, nil); err == nil {
		t.Error("superviseTarget ran a relative target[0] instead of refusing it")
	}
	if _, err := superviseTarget(nil, nil); err == nil {
		t.Error("superviseTarget ran an empty target instead of refusing it")
	}
}

// The bridge is the in-sandbox hop between the target's loopback proxy port and
// the host-side proxy socket. These tests exercise it directly with a fake unix
// "proxy" and a plain TCP client - no sandbox needed - so its byte-plumbing is
// covered independently of the end-to-end sandbox test.

// echoSocket starts a unix listener that echoes a banner then whatever it
// receives, standing in for the host-side proxy.
func echoSocket(t *testing.T) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "proxy.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.WriteString(c, "BANNER\n")
				io.Copy(c, c) // echo
			}()
		}
	}()
	return sock
}

func TestBridgeForwardsBothDirections(t *testing.T) {
	sock := echoSocket(t)

	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			go bridgeConn(c, sock)
		}
	}()

	c, err := net.Dial("tcp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))

	br := bufio.NewReader(c)
	banner, err := br.ReadString('\n')
	if err != nil || !strings.Contains(banner, "BANNER") {
		t.Fatalf("did not receive the upstream banner through the bridge: %q, %v", banner, err)
	}

	// Client → upstream → echo → client must round-trip.
	fmt.Fprintln(c, "ping")
	echo, err := br.ReadString('\n')
	if err != nil || !strings.Contains(echo, "ping") {
		t.Fatalf("bridge did not round-trip client bytes: %q, %v", echo, err)
	}
}

// A transfer busy in one direction while the other is silent must not trip the
// idle timeout: activity in either direction re-arms both conns. With a
// per-direction deadline the silent conn's deadline would expire and - because
// SetDeadline bounds writes too - abort the busy direction mid-transfer.
func TestBridgeOneWayTransferNotIdleTimedOut(t *testing.T) {
	old := idleTimeout
	idleTimeout = 200 * time.Millisecond
	defer func() { idleTimeout = old }()

	// A silent upstream: it drains what the client sends but never replies, so the
	// upstream->client direction stays idle for the whole transfer.
	sock := filepath.Join(t.TempDir(), "proxy.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got := make(chan int, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		n, _ := io.Copy(io.Discard, c)
		got <- int(n)
	}()

	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	go func() {
		c, err := tcp.Accept()
		if err != nil {
			return
		}
		bridgeConn(c, sock)
	}()

	c, err := net.Dial("tcp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Total transfer (~300ms) outlasts the idle timeout, but each per-chunk gap
	// (20ms) stays an order of magnitude under it, so scheduler jitter under load
	// cannot spuriously trip the timeout.
	const chunks = 15
	const spacing = 20 * time.Millisecond
	for i := range chunks {
		if _, err := io.WriteString(c, "x"); err != nil {
			t.Fatalf("write %d: a busy one-way transfer was torn down by the idle timeout: %v", i, err)
		}
		time.Sleep(spacing)
	}
	c.(*net.TCPConn).CloseWrite()

	select {
	case n := <-got:
		if n != chunks {
			t.Fatalf("upstream received %d bytes, want %d", n, chunks)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upstream did not receive the full transfer")
	}
}

// A half-close from the client (it is done sending) must not truncate data the
// upstream is still delivering. The prior implementation waited on only one
// direction and closed both, dropping in-flight bytes.
func TestBridgeDoesNotTruncateOnClientHalfClose(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "proxy.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	// This upstream sends a burst only after the client has stopped writing.
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.ReadAll(io.LimitReader(c, 4)) // read the client's "bye\n"-ish
		time.Sleep(50 * time.Millisecond)
		io.WriteString(c, "LATE-PAYLOAD\n")
	}()

	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	go func() {
		c, err := tcp.Accept()
		if err != nil {
			return
		}
		bridgeConn(c, sock)
	}()

	c, err := net.Dial("tcp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))

	io.WriteString(c, "bye\n")
	c.(*net.TCPConn).CloseWrite() // client half-closes after sending

	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("reading late payload: %v", err)
	}
	if !strings.Contains(string(got), "LATE-PAYLOAD") {
		t.Fatalf("client half-close truncated an in-flight upstream response; got %q", got)
	}
}

// dropInheritedFDs must mark an inherited descriptor close-on-exec (so it is
// dropped at the exec into the target) while leaving it usable in this process (so
// the launcher's own runtime descriptors keep working). An open file stands in for
// a descriptor bento's parent leaked without O_CLOEXEC.
func TestDropInheritedFDsMarksCloexec(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "leaked")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// Start without close-on-exec, as an inherited descriptor would be.
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(f.Fd(), unix.F_SETFD, flags&^unix.FD_CLOEXEC); err != nil {
		t.Fatal(err)
	}

	if err := dropInheritedFDs(); err != nil {
		t.Fatalf("dropInheritedFDs: %v", err)
	}

	got, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got&unix.FD_CLOEXEC == 0 {
		t.Errorf("an inherited descriptor was not marked close-on-exec: flags=%#x", got)
	}
	// Still usable in-process: marking does not close.
	if _, err := f.WriteString("x"); err != nil {
		t.Errorf("descriptor unusable after marking close-on-exec: %v", err)
	}
}
