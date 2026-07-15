package launcher

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
