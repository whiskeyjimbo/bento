package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/whiskeyjimbo/bento-v2/internal/policy"
)

// fakeUpstream is a canned server the proxy "dials" instead of the real network:
// it echoes a banner so a test can prove bytes flow end-to-end through an
// established tunnel.
func fakeDialer(banner string) func(context.Context, string, string) (net.Conn, error) {
	return func(_ context.Context, _, addr string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			fmt.Fprintf(server, "%s from %s", banner, addr)
			// Keep the pipe open briefly so the copy can complete, then close.
			time.Sleep(20 * time.Millisecond)
			server.Close()
		}()
		return client, nil
	}
}

// startProxy serves p on a unix socket and returns a dialer to it plus a cleanup.
func startProxy(t *testing.T, p *Proxy) (dialProxy func() net.Conn, stop func()) {
	t.Helper()
	dir := t.TempDir()
	sock := dir + "/proxy.sock"
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Serve(ctx, l); close(done) }()

	dialProxy = func() net.Conn {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	stop = func() { cancel(); <-done }
	return dialProxy, stop
}

// connect sends a CONNECT request and returns the status line.
func connect(t *testing.T, c net.Conn, target string) (status string, br *bufio.Reader) {
	t.Helper()
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br = bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading status: %v", err)
	}
	return strings.TrimSpace(line), br
}

func TestAllowedHostTunnels(t *testing.T) {
	p := New([]policy.NetworkRule{{Host: "example.com", Port: "443"}}, WithDialer(fakeDialer("HELLO")))
	dialProxy, stop := startProxy(t, p)
	defer stop()

	c := dialProxy()
	defer c.Close()
	status, br := connect(t, c, "example.com:443")
	if !strings.Contains(status, "200") {
		t.Fatalf("status = %q, want 200", status)
	}
	// Bytes from the fake upstream must flow through the established tunnel.
	rest, _ := io.ReadAll(br)
	if !strings.Contains(string(rest), "HELLO") {
		t.Errorf("tunnel did not carry upstream bytes; got %q", rest)
	}
}

func TestDeniedHostRefusedWithReason(t *testing.T) {
	var seen []string
	p := New(
		[]policy.NetworkRule{{Host: "example.com", Port: "443"}},
		WithDialer(fakeDialer("HELLO")),
		WithObserver(func(d Decision, host, port string) { seen = append(seen, string(d)+" "+host) }),
	)
	dialProxy, stop := startProxy(t, p)
	defer stop()

	c := dialProxy()
	defer c.Close()
	status, br := connect(t, c, "evil.com:443")
	if !strings.Contains(status, "403") {
		t.Fatalf("status = %q, want 403", status)
	}
	body, _ := io.ReadAll(br)
	if !strings.Contains(string(body), "evil.com") {
		t.Errorf("refusal body should name the denied host; got %q", body)
	}
	if len(seen) != 1 || !strings.HasPrefix(seen[0], "deny") {
		t.Errorf("observer saw %v, want a single deny", seen)
	}
}

// WithoutEgress (profiling) records the intended destination and refuses it,
// even for a host the allowlist would permit, and never opens an upstream — so
// the destination is captured while the script's data stays on the host.
func TestWithoutEgressRecordsButRefuses(t *testing.T) {
	var seen []string
	var dialed bool
	var mu sync.Mutex
	p := New(
		[]policy.NetworkRule{{Host: "*", Port: "*"}}, // allow-all, as profiling uses
		WithoutEgress(),
		WithDialer(func(context.Context, string, string) (net.Conn, error) {
			mu.Lock()
			dialed = true
			mu.Unlock()
			return nil, fmt.Errorf("should not be reached")
		}),
		WithObserver(func(d Decision, host, port string) { seen = append(seen, host+":"+port) }),
	)
	dialProxy, stop := startProxy(t, p)
	defer stop()

	c := dialProxy()
	defer c.Close()
	status, _ := connect(t, c, "example.com:443")
	if !strings.Contains(status, "403") {
		t.Fatalf("status = %q, want 403 (recorded but not forwarded)", status)
	}
	if len(seen) != 1 || seen[0] != "example.com:443" {
		t.Errorf("observer saw %v, want the destination recorded", seen)
	}
	mu.Lock()
	defer mu.Unlock()
	if dialed {
		t.Error("WithoutEgress must never open an upstream connection")
	}
}

func TestDeniedHostIsNeverDialed(t *testing.T) {
	var dialed bool
	var mu sync.Mutex
	p := New(
		[]policy.NetworkRule{{Host: "example.com", Port: "443"}},
		WithDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			dialed = true
			mu.Unlock()
			return nil, fmt.Errorf("should not be reached")
		}),
	)
	dialProxy, stop := startProxy(t, p)
	defer stop()

	c := dialProxy()
	defer c.Close()
	connect(t, c, "evil.com:443")

	mu.Lock()
	defer mu.Unlock()
	if dialed {
		t.Error("a denied host was dialed; the allowlist check must happen before any upstream connection")
	}
}

func TestPortMismatchDenied(t *testing.T) {
	p := New([]policy.NetworkRule{{Host: "example.com", Port: "443"}}, WithDialer(fakeDialer("x")))
	dialProxy, stop := startProxy(t, p)
	defer stop()

	c := dialProxy()
	defer c.Close()
	status, _ := connect(t, c, "example.com:8080")
	if !strings.Contains(status, "403") {
		t.Errorf("a rule for :443 must not permit :8080; status = %q", status)
	}
}

// The proxy must bound concurrent tunnels so untrusted code cannot exhaust host
// resources by opening connections in a loop. Beyond the cap, connections are
// refused (503) rather than handled.
func TestConcurrencyIsCapped(t *testing.T) {
	// A dialer that blocks until the test unblocks it, so every accepted tunnel
	// occupies a slot and none free up while the cap is being probed.
	block := make(chan struct{})
	p := New([]policy.NetworkRule{{Host: "example.com", Port: "443"}},
		WithDialer(func(context.Context, string, string) (net.Conn, error) {
			<-block
			return nil, fmt.Errorf("test dialer unblocked")
		}))
	dialProxy, stop := startProxy(t, p)
	// Unblock the handlers BEFORE stopping, or Serve's wg.Wait would deadlock on
	// handlers that never return.
	defer func() { close(block); stop() }()

	// Fill every slot with a held-open tunnel.
	held := make([]net.Conn, 0, maxConcurrent)
	for i := 0; i < maxConcurrent; i++ {
		c := dialProxy()
		fmt.Fprintf(c, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
		held = append(held, c)
	}
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()

	// Give the handlers a moment to occupy their slots, then the next connection
	// must be refused at capacity rather than handled.
	over := dialProxy()
	defer over.Close()
	fmt.Fprintf(over, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
	over.SetReadDeadline(time.Now().Add(3 * time.Second))
	status, _ := bufio.NewReader(over).ReadString('\n')
	if !strings.Contains(status, "503") {
		t.Errorf("connection past the cap should be refused with 503; got %q", status)
	}
}

func TestMalformedRequestRejected(t *testing.T) {
	p := New([]policy.NetworkRule{{Host: "example.com", Port: "443"}}, WithDialer(fakeDialer("x")))
	dialProxy, stop := startProxy(t, p)
	defer stop()

	for _, req := range []string{
		"GET http://example.com/ HTTP/1.1\r\n\r\n", // not CONNECT
		"CONNECT example.com HTTP/1.1\r\n\r\n",     // no port
		"garbage\r\n\r\n",
	} {
		c := dialProxy()
		fmt.Fprint(c, req)
		br := bufio.NewReader(c)
		line, err := br.ReadString('\n')
		if err != nil {
			c.Close()
			continue // closing without a response is also an acceptable rejection
		}
		if strings.Contains(line, "200") {
			t.Errorf("malformed request %q was accepted", req)
		}
		c.Close()
	}
}
