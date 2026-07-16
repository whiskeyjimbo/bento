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
// even for a host the allowlist would permit, and never opens an upstream, so
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

// A request with no terminating newline must not let a sandboxed client grow the
// host process's memory: the proxy caps what it buffers before the tunnel and
// rejects an oversized request instead of reading it forever.
func TestOversizedRequestRejected(t *testing.T) {
	p := New([]policy.NetworkRule{{Host: "example.com", Port: "443"}}, WithDialer(fakeDialer("x")))
	dialProxy, stop := startProxy(t, p)
	defer stop()

	c := dialProxy()
	defer c.Close()
	// Stream more than the cap with no newline, in the background so the proxy
	// closing its read side cannot deadlock the writer.
	go func() {
		junk := strings.Repeat("A", maxRequestBytes+4096)
		io.WriteString(c, junk)
	}()

	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	status, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return // closing without a response is an acceptable rejection
	}
	if strings.Contains(status, "200") {
		t.Errorf("oversized newline-free request was accepted; got %q", status)
	}
}

func TestClassifyIP(t *testing.T) {
	cases := map[ipClass][]string{
		// Never reachable through the proxy, not even with an explicit rule.
		ipHostReserved: {
			"127.0.0.1", "::1", "::ffff:127.0.0.1", // loopback
			"169.254.169.254", "fe80::1", // link-local (incl. cloud metadata)
			"0.0.0.0", "::", // unspecified
			"64:ff9b::a9fe:a9fe", // NAT64 of 169.254.169.254 (metadata)
			"64:ff9b::7f00:1",    // NAT64 of 127.0.0.1
		},
		// Reachable only via an explicit IP-literal rule.
		ipPrivate: {
			"10.0.0.5", "172.16.0.1", "192.168.1.1", "fc00::1", // RFC1918 / ULA
			"100.64.0.1", "100.127.255.255", // CGNAT
			"64:ff9b::a00:5",    // NAT64 of 10.0.0.5
			"2002:0a00:0005::1", // 6to4 embedding 10.0.0.5
		},
		// Governed by the allowlist alone.
		ipPublic: {
			"1.1.1.1", "8.8.8.8", "93.184.216.34",
			"2606:2800:220:1:248:1893:25c8:1946",
			"100.63.255.255", "100.128.0.1", // just outside CGNAT 100.64/10
			"64:ff9b::808:808", // NAT64 of public 8.8.8.8 stays public
		},
	}
	for want, ips := range cases {
		for _, s := range ips {
			if got := classifyIP(net.ParseIP(s)); got != want {
				t.Errorf("classifyIP(%s) = %d, want %d", s, got, want)
			}
		}
	}
}

// An allowlisted hostname that resolves to a non-public address must be refused:
// the name check passed, but the sandbox must not reach host-internal services
// (loopback, cloud metadata, RFC1918) by resolving a permitted name to them.
func TestBlocksPermittedHostResolvingToNonPublic(t *testing.T) {
	p := New([]policy.NetworkRule{{Host: "localhost", Port: "9"}})
	dialProxy, stop := startProxy(t, p)
	defer stop()

	c := dialProxy()
	defer c.Close()
	status, br := connect(t, c, "localhost:9")
	if !strings.Contains(status, "403") {
		t.Fatalf("status = %q, want 403 (localhost resolves to loopback)", status)
	}
	body, _ := io.ReadAll(br)
	if !strings.Contains(string(body), "non-public") {
		t.Errorf("refusal body should explain the non-public address; got %q", body)
	}
}

// The proxy runs on the host, so dialing loopback reaches the HOST's loopback
// services. An explicit loopback rule must NOT reach them - loopback is never
// exempt - so validate's warning that loopback rules cannot reach the host holds.
func TestExplicitLoopbackRuleStillBlocked(t *testing.T) {
	p := New([]policy.NetworkRule{{Host: "127.0.0.1", Port: "6379"}})
	dialProxy, stop := startProxy(t, p)
	defer stop()

	c := dialProxy()
	defer c.Close()
	status, _ := connect(t, c, "127.0.0.1:6379")
	if !strings.Contains(status, "403") {
		t.Fatalf("status = %q, want 403 (an explicit loopback rule must not reach the host)", status)
	}
}

// The explicit-IP-literal exemption applies to private space (a deliberate
// internal-egress choice) but never to loopback/link-local, which name the host.
func TestGuardExemptsExplicitPrivateNotLoopback(t *testing.T) {
	p := New([]policy.NetworkRule{
		{Host: "10.0.0.5", Port: "443"},
		{Host: "127.0.0.1", Port: "443"},
	})
	guard := func(addr string) error { return p.guardUpstream(context.Background(), "tcp", addr, nil) }

	if err := guard("10.0.0.5:443"); err != nil {
		t.Errorf("an explicit private-IP rule should be permitted: %v", err)
	}
	if err := guard("10.0.0.6:443"); err == nil {
		t.Error("a private IP with no rule must be blocked")
	}
	if err := guard("127.0.0.1:443"); err == nil {
		t.Error("loopback must be blocked even with an explicit rule")
	}
}

// An IPv6 zone id makes net.ParseIP return nil; the guard must strip it and
// classify the underlying address rather than fail open. The mapped-IPv4 form
// reaches the IPv4 cloud-metadata endpoint and host loopback (the kernel dials
// the embedded address ignoring the zone), and a dotted zone lets the CONNECT
// host match an ordinary ".suffix" allowlist - so this is not wildcard-only.
func TestGuardBlocksZonedHostReserved(t *testing.T) {
	// A permissive suffix rule, to prove the bypass is not limited to wildcards.
	p := New([]policy.NetworkRule{{Host: ".example.com", Port: "*"}})
	guard := func(addr string) error { return p.guardUpstream(context.Background(), "tcp", addr, nil) }

	blocked := []string{
		"[fe80::1%eth0]:80",                // link-local, zoned (bracketed, the form ControlContext delivers)
		"[::1%lo]:6379",                    // loopback, zoned IPv6
		"169.254.169.254%eth0:80",          // collapsed mapped-IPv4 metadata
		"[::ffff:169.254.169.254%eth0]:80", // mapped-IPv4 metadata, bracketed
		"not-an-ip%zone:80",                // unparseable after stripping: fail closed, do not dial blind
	}
	for _, addr := range blocked {
		if err := guard(addr); err == nil {
			t.Errorf("guard(%q) allowed a zoned/unparseable host-reserved address; want blocked", addr)
		}
	}

	// Prove the zone strip actually ran, not merely the fail-closed-on-unparseable
	// branch: a mapped loopback with a dotted zone (which matches the .example.com
	// rule) must be refused as its classified 127.0.0.1. That dotted address only
	// appears in the error if the guard stripped the zone and classified the
	// underlying IP; the raw fail-closed path would report the whole address string.
	err := guard("[::ffff:127.0.0.1%foo.example.com]:6379")
	blk, ok := err.(*blockedUpstreamError)
	if !ok {
		t.Fatalf("guard mapped-loopback-with-dotted-zone: got %v, want *blockedUpstreamError", err)
	}
	if blk.addr != "127.0.0.1" {
		t.Errorf("blocked addr = %q, want 127.0.0.1 (the zone strip + classify must run, not raw fail-closed)", blk.addr)
	}

	// A plain public literal must still be permitted (no over-blocking).
	if err := guard("93.184.216.34:443"); err != nil {
		t.Errorf("a public address must still be allowed: %v", err)
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
