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

	"github.com/whiskeyjimbo/bento-v2/policy"
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
	for range maxConcurrent {
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

// A transfer that stays busy in one direction while the other is silent must not
// trip the idle timeout: activity in either direction re-arms both conns. With a
// per-direction deadline, the silent conn's deadline would expire and - because
// SetDeadline bounds writes too - abort the busy direction mid-transfer.
func TestTunnelOneWayTransferNotIdleTimedOut(t *testing.T) {
	old := idleTimeout
	idleTimeout = 200 * time.Millisecond
	defer func() { idleTimeout = old }()

	// tunnel writes client->upstream and upstream->client; the test feeds the
	// client side and drains the upstream side, leaving the upstream->client
	// direction permanently silent.
	sandbox, clientConn := net.Pipe()
	upstreamConn, server := net.Pipe()
	defer sandbox.Close()
	defer server.Close()
	go tunnel(clientConn, clientConn, upstreamConn)

	// Total transfer (~300ms) outlasts the idle timeout, but each per-chunk gap
	// (20ms) stays an order of magnitude under it, so scheduler jitter under load
	// cannot spuriously trip the timeout.
	const chunks = 15
	const spacing = 20 * time.Millisecond
	go func() {
		for range chunks {
			if _, err := io.WriteString(sandbox, "x"); err != nil {
				return
			}
			time.Sleep(spacing)
		}
		sandbox.Close()
	}()

	// Read exactly the bytes sent rather than to EOF: net.Pipe has no CloseWrite,
	// so halfClose cannot signal EOF here. Under the bug the busy direction is
	// aborted at the idle timeout and fewer than chunks bytes arrive.
	server.SetDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, chunks)
	if n, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("forwarded %d of %d bytes: a busy one-way transfer was torn down by the idle timeout: %v", n, chunks, err)
	}
}

// A run cancellation must tear down in-flight tunnels promptly rather than leave
// their goroutines and sockets alive until the idle timeout. idleTimeout stays at
// its default here so the only thing that can end the tunnel is the cancellation.
func TestServeCancelTearsDownTunnel(t *testing.T) {
	// A dialer whose upstream stays open and silent, so the tunnel blocks in both
	// copy loops with no traffic and only cancellation can end it.
	held := make(chan net.Conn, 1)
	p := New([]policy.NetworkRule{{Host: "example.com", Port: "443"}},
		WithDialer(func(context.Context, string, string) (net.Conn, error) {
			c, s := net.Pipe()
			held <- s
			return c, nil
		}))
	dialProxy, stop := startProxy(t, p)
	// Non-blocking: on an early failure the dialer may never run and held is empty,
	// so a plain receive here would hang the test past its Fatal instead of failing.
	t.Cleanup(func() {
		select {
		case c := <-held:
			c.Close()
		default:
		}
	})

	c := dialProxy()
	defer c.Close()
	if status, _ := connect(t, c, "example.com:443"); !strings.Contains(status, "200") {
		stop()
		t.Fatalf("status = %q, want 200", status)
	}

	// stop() cancels Serve's ctx and waits for Serve to return; that only happens
	// once the handler's tunnel goroutines exit, so it stands in for teardown.
	done := make(chan struct{})
	go func() { stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after cancellation; the tunnel was not torn down")
	}
}

// Cancellation must also unblock a handler still parsing the CONNECT request, not
// only an established tunnel: a client that connects and sends nothing otherwise
// pins its slot until connectTimeout, and Serve blocks on it.
func TestServeCancelUnblocksPendingConnect(t *testing.T) {
	p := New([]policy.NetworkRule{{Host: "example.com", Port: "443"}}, WithDialer(fakeDialer("x")))
	dialProxy, stop := startProxy(t, p)

	c := dialProxy()
	defer c.Close()
	// Connect but never send a CONNECT line, so the handler sits in readConnect.
	if _, err := c.Write([]byte("CONNECT ")); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() { stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after cancellation; a pending CONNECT was not interrupted")
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

// A gatekeeper admits a host the static allowlist denies, and the connection
// then tunnels like any allowed host. The observer sees the distinct gate
// decision, not a plain allow, so the run stays honest about the widening.
func TestGatekeeperAdmitsUndeclaredHost(t *testing.T) {
	var seen []string
	p := New(
		[]policy.NetworkRule{{Host: "example.com", Port: "443"}},
		WithDialer(fakeDialer("HELLO")),
		WithGatekeeper(func(context.Context, string, string) bool { return true }),
		WithObserver(func(d Decision, host, port string) { seen = append(seen, string(d)+" "+host) }),
	)
	dialProxy, stop := startProxy(t, p)
	defer stop()

	c := dialProxy()
	defer c.Close()
	status, br := connect(t, c, "undeclared.com:443")
	if !strings.Contains(status, "200") {
		t.Fatalf("status = %q, want 200 (gate admitted the host)", status)
	}
	rest, _ := io.ReadAll(br)
	if !strings.Contains(string(rest), "HELLO") {
		t.Errorf("gate-admitted tunnel did not carry upstream bytes; got %q", rest)
	}
	if len(seen) != 1 || !strings.HasPrefix(seen[0], string(AdmittedByGate)) {
		t.Errorf("observer saw %v, want a single %q decision", seen, AdmittedByGate)
	}
}

// A gatekeeper that declines leaves the declarative behavior intact: the host is
// refused exactly as with no gate.
func TestGatekeeperDenyStillRefused(t *testing.T) {
	p := New(
		[]policy.NetworkRule{{Host: "example.com", Port: "443"}},
		WithDialer(fakeDialer("HELLO")),
		WithGatekeeper(func(context.Context, string, string) bool { return false }),
	)
	dialProxy, stop := startProxy(t, p)
	defer stop()

	c := dialProxy()
	defer c.Close()
	status, _ := connect(t, c, "undeclared.com:443")
	if !strings.Contains(status, "403") {
		t.Fatalf("status = %q, want 403 (gate declined)", status)
	}
}

// Profiling (WithoutEgress) must never consult the gate: the refuse check
// precedes the allowlist check, so a profiling run captures destinations without
// any host's data leaving, gate or not.
func TestGatekeeperNotConsultedWhileProfiling(t *testing.T) {
	consulted := false
	p := New(
		[]policy.NetworkRule{{Host: "*", Port: "*"}},
		WithoutEgress(),
		WithGatekeeper(func(context.Context, string, string) bool { consulted = true; return true }),
	)
	dialProxy, stop := startProxy(t, p)
	defer stop()

	c := dialProxy()
	defer c.Close()
	status, _ := connect(t, c, "example.com:443")
	if !strings.Contains(status, "403") {
		t.Fatalf("status = %q, want 403 (profiling refuses)", status)
	}
	if consulted {
		t.Error("the gate must not be consulted in profiling mode")
	}
}

// A gate can widen to public hosts, but guardUpstream still runs on the dial: a
// gate-admitted hostname that resolves to a private IP with no explicit IP rule
// stays blocked. This uses the real guarded dialer (not WithDialer, which would
// bypass the guard); localhost:9 resolves to loopback and is refused pre-connect.
func TestGatekeeperCannotReachNonPublic(t *testing.T) {
	p := New(
		nil,
		WithGatekeeper(func(context.Context, string, string) bool { return true }),
	)
	dialProxy, stop := startProxy(t, p)
	defer stop()

	c := dialProxy()
	defer c.Close()
	status, br := connect(t, c, "localhost:9")
	if !strings.Contains(status, "403") {
		t.Fatalf("status = %q, want 403 (gate admission cannot reach loopback)", status)
	}
	body, _ := io.ReadAll(br)
	if !strings.Contains(string(body), "non-public") {
		t.Errorf("refusal body should explain the non-public address; got %q", body)
	}
}

// A gate that blocks (a pending human prompt) must return once the run's ctx is
// cancelled, or it pins a handler slot and stalls teardown. The gate contract is
// to watch ctx.Done(); the proxy passes the handler's ctx so it can.
func TestGatekeeperUnblockedByCancel(t *testing.T) {
	p := New(nil, WithGatekeeper(func(ctx context.Context, _, _ string) bool {
		<-ctx.Done() // block as a human prompt would, until the run ends
		return false
	}))
	dialProxy, stop := startProxy(t, p)

	c := dialProxy()
	defer c.Close()
	// Send a full CONNECT so the handler reaches the gate and blocks there.
	fmt.Fprintf(c, "CONNECT undeclared.com:443 HTTP/1.1\r\n\r\n")

	done := make(chan struct{})
	go func() { stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after cancellation; a gate blocked in a prompt was not interrupted")
	}
}

// A panicking embedder gate must fail loudly-as-deny: handle's own recover would
// otherwise drop the connection with no 403 and no report(), a silent failure.
func TestGatekeeperPanicIsDeny(t *testing.T) {
	var seen []string
	p := New(
		nil,
		WithGatekeeper(func(context.Context, string, string) bool { panic("embedder gate blew up") }),
		WithObserver(func(d Decision, host, port string) { seen = append(seen, string(d)+" "+host) }),
	)
	dialProxy, stop := startProxy(t, p)
	defer stop()

	c := dialProxy()
	defer c.Close()
	status, _ := connect(t, c, "undeclared.com:443")
	if !strings.Contains(status, "403") {
		t.Fatalf("status = %q, want 403 (a panicking gate denies)", status)
	}
	if len(seen) != 1 || !strings.HasPrefix(seen[0], string(Denied)) {
		t.Errorf("observer saw %v, want a single deny", seen)
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
