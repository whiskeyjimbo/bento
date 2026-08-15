package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/whiskeyjimbo/bento/policy"
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
	go func() { _ = p.Serve(ctx, l); close(done) }()

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

// A CONNECT target carrying a deceiving character is a crafted attempt to mislead the
// host-side egress log (the host flows into report() and the 403 body) and every other
// consumer of the recorded host. readConnect must refuse it at entry rather than pass
// it through: a control byte reprograms the terminal, a bidi override reorders the
// display, a zero-width character hides a segment, and a raw 8-bit C1 is a CSI some
// terminals honor directly while decoding as RuneError rather than as its code point.
func TestReadConnectRejectsDeceivingTarget(t *testing.T) {
	for _, tc := range []struct{ target, want string }{
		{"ex\x1bample.com:443", "a control character"},
		{"example.com:4\x0043", "a control character"},
		{"host\x07:443", "a control character"},
		{"ex\u202eample.com:443", "a bidirectional formatting character"},
		{"ex\u200bample.com:443", "a zero-width or invisible character"},
		{"ex\U000E0041ample.com:443", "a zero-width or invisible character"},
		{"ex\u009bample.com:443", "a control character"},
		{"ex\x9bample.com:443", "invalid UTF-8"},
	} {
		client, server := net.Pipe()
		go func() {
			fmt.Fprintf(client, "CONNECT %s HTTP/1.1\r\n\r\n", tc.target)
		}()
		_, _, _, err := readConnect(server)
		client.Close()
		server.Close()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("target %q: expected a rejection naming %q; got %v", tc.target, tc.want, err)
		}
	}
}

// acceptErr wraps errno the way a real net.Listener does - *net.OpError around an
// *os.SyscallError around the errno - so a test exercises the unwrapping recoverableAccept
// actually has to do. A bare errno would pass an equality check that production never sees.
func acceptErr(errno syscall.Errno) error {
	return &net.OpError{Op: "accept", Net: "unix", Err: os.NewSyscallError("accept", errno)}
}

// flakyListener wraps a listener and makes the first n Accept calls fail with err, so a
// transient host condition can be reproduced without one: ENFILE is caused by processes
// outside bento and cannot be provoked from a test.
type flakyListener struct {
	net.Listener
	mu        sync.Mutex
	remaining int
	err       error
	failures  int
}

func (l *flakyListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.remaining > 0 {
		l.remaining--
		l.failures++
		l.mu.Unlock()
		return nil, l.err
	}
	l.mu.Unlock()
	return l.Listener.Accept()
}

func (l *flakyListener) failed() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.failures
}

// The egress fence has to outlive a transient Accept failure. The host can hit ENFILE for
// a moment because of processes bento knows nothing about; if that ended Serve, the unix
// socket would stay bind-mounted into the sandbox with nothing behind it, and every later
// CONNECT would meet a dead socket rather than an allowlist decision - the run's egress
// silently unenforced-by-absence for its whole remaining lifetime.
func TestServeSurvivesATransientAcceptError(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ENFILE, syscall.EMFILE, syscall.ECONNABORTED, syscall.ENOMEM, syscall.ENOBUFS} {
		dir := t.TempDir()
		sock := dir + "/proxy.sock"
		base, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		l := &flakyListener{Listener: base, remaining: 3, err: acceptErr(errno)}

		p := New([]policy.NetworkRule{{Host: "example.com", Port: "443"}}, WithDialer(fakeDialer("HELLO")))
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- p.Serve(ctx, l) }()

		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatalf("%v: dialing the proxy after a transient Accept error: %v", errno, err)
		}
		status, _ := connect(t, c, "example.com:443")
		c.Close()
		cancel()

		if !strings.Contains(status, "200") {
			t.Errorf("%v: status = %q, want 200 - the fence stopped serving after a recoverable error", errno, status)
		}
		if l.failed() != 3 {
			t.Errorf("%v: listener failed %d times, want 3 - the test did not exercise the retry", errno, l.failed())
		}
		if err := <-done; err != nil {
			t.Errorf("%v: Serve = %v, want nil - the run ended cleanly", errno, err)
		}
	}
}

// The retry must not swallow the failure that ends the run: the closer goroutine ends
// Serve by closing the listener, so treating net.ErrClosed as recoverable would spin
// through teardown instead of returning.
func TestServeStopsOnAClosedListener(t *testing.T) {
	dir := t.TempDir()
	base, err := net.Listen("unix", dir+"/proxy.sock")
	if err != nil {
		t.Fatal(err)
	}
	p := New(nil, WithDialer(fakeDialer("HELLO")))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Serve(ctx, base) }()
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve = %v, want nil on a cancelled run", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return after cancellation; a closed listener is being retried")
	}
}

// An unrecoverable Accept error still ends Serve and is still reported, so the caller can
// mark the run degraded. The retry narrows what counts as terminal; it does not remove it.
func TestServeStillReportsAFatalAcceptError(t *testing.T) {
	dir := t.TempDir()
	base, err := net.Listen("unix", dir+"/proxy.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	l := &flakyListener{Listener: base, remaining: 1, err: acceptErr(syscall.EINVAL)}

	p := New(nil, WithDialer(fakeDialer("HELLO")))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := p.Serve(ctx, l); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("Serve = %v, want the EINVAL that stopped it", err)
	}
}

// The two refusals of an undeclared destination call for different operator action, and
// this frame is the only one that can tell them apart: downstream sees one destination
// and one verdict. Reporting a gate's "no" as an allowlist denial tells the human who
// just answered the prompt that their manifest is missing a rule.
func TestGateDenialIsReportedApartFromAllowlistDenial(t *testing.T) {
	for _, tc := range []struct {
		name string
		gate func(context.Context, string, string) bool
		want Decision
	}{
		{"no gate at all", nil, Denied},
		{"a gate that refuses", func(context.Context, string, string) bool { return false }, GateDenied},
	} {
		var got []Decision
		opts := []Option{WithDialer(fakeDialer("HELLO")),
			WithObserver(func(d Decision, _, _ string) { got = append(got, d) })}
		if tc.gate != nil {
			opts = append(opts, WithGatekeeper(tc.gate))
		}
		p := New(nil, opts...)
		dialProxy, stop := startProxy(t, p)
		c := dialProxy()
		status, _ := connect(t, c, "example.com:443")
		c.Close()
		stop()

		if !strings.Contains(status, "403") {
			t.Errorf("%s: status = %q, want 403", tc.name, status)
		}
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("%s: decisions = %v, want exactly [%v]", tc.name, got, tc.want)
		}
	}
}

// A supervised run with an empty network: block is the documented prompt-on-every-host
// mode, so every refusal in it is the operator's own - nothing there is refused by an
// allowlist that has no rules to refuse with.
func TestGatedRunWithNoRulesNeverReportsAnAllowlistDenial(t *testing.T) {
	var got []Decision
	p := New(nil,
		WithDialer(fakeDialer("HELLO")),
		WithGatekeeper(func(_ context.Context, host, _ string) bool { return host == "ok.example" }),
		WithObserver(func(d Decision, _, _ string) { got = append(got, d) }))
	dialProxy, stop := startProxy(t, p)
	for _, target := range []string{"ok.example:443", "no.example:443"} {
		c := dialProxy()
		connect(t, c, target)
		c.Close()
	}
	stop()

	want := []Decision{AdmittedByGate, GateDenied}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("decisions = %v, want %v", got, want)
	}
}

// A client speaking plain http:// through a proxy sends an absolute-URI request rather
// than a CONNECT. The proxy tunnels CONNECT only, so the request is refused - but the
// destination it named must reach the observer, or a manifest rule covering that host
// reads as granted everywhere while carrying no traffic and nothing in the run says so.
func TestUntunneledRequestReportsItsDestination(t *testing.T) {
	for _, tc := range []struct{ line, host, port string }{
		{"GET http://example.com/ HTTP/1.1", "example.com", "80"},
		{"POST http://example.com:8080/x HTTP/1.1", "example.com", "8080"},
		{"GET https://example.com/ HTTP/1.1", "example.com", "443"},
		{"GET http://[2606:2800::1]/ HTTP/1.1", "2606:2800::1", "80"},
		// The root label is stripped here as it is on the CONNECT path, so the reported
		// destination matches the rule a user would write for it.
		{"GET http://example.com./ HTTP/1.1", "example.com", "80"},
	} {
		var got []Decision
		var gotHost, gotPort string
		p := New([]policy.NetworkRule{{Host: "example.com", Port: "80"}},
			WithDialer(fakeDialer("HELLO")),
			WithObserver(func(d Decision, host, port string) {
				got = append(got, d)
				gotHost, gotPort = host, port
			}))
		dialProxy, stop := startProxy(t, p)
		c := dialProxy()
		fmt.Fprintf(c, "%s\r\nHost: example.com\r\n\r\n", tc.line)
		status, _ := bufio.NewReader(c).ReadString('\n')
		c.Close()
		stop()

		if !strings.Contains(status, "400") {
			t.Errorf("%q: status = %q, want 400", tc.line, strings.TrimSpace(status))
		}
		if len(got) != 1 || got[0] != Untunneled {
			t.Errorf("%q: decisions = %v, want exactly [%v]", tc.line, got, Untunneled)
		}
		if gotHost != tc.host || gotPort != tc.port {
			t.Errorf("%q: reported %q:%q, want %q:%q", tc.line, gotHost, gotPort, tc.host, tc.port)
		}
	}
}

// The absolute-URI host reaches report(), the run's recorded destinations, and a
// host-side render of them - exactly where a CONNECT target goes, so it gets exactly the
// screen a CONNECT target gets. A target that fails it is still refused, and is reported
// as the bare Refused every unparseable request line gets, rather than carrying an
// unscreened destination onward under Untunneled.
func TestUntunneledRequestScreensItsDestination(t *testing.T) {
	for _, target := range []string{
		"http://ex\x1bample.com/",
		"http://ex\u202eample.com/",
		"http://example.com:08080/",
		"ftp://example.com/",
		"/relative/path",
	} {
		var got []Decision
		var gotHost, gotPort string
		p := New(nil, WithDialer(fakeDialer("HELLO")),
			WithObserver(func(d Decision, host, port string) {
				got = append(got, d)
				gotHost, gotPort = host, port
			}))
		dialProxy, stop := startProxy(t, p)
		c := dialProxy()
		fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", target)
		status, _ := bufio.NewReader(c).ReadString('\n')
		c.Close()
		stop()

		if !strings.Contains(status, "400") {
			t.Errorf("%q: status = %q, want 400", target, strings.TrimSpace(status))
		}
		if len(got) != 1 || got[0] != Refused {
			t.Errorf("%q: decisions = %v, want exactly [%v]", target, got, Refused)
		}
		if gotHost != "" || gotPort != "" {
			t.Errorf("%q: reported %q:%q, want no destination - an unscreened one must not be carried", target, gotHost, gotPort)
		}
	}
}

// Profiling refuses every CONNECT it records, but a non-CONNECT request dies before that
// branch is reached - which is why a plain-HTTP destination was silently absent from the
// proposal. The report has to happen on the read path, in either mode.
func TestUntunneledRequestIsReportedWhileProfiling(t *testing.T) {
	var got []Decision
	p := New(nil, WithoutEgress(),
		WithObserver(func(d Decision, _, _ string) { got = append(got, d) }))
	dialProxy, stop := startProxy(t, p)
	c := dialProxy()
	fmt.Fprint(c, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if _, err := bufio.NewReader(c).ReadString('\n'); err != nil {
		t.Fatalf("reading status: %v", err)
	}
	c.Close()
	stop()

	if len(got) != 1 || got[0] != Untunneled {
		t.Errorf("decisions = %v, want exactly [%v]", got, Untunneled)
	}
}

// A port the dialer will silently renumber ("08080" becomes 8080) or reject
// outright ("0x1f90") must not reach the allowlist: Allows would see the raw
// spelling while guardUpstream sees the resolved one, so the two layers would
// judge different ports on the same connection.
func TestReadConnectRejectsNonCanonicalPort(t *testing.T) {
	for _, target := range []string{"example.com:08080", "example.com:0x1f90", "example.com:", "example.com:65536", "example.com:000443", "example.com:0"} {
		client, server := net.Pipe()
		go func() {
			fmt.Fprintf(client, "CONNECT %s HTTP/1.1\r\n\r\n", target)
		}()
		_, _, _, err := readConnect(server)
		client.Close()
		server.Close()
		if err == nil || !strings.Contains(err.Error(), "malformed target port") {
			t.Errorf("target %q: expected a malformed-port rejection; got %v", target, err)
		}
	}
}

// A range rule parses its target numerically, so "08080" satisfies 8000-9000 while
// the equivalent single-port rule (a string compare) refuses it. Admitting either
// would tunnel a connection whose port the allowlist and the egress guard spell
// differently, so the proxy must refuse the target outright.
func TestNonCanonicalPortNeverTunnels(t *testing.T) {
	for _, rule := range []policy.NetworkRule{{Host: "example.com", Port: "8000-9000"}, {Host: "example.com", Port: "8080"}} {
		p := New([]policy.NetworkRule{rule}, WithDialer(fakeDialer("HELLO")))
		dialProxy, stop := startProxy(t, p)

		c := dialProxy()
		status, _ := connect(t, c, "example.com:08080")
		if !strings.Contains(status, "400") {
			t.Errorf("rule %+v: status = %q for port 08080, want 400", rule, status)
		}
		c.Close()
		stop()
	}
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

// A hostname rule must not be satisfiable by dialing the address that hostname
// resolves to. The allowlist matches the CONNECT authority as a string, so a target
// naming the IP is a different target than the rule's name - otherwise anyone who
// resolved an allowlisted name once could reach any host sharing that address (shared
// CDN/reverse-proxy IPs), and a rule scoped to one name would silently widen to every
// site behind it. Both an apex rule and a subdomain-suffix rule are pinned, because the
// suffix form is the one a reader is most likely to assume is address-based.
func TestIPLiteralDoesNotSatisfyHostnameRule(t *testing.T) {
	for name, rule := range map[string]policy.NetworkRule{
		"literal host rule":  {Host: "example.com", Port: "443"},
		"suffix host rule":   {Host: ".example.com", Port: "443"},
		"wildcard port rule": {Host: "example.com", Port: "*"},
	} {
		t.Run(name, func(t *testing.T) {
			p := New([]policy.NetworkRule{rule}, WithDialer(fakeDialer("HELLO")))
			dialProxy, stop := startProxy(t, p)
			defer stop()

			c := dialProxy()
			defer c.Close()
			// 93.184.216.34 was example.com's public address; an attacker who resolved
			// the name offline would dial exactly this.
			status, _ := connect(t, c, "93.184.216.34:443")
			if !strings.Contains(status, "403") {
				t.Errorf("an IP literal satisfied the hostname rule %+v: status = %q, want 403", rule, status)
			}
		})
	}

	// Positive control: the same IP literal IS reachable when a rule names the address
	// itself. Without this the denials above would also pass if the proxy rejected every
	// IP-literal target for some unrelated reason, which would prove nothing about the
	// name-versus-address distinction this test exists to pin.
	t.Run("explicit IP rule admits it", func(t *testing.T) {
		p := New([]policy.NetworkRule{{Host: "93.184.216.34", Port: "443"}}, WithDialer(fakeDialer("HELLO")))
		dialProxy, stop := startProxy(t, p)
		defer stop()

		c := dialProxy()
		defer c.Close()
		status, _ := connect(t, c, "93.184.216.34:443")
		if !strings.Contains(status, "200") {
			t.Fatalf("an explicit IP rule must admit its own address: status = %q, want 200", status)
		}
	})
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
	var mu sync.Mutex
	var refused int
	p := New([]policy.NetworkRule{{Host: "example.com", Port: "443"}},
		WithDialer(func(context.Context, string, string) (net.Conn, error) {
			<-block
			return nil, fmt.Errorf("test dialer unblocked")
		}),
		WithObserver(func(d Decision, host, port string) {
			if d != Refused {
				return
			}
			mu.Lock()
			refused++
			mu.Unlock()
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
	// The refusal must reach the observer, or a run that floods the proxy is reported
	// as one that never attempted egress at all.
	mu.Lock()
	defer mu.Unlock()
	if refused == 0 {
		t.Error("a connection refused at capacity must be reported to the observer")
	}
}

// The observer is embedder code, and a Refused decision is reported from Serve's
// own accept goroutine - so a panic there would take the whole bento process down
// rather than end one connection. The accept loop must survive it and keep
// refusing.
func TestObserverPanicOnRefusedDoesNotKillServe(t *testing.T) {
	block := make(chan struct{})
	p := New([]policy.NetworkRule{{Host: "example.com", Port: "443"}},
		WithDialer(func(context.Context, string, string) (net.Conn, error) {
			<-block
			return nil, fmt.Errorf("test dialer unblocked")
		}),
		WithObserver(func(Decision, string, string) { panic("embedder observer blew up") }))
	dialProxy, stop := startProxy(t, p)
	defer func() { close(block); stop() }()

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

	// Two over-cap connections: the first drives the panicking report, the second
	// shows the accept loop is still there to refuse it.
	for i := range 2 {
		over := dialProxy()
		defer over.Close()
		fmt.Fprintf(over, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
		over.SetReadDeadline(time.Now().Add(3 * time.Second))
		status, err := bufio.NewReader(over).ReadString('\n')
		if err != nil {
			t.Fatalf("over-cap connection %d got no status: %v", i, err)
		}
		if !strings.Contains(status, "503") {
			t.Errorf("over-cap connection %d: status = %q, want 503", i, status)
		}
	}
}

// A panicking observer must not cost the connection it reports either. handle's
// blanket recover would otherwise swallow the panic into a dropped connection with
// no status line at all, which is neither an allow nor a deny.
func TestObserverPanicDoesNotDropTheConnection(t *testing.T) {
	p := New([]policy.NetworkRule{{Host: "example.com", Port: "443"}},
		WithDialer(fakeDialer("tunnel")),
		WithObserver(func(Decision, string, string) { panic("embedder observer blew up") }))
	dialProxy, stop := startProxy(t, p)
	defer stop()

	c := dialProxy()
	defer c.Close()
	status, br := connect(t, c, "example.com:443")
	if !strings.Contains(status, "200") {
		t.Fatalf("status = %q, want 200 - a faulty observer must not deny an allowed host", status)
	}
	if _, err := br.ReadString('\n'); err != nil { // the blank line closing the 200
		t.Fatalf("reading the response terminator: %v", err)
	}
	banner := make([]byte, len("tunnel"))
	if _, err := io.ReadFull(br, banner); err != nil {
		t.Fatalf("reading the tunnel after an observer panic: %v", err)
	}
	if string(banner) != "tunnel" {
		t.Errorf("tunnel carried %q, want the upstream banner", banner)
	}
}

// A panic before the tunnel is established answers the client with a status line, like
// every other outcome the handler can reach. Left bare, the connection just closes and
// the target reads a proxy fault as a network hiccup and retries into it.
//
// The fault is reported too, for the reason report() and callGate() each recover under
// a named outcome: a connection the proxy dropped without reaching an allowlist
// decision is the one thing the run record must not show as nothing having happened.
// Faulted carries no destination even here, where the panic landed after the CONNECT
// was read, because it must also describe a panic that landed before one was.
func TestPanicBeforeTheTunnelAnswersWithAStatus(t *testing.T) {
	var seen []Decision
	p := New([]policy.NetworkRule{{Host: "*", Port: "*"}},
		WithObserver(func(d Decision, _, _ string) { seen = append(seen, d) }),
		WithDialer(func(context.Context, string, string) (net.Conn, error) { panic("dialer blew up") }))
	dialProxy, stop := startProxy(t, p)
	defer stop()

	c := dialProxy()
	defer c.Close()
	status, _ := connect(t, c, "example.com:443")
	if !strings.Contains(status, "502") {
		t.Errorf("status = %q, want 502 after a panic in the handler", status)
	}
	// The status is written after the report, so reading it orders this against the
	// handler.
	if !slices.Contains(seen, Faulted) {
		t.Errorf("decisions = %v, want a Faulted among them", seen)
	}
}

// A listener that stops accepting on its own kills the egress fence for the rest of
// the run, so Serve must hand that error back rather than return as if the run had
// ended it. Only a caller-cancelled Serve returns nil.
func TestServeReturnsTerminalAcceptError(t *testing.T) {
	want := fmt.Errorf("listener is gone")
	l := &deadListener{err: want}
	p := New([]policy.NetworkRule{{Host: "example.com", Port: "443"}}, WithDialer(fakeDialer("x")))
	if err := p.Serve(context.Background(), l); !errors.Is(err, want) {
		t.Errorf("Serve() = %v, want the listener's terminal error %v", err, want)
	}
}

// The terminal Accept error survives the handler drain. An open tunnel holds
// wg.Wait until the run is cancelled, so reading "did the run end?" after the drain
// would find every mid-run listener death cancelled and report a clean end - and
// noteDeadListener would leave LayerNetwork Enforced for a run whose egress fence
// was gone from the moment the tunnel opened.
func TestServeReturnsAcceptErrorThatPrecededCancellation(t *testing.T) {
	dir := t.TempDir()
	real, err := net.Listen("unix", dir+"/proxy.sock")
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Errorf("listener is gone")
	l := &dyingListener{Listener: real, err: want, died: make(chan struct{})}

	// An upstream that stays open, so the handler is still in the tunnel - and still
	// counted by wg - when the listener dies.
	held, upstream := net.Pipe()
	defer upstream.Close()
	p := New([]policy.NetworkRule{{Host: "example.com", Port: "443"}},
		WithDialer(func(context.Context, string, string) (net.Conn, error) { return held, nil }))

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- p.Serve(ctx, l) }()

	c, err := net.Dial("unix", dir+"/proxy.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if status, _ := connect(t, c, "example.com:443"); !strings.Contains(status, "200") {
		t.Fatalf("status = %q, want the tunnel established", status)
	}
	// The tunnel is up; wait for the listener to have failed on its own before ending the
	// run, so the two orderings this test distinguishes are staged rather than timed. A
	// cancel that beats the accept error makes Serve report a clean end and the assertion
	// below fails for the wrong reason.
	<-l.died
	cancel()
	if err := <-served; !errors.Is(err, want) {
		t.Errorf("Serve() = %v, want the listener's terminal error %v", err, want)
	}
}

// dyingListener delegates the first Accept and then fails on its own, standing in
// for a listener that stops accepting mid-run.
// died is closed as the terminal error is handed back, so a caller can order its own
// teardown after the death instead of guessing at it. The once is for the accept loop
// asking a second time, which it does when the caller does not stop on the first error.
type dyingListener struct {
	net.Listener
	err      error
	accepted bool
	died     chan struct{}
	dies     sync.Once
}

func (l *dyingListener) Accept() (net.Conn, error) {
	if l.accepted {
		l.dies.Do(func() { close(l.died) })
		return nil, l.err
	}
	l.accepted = true
	return l.Listener.Accept()
}

// NAT64 discovery writes p.nat64 with no lock, safe only because it runs before any
// handler exists. A second Serve on the same *Proxy would rewrite it while the first
// Serve's tunnels are classifying against it, so re-entry must be refused before
// discovery runs at all.
func TestSecondServeIsRefusedBeforeItRewritesDiscovery(t *testing.T) {
	calls := 0
	lookup := func(context.Context) ([]net.IP, error) {
		calls++
		if calls == 1 {
			return []net.IP{net.ParseIP("2001:db8:1:2:3:4:c000:aa")}, nil // /96 site prefix
		}
		return []net.IP{net.ParseIP("2001:db8:aaaa:bbbb::c000:aa")}, nil // a different prefix
	}
	p := New(egressRules, WithNAT64Discovery(lookup), WithDialer(fakeDialer("x")))
	if err := p.Serve(context.Background(), &deadListener{err: fmt.Errorf("listener is gone")}); err == nil {
		t.Fatal("first Serve should return the listener's terminal error")
	}
	first := p.nat64

	err := p.Serve(context.Background(), &deadListener{err: fmt.Errorf("listener is gone")})
	if err == nil {
		t.Error("a second Serve on the same Proxy must be refused, not served")
	}
	if calls != 1 {
		t.Errorf("discovery ran %d times; a refused Serve must not re-run it", calls)
	}
	if len(p.nat64) != len(first) || (len(first) > 0 && p.nat64[0] != first[0]) {
		t.Errorf("nat64 = %+v after the refused Serve, want the first Serve's %+v", p.nat64, first)
	}
}

// deadListener fails every Accept, standing in for a listener whose socket has been
// removed or whose fd was closed out from under the proxy.
type deadListener struct {
	err error
}

func (d *deadListener) Accept() (net.Conn, error) { return nil, d.err }
func (d *deadListener) Close() error              { return nil }
func (d *deadListener) Addr() net.Addr            { return &net.UnixAddr{Name: "dead", Net: "unix"} }

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
		_, _ = io.WriteString(c, junk)
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
	// tunnel writes client->upstream and upstream->client; the test feeds the
	// client side and drains the upstream side, leaving the upstream->client
	// direction permanently silent.
	sandbox, clientConn := net.Pipe()
	upstreamConn, server := net.Pipe()
	defer sandbox.Close()
	defer server.Close()
	go tunnel(clientConn, clientConn, upstreamConn, 200*time.Millisecond)

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
			"0.1.2.3",                      // this-network 0.0.0.0/8 beyond 0.0.0.0 itself
			"198.18.0.1", "198.19.255.255", // RFC 2544 benchmarking 198.18.0.0/15
			"240.0.0.1", "255.255.255.254", // reserved 240.0.0.0/4
			"255.255.255.255",    // limited broadcast (within 240/4)
			"64:ff9b::a9fe:a9fe", // NAT64 of 169.254.169.254 (metadata)
			"64:ff9b::7f00:1",    // NAT64 of 127.0.0.1
			"64:ff9b::c612:1",    // NAT64 of 198.18.0.1 (benchmarking)
			"ff05::1", "ff0e::1", // site-local and global multicast
			"::a9fe:a9fe",        // IPv4-compatible ::169.254.169.254 (metadata)
			"fec0::1", "feff::1", // deprecated IPv6 site-local fec0::/10 (RFC 3879)
		},
		// Reachable only via an explicit IP-literal rule.
		ipPrivate: {
			"10.0.0.5", "172.16.0.1", "192.168.1.1", "fc00::1", // RFC1918 / ULA
			"100.64.0.1", "100.127.255.255", // CGNAT
			"64:ff9b::a00:5",    // NAT64 of 10.0.0.5
			"2002:0a00:0005::1", // 6to4 embedding 10.0.0.5
			"::0a00:0005",       // IPv4-compatible ::10.0.0.5
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
	var decision Decision
	p := New([]policy.NetworkRule{{Host: "localhost", Port: "9"}},
		WithObserver(func(d Decision, _, _ string) { decision = d }))
	dialProxy, stop := startProxy(t, p)
	defer stop()

	c := dialProxy()
	defer c.Close()
	status, br := connect(t, c, "localhost:9")
	if !strings.Contains(status, "502") {
		t.Fatalf("status = %q, want 502 (localhost resolves to loopback)", status)
	}
	// The status alone cannot carry this: nothing listens on port 9 either, so a
	// removed guard would answer with the same 502 and the test would pass over a
	// hole. The guard's verdict is only visible on the host side.
	if decision != GuardBlocked {
		t.Errorf("observer reported %q, want %q - the guard did not refuse this dial", decision, GuardBlocked)
	}
	body, _ := io.ReadAll(br)
	// The refusal must not answer the query it refused: naming the resolved address
	// would let a confined process enumerate the host's DNS one denial at a time.
	if strings.Contains(string(body), "127.0.0.1") {
		t.Errorf("refusal body discloses the resolved address; got %q", body)
	}
}

// Refusing the guard's block distinctly from an ordinary dial failure was itself an
// oracle: under a permissive allowlist - `bento profile --allow-network` runs *:* -
// a confined process could walk arbitrary names and classify each one as
// private-resolving or not, one CONNECT at a time. The two answers must be the same
// bytes. The host keeps the distinction; only the sandbox loses it.
func TestGuardRefusalIsIndistinguishableFromDialFailure(t *testing.T) {
	var p *Proxy
	var decisions sync.Map
	p = New([]policy.NetworkRule{{Host: "*", Port: "*"}},
		WithObserver(func(d Decision, host, _ string) { decisions.Store(host, d) }),
		WithDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, _ := net.SplitHostPort(addr)
			// Both names resolve; only one lands in private space.
			if host == "private.example.com" {
				host = "10.0.0.5"
			} else {
				host = "8.8.8.8"
			}
			if err := p.guardUpstream(ctx, network, net.JoinHostPort(host, port), nil); err != nil {
				return nil, err
			}
			return nil, &net.OpError{Op: "dial", Net: network, Addr: fakeAddr(addr), Err: errors.New("connection refused")}
		}))
	dialProxy, stop := startProxy(t, p)
	defer stop()

	answer := func(target string) string {
		c := dialProxy()
		defer c.Close()
		status, br := connect(t, c, target)
		body, _ := io.ReadAll(br)
		return status + "\n" + string(body)
	}
	// The same host:port in both, so any difference is the verdict and not the name.
	blocked := answer("private.example.com:443")
	failed := strings.ReplaceAll(answer("public.example.com:443"), "public.", "private.")
	if blocked != failed {
		t.Errorf("a guard block answers %q but a dial failure answers %q; the split classifies the name for the sandbox", blocked, failed)
	}
	if d, _ := decisions.Load("private.example.com"); d != GuardBlocked {
		t.Errorf("observer reported %v for the guard-blocked host, want %q - the host must keep the distinction the sandbox lost", d, GuardBlocked)
	}
	if d, _ := decisions.Load("public.example.com"); d != Allowed {
		t.Errorf("observer reported %v for the ordinary dial failure, want %q", d, Allowed)
	}
}

// A name resolving to several addresses keeps the guard's signal even though the error
// it returns belongs to another address. net.Dialer tries each in turn and returns the
// FIRST one's error, so for [dead-timeout, 10.0.0.1] the blockedUpstreamError raised on
// the second address never reaches handle - and the operator would be told the
// connection was allowed, for a connection that reached nothing.
func TestGuardBlockSurvivesAnotherAddressesError(t *testing.T) {
	var p *Proxy
	var decision Decision
	done := make(chan struct{})
	p = New([]policy.NetworkRule{{Host: "*", Port: "*"}},
		WithObserver(func(d Decision, _, _ string) { decision = d; close(done) }),
		WithDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
			// The dialer's own shape: every address is guarded, the first one's error wins.
			first := &net.OpError{Op: "dial", Net: network, Addr: fakeAddr("192.0.2.1:443"), Err: errors.New("i/o timeout")}
			_ = p.guardUpstream(ctx, network, "192.0.2.1:443", nil)
			_ = p.guardUpstream(ctx, network, "10.0.0.1:443", nil)
			return nil, first
		}))
	dialProxy, stop := startProxy(t, p)
	defer stop()

	c := dialProxy()
	defer c.Close()
	connect(t, c, "twofaced.example.com:443")
	<-done
	if decision != GuardBlocked {
		t.Errorf("observer reported %q, want %q - the guard refused an address and only the report says so", decision, GuardBlocked)
	}
}

// A dial that fails for an ordinary reason must not report the address it tried:
// *net.OpError names the resolved peer, which is the same disclosure the refusal
// path avoids, reached through the 502 instead.
func TestDialFailureBodyHidesResolvedAddress(t *testing.T) {
	p := New([]policy.NetworkRule{{Host: "internal.example", Port: "443"}},
		WithDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, &net.OpError{Op: "dial", Net: network, Addr: fakeAddr("10.0.0.5:443"), Err: errors.New("connection refused")}
		}))
	dialProxy, stop := startProxy(t, p)
	defer stop()

	c := dialProxy()
	defer c.Close()
	status, br := connect(t, c, "internal.example:443")
	if !strings.Contains(status, "502") {
		t.Fatalf("status = %q, want 502", status)
	}
	body, _ := io.ReadAll(br)
	if strings.Contains(string(body), "10.0.0.5") {
		t.Errorf("dial-failure body discloses the resolved address; got %q", body)
	}
}

// fakeAddr stands in for the resolved peer a *net.OpError carries.
type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

// The proxy runs on the host, so dialing loopback reaches the HOST's loopback
// services. An explicit loopback rule must NOT reach them - loopback is never
// exempt - so validate's warning that loopback rules cannot reach the host holds.
func TestExplicitLoopbackRuleStillBlocked(t *testing.T) {
	var decision Decision
	p := New([]policy.NetworkRule{{Host: "127.0.0.1", Port: "6379"}},
		WithObserver(func(d Decision, _, _ string) { decision = d }))
	dialProxy, stop := startProxy(t, p)
	defer stop()

	c := dialProxy()
	defer c.Close()
	status, _ := connect(t, c, "127.0.0.1:6379")
	// 502: the guard answers exactly as a dial failure does, so the block shows on
	// the host side, not in a distinct status. Asserting only the status would make
	// the verdict environment-dependent - it would pass over a removed guard on a
	// machine with nothing on 6379, and fail with a 200 on one running redis.
	if !strings.Contains(status, "502") {
		t.Fatalf("status = %q, want 502 (an explicit loopback rule must not reach the host)", status)
	}
	if decision != GuardBlocked {
		t.Errorf("observer reported %q, want %q - the guard did not refuse this dial", decision, GuardBlocked)
	}
}

// The private-IP exemption belongs to the connection whose CONNECT target named
// the literal, not to the rule set as a whole. Listing 10.0.0.5 must not also let
// a hostname or wildcard rule reach it through hostile DNS - the resolved address
// alone cannot tell the two apart, so the grant has to come from the CONNECT.
//
// Resolution is faked by the dialer (the guard's verdict is still the production
// one, as in the concurrency test) because the point is a name resolving somewhere
// its own rule never named.
func TestPrivateIPExemptionRequiresLiteralTarget(t *testing.T) {
	cases := []struct {
		name    string
		rules   []policy.NetworkRule
		connect string
		// resolved is what the CONNECT host resolves to; empty means it is a literal
		// the dialer passes through unchanged.
		resolved string
		want     string
	}{
		{
			name:     "hostname rule resolving onto another rule's literal",
			rules:    []policy.NetworkRule{{Host: ".example.com", Port: "*"}, {Host: "10.0.0.5", Port: "443"}},
			connect:  "x.example.com:443",
			resolved: "10.0.0.5",
			want:     "502",
		},
		{
			name:    "the literal's own rule",
			rules:   []policy.NetworkRule{{Host: ".example.com", Port: "*"}, {Host: "10.0.0.5", Port: "443"}},
			connect: "10.0.0.5:443",
			want:    "200",
		},
		{
			// The DNS root label passes policy.Allows (normalizeHost strips it) but is not
			// an address, so an unstripped target would lose the grant its own rule gives
			// and the rule would be silently inert in that spelling.
			name:    "the literal's own rule, spelled with a trailing dot",
			rules:   []policy.NetworkRule{{Host: "10.0.0.5", Port: "443"}},
			connect: "10.0.0.5.:443",
			want:    "200",
		},
		{
			name:    "wildcard rule matching a literal target",
			rules:   []policy.NetworkRule{{Host: "*", Port: "*"}},
			connect: "10.0.0.5:443",
			want:    "502",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var p *Proxy
			p = New(tc.rules, WithDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				if tc.resolved != "" {
					host = tc.resolved
				}
				if err := p.guardUpstream(ctx, network, net.JoinHostPort(host, port), nil); err != nil {
					return nil, err
				}
				return fakeDialer("tunnel")(ctx, network, addr)
			}))
			dialProxy, stop := startProxy(t, p)
			defer stop()

			c := dialProxy()
			defer c.Close()
			status, _ := connect(t, c, tc.connect)
			if !strings.Contains(status, tc.want) {
				t.Errorf("CONNECT %s: status = %q, want %s", tc.connect, status, tc.want)
			}
		})
	}
}

// handle withholds the literal grant from a gate-admitted connection, and that
// guard is not redundant with the gate having been consulted at all: the allowlist
// matches the CONNECT host textually while literalGrantFor matches by address, so
// a v4-mapped spelling of a rule's own literal misses the rule, reaches the gate,
// and would carry a grant into private space if the grant were derived after
// admission. A gate yes must never reach anywhere the guard would otherwise block.
func TestGateAdmissionCarriesNoLiteralGrant(t *testing.T) {
	var p *Proxy
	p = New([]policy.NetworkRule{{Host: "10.0.0.5", Port: "443"}},
		WithGatekeeper(func(context.Context, string, string) bool { return true }),
		WithDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
			if err := p.guardUpstream(ctx, network, addr, nil); err != nil {
				return nil, err
			}
			return fakeDialer("tunnel")(ctx, network, addr)
		}))
	dialProxy, stop := startProxy(t, p)
	defer stop()

	c := dialProxy()
	defer c.Close()
	status, _ := connect(t, c, "[::ffff:10.0.0.5]:443")
	if !strings.Contains(status, "502") {
		t.Errorf("status = %q, want 502 - a gate admission must not inherit the rule's literal grant", status)
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
	var blk *blockedUpstreamError
	if !errors.As(err, &blk) {
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
// gate-admitted hostname that resolves to a non-public address stays blocked - a
// gate admission means no rule matched, so it carries no literal grant either.
// This uses the real guarded dialer (not WithDialer, which would
// bypass the guard); localhost:9 resolves to loopback and is refused pre-connect.
func TestGatekeeperCannotReachNonPublic(t *testing.T) {
	var decision Decision
	p := New(
		nil,
		WithGatekeeper(func(context.Context, string, string) bool { return true }),
		WithObserver(func(d Decision, _, _ string) { decision = d }),
	)
	dialProxy, stop := startProxy(t, p)
	defer stop()

	c := dialProxy()
	defer c.Close()
	status, _ := connect(t, c, "localhost:9")
	if !strings.Contains(status, "502") {
		t.Fatalf("status = %q, want 502 (gate admission cannot reach loopback)", status)
	}
	// The client cannot tell this from a dial failure, so the block shows on the host
	// side: GuardBlocked, not AdmittedByGate, which is what keeps the run's
	// gate-admitted list from claiming a destination the guard never let through.
	if decision != GuardBlocked {
		t.Errorf("observer reported %q, want %q", decision, GuardBlocked)
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
	// Reported as a gate denial, not an allowlist one: the gate was consulted and did not
	// admit, which is what that decision claims and the whole of what it claims.
	if len(seen) != 1 || !strings.HasPrefix(seen[0], string(GateDenied)) {
		t.Errorf("observer saw %v, want a single gate deny", seen)
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

// Every handler consults the gatekeeper from its own goroutine, so the gate, the
// dialer and the observer all run concurrently on a real run - and nothing else
// tests them that way. The gate's own axes are covered singly (panic denies,
// cancellation unblocks a gate blocked in a prompt, the slot cap refuses past
// capacity); what is untested is whether a decision stays attached to ITS
// connection when many are in flight. A verdict that crossed connections would
// open a tunnel to a host the gate denied, which no single-connection test can see.
//
// Every gate call is held until all of them have arrived, so the decisions really
// do overlap rather than happening to serialize. RUN THIS WITH -race: state shared
// between handlers is what crossed verdicts are made of, and a mutation that parks
// a verdict on the Proxy passes this test repeatedly without the detector - the
// window between writing and reading it back is too narrow to observe. The race
// detector is what turns the shared write into a failure.
//
// Declared hosts run alongside the gated ones so the two admission LABELS are
// separated under load as well: every host here would be reported AdmittedByGate
// if that flag were shared, and a run that only used undeclared hosts could not
// tell the labels apart.
func TestGatekeeperUnderConcurrencyOpensOnlyAdmittedTunnels(t *testing.T) {
	const (
		gated    = 64 // half admitted, half denied, all held in the gate at once
		declared = 16 // allowed by rule, so they never consult the gate
	)

	var (
		mu        sync.Mutex
		dialed    []string
		decisions = map[string]Decision{}
	)
	arrived := make(chan struct{}, gated)
	release := make(chan struct{})

	rules := make([]policy.NetworkRule, declared)
	for i := range rules {
		rules[i] = policy.NetworkRule{Host: fmt.Sprintf("declared%d.example.com", i), Port: "443"}
	}
	p := New(
		rules,
		WithGatekeeper(func(_ context.Context, host, _ string) bool {
			arrived <- struct{}{}
			<-release
			return strings.HasPrefix(host, "admit")
		}),
		WithDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			dialed = append(dialed, addr)
			mu.Unlock()
			return fakeDialer("tunnel")(ctx, network, addr)
		}),
		WithObserver(func(d Decision, host, port string) {
			mu.Lock()
			decisions[host] = d
			mu.Unlock()
		}),
	)
	dialProxy, stop := startProxy(t, p)
	// Releasing before stop() is what lets Serve's wg.Wait return; the Once covers
	// the fatal paths below, which would otherwise leave every handler in the gate.
	unblock := sync.OnceFunc(func() { close(release) })
	defer func() { unblock(); stop() }()

	hosts := make([]string, 0, gated+declared)
	for i := range gated {
		name := "admit%d.example.com"
		if i%2 == 1 {
			name = "deny%d.example.com"
		}
		hosts = append(hosts, fmt.Sprintf(name, i))
	}
	for i := range declared {
		hosts = append(hosts, fmt.Sprintf("declared%d.example.com", i))
	}

	type result struct {
		host   string
		status string
	}
	results := make(chan result, len(hosts))
	for _, host := range hosts {
		// Dialed here rather than inside the goroutine: dialProxy reports a failure with
		// t.Fatal, which from a spawned goroutine would kill it silently and leave the
		// arrival barrier below blaming a stuck handler for a failed dial.
		c := dialProxy()
		defer c.Close()
		go func() {
			c.SetDeadline(time.Now().Add(30 * time.Second))
			fmt.Fprintf(c, "CONNECT %s:443 HTTP/1.1\r\n\r\n", host)
			status, err := bufio.NewReader(c).ReadString('\n')
			if err != nil {
				status = "read error: " + err.Error()
			}
			results <- result{host, strings.TrimSpace(status)}
		}()
	}

	// Hold every gate call until all of them are in it, so the verdicts below are
	// decided concurrently. Without this the handlers could serialize and the test
	// would prove only what the single-connection tests already do.
	for range gated {
		select {
		case <-arrived:
		case <-time.After(30 * time.Second):
			t.Fatal("not every connection reached the gatekeeper; a handler is stuck before the gate")
		}
	}
	unblock()

	for range hosts {
		r := <-results
		want := "403"
		if !strings.HasPrefix(r.host, "deny") {
			want = "200"
		}
		if !strings.Contains(r.status, want) {
			t.Errorf("%s got %q, want %s - a gate verdict landed on the wrong connection", r.host, r.status, want)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	for host, d := range decisions {
		var want Decision
		switch {
		case strings.HasPrefix(host, "admit"):
			want = AdmittedByGate
		case strings.HasPrefix(host, "deny"):
			// The gate was consulted on these and refused, which is GateDenied - no rule
			// covered them, so the allowlist alone never got the chance to refuse.
			want = GateDenied
		default:
			want = Allowed // permitted by rule, so the gate was never consulted
		}
		if d != want {
			t.Errorf("observer reported %s as %q, want %q", host, d, want)
		}
	}
	if len(decisions) != len(hosts) {
		t.Errorf("observer saw %d decisions, want one per connection (%d)", len(decisions), len(hosts))
	}
	// The teeth: a denied host must never have been dialed. A tunnel to it is an open
	// state the 403 status would not reveal, since the status is written by the same
	// handler either way.
	if want := gated/2 + declared; len(dialed) != want {
		t.Errorf("dialed %d upstreams, want one per admitted host (%d): %v", len(dialed), want, dialed)
	}
	for _, addr := range dialed {
		if strings.HasPrefix(addr, "deny") {
			t.Errorf("dialed %q, which the gatekeeper denied", addr)
		}
	}
}

// The other half of the gate's concurrency story: a run cancelled while every
// handler sits in the gatekeeper must leave nothing open. TestGatekeeperUnblockedByCancel
// proves one blocked gate is interrupted; with the whole slot pool blocked, a gate
// that outlived its context would strand every handler, hold Serve in wg.Wait, and
// leave the run unable to finish - and a verdict that arrived after cancellation
// would dial an upstream for a run that no longer exists.
func TestConcurrentGatesBlockedAtCancelOpenNoTunnels(t *testing.T) {
	const conns = 64

	var (
		mu     sync.Mutex
		dialed []string
	)
	arrived := make(chan struct{}, conns)

	p := New(
		nil,
		WithGatekeeper(func(ctx context.Context, _, _ string) bool {
			arrived <- struct{}{}
			<-ctx.Done() // block as a human prompt would, until the run ends
			return false
		}),
		WithDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			dialed = append(dialed, addr)
			mu.Unlock()
			return fakeDialer("tunnel")(ctx, network, addr)
		}),
	)
	dialProxy, stop := startProxy(t, p)

	for i := range conns {
		// Dialed here rather than inside the goroutine: dialProxy reports a failure with
		// t.Fatal, which from a spawned goroutine would kill it silently.
		c := dialProxy()
		defer c.Close()
		go fmt.Fprintf(c, "CONNECT undeclared%d.example.com:443 HTTP/1.1\r\n\r\n", i)
	}
	for range conns {
		select {
		case <-arrived:
		case <-time.After(30 * time.Second):
			t.Fatal("not every connection reached the gatekeeper; a handler is stuck before the gate")
		}
	}

	done := make(chan struct{})
	go func() { stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Serve did not return after cancellation; gates blocked in a prompt were not all interrupted")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(dialed) != 0 {
		t.Errorf("cancellation left %d upstreams dialed, want none: %v", len(dialed), dialed)
	}
}

// halfClose prefers CloseWrite and falls back to SetDeadline only for conns that lack
// it. Production conns (unix, TCP) all have CloseWrite, but every other tunnel test
// fakes the upstream with net.Pipe, which does not - so the branch that actually runs
// in production is the one nothing covers. This drives a real TCP upstream to close
// that gap.
//
// The property is what separates the two branches: a client that half-closes signals
// EOF upstream while the return direction stays open, so data the upstream sends after
// seeing EOF still reaches the client. The SetDeadline fallback kills both directions
// at once and would lose it.
func TestTunnelHalfCloseKeepsTheReturnDirectionOpen(t *testing.T) {
	// An upstream that reads to EOF, then replies. It can only answer if the tunnel
	// delivered the half-close AND kept the reverse direction alive.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		got, _ := io.ReadAll(c)
		fmt.Fprintf(c, "saw-eof-after:%s", got)
	}()

	p := New([]policy.NetworkRule{{Host: "example.com", Port: "443"}},
		WithDialer(func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("tcp", ln.Addr().String())
		}))
	dialProxy, stop := startProxy(t, p)
	defer stop()

	c := dialProxy()
	defer c.Close()
	status, br := connect(t, c, "example.com:443")
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT = %q, want 200", status)
	}
	if _, err := io.WriteString(c, "ping"); err != nil {
		t.Fatal(err)
	}
	// Half-close the client's write side; the proxy must carry that to the upstream as
	// EOF rather than tearing the whole tunnel down.
	if err := c.(*net.UnixConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	reply, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("reading the upstream reply after half-close: %v", err)
	}
	// connect reads only the status line, so the header terminator is still buffered.
	if got := strings.TrimPrefix(string(reply), "\r\n"); got != "saw-eof-after:ping" {
		t.Errorf("reply = %q, want the upstream's post-EOF answer to survive the half-close", got)
	}
}

// A malformed target is echoed back with %q, which expands each control byte to
// four characters, so a request under the 64 KiB read limit produces a status body
// several times the socket buffer. Against a client that never reads, an unbounded
// write blocks in the kernel with no deadline in scope and pins the handler slot,
// its goroutine and its fd for the rest of the run.
func TestStatusWriteDoesNotPinAHandlerOnAClientThatNeverReads(t *testing.T) {
	p := New([]policy.NetworkRule{{Host: "example.com", Port: "443"}})
	dialProxy, stop := startProxy(t, p)
	defer stop()

	c := dialProxy()
	defer c.Close()
	// No colon, so net.SplitHostPort fails and the raw target reaches the error body
	// before any character screen: ~240 KB against a wmem_default of ~208 KB.
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\n\r\n", strings.Repeat("\x01", 60000))

	// The handler is done when it closes the conn. Probe with a write rather than a
	// read: reading would drain the socket and unblock the very write under test.
	deadline := time.Now().Add(statusWriteTimeout + 5*time.Second)
	for time.Now().Before(deadline) {
		if _, err := c.Write([]byte("x")); err != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("handler still held the connection after the status write should have timed out")
}

// Every connection the proxy handles must reach the run's egress record; one that
// dies at the parse boundary is the case that used to reach none. It names no
// destination - none parsed - but a run whose every connection died here must not
// read as one that never touched the network, which is what the count is for.
func TestParseFailureIsReportedAsRefused(t *testing.T) {
	for _, tc := range []struct{ name, request string }{
		{"not http", "GARBAGE\r\n"},
		{"no port", "CONNECT example.com HTTP/1.1\r\n\r\n"},
		{"empty host", "CONNECT :443 HTTP/1.1\r\n\r\n"},
		{"non-canonical port", "CONNECT example.com:0x1f90 HTTP/1.1\r\n\r\n"},
		{"deceiving host", "CONNECT exam\x9bple.com:443 HTTP/1.1\r\n\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var seen []Decision
			p := New([]policy.NetworkRule{{Host: "*", Port: "*"}},
				WithObserver(func(d Decision, _, _ string) {
					mu.Lock()
					defer mu.Unlock()
					seen = append(seen, d)
				}),
				WithDialer(fakeDialer("tunnel")))
			dialProxy, stop := startProxy(t, p)
			defer stop()

			c := dialProxy()
			defer c.Close()
			fmt.Fprint(c, tc.request)
			// The report happens before the status line, so reading the 400 orders this
			// against the handler.
			br := bufio.NewReader(c)
			status, err := br.ReadString('\n')
			if err != nil {
				t.Fatalf("reading status: %v", err)
			}
			if !strings.Contains(status, "400") {
				t.Fatalf("status = %q, want 400", strings.TrimSpace(status))
			}
			mu.Lock()
			defer mu.Unlock()
			if !slices.Equal(seen, []Decision{Refused}) {
				t.Errorf("decisions = %v, want exactly [%s]", seen, Refused)
			}
		})
	}
}

// deadlinePanicConn is an upstream whose SetDeadline panics, which is how a panic is
// driven from tunnel's extend() - on handle's own goroutine, after the 200.
type deadlinePanicConn struct{ net.Conn }

func (deadlinePanicConn) SetDeadline(time.Time) error { panic("upstream deadline blew up") }

// A panic after the tunnel is established must not add a Faulted to the connection's
// already-reported decision. Downstream counts a fault as a connection whose handler
// reached no outcome and degrades the network layer for it; this one was allowed,
// dialed and tunneled, so reporting both counts one connection twice and degrades a
// layer that did enforce the manifest on it.
func TestPanicAfterTheTunnelDoesNotReportAFault(t *testing.T) {
	var mu sync.Mutex
	var seen []Decision
	p := New([]policy.NetworkRule{{Host: "*", Port: "*"}},
		WithObserver(func(d Decision, _, _ string) {
			mu.Lock()
			defer mu.Unlock()
			seen = append(seen, d)
		}),
		WithDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := fakeDialer("tunnel")(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return deadlinePanicConn{c}, nil
		}))
	dialProxy, stop := startProxy(t, p)
	defer stop()

	c := dialProxy()
	defer c.Close()
	status, br := connect(t, c, "example.com:443")
	if !strings.Contains(status, "200") {
		t.Fatalf("status = %q, want 200 (the panic must land after the tunnel)", status)
	}
	// The handler's recover runs before its deferred client.Close, so an EOF here
	// orders the assertion after whatever the recover reported.
	if _, err := io.ReadAll(br); err != nil {
		t.Fatalf("draining the tunnel: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(seen, []Decision{Allowed}) {
		t.Errorf("decisions = %v, want exactly [%s]", seen, Allowed)
	}
}
