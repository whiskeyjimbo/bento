// Package proxy is Bento's egress allowlist enforcement point.
//
// It is a host-side HTTP CONNECT proxy: the sandbox is funneled to it (over a
// bind-mounted unix socket) and can reach the outside world only through it. For
// each tunnel the client requests, the proxy checks the target host:port against
// the policy's rules and either establishes the tunnel or refuses it with a
// message the script can see. The namespace fence is what makes this the *only*
// way out; the proxy is what makes it a *selective* way out.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/whiskeyjimbo/bento-v2/policy"
)

// Decision is the outcome of an allowlist check, reported to the observer.
type Decision string

const (
	Allowed Decision = "allow"
	Denied  Decision = "deny"
)

// Proxy enforces an egress allowlist for CONNECT tunnels.
type Proxy struct {
	rules []policy.NetworkRule

	// dial opens the upstream connection. It is a seam so tests can supply a fake
	// upstream without real network access; production uses net.Dialer.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)

	// observe is called for every decision. Profiling and logging hang off it;
	// nil disables observation.
	observe func(d Decision, host, port string)

	// refuse records each CONNECT and then refuses it, never opening an upstream.
	// Profiling uses it to learn a script's intended destinations without letting
	// the script's data leave the host.
	refuse bool
}

// Option configures a Proxy.
type Option func(*Proxy)

// WithDialer overrides how upstream connections are made.
func WithDialer(dial func(ctx context.Context, network, addr string) (net.Conn, error)) Option {
	return func(p *Proxy) { p.dial = dial }
}

// WithObserver installs a callback invoked for every allow/deny decision.
func WithObserver(observe func(d Decision, host, port string)) Option {
	return func(p *Proxy) { p.observe = observe }
}

// WithoutEgress makes the proxy record every CONNECT and then refuse it, without
// opening any upstream connection. Profiling uses it to capture a script's
// intended destinations while keeping its data on the host.
func WithoutEgress() Option {
	return func(p *Proxy) { p.refuse = true }
}

// New returns a proxy that permits only the given rules.
func New(rules []policy.NetworkRule, opts ...Option) *Proxy {
	p := &Proxy{rules: rules}
	// ControlContext fires just before each upstream connect with the resolved
	// address, so the allowlisted-name-resolves-to-internal-IP hole is closed
	// against the actual IP being dialed, with no separate resolve step to race.
	//
	// PreferGo pins the pure-Go resolver, closing the cgo getaddrinfo fallback so
	// upstream resolution follows one libc-independent path (reads resolv.conf and
	// hosts directly). The cost is names only the host resolver would answer:
	// nsswitch-only modules and macOS scoped resolvers (VPN split DNS) do not apply,
	// and .local goes to unicast DNS rather than mDNS - acceptable because egress
	// targets are public hosts, and an explicit IP-literal rule dials the address
	// without resolving at all. The stdlib already handles the EDNS/truncation/retry
	// edges, and guardUpstream validates whatever address it returns, so bento owns
	// no separate DNS stack.
	d := &net.Dialer{
		ControlContext: p.guardUpstream,
		Resolver:       &net.Resolver{PreferGo: true},
	}
	p.dial = d.DialContext
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// blockedUpstreamError is returned by guardUpstream when a resolved address must
// not be dialed: a non-public IP the rules do not explicitly authorize, or an
// address the guard cannot parse (refused rather than dialed blind). handle uses
// it to refuse the tunnel distinctly from an ordinary dial failure.
type blockedUpstreamError struct{ addr string }

func (e *blockedUpstreamError) Error() string {
	return fmt.Sprintf("refusing egress to non-public address %s", e.addr)
}

// guardUpstream rejects connecting to a resolved address that names a
// host-internal or infrastructure target (loopback, link-local including
// 169.254.169.254 cloud metadata, private/ULA, CGNAT, unspecified). Since the
// allowlist matches on the CONNECT hostname, a permitted name that resolves to
// such an address would otherwise let a sandboxed script reach services the host
// can see but the sandbox must not. The exception is an address the rules name
// as an explicit IP literal: listing 10.0.0.5 is a deliberate choice to reach
// it, whereas a hostname (or wildcard) resolving there is not.
func (p *Proxy) guardUpstream(_ context.Context, _, address string, _ syscall.RawConn) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		// The dialer hands ControlContext a resolved host:port; an address that does
		// not even split is anomalous, so refuse it rather than fail open.
		return &blockedUpstreamError{addr: address}
	}
	// Strip an IPv6 zone id before parsing. net.ParseIP rejects a zoned literal -
	// "fe80::1%eth0", and the mapped-IPv4 "::ffff:169.254.169.254%eth0" or its
	// collapsed "169.254.169.254%eth0" form - returning nil. Without this the zoned
	// address would slip past classification into the fail-open path below, and the
	// kernel then dials the underlying (host-reserved) address ignoring the zone.
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// A resolved dial target that is not a plain IP cannot be classified, so
		// refuse it rather than dial an address the guard could not vet.
		return &blockedUpstreamError{addr: address}
	}
	switch classifyIP(ip) {
	case ipHostReserved:
		// Loopback, link-local (incl. cloud metadata), and unspecified name the host
		// itself or its infrastructure. The proxy runs on the host, so dialing these
		// reaches the HOST's own services - never a legitimate sandbox egress target,
		// so no rule may reach them, not even an explicit IP literal.
		return &blockedUpstreamError{addr: ip.String()}
	case ipPrivate:
		// RFC1918/ULA/CGNAT may be a deliberate internal-egress target, but only when
		// a rule names the exact IP literal; a permitted hostname resolving there is
		// the SSRF case and stays blocked.
		if !p.explicitlyAllowsIP(ip, port) {
			return &blockedUpstreamError{addr: ip.String()}
		}
	}
	return nil
}

// explicitlyAllowsIP reports whether a rule names this exact IP as a literal (not
// a hostname or wildcard) for this port. Only such a rule exempts a non-public
// address from the guard.
func (p *Proxy) explicitlyAllowsIP(ip net.IP, port string) bool {
	for _, r := range p.rules {
		if rip := net.ParseIP(r.Host); rip != nil && rip.Equal(ip) && policy.PortMatches(r.Port, port) {
			return true
		}
	}
	return false
}

// ipClass groups a resolved address by how the egress guard treats it.
type ipClass int

const (
	// ipPublic is a routable address the allowlist alone governs.
	ipPublic ipClass = iota
	// ipHostReserved names the host or its infrastructure - loopback, link-local
	// (incl. cloud metadata), unspecified. No rule may reach it through the proxy.
	ipHostReserved
	// ipPrivate is RFC1918/ULA/CGNAT space: reachable only when a rule names the
	// exact IP literal, never by resolving a permitted hostname to it.
	ipPrivate
)

// classifyIP groups ip for the egress guard. An IPv6 transition address embeds an
// IPv4 that To4 does not surface, so a synthesized address (DNS64/NAT64 is the
// live case on IPv6-only subnets) is classified by its embedded IPv4.
func classifyIP(ip net.IP) ipClass {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() {
		return ipHostReserved
	}
	if ip.IsPrivate() {
		return ipPrivate
	}
	if v4 := ip.To4(); v4 != nil {
		// CGNAT 100.64.0.0/10 (RFC 6598) is not covered by IsPrivate but names
		// carrier/infrastructure space just the same.
		if v4[0] == 100 && v4[1]&0xc0 == 64 {
			return ipPrivate
		}
		return ipPublic
	}
	if embedded := embeddedIPv4(ip); embedded != nil {
		return classifyIP(embedded)
	}
	return ipPublic
}

// embeddedIPv4 returns the IPv4 carried by an IPv6 transition address, or nil.
// It covers the NAT64 well-known prefix 64:ff9b::/96 and 6to4 (2002::/16). Other
// NAT64 prefix lengths (the RFC 6052 split-byte layouts), the RFC 8215 local-use
// prefix, operator-specific prefixes, and Teredo are not decoded - a defense in
// depth gap, since the allowlist must still permit the hostname at all.
func embeddedIPv4(ip net.IP) net.IP {
	ip16 := ip.To16()
	if ip16 == nil {
		return nil
	}
	// 6to4: 2002:AABB:CCDD::/48 carries AA.BB.CC.DD at bytes 2..5.
	if ip16[0] == 0x20 && ip16[1] == 0x02 {
		return net.IPv4(ip16[2], ip16[3], ip16[4], ip16[5])
	}
	// NAT64 well-known prefix 64:ff9b::/96 carries the IPv4 in the last 4 bytes.
	if bytes.Equal(ip16[:12], []byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0}) {
		return net.IPv4(ip16[12], ip16[13], ip16[14], ip16[15])
	}
	return nil
}

// maxConcurrent bounds how many tunnels the proxy handles at once. It caps the
// host-side goroutines and file descriptors untrusted code can pin by opening
// connections in a loop; the cgroup limits confine the sandbox, but not this
// host process. The limit is generous enough that no legitimate script reaches
// it; a script that does is refused, not allowed to exhaust the host.
const maxConcurrent = 512

// Serve accepts connections on l and enforces the allowlist on each until ctx is
// cancelled or l is closed. It returns when l stops accepting.
func (p *Proxy) Serve(ctx context.Context, l net.Listener) error {
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrent)
	// Derive a cancellable context so the closer goroutine below always exits,
	// including when Accept returns an error while the caller's ctx is still live.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	for {
		c, err := l.Accept()
		if err != nil {
			wg.Wait()
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case sem <- struct{}{}:
			wg.Go(func() {
				defer func() { <-sem }()
				p.handle(ctx, c)
			})
		default:
			// At capacity: refuse rather than let the host process grow unbounded.
			writeStatus(c, "503 Service Unavailable", "bento egress proxy is at its connection limit")
			c.Close()
		}
	}
}

// connectTimeout bounds how long a client may take to send its CONNECT request
// before its handler slot is reclaimed, so a client that connects and sends
// nothing cannot pin a concurrency slot for the whole run.
const connectTimeout = 30 * time.Second

func (p *Proxy) handle(ctx context.Context, client net.Conn) {
	defer client.Close()
	// A panic in a handler must not take down the whole bento process mid-run; the
	// slot is released by Serve's deferred receive regardless.
	defer func() { _ = recover() }()

	// A run cancellation (timeout or abort) must unblock this handler at once, not
	// leave it pinning a slot until readConnect's connectTimeout or the tunnel's
	// idle timeout expires. Closing client interrupts the CONNECT read and the
	// client-side copy loop; upstream gets the same treatment once dialed. stop()
	// drops the registration on the normal path, so nothing stays registered past
	// the handler.
	stopClient := context.AfterFunc(ctx, func() { client.Close() })
	defer stopClient()

	client.SetReadDeadline(time.Now().Add(connectTimeout))
	host, port, br, err := readConnect(client)
	if err != nil {
		writeStatus(client, "400 Bad Request", err.Error())
		return
	}
	// Hand the tunnel a clean slate; copyIdle installs its own idle deadlines.
	client.SetReadDeadline(time.Time{})

	if p.refuse {
		// Record the intended destination, then refuse: the script learns it could
		// not connect, and its data never leaves the host. The plaintext body
		// surfaces in the script's own error output.
		p.report(Denied, host, port)
		writeStatus(client, "403 Forbidden",
			fmt.Sprintf("bento recorded intended egress to %s:%s but did not forward it (profiling; re-run with --allow-network to permit it)", host, port))
		return
	}

	if !policy.Allows(p.rules, host, port) {
		p.report(Denied, host, port)
		// The body is plaintext so it surfaces in the script's own error output,
		// so a curl/requests user sees exactly which host was refused, not a blank
		// failure.
		writeStatus(client, "403 Forbidden",
			fmt.Sprintf("bento denied egress to %s:%s (not in the manifest's network allowlist)", host, port))
		return
	}

	upstream, err := p.dial(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		var blocked *blockedUpstreamError
		if errors.As(err, &blocked) {
			p.report(Denied, host, port)
			writeStatus(client, "403 Forbidden",
				fmt.Sprintf("bento denied egress to %s:%s (%s resolves to non-public address %s; list it as an explicit IP rule if you meant it)", host, port, host, blocked.addr))
			return
		}
		p.report(Allowed, host, port)
		writeStatus(client, "502 Bad Gateway", fmt.Sprintf("bento could not reach %s:%s: %v", host, port, err))
		return
	}
	defer upstream.Close()

	// Cancellation must also interrupt the upstream-side copy loop, which is
	// otherwise blocked on Read until the idle timeout. Pairs with stopClient above.
	stopUpstream := context.AfterFunc(ctx, func() { upstream.Close() })
	defer stopUpstream()

	p.report(Allowed, host, port)
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	// The client half is read through br, not client, because a pipelining client
	// may have already sent its TLS ClientHello into br's buffer along with the
	// CONNECT headers; reading the raw conn would drop those bytes and break the
	// handshake.
	tunnel(br, client, upstream)
}

func (p *Proxy) report(d Decision, host, port string) {
	if p.observe != nil {
		p.observe(d, host, port)
	}
}

// maxRequestBytes bounds the CONNECT request line plus headers the proxy reads
// before establishing the tunnel. Without it, ReadString('\n') on a newline-free
// stream grows the host process's memory unbounded, and the proxy runs on the
// host, outside the sandbox's cgroup. Only the request line, headers, and one
// bufio prefetch count against the cap; a pipelined TLS ClientHello need not fit
// under it, and the cap is lifted for the tunnel body once the request is parsed.
const maxRequestBytes = 64 * 1024

// readConnect parses a single `CONNECT host:port HTTP/1.1` request and drains its
// headers. Only CONNECT is accepted: this proxy tunnels TLS, it does not relay
// plaintext HTTP, so there is nothing to inspect or rewrite in a request body.
// It returns the buffered reader so the caller can keep reading the client from
// it: bytes pipelined after the headers are already buffered here.
func readConnect(c net.Conn) (host, port string, br *bufio.Reader, err error) {
	lr := &io.LimitedReader{R: c, N: maxRequestBytes}
	br = bufio.NewReader(lr)
	line, err := br.ReadString('\n')
	if err != nil {
		return "", "", nil, fmt.Errorf("reading request: %w", err)
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || strings.ToUpper(fields[0]) != "CONNECT" {
		return "", "", nil, fmt.Errorf("expected a CONNECT request")
	}
	host, port, err = net.SplitHostPort(fields[1])
	if err != nil {
		return "", "", nil, fmt.Errorf("malformed target %q: %w", fields[1], err)
	}
	if host == "" {
		return "", "", nil, fmt.Errorf("empty target host")
	}
	// Drain the remaining request headers up to the blank line.
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			return "", "", nil, fmt.Errorf("reading headers: %w", err)
		}
		if h == "\r\n" || h == "\n" {
			break
		}
	}
	// Request parsed; lift the cap so the tunnel body copy through br is unbounded.
	lr.N = math.MaxInt64
	return host, port, br, nil
}

func writeStatus(c net.Conn, status, body string) {
	fmt.Fprintf(c, "HTTP/1.1 %s\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s\n", status, body)
}

// idleTimeout tears down a tunnel that has sat with no traffic in either
// direction for this long, so untrusted code cannot pin host resources with idle
// connections held open indefinitely.
var idleTimeout = 5 * time.Minute

// tunnel copies bytes both ways until either side closes or the tunnel goes idle.
// The client side is read through clientR (which may hold buffered bytes); client
// and upstream are the conns used to write, half-close, and bound idleness.
func tunnel(clientR io.Reader, client, upstream net.Conn) {
	// Traffic in either direction means the tunnel is active, so re-arm the idle
	// deadline on BOTH conns on every read. A long one-way transfer (a large
	// upload with a silent upstream, say) keeps only its own direction busy; if
	// each direction armed only its own conn, the silent side would trip the idle
	// timeout after idleTimeout and - because SetDeadline bounds writes too - kill
	// the active side's next write, aborting a transfer that never went idle.
	extend := func() {
		t := time.Now().Add(idleTimeout)
		client.SetDeadline(t)
		upstream.SetDeadline(t)
	}
	extend()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); copyIdle(upstream, clientR, extend); halfClose(upstream) }()
	go func() { defer wg.Done(); copyIdle(client, upstream, extend); halfClose(client) }()
	wg.Wait()
}

// copyIdle copies src→dst, calling extend on every read so activity in this
// direction keeps the tunnel's idle deadline fresh; an idle tunnel is torn down
// after idleTimeout when neither direction reads.
func copyIdle(dst io.Writer, src io.Reader, extend func()) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			extend()
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// halfClose signals EOF to the write side of c so the paired copy finishes
// instead of hanging on a peer that will never send again.
func halfClose(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	c.SetDeadline(time.Now())
}
