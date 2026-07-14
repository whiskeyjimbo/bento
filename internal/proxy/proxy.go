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
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/whiskeyjimbo/bento-v2/internal/policy"
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

// New returns a proxy that permits only the given rules.
func New(rules []policy.NetworkRule, opts ...Option) *Proxy {
	var d net.Dialer
	p := &Proxy{rules: rules, dial: d.DialContext}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// maxConcurrent bounds how many tunnels the proxy handles at once. It caps the
// host-side goroutines and file descriptors untrusted code can pin by opening
// connections in a loop — the cgroup limits confine the sandbox, but not this
// host process. The limit is generous enough that no legitimate script reaches
// it; a script that does is refused, not allowed to exhaust the host.
const maxConcurrent = 512

// Serve accepts connections on l and enforces the allowlist on each until ctx is
// cancelled or l is closed. It returns when l stops accepting.
func (p *Proxy) Serve(ctx context.Context, l net.Listener) error {
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrent)
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

	client.SetReadDeadline(time.Now().Add(connectTimeout))
	host, port, br, err := readConnect(client)
	if err != nil {
		writeStatus(client, "400 Bad Request", err.Error())
		return
	}
	// Hand the tunnel a clean slate; copyIdle installs its own idle deadlines.
	client.SetReadDeadline(time.Time{})

	if !policy.Allows(p.rules, host, port) {
		p.report(Denied, host, port)
		// The body is plaintext so it surfaces in the script's own error output —
		// a curl/requests user sees exactly which host was refused, not a blank
		// failure.
		writeStatus(client, "403 Forbidden",
			fmt.Sprintf("bento denied egress to %s:%s (not in the manifest's network allowlist)", host, port))
		return
	}

	upstream, err := p.dial(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		p.report(Allowed, host, port)
		writeStatus(client, "502 Bad Gateway", fmt.Sprintf("bento could not reach %s:%s: %v", host, port, err))
		return
	}
	defer upstream.Close()

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

// readConnect parses a single `CONNECT host:port HTTP/1.1` request and drains its
// headers. Only CONNECT is accepted: this proxy tunnels TLS, it does not relay
// plaintext HTTP, so there is nothing to inspect or rewrite in a request body.
// It returns the buffered reader so the caller can keep reading the client from
// it — bytes pipelined after the headers are already buffered here.
func readConnect(c net.Conn) (host, port string, br *bufio.Reader, err error) {
	br = bufio.NewReader(c)
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
	return host, port, br, nil
}

func writeStatus(c net.Conn, status, body string) {
	fmt.Fprintf(c, "HTTP/1.1 %s\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s\n", status, body)
}

// idleTimeout tears down a tunnel that has sat with no traffic in either
// direction for this long, so untrusted code cannot pin host resources with idle
// connections held open indefinitely.
const idleTimeout = 5 * time.Minute

// tunnel copies bytes both ways until either side closes or the tunnel goes idle.
// The client side is read through clientR (which may hold buffered bytes); client
// and upstream are the conns used to write, half-close, and bound idleness.
func tunnel(clientR io.Reader, client, upstream net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); copyIdle(upstream, clientR, client); halfClose(upstream) }()
	go func() { defer wg.Done(); copyIdle(client, upstream, upstream); halfClose(client) }()
	wg.Wait()
}

// copyIdle copies src→dst, resetting ctl's deadline on every read so an active
// tunnel stays open while an idle one is torn down after idleTimeout. ctl is the
// connection src ultimately reads from.
func copyIdle(dst io.Writer, src io.Reader, ctl net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		ctl.SetDeadline(time.Now().Add(idleTimeout))
		n, err := src.Read(buf)
		if n > 0 {
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
