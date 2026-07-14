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

// Serve accepts connections on l and enforces the allowlist on each until ctx is
// cancelled or l is closed. It returns when l stops accepting.
func (p *Proxy) Serve(ctx context.Context, l net.Listener) error {
	var wg sync.WaitGroup
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
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.handle(ctx, c)
		}()
	}
}

func (p *Proxy) handle(ctx context.Context, client net.Conn) {
	defer client.Close()

	host, port, err := readConnect(client)
	if err != nil {
		writeStatus(client, "400 Bad Request", err.Error())
		return
	}

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
	splice(client, upstream)
}

func (p *Proxy) report(d Decision, host, port string) {
	if p.observe != nil {
		p.observe(d, host, port)
	}
}

// readConnect parses a single `CONNECT host:port HTTP/1.1` request and drains its
// headers. Only CONNECT is accepted: this proxy tunnels TLS, it does not relay
// plaintext HTTP, so there is nothing to inspect or rewrite in a request body.
func readConnect(c net.Conn) (host, port string, err error) {
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		return "", "", fmt.Errorf("reading request: %w", err)
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || strings.ToUpper(fields[0]) != "CONNECT" {
		return "", "", fmt.Errorf("expected a CONNECT request")
	}
	host, port, err = net.SplitHostPort(fields[1])
	if err != nil {
		return "", "", fmt.Errorf("malformed target %q: %w", fields[1], err)
	}
	if host == "" {
		return "", "", fmt.Errorf("empty target host")
	}
	// Drain the remaining request headers up to the blank line.
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			return "", "", fmt.Errorf("reading headers: %w", err)
		}
		if h == "\r\n" || h == "\n" {
			break
		}
	}
	return host, port, nil
}

func writeStatus(c net.Conn, status, body string) {
	fmt.Fprintf(c, "HTTP/1.1 %s\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s\n", status, body)
}

// splice copies bytes in both directions until either side closes, then tears
// the tunnel down. It returns only when both directions are finished, so a
// half-closed direction cannot truncate an in-flight response.
func splice(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		// Unblock the other direction: once one side is done, signal EOF onward so
		// the paired copy can finish instead of hanging on a peer that will never
		// send again.
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.SetDeadline(time.Now())
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}
