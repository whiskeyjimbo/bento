package proxy

import (
	"errors"
	"fmt"
	"net"
)

// handler is the per-connection callback a concrete proxy implements
// (SOCKS5 wire protocol, HTTP CONNECT, etc.).
type handler func(net.Conn)

// tcpProxy is the shared bind/serve/close machinery used by the
// concrete proxies. Holds a slice of listeners (IPv4 + IPv6 by
// default) so a single proxy serves both address families on
// independent ephemeral ports.
type tcpProxy struct {
	listeners []net.Listener
	opts      *options
	prefix    string // log prefix, e.g. "socks5", "http-connect"
	handle    handler
}

// newTCPProxy binds listener(s) according to opts. If opts.bindAddr
// is explicit, only that address is bound. Otherwise we bind both
// 127.0.0.1 and [::1] on ephemeral ports — failing IPv6 binding is a
// warning, not an error (rare to have no v6 stack but it happens).
func newTCPProxy(logPrefix string, opts *options, h handler) (*tcpProxy, error) {
	p := &tcpProxy{opts: opts, prefix: logPrefix, handle: h}

	addrs := []string{opts.bindAddr}
	if opts.bindAddr == defaultBindAddr {
		// Default path: dual-stack. Each gets its own ephemeral port.
		addrs = []string{"127.0.0.1:0", "[::1]:0"}
	}

	for _, addr := range addrs {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			// IPv6 binding may fail on hosts without v6. Skip and continue
			// when we have at least one listener already.
			if len(p.listeners) > 0 {
				if opts.logger != nil {
					opts.logger.Printf("["+logPrefix+"] skipping bind %s: %v", addr, err)
				}
				continue
			}
			return nil, fmt.Errorf("%s listen %s: %w", logPrefix, addr, err)
		}
		p.listeners = append(p.listeners, ln)
	}
	if len(p.listeners) == 0 {
		return nil, fmt.Errorf("%s: no listeners bound", logPrefix)
	}
	return p, nil
}

// Addr returns the first bound address. Kept for backwards
// compatibility with callers that don't care about address family.
func (p *tcpProxy) Addr() string { return p.listeners[0].Addr().String() }

// Addrs returns every bound address (typically one v4 + one v6).
// Used by the runner to populate BENTO_ALLOW_PORTS with ALL the
// listener ports so a script's choice of address family isn't
// constrained by the proxy's first binding.
func (p *tcpProxy) Addrs() []string {
	out := make([]string, 0, len(p.listeners))
	for _, ln := range p.listeners {
		out = append(out, ln.Addr().String())
	}
	return out
}

// Close stops the proxy. In-flight connections may continue briefly.
func (p *tcpProxy) Close() error {
	var errs []error
	for _, ln := range p.listeners {
		if err := ln.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (p *tcpProxy) serve() {
	for _, ln := range p.listeners {
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go p.handle(c)
			}
		}()
	}
}

func (p *tcpProxy) logf(format string, args ...any) {
	if p.opts.logger != nil {
		p.opts.logger.Printf("["+p.prefix+"] "+format, args...)
	}
}
