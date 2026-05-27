package proxy

import (
	"time"

	"github.com/whiskeyjimbo/bento/internal/grants"
	"github.com/whiskeyjimbo/bento/internal/spec"
)

// ProxyServer defines the interface for running transparent/filtering proxies.
type ProxyServer interface {
	Start()
	Addr() string
	Addrs() []string
	Close() error
}

// Authorizer validates whether a network destination is permitted.
type Authorizer interface {
	Authorize(host string, port int) (bool, string)
}

// Option configures a proxy's startup behavior.
type Option func(*options)

// options is the per-proxy configuration assembled from Option values.
type options struct {
	bindAddr    string
	logger      Logger
	dialTimeout time.Duration
	idleTimeout time.Duration
	grants      grants.Callback      // optional: prompt on match failure
	grantCache  grants.DecisionCache // shared between HTTP and SOCKS5
	authorizer  Authorizer           // custom authorizer (takes precedence)
}

// defaultBindAddr sentinels "dual-stack default" — bind 127.0.0.1:0 and [::1]:0.
const defaultBindAddr = ""

// applyOptionsFor builds options and installs a defaultAuthorizer if none was set,
// so handlers can call opts.authorizer.Authorize unconditionally.
func applyOptionsFor(perm *spec.NetworkPerm, opts []Option) *options {
	o := defaultOptions()
	for _, opt := range opts {
		opt(o)
	}
	if o.authorizer == nil {
		o.authorizer = &defaultAuthorizer{
			perm:       perm,
			grants:     o.grants,
			grantCache: o.grantCache,
		}
	}
	return o
}

func defaultOptions() *options {
	return &options{
		bindAddr:    defaultBindAddr,
		dialTimeout: 10 * time.Second,
		idleTimeout: 30 * time.Second,
	}
}

// WithLogger directs diagnostic output to l. Pass nil to silence.
func WithLogger(l Logger) Option {
	return func(o *options) { o.logger = l }
}

// WithBindAddr overrides the default dual-stack loopback bind.
func WithBindAddr(addr string) Option {
	return func(o *options) { o.bindAddr = addr }
}

// WithDialTimeout sets the upstream connect timeout (default 10s).
func WithDialTimeout(d time.Duration) Option {
	return func(o *options) { o.dialTimeout = d }
}

// WithIdleTimeout sets the handshake idle deadline (default 30s).
// Cleared once the tunnel is established so long-lived streams aren't reaped.
func WithIdleTimeout(d time.Duration) Option {
	return func(o *options) { o.idleTimeout = d }
}

// WithGrants installs an allowlist-miss callback. Decisions are cached in shared
// so HTTP and SOCKS5 don't double-prompt the same host:port.
func WithGrants(cb grants.Callback, shared grants.DecisionCache) Option {
	return func(o *options) {
		o.grants = cb
		o.grantCache = shared
	}
}

// WithAuthorizer installs a custom destination authorizer.
func WithAuthorizer(auth Authorizer) Option {
	return func(o *options) { o.authorizer = auth }
}
