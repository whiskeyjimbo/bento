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

// defaultBindAddr is the sentinel for "dual-stack default" — the
// proxy binds both 127.0.0.1:0 and [::1]:0. Callers can override via
// WithBindAddr; tests and special cases use a specific value.
const defaultBindAddr = "" // intentionally empty; tcpProxy compares against this

// applyOptions builds the options from defaults + caller-supplied
// Option funcs. After this, opts.authorizer is always non-nil — if
// the caller didn't supply one, we install a defaultAuthorizer that
// consults the manifest's allowlist (and the optional grant
// callback). Handlers can therefore call opts.authorizer.Authorize
// unconditionally; no per-request branch.
//
// applyOptions takes the manifest's NetworkPerm because the default
// authorizer needs it. Callers that pass WithAuthorizer override
// the default.
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

// WithLogger directs the proxy's diagnostic output to l. Pass nil to
// silence.
func WithLogger(l Logger) Option {
	return func(o *options) { o.logger = l }
}

// WithBindAddr changes where the proxy listens. Default 127.0.0.1:0
// (loopback, ephemeral port). Useful for binding to ::1 (IPv6 loopback)
// or, in tests, to a specific port.
func WithBindAddr(addr string) Option {
	return func(o *options) { o.bindAddr = addr }
}

// WithDialTimeout sets the upstream connect timeout. Default 10s.
func WithDialTimeout(d time.Duration) Option {
	return func(o *options) { o.dialTimeout = d }
}

// WithIdleTimeout sets the per-connection idle deadline during the
// initial handshake. Once the proxy has established a tunnel, the
// deadline is cleared so long-lived TCP streams aren't reaped.
// Default 30s.
func WithIdleTimeout(d time.Duration) Option {
	return func(o *options) { o.idleTimeout = d }
}

// WithGrants installs an interactive permission callback. When the
// allowlist match fails, the proxy consults cb instead of immediately
// denying; decisions are cached in shared so HTTP and SOCKS5 don't
// double-prompt the same host:port. Without this option, failed
// matches are hard-denied as before.
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
