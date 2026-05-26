// Package grants is the per-Run permission-prompt machinery.
//
// When a callback is configured (via runner.WithGrantCallback or
// bento.WithGrantCallback), proxy match failures consult it instead
// of immediately denying. The callback returns Allow or Deny. The
// proxy caches decisions per host:port so a script making 100 requests
// to the same host prompts once.
//
// The CLI's --prompt / -i flag installs a TTY-backed callback that
// reads /dev/tty. Library consumers without a TTY plug in their own
// (auto-allow, deny-with-log, GUI dialog, Slack approval, etc.).
package grants

import "sync"

// Request is what the proxy hands the callback when an unrecognized
// host:port shows up. Network is the only kind today; future kinds
// (file open, exec spawn) would extend Kind.
type Request struct {
	Kind Kind
	Host string
	Port int
}

// Kind discriminates Request types.
type Kind int

const (
	KindNetwork Kind = iota // outbound TCP connect (HTTP CONNECT or SOCKS5)
)

// Decision is what the callback returns. Allow/Deny is all v1 needs;
// future versions may add timeouts or scope hints.
type Decision int

const (
	DecisionDeny  Decision = iota // refuse this request (and cache the no)
	DecisionAllow                 // permit this request (and cache the yes)
)

// Callback is the per-Run grant decider. Called by the proxies on
// host:port that aren't in the manifest's network allowlist. Must be
// safe to call from multiple goroutines.
type Callback func(Request) Decision

// DecisionCache abstracts decision memoization for network and resource
// prompts. Shared between proxies and runners.
type DecisionCache interface {
	Lookup(r Request) (Decision, bool)
	Store(r Request, d Decision)
}

// Cache memoizes decisions for the lifetime of one Run so scripts
// making many connections to the same host prompt once. Shared
// between HTTP and SOCKS5 proxies (a script might use both, and
// double-prompting the same host:port from both is bad UX).
type Cache struct {
	mu sync.Mutex
	m  map[string]Decision
}

// CacheOption configures a decision Cache.
type CacheOption func(*cacheOpts)

type cacheOpts struct {
	capacity int
}

// WithInitialCapacity pre-allocates cache map storage.
func WithInitialCapacity(cap int) CacheOption {
	return func(o *cacheOpts) { o.capacity = cap }
}

// NewCache returns an empty cache.
func NewCache(opts ...CacheOption) *Cache {
	co := &cacheOpts{}
	for _, opt := range opts {
		opt(co)
	}
	cap := max(co.capacity, 0)
	return &Cache{m: make(map[string]Decision, cap)}
}

// Lookup returns a cached decision for the request, or (0, false).
func (c *Cache) Lookup(r Request) (Decision, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	d, ok := c.m[r.key()]
	return d, ok
}

// Store remembers a decision for the rest of this Run.
func (c *Cache) Store(r Request, d Decision) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[r.key()] = d
}

func (r Request) key() string {
	return r.Host + ":" + portString(r.Port)
}

func portString(p int) string {
	if p == 0 {
		return "0"
	}
	var b [6]byte
	i := len(b)
	for p > 0 {
		i--
		b[i] = byte('0' + p%10)
		p /= 10
	}
	return string(b[i:])
}
