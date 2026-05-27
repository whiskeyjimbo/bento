// Package grants is the per-Run permission-prompt machinery.
// Proxy match failures consult a Callback instead of immediately denying;
// decisions are cached per host:port for the rest of the Run.
package grants

import (
	"strconv"
	"sync"
)

// Request is what the proxy hands the callback when an unrecognized host:port shows up.
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

// Decision is what the callback returns.
type Decision int

const (
	DecisionDeny  Decision = iota // refuse this request (and cache the no)
	DecisionAllow                 // permit this request (and cache the yes)
)

// Callback is the per-Run grant decider, consulted on allowlist misses.
// Must be safe to call from multiple goroutines.
type Callback func(Request) Decision

// DecisionCache abstracts decision memoization, shared between proxies and runners.
type DecisionCache interface {
	Lookup(r Request) (Decision, bool)
	Store(r Request, d Decision)
}

// Cache memoizes decisions for the lifetime of one Run, shared across HTTP and SOCKS5
// proxies so a script using both doesn't double-prompt for the same host:port.
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
	return r.Host + ":" + strconv.Itoa(r.Port)
}
