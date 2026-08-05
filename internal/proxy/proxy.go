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
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/whiskeyjimbo/bento/policy"
)

// Decision is the outcome of an allowlist check, reported to the observer.
type Decision string

const (
	Allowed Decision = "allow"
	Denied  Decision = "deny"
	// AdmittedByGate marks a connection the static allowlist denied but a
	// gatekeeper admitted at runtime. It is distinct from Allowed so a run can be
	// honest about egress it permitted beyond the declared manifest.
	AdmittedByGate Decision = "gate"
	// Refused marks a connection turned away at the concurrency limit, before its
	// CONNECT was read - so it carries no host or port. It is reported so a run that
	// floods the proxy is not counted as one that never touched the network.
	Refused Decision = "refused"
	// GateDenied marks a connection the static allowlist did not permit and a gatekeeper,
	// consulted about it, refused. It is the negative half of AdmittedByGate and is
	// distinct from Denied for the same reason: the operator action differs. A Denied
	// destination is fixed by naming it in the manifest; a GateDenied one was named to a
	// supervisor who said no, which under the prompt-on-every-host mode (an empty
	// network: block and a gate) is every refusal there is.
	GateDenied Decision = "gate-deny"
	// Untunneled marks a request the proxy refused because it was not a CONNECT: the
	// shape a client sends for plain http:// through a proxy. It is distinct from Denied
	// because no rule can fix it - the destination may be granted and still never carry
	// traffic - and distinct from a bare parse failure because it names the destination
	// the request line addressed.
	Untunneled Decision = "untunneled"
	// GuardBlocked marks a connection the allowlist (or a gate) permitted by name but
	// the upstream guard then refused, because the name resolved to an address the
	// sandbox must not reach. It is distinct from Denied because the two call for
	// different operator action - widening the allowlist cannot fix a guard block,
	// while naming the address as an explicit IP rule can - and the client is told
	// nothing that separates the guard's refusal from an ordinary dial failure, so
	// the observer is the only place the distinction survives.
	GuardBlocked Decision = "blocked"
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

	// gate decides a host the static allowlist does not permit. Nil means deny,
	// preserving the declarative box behavior; see WithGatekeeper.
	gate func(ctx context.Context, host, port string) bool

	// refuse records each CONNECT and then refuses it, never opening an upstream.
	// Profiling uses it to learn a script's intended destinations without letting
	// the script's data leave the host.
	refuse bool

	// discoverAAAA looks up ipv4only.arpa's AAAA records for RFC 7050 NAT64
	// discovery; nil disables it. Set once before Serve, then read-only. See nat64.go.
	discoverAAAA func(ctx context.Context) ([]net.IP, error)

	// nat64 holds the NAT64 prefixes discovered at Serve start. Written once, before
	// any handler runs, so concurrent classify reads need no lock. The served guard
	// is what makes "once" true: a second Serve would rewrite it under live handlers.
	nat64 []nat64Prefix

	// nat64Inconclusive records that discovery could not rule out a site NAT64
	// prefix - the resolver never answered - so classify must fail closed on an
	// undecodable IPv6. Written and read under the same once-before-Serve
	// discipline as nat64.
	nat64Inconclusive bool

	// served marks that Serve has been entered, so a Proxy is used at most once.
	served atomic.Bool
}

// Option configures a Proxy.
type Option func(*Proxy)

// WithDialer overrides how upstream connections are made.
func WithDialer(dial func(ctx context.Context, network, addr string) (net.Conn, error)) Option {
	return func(p *Proxy) { p.dial = dial }
}

// WithObserver installs a callback invoked for every allow/deny decision. It runs
// on the deciding connection's goroutine, and for a Refused decision on Serve's
// accept goroutine, so it must not block: a slow observer stalls the connection it
// reports, and on the accept path it stalls every connection behind it. A panic is
// contained and the connection proceeds; the decision it carried is simply lost.
//
// host and port are ATTACKER-CONTROLLED, as they are for WithGatekeeper: sanitize
// before displaying either to a human. A Refused decision carries neither, having
// been made before the CONNECT was read. A GuardBlocked decision carries the CONNECT
// target, not the address it resolved to: the guard's own text names the address, and
// that never leaves the host side.
func WithObserver(observe func(d Decision, host, port string)) Option {
	return func(p *Proxy) { p.observe = observe }
}

// WithGatekeeper supplies a decision for a host the static allowlist does not
// already permit. It is consulted per connection, in that connection's own
// goroutine, so it MAY block to prompt a human - but it must return false once
// ctx is done (the run is ending), or it will pin a handler slot and stall run
// teardown. Nil (unset) means deny, preserving the declarative box behavior.
//
// host and port are ATTACKER-CONTROLLED: a sandboxed target chose them, so a
// crafted hostname can carry terminal escapes or look-alike characters.
// Sanitize before displaying either to a human.
//
// Admission only widens to public hosts: guardUpstream still runs on the dial, so
// a gate can never reach loopback, cloud-metadata, or private space. That rests on
// handle withholding the private-IP literal grant from a gate-admitted connection,
// which is load-bearing and not implied by the gate having been consulted at all:
// the allowlist matches the CONNECT host textually while literalGrantFor matches by
// address, so CONNECT [::ffff:10.0.0.5]:443 against a rule for 10.0.0.5:443 misses
// the rule, reaches the gate, and would carry a grant into private space if the
// grant were derived after admission.
//
// A panic in the gate is treated as a denial (the connection gets a 403 and is
// reported Denied), never swallowed silently.
//
// A pending prompt pins one of the proxy's bounded handler slots with no
// deadline, so a hostile target can fire many undeclared CONNECTs to flood the
// caller with prompts; serializing or rate-limiting them is the caller's job,
// and ctx cancellation is how it sheds that load.
func WithGatekeeper(gate func(ctx context.Context, host, port string) bool) Option {
	return func(p *Proxy) { p.gate = gate }
}

// WithNAT64Discovery enables RFC 7050 NAT64 prefix discovery via lookup, called
// once at Serve start. It lets the egress guard decode a synthesized RFC1918
// target that would otherwise pass as a public IPv6. Production uses
// DefaultNAT64Lookup; tests inject a fake to stay hermetic.
func WithNAT64Discovery(lookup func(ctx context.Context) ([]net.IP, error)) Option {
	return func(p *Proxy) { p.discoverAAAA = lookup }
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
		// Without this a CONNECT to an allowed hostname that resolves to a blackholed
		// address holds its handler slot for the kernel's full SYN retry budget (~127s).
		// connectTimeout bounds only the CONNECT read, so maxConcurrent such requests
		// exhaust the concurrency cap the sandbox is supposed to be unable to exhaust -
		// the run's own egress stops working while the dials sit there.
		Timeout: dialTimeout,
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
// it to report the refusal as GuardBlocked rather than as the connection's own
// decision.
// What the CLIENT is told is deliberately identical to an ordinary dial failure:
// telling the two apart classifies the name against the host's internal DNS.
type blockedUpstreamError struct{ addr string }

func (e *blockedUpstreamError) Error() string {
	return fmt.Sprintf("refusing egress to non-public address %s", e.addr)
}

// guardUpstream rejects connecting to a resolved address that names a
// host-internal or infrastructure target (loopback, link-local including
// 169.254.169.254 cloud metadata, private/ULA, CGNAT, unspecified). Since the
// allowlist matches on the CONNECT hostname, a permitted name that resolves to
// such an address would otherwise let a sandboxed script reach services the host
// can see but the sandbox must not. The exception is an address the CONNECT
// target itself named as an IP literal that a rule names for the port: listing
// 10.0.0.5 and asking for 10.0.0.5 is a deliberate choice to reach it, whereas a
// hostname (or wildcard) resolving there is not. handle decides that per
// connection and carries the verdict in the dial context; see literalGrantOf.
func (p *Proxy) guardUpstream(ctx context.Context, _, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
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
	switch p.classify(ip) {
	case ipHostReserved:
		// Loopback, link-local (incl. cloud metadata), and unspecified name the host
		// itself or its infrastructure. The proxy runs on the host, so dialing these
		// reaches the HOST's own services - never a legitimate sandbox egress target,
		// so no rule may reach them, not even an explicit IP literal.
		return &blockedUpstreamError{addr: ip.String()}
	case ipPrivate:
		// RFC1918/ULA/CGNAT may be a deliberate internal-egress target, but only for
		// the literal grant this connection carries; a permitted hostname resolving
		// there is the SSRF case and stays blocked. A context with no grant (any
		// caller but handle) is treated as no grant, so the guard fails closed.
		if grant := literalGrantOf(ctx); grant == nil || !grant.Equal(ip) {
			return &blockedUpstreamError{addr: ip.String()}
		}
	}
	return nil
}

// literalGrantKey names the per-connection literal grant in the dial context.
type literalGrantKey struct{}

// withLiteralGrant marks a dial as authorized to reach one private IP literal:
// the CONNECT target was that literal and a rule names it for the port. Passing
// the IP rather than the CONNECT host keeps the guard from re-deriving policy
// from an attacker-controlled name - the whole shape of the bug this closes.
func withLiteralGrant(ctx context.Context, ip net.IP) context.Context {
	return context.WithValue(ctx, literalGrantKey{}, ip)
}

// literalGrantOf returns the private IP literal this dial may reach, or nil.
func literalGrantOf(ctx context.Context) net.IP {
	ip, _ := ctx.Value(literalGrantKey{}).(net.IP)
	return ip
}

// literalGrantFor returns the IP a literal CONNECT target is authorized to
// reach, or nil. It is non-nil only when host is an IP literal and some rule
// names that same IP - compared as addresses, so a rule spelled ::ffff:10.0.0.5
// grants a CONNECT to 10.0.0.5 - with a port pattern covering port. A wildcard or
// hostname rule matching a literal target grants nothing: the exemption is for a
// rule that deliberately names the address.
func (p *Proxy) literalGrantFor(host, port string) net.IP {
	// Strip an IPv6 zone id, as guardUpstream does, so the two layers agree on the
	// address a zoned literal names rather than diverging on the spelling.
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	for _, r := range p.rules {
		if rip := net.ParseIP(r.Host); rip != nil && rip.Equal(ip) && policy.PortMatches(r.Port, port) {
			return ip
		}
	}
	return nil
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

// isIPv6SiteLocal reports whether ip is in the deprecated IPv6 site-local range
// fec0::/10 (RFC 3879). net.IP has no predicate for it - IsPrivate matches only ULA
// fc00::/7 and IsLinkLocalUnicast only fe80::/10 - so an address in it would classify
// as public. It is deprecated and unrouted on modern networks, but a host that still
// routes it could otherwise be reached through a permitted hostname resolving there.
func isIPv6SiteLocal(ip net.IP) bool {
	ip16 := ip.To16()
	return ip16 != nil && ip.To4() == nil && ip16[0] == 0xfe && ip16[1]&0xc0 == 0xc0
}

// classifyIP groups ip for the egress guard. An IPv6 transition address embeds an
// IPv4 that To4 does not surface, so a synthesized address (DNS64/NAT64 is the
// live case on IPv6-only subnets) is classified by its embedded IPv4.
func classifyIP(ip net.IP) ipClass {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() ||
		ip.IsUnspecified() || isIPv6SiteLocal(ip) {
		return ipHostReserved
	}
	if ip.IsPrivate() {
		return ipPrivate
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		// Never a valid egress destination, so denied even when a rule names the
		// literal: this-network 0.0.0.0/8 (IsUnspecified catches only 0.0.0.0
		// itself), RFC 2544 benchmarking 198.18.0.0/15, and reserved 240.0.0.0/4
		// (which subsumes the 255.255.255.255 limited broadcast).
		case v4[0] == 0,
			v4[0] == 198 && v4[1]&0xfe == 18,
			v4[0]&0xf0 == 240:
			return ipHostReserved
		// CGNAT 100.64.0.0/10 (RFC 6598) is not covered by IsPrivate but names
		// carrier/infrastructure space just the same.
		case v4[0] == 100 && v4[1]&0xc0 == 64:
			return ipPrivate
		}
		return ipPublic
	}
	if isRFC8215LocalUse(ip) {
		return classifyRFC8215(ip)
	}
	if embedded := embeddedIPv4(ip); embedded != nil {
		return classifyIP(embedded)
	}
	return ipPublic
}

// isRFC8215LocalUse reports whether ip is in 64:ff9b:1::/48, the local-use prefix
// RFC 8215 reserves for a site's own NAT64.
func isRFC8215LocalUse(ip net.IP) bool {
	ip16 := ip.To16()
	return ip16 != nil && ip.To4() == nil && bytes.Equal(ip16[:6], []byte{0x00, 0x64, 0xff, 0x9b, 0x00, 0x01})
}

// classifyRFC8215 classifies an address in the local-use /48. Unlike the
// well-known prefix, that /48 is a container a site carves its own Pref64 out of
// at any RFC 6052 length, so the embedded IPv4 has no fixed position. The address
// is therefore never public here: local-use space is not globally routable, so it
// is at least private whatever it wraps, and the decode only has to find the one
// verdict that is stricter still - a target naming the host itself, which no rule
// may reach even by literal. Every length the container admits is tried, so a
// wrapped metadata address is caught whichever carve produced it.
//
// A length whose layout the address does not actually satisfy is skipped, or a
// carve shorter than the candidate would be read at offsets that fall on its zero
// padding and make almost anything in the /48 look host-reserved. RFC 6052 sec 2.2
// pins two things a real carve must show: the u-octet at byte 8 is zero below /96,
// and every byte after the embedded IPv4 is zero. An all-zero candidate is padding
// rather than this-network, so it is skipped too.
//
// This is not exact. A carve SHORTER than the candidate length can still satisfy
// both rules and read as some other address - a /48-wrapped 8.127.3.4 looks like
// 127.3.4.0 at /56 - so the escalation can over-refuse. That costs a literal rule
// naming an address inside a non-routable /48, which is the cheap direction to be
// wrong in.
func classifyRFC8215(ip net.IP) ipClass {
	ip16 := ip.To16()
	for _, length := range rfc6052Lengths {
		if length < 48 {
			continue
		}
		if length < 96 && ip16[8] != 0 {
			continue
		}
		pos := rfc6052Positions[length]
		if !bytes.Equal(ip16[pos[3]+1:], make([]byte, 15-pos[3])) {
			continue
		}
		v4 := net.IPv4(ip16[pos[0]], ip16[pos[1]], ip16[pos[2]], ip16[pos[3]])
		if v4.IsUnspecified() {
			continue
		}
		if classifyIP(v4) == ipHostReserved {
			return ipHostReserved
		}
	}
	return ipPrivate
}

// embeddedIPv4 returns the IPv4 carried by an IPv6 transition address, or nil.
// It covers the NAT64 well-known prefix 64:ff9b::/96 and 6to4 (2002::/16). The
// RFC 8215 local-use /48 has no fixed embedding position and is handled by
// classifyRFC8215 instead. Everything else is left undecoded: operator-specific
// prefixes, Teredo, IPv4-translated ::ffff:0:0/96, and ISATAP, whose ::0:5efe:a.b.c.d
// suffix sits under an arbitrary /64 and so cannot be recognized by prefix at all. Such
// an address classifies on its own merits, which is why the site prefix a DNS64 network
// actually uses is learned by discovery instead (see nat64.go), and why the allowlist
// must still permit the hostname at all.
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
	// Deprecated IPv4-compatible ::a.b.c.d (all-zero high 96 bits) also carries a v4
	// in the last 4 bytes. ::1 and :: reach classifyIP's loopback/unspecified checks
	// before this, so a value here is a real embedded address, not those.
	if bytes.Equal(ip16[:12], make([]byte, 12)) {
		return net.IPv4(ip16[12], ip16[13], ip16[14], ip16[15])
	}
	return nil
}

// maxConcurrent bounds how many tunnels the proxy handles at once. It caps the
// host-side goroutines and file descriptors untrusted code can pin by opening
// connections in a loop; the cgroup limits confine the sandbox, but not this
// host process. The limit is generous enough that no legitimate script reaches it; a
// script that does is refused rather than served. What that bounds is BENTO's own
// contribution - nothing here sets an rlimit or otherwise speaks for the host, which
// can still hit fd exhaustion from processes bento knows nothing about. Accept's own
// retry below is what keeps that from ending the run's egress.
const maxConcurrent = 512

// Accept retry bounds after a recoverable error: start short and double to the ceiling,
// so a condition that clears in milliseconds costs milliseconds while one that persists
// does not spin.
const (
	acceptRetryStart = 5 * time.Millisecond
	acceptRetryMax   = time.Second
)

// recoverableAccept reports whether an Accept error is a transient condition the listener
// survives. ENFILE and EMFILE are fd exhaustion - system-wide or this process's - which
// processes outside bento cause and which clears on its own; ECONNABORTED is a client
// that went away between SYN and accept. net.ErrClosed is deliberately excluded: the
// closer goroutine uses exactly that to end the run, so retrying it would spin through
// teardown. Errors are matched by errno rather than through net.Error.Temporary, which is
// deprecated and reports true for cases (a deadline) this must not retry blindly.
func recoverableAccept(err error) bool {
	if errors.Is(err, net.ErrClosed) {
		return false
	}
	return errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.EMFILE) ||
		errors.Is(err, syscall.ENFILE)
}

// Serve accepts connections on l and enforces the allowlist on each until ctx is
// cancelled or l is closed. It returns when l stops accepting.
//
// A Proxy serves at most once. NAT64 discovery writes p.nat64 unlocked on the
// promise that no handler is running yet, which a second Serve would break, so
// re-entry is an error rather than a data race under live tunnels.
func (p *Proxy) Serve(ctx context.Context, l net.Listener) error {
	if !p.served.CompareAndSwap(false, true) {
		return errors.New("proxy: Serve called more than once on the same Proxy")
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrent)
	// Derive a cancellable context so the closer goroutine below always exits,
	// including when Accept returns an error while the caller's ctx is still live.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Learn the host's NAT64 prefix once, before any connection is handled, so
	// classify reads p.nat64 without a lock. Bounded so a slow or dead resolver
	// delays run start by at most this; a deadline that expires answers nothing, so
	// discovery records that and classify fails closed rather than assuming no DNS64.
	discoverCtx, discoverCancel := context.WithTimeout(ctx, nat64DiscoveryTimeout)
	p.discoverNAT64(discoverCtx)
	discoverCancel()
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	retryDelay := time.Duration(0)
	for {
		c, err := l.Accept()
		if err != nil {
			// A recoverable error is the HOST's condition, not this run's, and the fence
			// must outlive it: returning would leave the socket still bind-mounted into the
			// sandbox with nothing serving it, so every later CONNECT meets a dead socket
			// instead of an allowlist decision. A run degraded that way for its whole
			// remaining lifetime is strictly worse than a pause of milliseconds, which is
			// why this is a retry and not a report.
			if ctx.Err() == nil && recoverableAccept(err) {
				if retryDelay == 0 {
					retryDelay = acceptRetryStart
				} else {
					retryDelay = min(retryDelay*2, acceptRetryMax)
				}
				// The wait is on ctx as well as the timer: a backoff can straddle teardown,
				// and a run that ends mid-delay must stop accepting now rather than serve out
				// the delay first. The next Accept then meets the closed listener and takes
				// the terminal path below.
				t := time.NewTimer(retryDelay)
				select {
				case <-ctx.Done():
					t.Stop()
				case <-t.C:
				}
				continue
			}
			// Whether the run had already ended is read HERE, not after the drain: an
			// open tunnel holds wg.Wait until run teardown, so a listener that died on
			// its own at minute one would find ctx cancelled by the time the last
			// handler finished and report a clean end. What the caller needs to know is
			// whether the run was over when accepting stopped.
			ended := ctx.Err() != nil
			wg.Wait()
			if ended {
				return nil
			}
			return err
		}
		// The listener is healthy again, so the next transient error starts its backoff
		// from the bottom rather than inheriting an old ceiling.
		retryDelay = 0
		select {
		case sem <- struct{}{}:
			wg.Go(func() {
				defer func() { <-sem }()
				p.handle(ctx, c)
			})
		default:
			// At capacity: refuse rather than let the host process grow unbounded. The
			// refusal is recorded before the client is told, so a caller that observes
			// the 503 has already observed the report.
			p.report(Refused, "", "")
			writeStatus(c, "503 Service Unavailable", "bento egress proxy is at its connection limit")
			c.Close()
		}
	}
}

// dialTimeout bounds a single upstream connect. It is generous next to a healthy TCP
// handshake and short next to the kernel's SYN retry budget, which is what it exists to
// cut short; a legitimate destination that needs longer than this is already failing.
const dialTimeout = 15 * time.Second

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
		// A non-CONNECT request that named its destination is reported before the refuse
		// branch below, so profiling records it too. Without this the destination is lost
		// entirely: the client sees a 400 that names no policy, and a manifest rule can
		// grant the host and port while nothing ever tunnels to them.
		var untunneled *untunneledError
		if errors.As(err, &untunneled) {
			p.report(Untunneled, untunneled.host, untunneled.port)
		}
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

	admittedByGate := false
	if !policy.Allows(p.rules, host, port) {
		if !p.callGate(ctx, host, port) {
			// Which of the two refused is recorded, because the remedy differs and only
			// this frame knows: downstream sees one destination and one verdict. A gate
			// that panicked is reported here too - it was consulted and did not admit,
			// which is what the report claims and all it claims.
			decision := Denied
			if p.gate != nil {
				decision = GateDenied
			}
			p.report(decision, host, port)
			// The body is plaintext so it surfaces in the script's own error output, so a
			// curl/requests user sees exactly which host was refused, not a blank failure.
			// It is the SAME body either way, and deliberately says only what the allowlist
			// did: naming a gate would tell a target whose every request is refused that a
			// human is in the loop, which it could otherwise learn only by having some
			// request admitted - and that is what it wants to know before trying to fatigue
			// them into a yes. The gate is consulted only after the allowlist misses, so
			// this text is true of both. The distinction the operator needs survives in the
			// decision above, host-side, where the target cannot read it.
			writeStatus(client, "403 Forbidden",
				fmt.Sprintf("bento denied egress to %s:%s (not in the manifest's network allowlist)", host, port))
			return
		}
		admittedByGate = true
	}

	// A gate admission is reported distinctly from a manifest allow so the run
	// stays honest about egress it permitted beyond the declared policy. The
	// blocked-upstream refusal below reports GuardBlocked instead: the guard overrides
	// the gate, so a gate-admitted host resolving to non-public space was never
	// admitted past it.
	decision := Allowed
	if admittedByGate {
		decision = AdmittedByGate
	}

	// The literal grant is decided here, where the CONNECT target and the rules are
	// both in scope, and never re-derived downstream: guardUpstream sees only which
	// private address (if any) this connection may reach.
	dialCtx := ctx
	if !admittedByGate {
		if grant := p.literalGrantFor(host, port); grant != nil {
			dialCtx = withLiteralGrant(ctx, grant)
		}
	}
	upstream, err := p.dial(dialCtx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		var blocked *blockedUpstreamError
		if errors.As(err, &blocked) {
			// Reported GuardBlocked, but answered exactly as an ordinary dial failure is. A
			// distinct refusal here told the client that the name resolved into
			// non-public space, which under a permissive allowlist (`bento profile
			// --allow-network` runs *:*) lets a confined process classify arbitrary
			// names against the host's internal DNS one CONNECT at a time. Naming the
			// RESOLVED address would enumerate it outright, which is why the dial error
			// stays out of the shared body too - a *net.OpError carries the Addr in its
			// own text. The guard still refuses before any SYN while a real dial costs an
			// RTT, so this removes the textual oracle, not the timing one.
			p.report(GuardBlocked, host, port)
			writeStatus(client, "502 Bad Gateway", fmt.Sprintf("bento could not reach %s:%s", host, port))
			return
		}
		p.report(decision, host, port)
		writeStatus(client, "502 Bad Gateway", fmt.Sprintf("bento could not reach %s:%s", host, port))
		return
	}
	defer upstream.Close()

	// Cancellation must also interrupt the upstream-side copy loop, which is
	// otherwise blocked on Read until the idle timeout. Pairs with stopClient above.
	stopUpstream := context.AfterFunc(ctx, func() { upstream.Close() })
	defer stopUpstream()

	p.report(decision, host, port)
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	// The client half is read through br, not client, because a pipelining client
	// may have already sent its TLS ClientHello into br's buffer along with the
	// CONNECT headers; reading the raw conn would drop those bytes and break the
	// handshake.
	tunnel(br, client, upstream)
}

// report hands a decision to the observer, containing a panic there rather than
// letting it escape. The observer is embedder code called from two places with no
// recover of their own worth relying on: Serve's accept goroutine, where a panic
// would take down the whole bento process mid-run, and handle, whose blanket
// recover would swallow it into a dropped connection with no status line. Neither
// outcome should follow from a faulty callback, so the decision is delivered
// best-effort and the connection proceeds.
func (p *Proxy) report(d Decision, host, port string) {
	if p.observe == nil {
		return
	}
	defer func() { _ = recover() }()
	p.observe(d, host, port)
}

// callGate consults the gatekeeper for a host the allowlist did not permit,
// returning whether to admit it. A nil gate denies. A panic is recovered here
// and treated as a denial: handle's own recover would otherwise swallow a
// panicking embedder gate into a silently dropped connection with no 403 and no
// report(), so the outcome would neither surface nor even count.
func (p *Proxy) callGate(ctx context.Context, host, port string) (admit bool) {
	if p.gate == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			admit = false
		}
	}()
	return p.gate(ctx, host, port)
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
// plaintext HTTP, so there is nothing to inspect or rewrite in a request body. A
// non-CONNECT request that named a destination is refused through untunneledError,
// which carries that destination so the refusal can be reported rather than read as a
// parse failure.
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
		if len(fields) >= 2 {
			if host, port, ok := absoluteURITarget(fields[1]); ok {
				return "", "", nil, &untunneledError{host: host, port: port}
			}
		}
		return "", "", nil, fmt.Errorf("expected a CONNECT request")
	}
	host, port, err = net.SplitHostPort(fields[1])
	if err != nil {
		return "", "", nil, fmt.Errorf("malformed target %q: %w", fields[1], err)
	}
	// The DNS root label is a spelling of the same name, and policy.Allows already
	// normalizes it away - but literalGrantFor parses the host as an address, where
	// "10.0.0.5." is not one. Left standing, a CONNECT in that spelling passes an
	// explicit-IP rule's allowlist check and then loses the grant the rule exists to
	// give, so the rule is silently inert. Strip it here, on the canonicalPort
	// precedent below: one spelling at every layer. Exactly one label is stripped, as
	// normalizeHost strips one. A doubled dot survives both and the two layers do
	// still part ways there - but only in the safe direction: net.ParseIP rejects any
	// remaining dot, so no grant can outlive one, and the guard then refuses
	// indistinguishably from a dial failure.
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "", "", nil, fmt.Errorf("empty target host")
	}
	// A hostname, IP literal, or port never carries a deceiving character. One here is
	// a target crafted to mislead a host-side render of the egress log: host and port
	// flow into report() (the run's admitted-hosts list) and the 403 body, and the
	// recorded host reaches every other consumer of the observation. Hold the target to
	// the same screen policy.Validate applies to a path, so the refusal happens here
	// rather than in each consumer. That screen also rejects an undecodable byte, which
	// is what catches a raw 8-bit C1: 0x9b alone decodes as RuneError, not as U+009B, so
	// no rune predicate ever sees the CSI the terminal would act on.
	for _, s := range []string{host, port} {
		if r, ok := policy.FirstUnsafeRune(s); ok {
			return "", "", nil, fmt.Errorf("target contains %s", policy.DescribeUnsafeRune(r))
		}
	}
	// net.SplitHostPort hands back whatever sat after the colon: "08080" and
	// "0x1f90" both survive it, but the dialer resolves the first to 8080 and
	// rejects the second. A non-canonical port would be matched against the
	// allowlist and reported in one spelling while the connection is dialed in
	// another, and guardUpstream - which splits the address the dialer already
	// resolved - would disagree with Allows about the port of the same
	// connection. Refuse it at the boundary so every layer sees one spelling.
	if !canonicalPort(port) {
		return "", "", nil, fmt.Errorf("malformed target port %q", port)
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

// untunneledError refuses a request that is not a CONNECT but named the destination it
// wanted, which is what a client sends for plain http:// through a proxy. The proxy
// relays no plaintext HTTP (see readConnect), so the destination is recorded and refused
// rather than forwarded, and the text says which of the two remedies applies - the
// client's scheme, or the client's proxy mode - because no manifest edit is one of them.
type untunneledError struct{ host, port string }

func (e *untunneledError) Error() string {
	return fmt.Sprintf("bento's egress proxy tunnels CONNECT only, so the plain-HTTP request to %s:%s was refused; use https, or have the client issue CONNECT", e.host, e.port)
}

// absoluteURITarget returns the destination a non-CONNECT request line addressed, when
// that line carries the absolute URI a client sends through a proxy. It is held to
// exactly the screen readConnect applies to a CONNECT target, because it reaches exactly
// the same places: report(), the run's recorded destinations, and a host-side render of
// them. A target that fails the screen is not reported with a destination at all rather
// than carrying an unscreened one - the refusal happens either way.
func absoluteURITarget(target string) (host, port string, ok bool) {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return "", "", false
	}
	// Only the two schemes a proxy is asked to carry get a default port. Anything else
	// is not a destination this proxy would have tunneled even in principle, so it is
	// refused without a named destination rather than guessed at.
	switch u.Scheme {
	case "http":
		port = "80"
	case "https":
		port = "443"
	default:
		return "", "", false
	}
	if p := u.Port(); p != "" {
		port = p
	}
	// Strip the root label on the CONNECT path's precedent: one spelling at every layer,
	// so a destination reported here matches the rule a user would write for it.
	host = strings.TrimSuffix(u.Hostname(), ".")
	if host == "" || !canonicalPort(port) {
		return "", "", false
	}
	for _, s := range []string{host, port} {
		if _, unsafe := policy.FirstUnsafeRune(s); unsafe {
			return "", "", false
		}
	}
	return host, port, true
}

// canonicalPort reports whether s spells a port exactly as the dialer will
// resolve it: decimal digits, no leading zero, within the 16-bit range.
func canonicalPort(s string) bool {
	if s == "" || len(s) > 5 || (len(s) > 1 && s[0] == '0') {
		return false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n <= 65535
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
		_ = cw.CloseWrite()
		return
	}
	c.SetDeadline(time.Now())
}
