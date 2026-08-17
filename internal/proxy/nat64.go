package proxy

import (
	"bytes"
	"context"
	"errors"
	"net"
	"slices"
	"time"
)

// nat64DiscoveryTimeout bounds the one-time ipv4only.arpa lookup at Serve start so
// a slow or unreachable resolver delays run start by at most this. Expiring is not
// an answer, so it leaves discovery inconclusive and classify fails closed.
const nat64DiscoveryTimeout = 3 * time.Second

// NAT64 prefix discovery (RFC 7050). On a DNS64/NAT64 network a resolver
// synthesizes an AAAA for a v4-only host, embedding the IPv4 the gateway will
// route to. If that IPv4 is RFC1918, a permitted public hostname can be steered
// (via attacker-controlled DNS) to reach the LAN - guardUpstream sees only the
// synthesized IPv6, which classifyIP passes as public. classifyIP decodes just the
// well-known prefix 64:ff9b::/96 and 6to4, so a site-specific Pref64 slips through.
//
// Discovery learns the site prefix without a heuristic: resolving the well-known
// name ipv4only.arpa yields a synthesized AAAA that embeds the fixed IPv4
// 192.0.0.170 / 192.0.0.171 (RFC 7050 sec 3), and the embedding position reveals
// the prefix and its length. With no DNS64 (the common case) nothing is
// synthesized and discovery finds nothing, leaving classifyIP's well-known
// handling as the only decoder - exactly today's behavior.

const ipv4onlyName = "ipv4only.arpa"

// ipv4onlyV4 are the fixed IPv4 addresses of ipv4only.arpa (RFC 7050 sec 2.2). A
// synthesized AAAA embeds one of these; finding it locates the prefix.
var ipv4onlyV4 = [][4]byte{{192, 0, 0, 170}, {192, 0, 0, 171}}

// rfc6052Lengths are the valid NAT64 prefix lengths, longest first so the most
// specific (least likely coincidental) embedding wins when more than one explains
// a synthesized address.
var rfc6052Lengths = []int{96, 64, 56, 48, 40, 32}

// rfc6052Positions gives the byte offsets carrying the embedded IPv4 (a,b,c,d) for
// each prefix length. Byte 8 is the reserved u-octet and is skipped for prefixes
// shorter than /96 (RFC 6052 sec 2.2).
var rfc6052Positions = map[int][4]int{
	32: {4, 5, 6, 7},
	40: {5, 6, 7, 9},
	48: {6, 7, 9, 10},
	56: {7, 9, 10, 11},
	64: {9, 10, 11, 12},
	96: {12, 13, 14, 15},
}

// nat64Prefix is a discovered Pref64: the leading prefixLen bits identify the
// synthesis, and the embedded IPv4 is read at rfc6052Positions[prefixLen]. The
// array is comparable, so a nat64Prefix works as a map key for de-duplication.
type nat64Prefix struct {
	prefix    [16]byte
	prefixLen int
}

// embeddedV4 returns the IPv4 that ip carries under this prefix, or nil if ip does
// not match the prefix bits (so it was not synthesized by this Pref64).
func (n nat64Prefix) embeddedV4(ip net.IP) net.IP {
	ip16 := ip.To16()
	if ip16 == nil || ip.To4() != nil {
		return nil
	}
	if !bytes.Equal(ip16[:n.prefixLen/8], n.prefix[:n.prefixLen/8]) {
		return nil
	}
	pos := rfc6052Positions[n.prefixLen]
	return net.IPv4(ip16[pos[0]], ip16[pos[1]], ip16[pos[2]], ip16[pos[3]])
}

// deriveNAT64Prefix returns the Pref64 that synthesized addr for one of the fixed
// ipv4only.arpa IPv4s, or ok=false if addr embeds neither at any valid length (a
// plain public AAAA, which ipv4only.arpa has none of on a DNS64 network).
func deriveNAT64Prefix(addr net.IP) (nat64Prefix, bool) {
	ip16 := addr.To16()
	if ip16 == nil || addr.To4() != nil {
		return nat64Prefix{}, false
	}
	for _, length := range rfc6052Lengths {
		pos := rfc6052Positions[length]
		v4 := [4]byte{ip16[pos[0]], ip16[pos[1]], ip16[pos[2]], ip16[pos[3]]}
		if slices.Contains(ipv4onlyV4, v4) {
			var p nat64Prefix
			copy(p.prefix[:], ip16[:length/8]) // keep prefix bits, drop embedded/suffix
			p.prefixLen = length
			return p, true
		}
	}
	return nat64Prefix{}, false
}

// DefaultNAT64Lookup resolves ipv4only.arpa's AAAA records via the pure-Go
// resolver, following the host's DNS64 if one is configured. It is the production
// lookup for WithNAT64Discovery; the pure-Go resolver matches the one the proxy
// dials through, so discovery and egress see the same DNS.
func DefaultNAT64Lookup(ctx context.Context) ([]net.IP, error) {
	r := &net.Resolver{PreferGo: true}
	return r.LookupIP(ctx, "ip6", ipv4onlyName)
}

// discoverNAT64 records any site NAT64 prefix a DNS64 resolver synthesized, so
// classify can decode a synthesized RFC1918 target that classifyIP alone passes as
// public.
//
// An answer is conclusive only when it is one of the two shapes ipv4only.arpa can
// honestly have: a synthesized AAAA, which gives the prefix, or no AAAA at all
// (NXDOMAIN as *net.DNSError with IsNotFound, or an empty result), which proves
// there is no synthesis to decode. Anything else answers nothing and is recorded as
// inconclusive on the Proxy, so classify fails closed for what it can no longer rule
// out: an error - the resolver unreachable, refused, or the discovery deadline
// expiring - and equally an AAAA that derives no prefix, since treating either as
// "no DNS64" is the fail-open the site-prefix decode exists to close.
func (p *Proxy) discoverNAT64(ctx context.Context) {
	if p.discoverAAAA == nil {
		return
	}
	// No egress surface means nothing a synthesized address could reach, so skip the
	// lookup rather than pay it at every run's proxy start. A gatekeeper can admit
	// beyond the static rules, so its presence still warrants discovery.
	if len(p.rules) == 0 && p.gate == nil {
		return
	}
	addrs, err := p.discoverAAAA(ctx)
	if err != nil {
		var dnsErr *net.DNSError
		p.nat64Inconclusive = !errors.As(err, &dnsErr) || !dnsErr.IsNotFound
		return
	}
	seen := make(map[nat64Prefix]bool)
	for _, a := range addrs {
		pfx, ok := deriveNAT64Prefix(a)
		if !ok {
			// ipv4only.arpa has no real AAAA, so an address that embeds neither fixed
			// IPv4 at any RFC 6052 length was not synthesized by a scheme this can read
			// - a nonstandard DNS64, a captive portal, a blockpage. It neither yields a
			// prefix nor proves there is none, which is the inconclusive case.
			p.nat64Inconclusive = true
			continue
		}
		if !seen[pfx] {
			seen[pfx] = true
			p.nat64 = append(p.nat64, pfx)
		}
	}
}

// mayWrapUnroutableV4 reports whether any RFC 6052 position of ip decodes to an IPv4 a
// name must not steer the sandbox at: RFC1918, CGNAT, loopback or link-local. It asks the
// prefix-independent question the discovered prefixes cannot - whether these bytes COULD
// be a synthesis wrapping such an address - so it is a guess about an address rather than
// a decode of one, and only the classes an attacker would actually aim at count.
//
// Deliberately not every class classifyIP refuses: 0.0.0.0/8 and 240/4 are what a native
// AAAA's zero and high bytes read as at these offsets, and no NAT64 gateway routes a
// synthesis to them, so counting them would refuse ordinary IPv6 destinations to close
// nothing. The benchmarking range is kept - it costs one address in 32768 per offset,
// where those two cost a large share of all native AAAAs.
//
// Below /96 the u-octet (byte 8) is reserved and MUST be zero in a real RFC 6052
// embedding, which is why rfc6052Positions skips it there. A nonzero byte 8 therefore
// rules those lengths out, and skipping them is what keeps the false-positive rate down
// on addresses with a dense interface identifier - the ones most likely to spell
// something private by accident.
func mayWrapUnroutableV4(ip net.IP) bool {
	ip16 := ip.To16()
	if ip16 == nil || ip.To4() != nil {
		return false
	}
	for _, length := range rfc6052Lengths {
		if length < 96 && ip16[8] != 0 {
			continue
		}
		pos := rfc6052Positions[length]
		v4 := net.IPv4(ip16[pos[0]], ip16[pos[1]], ip16[pos[2]], ip16[pos[3]])
		if v4.IsPrivate() || v4.IsLoopback() || v4.IsLinkLocalUnicast() {
			return true
		}
		b := v4.To4()
		if b[0] == 100 && b[1]&0xc0 == 64 {
			return true
		}
		if b[0] == 198 && b[1]&0xfe == 18 {
			return true
		}
	}
	return false
}

// classify groups ip for the egress guard, extending classifyIP with any
// discovered NAT64 prefix: a synthesized address classifyIP passes as public is
// re-checked against its embedded IPv4, so a Pref64-wrapped RFC1918 target is
// classified private (and thus refused unless a rule names its literal).
//
// When discovery was inconclusive, an IPv6 that no transition prefix decodes may
// be a site synthesis wrapping RFC1918, and nothing left can tell. It is private
// rather than public: still reachable when a rule names the literal, refused when
// only a hostname pointed there, which is the SSRF shape this guards.
//
// The cost is real: after one failed lookup, every allowlisted host reachable ONLY
// over IPv6 is refused for the rest of the run, since a hostname rule grants no
// literal. A dual-stack host survives on the dialer's fallback to its A records.
func (p *Proxy) classify(ip net.IP) ipClass {
	c, _ := p.classifyNAT64(ip)
	return c
}

// classifyNAT64 is classify plus why it landed there: blackout is true only when the
// address is public to classifyIP, carries no transition prefix this can decode, and
// reaches ipPrivate for no other reason than that discovery was inconclusive. That is
// the refusal nothing else in the run record can account for - an allowlisted host
// reachable only over IPv6, refused because one lookup failed at proxy start - and
// guardUpstream counts it where the refusal is actually taken, so a host with no
// working DNS that never dialed such an address reports nothing.
func (p *Proxy) classifyNAT64(ip net.IP) (class ipClass, blackout bool) {
	c := classifyIP(ip)
	if c != ipPublic || ip.To4() != nil {
		return c, false
	}
	// A site may publish more than one Pref64, and embeddedV4 matches on prefix bits
	// alone, so a short prefix matches every address under it and decodes a different
	// IPv4 than the specific one does. Taking the strictest verdict over all matches
	// keeps the guard independent of the order discovery happened to append them.
	// Host-reserved is the strictest of the three: handle refuses it outright, where
	// private is still reachable under a matching literal grant.
	matched := false
	strictest := c
	for _, pfx := range p.nat64 {
		v4 := pfx.embeddedV4(ip)
		if v4 == nil {
			continue
		}
		matched = true
		switch classifyIP(v4) {
		case ipHostReserved:
			return ipHostReserved, false
		case ipPrivate:
			strictest = ipPrivate
		case ipPublic:
			// A public decode is what a Pref64 ordinarily wraps, and it cannot lower a
			// verdict another prefix has already raised.
		}
	}
	if matched {
		return strictest, false
	}
	// Discovery learns the prefixes the resolver synthesized ipv4only.arpa under, which on
	// a site publishing more than one Pref64 need not be all of them: an address wrapped
	// by a prefix discovery never saw reaches here unmatched, and returning c would pass a
	// synthesized RFC1918 target as public - the SSRF shape this decode exists to close.
	// So on a site known to run DNS64, an address whose bytes could spell a synthesis of
	// something unroutable is private - reachable under a literal grant, refused when only
	// a hostname pointed there, which is the same verdict and the same reasoning as the
	// inconclusive case below. It is private rather than host-reserved even where the
	// decode is loopback: nothing here proves the address IS a synthesis, and an outright
	// refusal is not a verdict to reach on a guess. Only the dangerous decodes count, so
	// native IPv6 egress on a DNS64 site keeps working - see mayWrapUnroutableV4.
	if len(p.nat64) > 0 && mayWrapUnroutableV4(ip) {
		return ipPrivate, false
	}
	if p.nat64Inconclusive && embeddedIPv4(ip) == nil {
		return ipPrivate, true
	}
	return c, false
}
