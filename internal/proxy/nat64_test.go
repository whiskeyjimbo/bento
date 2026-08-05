package proxy

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/whiskeyjimbo/bento/policy"
)

func fakeLookup(addrs ...net.IP) func(context.Context) ([]net.IP, error) {
	return func(context.Context) ([]net.IP, error) { return addrs, nil }
}

// egressRules gives the proxy an allow rule so discovery has a surface to protect;
// discoverNAT64 skips the lookup entirely when nothing is allowed.
var egressRules = []policy.NetworkRule{{Host: "*", Port: "443"}}

// A site NAT64 prefix (learned from ipv4only.arpa) must reclassify a synthesized
// RFC1918 target as private so guardUpstream refuses it, while leaving public
// targets - synthesized or unrelated - alone.
func TestNAT64DiscoveryReclassifiesSynthesizedRFC1918(t *testing.T) {
	// Site Pref64 is 2001:db8:1:2:3:4::/96; the DNS64 resolver synthesizes
	// ipv4only.arpa (192.0.0.170) under it.
	synth := net.ParseIP("2001:db8:1:2:3:4:c000:aa")
	p := New(egressRules, WithNAT64Discovery(fakeLookup(synth)))
	p.discoverNAT64(context.Background())
	if len(p.nat64) != 1 || p.nat64[0].prefixLen != 96 {
		t.Fatalf("discovery = %+v, want one /96 prefix", p.nat64)
	}

	cases := []struct {
		name string
		addr string
		want ipClass
	}{
		{"synthesized RFC1918", "2001:db8:1:2:3:4:c0a8:101", ipPrivate}, // 192.168.1.1
		{"synthesized public", "2001:db8:1:2:3:4:808:808", ipPublic},    // 8.8.8.8
		{"unrelated public v6", "2606:4700::1111", ipPublic},            // not under the prefix
	}
	for _, c := range cases {
		if got := p.classify(net.ParseIP(c.addr)); got != c.want {
			t.Errorf("%s: classify(%s) = %d, want %d", c.name, c.addr, got, c.want)
		}
	}
}

// A shorter prefix exercises the RFC 6052 u-octet skip (byte 8 is reserved, the
// embedded IPv4 resumes at byte 9).
func TestNAT64Discovery64Prefix(t *testing.T) {
	build := func(v4 [4]byte) net.IP {
		b := net.ParseIP("2001:db8:aaaa:bbbb::").To16() // /64 prefix in bytes 0-7, byte 8 = u = 0
		b[9], b[10], b[11], b[12] = v4[0], v4[1], v4[2], v4[3]
		return b
	}
	p := New(egressRules, WithNAT64Discovery(fakeLookup(build([4]byte{192, 0, 0, 171}))))
	p.discoverNAT64(context.Background())
	if len(p.nat64) != 1 || p.nat64[0].prefixLen != 64 {
		t.Fatalf("discovery = %+v, want one /64 prefix", p.nat64)
	}
	if got := p.classify(build([4]byte{10, 0, 0, 5})); got != ipPrivate {
		t.Errorf("/64 synthesized 10.0.0.5 classified %d, want ipPrivate (%d)", got, ipPrivate)
	}
}

// With no egress surface (no rules, no gate) discovery is skipped so a run that
// allows nothing does not pay the ipv4only.arpa lookup at proxy start.
func TestNAT64DiscoverySkippedWithoutEgressSurface(t *testing.T) {
	called := false
	p := New(nil, WithNAT64Discovery(func(context.Context) ([]net.IP, error) {
		called = true
		return nil, nil
	}))
	p.discoverNAT64(context.Background())
	if called {
		t.Error("discovery looked up ipv4only.arpa despite no rules and no gatekeeper")
	}
}

// Without discovery the custom-prefix case stays public (the documented baseline),
// while the well-known prefix is still decoded by classifyIP alone.
func TestNAT64WithoutDiscoveryLeavesBaseline(t *testing.T) {
	p := New(nil)
	if got := p.classify(net.ParseIP("2001:db8:1:2:3:4:c0a8:101")); got != ipPublic {
		t.Errorf("without discovery a custom-prefix target should stay public; got %d", got)
	}
	if got := p.classify(net.ParseIP("64:ff9b::c0a8:101")); got != ipPrivate { // 192.168.1.1, well-known
		t.Errorf("well-known NAT64 RFC1918 should classify private; got %d", got)
	}
}

// Every RFC 6052 prefix length must be recognized, and its embedded IPv4 read from
// the right bytes. The byte offsets below are written out from the RFC rather than
// read from rfc6052Positions, because a seed or fixture built from that map would
// move with a mis-indexed entry and agree with it: discovery would fail to derive
// the prefix at all, the reclassification would never be reached, and the test
// would pass while the layout it exists to pin was wrong. Only /96 and /64 are
// otherwise covered, and the short lengths are exactly where the reserved u-octet
// at byte 8 makes the layout easy to get wrong.
func TestNAT64DerivesEveryRFC6052Length(t *testing.T) {
	for _, c := range []struct {
		length int
		at     [4]int // where the embedded IPv4 sits, per RFC 6052 sec 2.2
	}{
		{32, [4]int{4, 5, 6, 7}},
		{40, [4]int{5, 6, 7, 9}},
		{48, [4]int{6, 7, 9, 10}},
		{56, [4]int{7, 9, 10, 11}},
		{64, [4]int{9, 10, 11, 12}},
		{96, [4]int{12, 13, 14, 15}},
	} {
		t.Run(fmt.Sprintf("/%d", c.length), func(t *testing.T) {
			embed := func(v4 [4]byte) net.IP {
				ip := make(net.IP, 16)
				// A documentation prefix (2001:db8::/32) padded out to the length under
				// test, so the prefix bits themselves are public and the verdict can only
				// come from the embedded address.
				copy(ip, []byte{0x20, 0x01, 0x0d, 0xb8})
				for i := 4; i < c.length/8; i++ {
					ip[i] = 0xaa
				}
				for i, pos := range c.at {
					ip[pos] = v4[i]
				}
				return ip
			}

			synth := embed([4]byte{192, 0, 0, 171}) // ipv4only.arpa, as a DNS64 resolver returns it
			pfx, ok := deriveNAT64Prefix(synth)
			if !ok || pfx.prefixLen != c.length {
				t.Fatalf("deriveNAT64Prefix(%v) = %+v, %v; want a /%d prefix", synth, pfx, ok, c.length)
			}

			p := New(egressRules, WithNAT64Discovery(fakeLookup(synth)))
			p.discoverNAT64(t.Context())
			private := embed([4]byte{192, 168, 1, 1})
			// A positive control: the address must be public on its prefix bits alone, or
			// the assertion below would hold without discovery having decoded anything.
			if got := classifyIP(private); got != ipPublic {
				t.Fatalf("%v classifies %d before discovery, so this fixture cannot show discovery working", private, got)
			}
			if got := p.classify(private); got != ipPrivate {
				t.Errorf("192.168.1.1 synthesized under the discovered /%d prefix (%v) classified %d, want ipPrivate (%d)",
					c.length, private, got, ipPrivate)
			}
		})
	}
}

// A resolver that never answers - unreachable, refused, or the discovery deadline
// expiring - leaves a site Pref64 possible and undetected, so an IPv6 no decoder
// understands must stop being treated as plain public space.
func TestNAT64InconclusiveDiscoveryFailsClosed(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
	}{
		{"timeout", &net.DNSError{Err: "i/o timeout", Name: ipv4onlyName, IsTimeout: true, IsTemporary: true}},
		{"refused", &net.DNSError{Err: "connection refused", Name: ipv4onlyName, IsTemporary: true}},
		{"not a DNS error", context.DeadlineExceeded},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := New(egressRules, WithNAT64Discovery(func(context.Context) ([]net.IP, error) {
				return nil, c.err
			}))
			p.discoverNAT64(t.Context())
			if !p.nat64Inconclusive {
				t.Fatal("discovery recorded a conclusive answer despite the resolver never answering")
			}
			if got := p.classify(net.ParseIP("2606:4700::1111")); got != ipPrivate {
				t.Errorf("undecodable IPv6 classified %d, want ipPrivate (%d)", got, ipPrivate)
			}
			// IPv4 is not synthesizable, so the fail-closed classification must not
			// reach it; nor may it override a decode that already answered.
			if got := p.classify(net.ParseIP("8.8.8.8")); got != ipPublic {
				t.Errorf("IPv4 classified %d under inconclusive discovery, want ipPublic (%d)", got, ipPublic)
			}
			if got := p.classify(net.ParseIP("64:ff9b::808:808")); got != ipPublic {
				t.Errorf("well-known-prefix 8.8.8.8 classified %d, want ipPublic (%d)", got, ipPublic)
			}
			// An ISATAP identifier is matched on a tag under an arbitrary /64, so a
			// global address can carry one by coincidence. That is a guess, not a decode,
			// and the demotion here rests on nothing being able to name what the address
			// wraps - so it must not count as an answer the way the prefix decodes above
			// do, or a coincidence would unlock the fail-closed path.
			if got := p.classify(net.ParseIP("2001:db8::200:5efe:8.8.8.8")); got != ipPrivate {
				t.Errorf("ISATAP-tagged IPv6 classified %d under inconclusive discovery, want ipPrivate (%d)", got, ipPrivate)
			}
		})
	}
}

// NXDOMAIN (or an answer with no AAAA) is what a network without DNS64 returns for
// ipv4only.arpa: the resolver answered and proved there is no synthesis, so the
// baseline stands and public IPv6 stays reachable.
func TestNAT64NotFoundIsConclusive(t *testing.T) {
	p := New(egressRules, WithNAT64Discovery(func(context.Context) ([]net.IP, error) {
		return nil, &net.DNSError{Err: "no such host", Name: ipv4onlyName, IsNotFound: true}
	}))
	p.discoverNAT64(t.Context())
	if p.nat64Inconclusive {
		t.Fatal("a not-found answer was treated as inconclusive")
	}
	if got := p.classify(net.ParseIP("2606:4700::1111")); got != ipPublic {
		t.Errorf("public IPv6 classified %d after a conclusive no-DNS64 answer, want ipPublic (%d)", got, ipPublic)
	}
}

// An AAAA that derives no prefix is not a no-DNS64 answer: ipv4only.arpa has no real
// AAAA, so a nonstandard synthesis or a captive-portal address leaves the site prefix
// unknown and classify must fail closed rather than pass a wrapped RFC1918 as public.
// An answer carrying no AAAA at all is the honest no-DNS64 shape and stays conclusive,
// as does a lookup that derived a prefix from at least one of its answers.
func TestNAT64NonDerivingAnswerIsInconclusive(t *testing.T) {
	cases := []struct {
		name  string
		addrs []net.IP
		want  bool
	}{
		{"captive-portal AAAA", []net.IP{net.ParseIP("2606:4700::1111")}, true},
		{"no AAAA at all", nil, false},
		{"synthesized", []net.IP{net.ParseIP("2001:db8:1:2:3:4:c000:aa")}, false},
		{"synthesized beside a stray", []net.IP{
			net.ParseIP("2001:db8:1:2:3:4:c000:aa"), net.ParseIP("2606:4700::1111"),
		}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := New(egressRules, WithNAT64Discovery(fakeLookup(c.addrs...)))
			p.discoverNAT64(t.Context())
			if p.nat64Inconclusive != c.want {
				t.Fatalf("nat64Inconclusive = %v, want %v", p.nat64Inconclusive, c.want)
			}
			// The undecodable IPv6 an inconclusive run must refuse: no transition prefix
			// explains it, so it may be a site synthesis wrapping RFC1918.
			want := ipPublic
			if c.want {
				want = ipPrivate
			}
			if got := p.classify(net.ParseIP("2606:4700::1111")); got != want {
				t.Errorf("classify = %d, want %d", got, want)
			}
		})
	}
}

// The RFC 8215 local-use prefix 64:ff9b:1::/48 is a container a site carves its own
// Pref64 out of, so every RFC 6052 length it admits must be decoded - not just a
// flat /48 reading, which would miss a target wrapped at any other length.
func TestRFC8215LocalUsePrefixDecodesEveryLength(t *testing.T) {
	for _, length := range []int{48, 56, 64, 96} {
		t.Run(fmt.Sprintf("/%d", length), func(t *testing.T) {
			build := func(v4 [4]byte) net.IP {
				ip := make(net.IP, 16)
				copy(ip, []byte{0x00, 0x64, 0xff, 0x9b, 0x00, 0x01})
				for i, pos := range rfc6052Positions[length] {
					ip[pos] = v4[i]
				}
				return ip
			}
			if got := classifyIP(build([4]byte{192, 168, 1, 1})); got != ipPrivate {
				t.Errorf("RFC1918 wrapped at /%d classified %d, want ipPrivate (%d)", length, got, ipPrivate)
			}
			if got := classifyIP(build([4]byte{169, 254, 169, 254})); got != ipHostReserved {
				t.Errorf("cloud metadata wrapped at /%d classified %d, want ipHostReserved (%d)", length, got, ipHostReserved)
			}
			// Local-use space is never public, but a public payload must stay merely
			// private: the zero padding a wrong length reads leads with 0.x.x.x, and
			// honoring that would make it host-reserved and unreachable even by a rule
			// naming the literal.
			if got := classifyIP(build([4]byte{8, 8, 8, 8})); got != ipPrivate {
				t.Errorf("public 8.8.8.8 wrapped at /%d classified %d, want ipPrivate (%d)", length, got, ipPrivate)
			}
		})
	}
}

// A wrapped this-network address is host-reserved, not merely private: 0.0.0.0/8
// names the gateway rather than a destination, so no rule may reach it even by
// naming the literal. It is only distinguishable from the zero padding a wrong
// carve length reads by RFC 6052's rule that the bytes after the embedded IPv4 are
// zero, which is what the length filter checks.
func TestRFC8215ThisNetworkStaysHostReserved(t *testing.T) {
	if got := classifyIP(net.ParseIP("64:ff9b:1::0.0.0.1")); got != ipHostReserved {
		t.Errorf("wrapped 0.0.0.1 classified %d, want ipHostReserved (%d)", got, ipHostReserved)
	}
	// The counterpart the filter exists to protect: a /96-carved public address must
	// not be read at /64 as its own zero padding (0.0.0.8) and refused as this-network.
	if got := classifyIP(net.ParseIP("64:ff9b:1::8.8.8.8")); got != ipPrivate {
		t.Errorf("wrapped 8.8.8.8 classified %d, want ipPrivate (%d)", got, ipPrivate)
	}
}
