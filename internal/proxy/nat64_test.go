package proxy

import (
	"context"
	"net"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/policy"
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
