package proxy

import (
	"net"
	"testing"
)

// NAT64 discovery takes its input from DNS - the one input on this path an
// attacker can influence without going through the sandbox at all, since a
// resolver can synthesize whatever AAAA it likes for ipv4only.arpa. Whatever it
// returns, discovery may only ever NARROW: it exists to catch a synthesized
// RFC1918 target that classifyIP passes as public, so a derived prefix that made
// some address classify public where classifyIP did not would hand the sandbox a
// reachable address the guard had already refused.
//
// The narrowing invariant alone is vacuous while no prefix is ever derived, so
// every iteration that does derive one also asserts the positive direction: a
// synthesized RFC1918 address under that prefix is caught.
func FuzzNAT64DiscoveryOnlyNarrows(f *testing.F) {
	// A synthesized ipv4only.arpa at each prefix length discovery understands, so the
	// seed corpus derives a prefix rather than only exercising the no-prefix path.
	f.Add([]byte(net.ParseIP("2001:db8:1:2:3:4:c000:aa").To16()), []byte(net.ParseIP("2001:db8:1:2:3:4:c0a8:101").To16()))
	f.Add([]byte(net.ParseIP("2001:db8:aaaa:bbbb:0:c000:ab00:0").To16()), []byte(net.ParseIP("10.0.0.5").To16()))
	f.Add([]byte(net.ParseIP("64:ff9b::c000:aa").To16()), []byte(net.ParseIP("64:ff9b::c0a8:101").To16()))
	f.Add([]byte(net.ParseIP("2606:4700::1111").To16()), []byte(net.ParseIP("8.8.8.8").To16()))
	f.Add([]byte(net.ParseIP("::").To16()), []byte(net.ParseIP("169.254.169.254").To16()))
	f.Add(make([]byte, 16), make([]byte, 16))

	f.Fuzz(func(t *testing.T, synth, target []byte) {
		if len(synth) != net.IPv6len || len(target) != net.IPv6len {
			t.Skip("discovery reads AAAA records, and only a 16-byte value is one")
		}
		p := New(egressRules, WithNAT64Discovery(fakeLookup(net.IP(synth))))
		p.discoverNAT64(t.Context())

		ip := net.IP(target)
		base, got := classifyIP(ip), p.classify(ip)
		if got == ipPublic && base != ipPublic {
			t.Errorf("discovery from %v turned %v from class %d into public - a prefix may only narrow, never widen",
				net.IP(synth), ip, base)
		}
		if base != ipPublic && got != base {
			t.Errorf("discovery from %v reclassified already-refused %v from %d to %d",
				net.IP(synth), ip, base, got)
		}

		// Teeth for the iterations that derived a prefix: the address that prefix would
		// synthesize for an RFC1918 host must be caught. Without this the invariant
		// above holds for a classify() that ignores p.nat64 entirely.
		for _, pfx := range p.nat64 {
			private := make(net.IP, 16)
			copy(private, pfx.prefix[:pfx.prefixLen/8])
			pos := rfc6052Positions[pfx.prefixLen]
			private[pos[0]], private[pos[1]], private[pos[2]], private[pos[3]] = 192, 168, 1, 1
			// A prefix whose own bits already name non-public space is refused by
			// classifyIP before any embedded address is read, so it proves nothing here.
			if classifyIP(private) != ipPublic {
				continue
			}
			if c := p.classify(private); c != ipPrivate {
				t.Errorf("192.168.1.1 synthesized under the discovered /%d prefix (%v) classified %d, want ipPrivate (%d)",
					pfx.prefixLen, private, c, ipPrivate)
			}
		}
	})
}
