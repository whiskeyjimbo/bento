package proxy

import (
	"encoding/binary"
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
// The narrowing invariant alone is weak - classify returns early for anything
// classifyIP already refused, so it holds structurally - and vacuous besides while
// no prefix is ever derived. The teeth are in the positive direction every
// iteration that DOES derive a prefix asserts: an RFC1918 address synthesized
// under that prefix is caught.
func FuzzNAT64DiscoveryOnlyNarrows(f *testing.F) {
	// pair seeds one synthesized ipv4only.arpa answer against one target address.
	// Both are fuzzed as uint64 halves rather than byte slices so every input is
	// exactly two addresses: a length check would spend most of the fuzzer's budget
	// skipping slices that are not 16 bytes long.
	pair := func(synth, target net.IP) {
		s16, t16 := synth.To16(), target.To16()
		f.Add(binary.BigEndian.Uint64(s16[:8]), binary.BigEndian.Uint64(s16[8:]),
			binary.BigEndian.Uint64(t16[:8]), binary.BigEndian.Uint64(t16[8:]))
	}
	// synth64 builds the /64 answer by hand: byte 8 is the RFC 6052 reserved u-octet,
	// so the embedded 192.0.0.171 resumes at byte 9. Writing it as a literal address
	// is how this seed silently embedded nothing and exercised only the /96 path.
	synth64 := net.ParseIP("2001:db8:aaaa:bbbb::").To16()
	synth64[9], synth64[10], synth64[11], synth64[12] = 192, 0, 0, 171

	pair(net.ParseIP("2001:db8:1:2:3:4:c000:aa"), net.ParseIP("2001:db8:1:2:3:4:c0a8:101"))
	pair(synth64, net.ParseIP("10.0.0.5"))
	pair(net.ParseIP("64:ff9b::c000:aa"), net.ParseIP("64:ff9b::c0a8:101"))
	pair(net.ParseIP("2606:4700::1111"), net.ParseIP("8.8.8.8"))
	pair(net.ParseIP("::"), net.ParseIP("169.254.169.254"))

	f.Fuzz(func(t *testing.T, synthHi, synthLo, targetHi, targetLo uint64) {
		var synth, target [16]byte
		binary.BigEndian.PutUint64(synth[:8], synthHi)
		binary.BigEndian.PutUint64(synth[8:], synthLo)
		binary.BigEndian.PutUint64(target[:8], targetHi)
		binary.BigEndian.PutUint64(target[8:], targetLo)

		p := New(egressRules, WithNAT64Discovery(fakeLookup(net.IP(synth[:]))))
		p.discoverNAT64(t.Context())

		ip := net.IP(target[:])
		base, got := classifyIP(ip), p.classify(ip)
		if got == ipPublic && base != ipPublic {
			t.Errorf("discovery from %v turned %v from class %d into public - a prefix may only narrow, never widen",
				net.IP(synth[:]), ip, base)
		}
		if base != ipPublic && got != base {
			t.Errorf("discovery from %v reclassified already-refused %v from %d to %d",
				net.IP(synth[:]), ip, base, got)
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
