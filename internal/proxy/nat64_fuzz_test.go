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
	// The synthesized answer is built from a typed input rather than fuzzed as raw
	// address bytes: sel picks the RFC 6052 prefix length and which of the two fixed
	// ipv4only.arpa IPv4s is embedded, and the prefix bits fill the rest. Fuzzing the
	// answer directly left it deriving no prefix on two thirds of iterations, so the
	// /40, /48, /56, /64 and /96 arms were reached only when mutation happened to keep
	// a valid embedding - every iteration now poses a well-formed Pref64 at a chosen
	// length. The target stays two raw halves: it is meant to be any address at all,
	// and a length check would spend the budget skipping slices that are not 16 bytes.
	seed := func(sel uint8, prefix string, target net.IP) {
		p16, t16 := net.ParseIP(prefix).To16(), target.To16()
		f.Add(sel, binary.BigEndian.Uint64(p16[:8]), binary.BigEndian.Uint64(p16[8:]),
			binary.BigEndian.Uint64(t16[:8]), binary.BigEndian.Uint64(t16[8:]))
	}
	// One seed per length, so the corpus starts with every arm of rfc6052Positions
	// covered rather than waiting for the fuzzer to find them.
	for i := range rfc6052Lengths {
		seed(uint8(i), "2001:db8:1:2:3:4:5:6", net.ParseIP("2001:db8:1:2:3:4:c0a8:101"))
	}
	seed(uint8(len(rfc6052Lengths)), "64:ff9b::", net.ParseIP("64:ff9b::c0a8:101"))
	seed(0, "2606:4700::", net.ParseIP("8.8.8.8"))
	seed(3, "::", net.ParseIP("169.254.169.254"))

	f.Fuzz(func(t *testing.T, sel uint8, prefixHi, prefixLo, targetHi, targetLo uint64) {
		length := rfc6052Lengths[int(sel)%len(rfc6052Lengths)]
		v4 := ipv4onlyV4[int(sel)/len(rfc6052Lengths)%len(ipv4onlyV4)]

		var synth, target [16]byte
		binary.BigEndian.PutUint64(synth[:8], prefixHi)
		binary.BigEndian.PutUint64(synth[8:], prefixLo)
		// Everything past the prefix is the synthesis's to write, and zeroing it is what
		// makes the embedding well-formed: below /96 that clears the reserved u-octet at
		// byte 8, which a real RFC 6052 address must have zero.
		for i := length / 8; i < len(synth); i++ {
			synth[i] = 0
		}
		for i, pos := range rfc6052Positions[length] {
			synth[pos] = v4[i]
		}
		binary.BigEndian.PutUint64(target[:8], targetHi)
		binary.BigEndian.PutUint64(target[8:], targetLo)

		// RFC 7050 contemplates a site publishing several Pref64, and a short one
		// matches every address a longer one under it does. Pairing each answer with a
		// /32 sharing its leading bytes makes every iteration a multi-prefix site, so
		// the teeth below also cover the case where two prefixes disagree.
		companion := make(net.IP, 16)
		copy(companion, synth[:4])
		companion[4], companion[5], companion[6], companion[7] = 192, 0, 0, 170

		p := New(egressRules, WithNAT64Discovery(fakeLookup(net.IP(synth[:]), companion)))
		p.discoverNAT64(t.Context())
		// The typed input's own invariant: every iteration poses a well-formed Pref64, so
		// every iteration must derive one. Without this a construction that stopped
		// embedding anything would quietly return the target to fuzzing one shape, which
		// is the state this input replaced.
		if len(p.nat64) == 0 {
			t.Fatalf("a well-formed /%d synthesis (%v) derived no prefix", length, net.IP(synth[:]))
		}

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
			// Host-reserved rather than private is also a catch, and the stricter one:
			// the companion /32 reads its own four bytes out of these same bits, and
			// those may decode into this-network or link-local space.
			if c := p.classify(private); c == ipPublic {
				t.Errorf("192.168.1.1 synthesized under the discovered /%d prefix (%v) classified public, want it refused",
					pfx.prefixLen, private)
			}
		}
	})
}
