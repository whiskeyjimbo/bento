package proxy

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/whiskeyjimbo/bento/policy"
)

// readConnect is the proxy's only parser of attacker-controlled bytes: everything
// after the CONNECT headers is copied opaquely, so this function is the whole
// parsing attack surface. Two properties have to survive arbitrary input.
//
// It must not panic. It runs strings.Fields, net.SplitHostPort and a rune scan over
// raw client bytes, including invalid UTF-8 and embedded NULs.
//
// More importantly, a request it ACCEPTS must yield a host and port fit to render:
// both flow into report() (the run's admitted-hosts list, printed on the host) and
// into the 403 body the target reads back, so a deceiving character surviving the
// parse is a terminal escape, a reordered display, or a hidden segment smuggled into
// the operator's console. Table tests pin the escapes someone thought of; this pins
// the property against the ones nobody did.
func FuzzReadConnect(f *testing.F) {
	f.Add("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	f.Add("CONNECT [::1]:443 HTTP/1.1\r\n\r\n")        // IPv6 literal, bracketed
	f.Add("CONNECT \x1bevil.com:443 HTTP/1.1\r\n\r\n") // escape in the host
	f.Add("CONNECT example.com:4\x0043 HTTP/1.1\r\n\r\n")
	f.Add("CONNECT ex\u202eample.com:443 HTTP/1.1\r\n\r\n") // bidi override in the host
	f.Add("CONNECT ex\u200bample.com:443 HTTP/1.1\r\n\r\n") // zero-width space in the host
	f.Add("CONNECT ex\x9bample.com:443 HTTP/1.1\r\n\r\n")   // raw 8-bit CSI, decodes as RuneError
	f.Add("CONNECT :443 HTTP/1.1\r\n\r\n")                  // empty host
	f.Add("CONNECT example.com:443 HTTP/1.1\r\n")           // headers never terminated
	f.Add("connect example.com:443 HTTP/1.1\r\n\r\n")
	f.Add("GET / HTTP/1.1\r\n\r\n") // not a CONNECT
	f.Add("CONNECT\r\n\r\n")
	f.Add("")

	f.Fuzz(func(t *testing.T, req string) {
		client, server := net.Pipe()
		go func() {
			// A partial write is fine: readConnect either parses what arrived or errors.
			// Closing unblocks it when the request has no terminator.
			_, _ = io.WriteString(client, req)
			client.Close()
		}()
		host, port, _, err := readConnect(server)
		// Closing releases the writer if readConnect returned before consuming req,
		// which would otherwise leak a goroutine blocked on the unbuffered pipe.
		server.Close()
		if err != nil {
			return
		}
		if host == "" {
			t.Fatalf("readConnect accepted a request with an empty host (req %q)", req)
		}
		for _, s := range []string{host, port} {
			if !utf8.ValidString(s) {
				t.Fatalf("readConnect accepted invalid UTF-8 in %q, which can carry a raw 8-bit C1 the rune screen never decodes (req %q)", s, req)
			}
			if r, bad := policy.FirstUnsafeRune(s); bad {
				t.Fatalf("readConnect accepted deceiving rune %q in %q, which reaches the egress log and the 403 body (req %q)", r, s, req)
			}
		}
	})
}

// The egress guard classifies an address, so every spelling of one address must
// reach the same verdict. classifyIP decodes only some of those spellings
// (IPv4-compatible, 6to4, the well-known Pref64), and each decoder is a separate
// branch that can be dropped or mis-indexed without any single-address test
// noticing: a reserved or RFC1918 target wearing a v6 rendering the decoder forgot
// classifies public, and guardUpstream then dials it.
//
// This is a differential property - every rendering agrees with the v4 - so it
// cannot see a hole that moves them all together. classifyIP's absolute verdicts
// are anchored by TestClassifyIP, TestAdversarialClassifyIP and the independent
// prefix table in FuzzGuardUpstreamRefusesNonPublicRenderings below.
//
// Fuzzing the four octets rather than raw bytes is deliberate: the property is
// about renderings of the SAME address, which needs a v4 to render from.
func FuzzClassifyIPIsRenderingAgnostic(f *testing.F) {
	f.Add(byte(192), byte(168), byte(1), byte(1))     // RFC1918
	f.Add(byte(169), byte(254), byte(169), byte(254)) // cloud metadata
	f.Add(byte(127), byte(0), byte(0), byte(1))       // loopback
	f.Add(byte(100), byte(64), byte(0), byte(1))      // CGNAT
	f.Add(byte(0), byte(0), byte(0), byte(0))         // unspecified
	f.Add(byte(198), byte(18), byte(0), byte(1))      // RFC 2544 benchmarking
	f.Add(byte(240), byte(0), byte(0), byte(1))       // reserved 240/4
	f.Add(byte(224), byte(0), byte(0), byte(1))       // multicast
	f.Add(byte(8), byte(8), byte(8), byte(8))         // public, the positive control
	f.Add(byte(93), byte(184), byte(216), byte(34))   // public

	f.Fuzz(func(t *testing.T, a, b, c, d byte) {
		v4 := net.IPv4(a, b, c, d)
		want := classifyIP(v4)

		// Built byte-wise rather than by parsing a formatted string: a rendering that
		// failed to parse would be a nil IP, which classifyIP passes as public, so the
		// test would report a decoder gap that is really a bug in its own fixture. The
		// v6-mapped form is not among them - net.IPv4 already returns it, so comparing
		// it against want would be the same call on the same bytes.
		compat := make(net.IP, 16) // deprecated IPv4-compatible ::a.b.c.d
		copy(compat[12:], []byte{a, b, c, d})
		sixToFour := make(net.IP, 16) // 6to4 2002:AABB:CCDD::
		sixToFour[0], sixToFour[1] = 0x20, 0x02
		copy(sixToFour[2:], []byte{a, b, c, d})
		wellKnown := make(net.IP, 16) // NAT64 well-known 64:ff9b::/96
		copy(wellKnown, []byte{0x00, 0x64, 0xff, 0x9b})
		copy(wellKnown[12:], []byte{a, b, c, d})

		for _, r := range []struct {
			name string
			ip   net.IP
		}{
			{"IPv4-compatible", compat},
			{"6to4", sixToFour},
			{"well-known Pref64", wellKnown},
		} {
			if got := classifyIP(r.ip); got != want {
				t.Errorf("%s rendering of %v classified %d, want %d as the v4 does - a decoder gap the egress guard would dial through",
					r.name, v4, got, want)
			}
		}
	})
}

// neverEgress names address space no sandbox may reach, written out here rather
// than derived from classifyIP so the guard is checked against an outside opinion.
// A property phrased in terms of classifyIP only proves the guard agrees with
// itself: gut classifyIP to "return ipPublic" and every such assertion still holds
// while the whole boundary is open.
//
// One-directional by design. An address outside the table is not asserted to be
// allowed - the transition renderings (6to4, Pref64) carry a v4 this table does not
// look through, and refusing more than the table names is always safe.
var neverEgress = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),      // this-network
	netip.MustParsePrefix("10.0.0.0/8"),     // RFC1918
	netip.MustParsePrefix("100.64.0.0/10"),  // CGNAT
	netip.MustParsePrefix("127.0.0.0/8"),    // loopback
	netip.MustParsePrefix("169.254.0.0/16"), // link-local, incl. cloud metadata
	netip.MustParsePrefix("172.16.0.0/12"),  // RFC1918
	netip.MustParsePrefix("192.168.0.0/16"), // RFC1918
	netip.MustParsePrefix("198.18.0.0/15"),  // RFC 2544 benchmarking
	netip.MustParsePrefix("224.0.0.0/4"),    // multicast
	netip.MustParsePrefix("240.0.0.0/4"),    // reserved, incl. limited broadcast
	netip.MustParsePrefix("::/128"),         // unspecified
	netip.MustParsePrefix("::1/128"),        // loopback
	netip.MustParsePrefix("fc00::/7"),       // ULA
	netip.MustParsePrefix("fe80::/10"),      // link-local
	netip.MustParsePrefix("fec0::/10"),      // deprecated site-local
	netip.MustParsePrefix("ff00::/8"),       // multicast
}

// guardUpstream is the SSRF backstop: it re-vets the address the dialer resolved
// to, after the allowlist has already passed the hostname. It composes a zone-id
// strip, a parse, a classification and an explicit-IP-rule exemption, and the bugs
// found in it so far have been textual - a spelling that slipped past
// classification. With no rules the exemption can never fire, so every address in
// neverEgress must be refused however it is spelled, and an address the guard
// could not parse at all must be refused rather than dialed unvetted.
//
// The public direction is asserted too, because "refuses everything" is what a
// guard broken shut looks like and it would satisfy every refusal above.
func FuzzGuardUpstreamRefusesNonPublicRenderings(f *testing.F) {
	seed := func(s string) {
		ip := net.ParseIP(s).To16()
		f.Add(binary.BigEndian.Uint64(ip[:8]), binary.BigEndian.Uint64(ip[8:]))
	}
	// One address from every neverEgress prefix. A prefix with no seed contributes
	// nothing at any realistic fuzz budget - the coverage guidance has no foothold to
	// mutate toward it, so dropping the clause that refuses it goes unnoticed for
	// millions of executions.
	seed("0.1.2.3")           // this-network
	seed("10.0.0.1")          // RFC1918
	seed("100.64.0.1")        // CGNAT
	seed("127.0.0.1")         // loopback
	seed("169.254.169.254")   // cloud metadata
	seed("172.16.0.1")        // RFC1918
	seed("192.168.1.1")       // RFC1918
	seed("198.18.0.1")        // RFC 2544 benchmarking
	seed("224.0.0.1")         // multicast
	seed("240.0.0.1")         // reserved
	seed("::")                // unspecified
	seed("::1")               // loopback
	seed("fd00::1")           // ULA
	seed("fe80::1")           // link-local
	seed("fec0::1")           // deprecated site-local
	seed("ff02::1")           // multicast
	seed("64:ff9b::c0a8:101") // well-known Pref64 wrapping RFC1918, outside the table
	seed("8.8.8.8")           // public, the positive control
	seed("2606:4700::1111")   // public

	// No rules and no gatekeeper: nothing can be exempted as an explicit IP literal,
	// so the guard's verdict is its classification alone.
	p := New(nil)

	// The address halves are fuzzed as two uint64s rather than a byte slice so every
	// input is exactly one address: a length check would spend most of the fuzzer's
	// budget skipping slices that are not 16 bytes long.
	f.Fuzz(func(t *testing.T, hi, lo uint64) {
		var raw [16]byte
		binary.BigEndian.PutUint64(raw[:8], hi)
		binary.BigEndian.PutUint64(raw[8:], lo)
		ip := net.IP(raw[:])
		text := ip.String()

		// A resolved dial target the guard cannot vet must fail closed. Which of the two
		// refusals it takes depends on the form: a v6 text carries colons, so the host
		// fails to split at all, while a dotted quad splits and then fails to parse.
		if err := p.guardUpstream(t.Context(), "", "host-"+text+":443", nil); err == nil {
			t.Errorf("guardUpstream allowed %q, which is not an address it could vet at all", text)
		}

		renderings := []string{
			net.JoinHostPort(text, "443"),
			// A zone id must be stripped before parsing: net.ParseIP rejects the zoned
			// literal outright, and the kernel then dials the underlying address ignoring
			// the zone. This is the shape of the bypass that was actually shipped once.
			net.JoinHostPort(text+"%eth0", "443"),
			// Hex case is not significant in a v6 literal, so an uppercased rendering
			// names the same address a lowercase comparison would miss.
			net.JoinHostPort(strings.ToUpper(text), "443"),
		}

		addr := netip.AddrFrom16(raw).Unmap()
		for _, pfx := range neverEgress {
			if !pfx.Contains(addr) {
				continue
			}
			for _, r := range renderings {
				if err := p.guardUpstream(t.Context(), "", r, nil); err == nil {
					t.Errorf("guardUpstream allowed %s, which is in %s - the sandbox reaches the host or the LAN through this spelling", r, pfx)
				}
			}
			return
		}

		if classifyIP(ip) != ipPublic {
			// Refusing beyond the table is the guard's job (transition renderings, and
			// space the table deliberately does not enumerate), so there is nothing left
			// to assert for this address.
			return
		}
		// The allow path must stay reachable, including through the zone strip - a strip
		// that refused a zoned public address would be a false refusal, and without this
		// clause every refusal above would hold for a guard that refused everything.
		for _, r := range renderings {
			if err := p.guardUpstream(t.Context(), "", r, nil); err != nil {
				t.Errorf("guardUpstream refused public %s: %v", r, err)
			}
		}
	})
}
