package proxy

import (
	"io"
	"net"
	"strings"
	"testing"
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
// into the 403 body the target reads back, so a control byte surviving the parse is
// a terminal-escape smuggled into the operator's console. Table tests pin the
// escapes someone thought of; this pins the property against the ones nobody did.
func FuzzReadConnect(f *testing.F) {
	f.Add("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	f.Add("CONNECT [::1]:443 HTTP/1.1\r\n\r\n")        // IPv6 literal, bracketed
	f.Add("CONNECT \x1bevil.com:443 HTTP/1.1\r\n\r\n") // escape in the host
	f.Add("CONNECT example.com:4\x0043 HTTP/1.1\r\n\r\n")
	f.Add("CONNECT :443 HTTP/1.1\r\n\r\n")        // empty host
	f.Add("CONNECT example.com:443 HTTP/1.1\r\n") // headers never terminated
	f.Add("connect example.com:443 HTTP/1.1\r\n\r\n")
	f.Add("GET / HTTP/1.1\r\n\r\n") // not a CONNECT
	f.Add("CONNECT\r\n\r\n")
	f.Add("")

	f.Fuzz(func(t *testing.T, req string) {
		client, server := net.Pipe()
		go func() {
			// A partial write is fine: readConnect either parses what arrived or errors.
			// Closing unblocks it when the request has no terminator.
			io.WriteString(client, req)
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
			for _, r := range s {
				if r < 0x20 || r == 0x7f {
					t.Fatalf("readConnect accepted control character %q in %q, which reaches the egress log and the 403 body (req %q)", r, s, req)
				}
			}
		}
	})
}

// The egress guard classifies an address, so every spelling of one address must
// reach the same verdict. classifyIP itself decodes only some of those spellings
// (mapped, IPv4-compatible, 6to4, the well-known Pref64), and each decoder is a
// separate branch that can be dropped or mis-indexed without any single-address
// test noticing: a reserved or RFC1918 target wearing a v6 rendering the decoder
// forgot classifies public, and guardUpstream then dials it.
//
// Fuzzing the four octets rather than raw bytes is deliberate - the property is
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
		// test would report a decoder gap that is really a bug in its own fixture.
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
			{"v6-mapped", v4.To16()},
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

// guardUpstream is the SSRF backstop: it re-vets the address the dialer resolved
// to, after the allowlist has already passed the hostname. It composes a zone-id
// strip, a parse, a classification and an explicit-IP-rule exemption, and every
// bug found in it so far has been textual - a spelling that slipped past
// classification. With no rules the exemption can never fire, so the whole
// non-public space must be refused however it is spelled.
//
// Both directions are asserted in one target because each is the other's control:
// "everything is refused" is what a guard that fails closed on all input looks
// like, and "the public address is allowed" is what proves the allow path is
// reachable at all.
func FuzzGuardUpstreamRefusesNonPublicRenderings(f *testing.F) {
	f.Add([]byte(net.ParseIP("127.0.0.1").To16()))
	f.Add([]byte(net.ParseIP("169.254.169.254").To16()))
	f.Add([]byte(net.ParseIP("192.168.1.1").To16()))
	f.Add([]byte(net.ParseIP("10.0.0.1").To16()))
	f.Add([]byte(net.ParseIP("fe80::1").To16()))
	f.Add([]byte(net.ParseIP("fd00::1").To16()))
	f.Add([]byte(net.ParseIP("::1").To16()))
	f.Add([]byte(net.ParseIP("64:ff9b::c0a8:101").To16()))
	f.Add([]byte(net.ParseIP("8.8.8.8").To16()))
	f.Add([]byte(net.ParseIP("2606:4700::1111").To16()))

	// No rules and no gatekeeper: nothing can be exempted as an explicit IP literal,
	// so the guard's verdict is its classification alone.
	p := New(nil)

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) != net.IPv6len {
			t.Skip("only a 16-byte address is a rendering of a single IP")
		}
		ip := net.IP(raw)
		text := ip.String()
		if net.ParseIP(text) == nil {
			t.Skipf("%v does not round-trip through its own text form", raw)
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

		if classifyIP(ip) == ipPublic {
			// The allow path must stay reachable, including through the zone strip - a
			// strip that refused a zoned public address would be a false refusal, and
			// without this clause every assertion below would hold for a guard that
			// refused everything.
			for _, addr := range renderings {
				if err := p.guardUpstream(t.Context(), "", addr, nil); err != nil {
					t.Errorf("guardUpstream refused public %s: %v", addr, err)
				}
			}
			return
		}
		for _, addr := range renderings {
			if err := p.guardUpstream(t.Context(), "", addr, nil); err == nil {
				t.Errorf("guardUpstream allowed non-public %s (class %d) - the sandbox reaches the host or the LAN through this spelling",
					addr, classifyIP(ip))
			}
		}
	})
}
