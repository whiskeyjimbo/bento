package proxy

import (
	"io"
	"net"
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
