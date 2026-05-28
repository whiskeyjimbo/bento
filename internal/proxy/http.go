package proxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/whiskeyjimbo/bento/internal/spec"
)

// HTTPConnect filters outbound HTTP/HTTPS by destination — the proxy that
// HTTP_PROXY/HTTPS_PROXY env vars natively understand.
type HTTPConnect struct {
	*tcpProxy
	perm *spec.NetworkPerm
}

// NewHTTPConnect binds the listener without starting the accept loop.
func NewHTTPConnect(perm *spec.NetworkPerm, opts ...Option) (*HTTPConnect, error) {
	h := &HTTPConnect{perm: perm}
	base, err := newTCPProxy("http-connect", applyOptionsFor(perm, opts), h.handle)
	if err != nil {
		return nil, err
	}
	h.tcpProxy = base
	return h, nil
}

// Start begins the accept loop in a goroutine.
func (h *HTTPConnect) Start() { go h.serve() }

// StartHTTPConnect is the New+Start convenience wrapper.
func StartHTTPConnect(perm *spec.NetworkPerm, opts ...Option) (*HTTPConnect, error) {
	h, err := NewHTTPConnect(perm, opts...)
	if err != nil {
		return nil, err
	}
	h.Start()
	return h, nil
}

func (h *HTTPConnect) handle(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(h.opts.idleTimeout))

	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		writeStatus(c, "405 Method Not Allowed")
		return
	}
	host, portStr, err := net.SplitHostPort(req.Host)
	if err != nil {
		writeStatus(c, "400 Bad Request")
		return
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		writeStatus(c, "400 Bad Request")
		return
	}

	if !isValidHost(host) {
		h.logf("DENY %q:%d (invalid host)", host, port)
		writeStatus(c, "400 Bad Request")
		return
	}
	allowed, tag := h.opts.authorizer.Authorize(host, port)
	h.logf("%s %s:%d", tag, host, port)
	if !allowed {
		// Include the rejected host:port in the response so error messages that
		// only surface the proxy response (and not bento's stderr log line)
		// still convey *what* was blocked. Both the X-Bento-Reject-Host header
		// and the plaintext body are seen by curl -v, requests' Response.text,
		// and Python's urllib URLError.reason in some configurations.
		writeRejectStatus(c, host, port)
		return
	}

	// Allowlist check happens before DNS, so denied hosts never reach the resolver.
	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(host, portStr), h.opts.dialTimeout)
	if err != nil {
		writeStatus(c, "502 Bad Gateway")
		return
	}
	defer upstream.Close()

	writeStatus(c, "200 Connection Established")
	c.SetDeadline(time.Time{})

	if n := br.Buffered(); n > 0 {
		buf, _ := br.Peek(n)
		upstream.Write(buf)
	}

	splice(c, upstream)
}

func writeStatus(c net.Conn, status string) {
	fmt.Fprintf(c, "HTTP/1.1 %s\r\n\r\n", status)
}

// writeRejectStatus emits a 403 that names the rejected host:port both in a
// custom header (machine-readable) and in the response body (so error
// messages that bubble up to humans still identify what was blocked).
func writeRejectStatus(c net.Conn, host string, port int) {
	body := fmt.Sprintf("bento blocked outbound connection to %s:%d — host not in manifest's network.rules", host, port)
	fmt.Fprintf(c,
		"HTTP/1.1 403 Forbidden\r\n"+
			"X-Bento-Reject-Host: %s:%d\r\n"+
			"Content-Type: text/plain\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n%s",
		host, port, len(body), body)
}
