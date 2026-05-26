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

// HTTPConnect filters outbound HTTP/HTTPS by destination. This is the
// proxy that HTTP_PROXY/HTTPS_PROXY env vars natively understand
// across curl/python/go/node/etc.
type HTTPConnect struct {
	*tcpProxy
	perm *spec.NetworkPerm
}

// NewHTTPConnect binds an HTTP CONNECT proxy listener without starting
// the accept loop. Call Start() to begin serving.
func NewHTTPConnect(perm *spec.NetworkPerm, opts ...Option) (*HTTPConnect, error) {
	h := &HTTPConnect{perm: perm}
	base, err := newTCPProxy("http-connect", applyOptions(opts), h.handle)
	if err != nil {
		return nil, err
	}
	h.tcpProxy = base
	return h, nil
}

// Start begins the accept loop in a goroutine. Safe to call once.
func (h *HTTPConnect) Start() { go h.serve() }

// StartHTTPConnect is the convenience wrapper: New + Start.
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
	var allowed bool
	var tag string
	if h.opts.authorizer != nil {
		allowed, tag = h.opts.authorizer.Authorize(host, port)
	} else {
		allowed, tag = allowOrPrompt(h.opts, h.perm, host, port)
	}
	h.logf("%s %s:%d", tag, host, port)
	if !allowed {
		writeStatus(c, "403 Forbidden")
		return
	}

	// Allowlist enforcement is complete BEFORE DNS resolution: denied
	// hosts never reach the host's resolver. Allowed hosts DO get
	// resolved here on the host — standard forward-proxy behavior,
	// not a security gap. The hostname is observable in the host's
	// DNS query stream. See README "How It Works" for details.
	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(host, portStr), h.opts.dialTimeout)
	if err != nil {
		writeStatus(c, "502 Bad Gateway")
		return
	}
	defer upstream.Close()

	writeStatus(c, "200 Connection Established")
	c.SetDeadline(time.Time{})

	// Flush any client bytes buffered past the request.
	if n := br.Buffered(); n > 0 {
		buf, _ := br.Peek(n)
		upstream.Write(buf)
	}

	splice(c, upstream)
}

func writeStatus(c net.Conn, status string) {
	fmt.Fprintf(c, "HTTP/1.1 %s\r\n\r\n", status)
}
