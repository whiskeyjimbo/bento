package proxy

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/whiskeyjimbo/bento/internal/spec"
)

// SOCKS5 is a minimal SOCKS5 server filtering CONNECT by NetworkPerm.
// No auth. ATYP DOMAIN + IPv4 only; IPv6/UDP/BIND refused.
type SOCKS5 struct {
	*tcpProxy
	perm *spec.NetworkPerm
}

// NewSOCKS5 binds the listener without starting the accept loop.
func NewSOCKS5(perm *spec.NetworkPerm, opts ...Option) (*SOCKS5, error) {
	s := &SOCKS5{perm: perm}
	base, err := newTCPProxy("socks5", applyOptionsFor(perm, opts), s.handle)
	if err != nil {
		return nil, err
	}
	s.tcpProxy = base
	return s, nil
}

// Start begins the accept loop in a goroutine.
func (s *SOCKS5) Start() { go s.serve() }

// StartSOCKS5 is the New+Start convenience wrapper.
func StartSOCKS5(perm *spec.NetworkPerm, opts ...Option) (*SOCKS5, error) {
	s, err := NewSOCKS5(perm, opts...)
	if err != nil {
		return nil, err
	}
	s.Start()
	return s, nil
}

func (s *SOCKS5) handle(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(s.opts.idleTimeout))

	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	if req[0] != 0x05 || req[1] != 0x01 {
		writeSocksReply(c, 0x07)
		return
	}

	var host string
	switch req[3] {
	case 0x01:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		host = net.IP(buf).String()
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(c, lenBuf); err != nil {
			return
		}
		nameBuf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(c, nameBuf); err != nil {
			return
		}
		host = string(nameBuf)
	default:
		writeSocksReply(c, 0x08)
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(c, portBuf); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(portBuf))

	if !isValidHost(host) {
		s.logf("DENY %q:%d (invalid host)", host, port)
		writeSocksReply(c, 0x02)
		return
	}
	allowed, tag := s.opts.authorizer.Authorize(host, port)
	s.logf("%s %s:%d", tag, host, port)
	if !allowed {
		writeSocksReply(c, 0x02)
		return
	}

	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), s.opts.dialTimeout)
	if err != nil {
		writeSocksReply(c, 0x05)
		return
	}
	defer upstream.Close()

	writeSocksReply(c, 0x00)
	c.SetDeadline(time.Time{})

	splice(c, upstream)
}

func writeSocksReply(c net.Conn, code byte) {
	c.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}
