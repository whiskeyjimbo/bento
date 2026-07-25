package proxy

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestAdversarialClassifyIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		ipStr     string
		wantClass ipClass
	}{
		{
			name:      "block_ipv4_loopback",
			ipStr:     "127.0.0.1",
			wantClass: ipHostReserved,
		},
		{
			name:      "block_ipv4_loopback_range",
			ipStr:     "127.255.255.255",
			wantClass: ipHostReserved,
		},
		{
			name:      "block_ipv4_link_local_cloud_metadata",
			ipStr:     "169.254.169.254",
			wantClass: ipHostReserved,
		},
		{
			name:      "block_ipv4_this_network_zero",
			ipStr:     "0.0.0.0",
			wantClass: ipHostReserved,
		},
		{
			name:      "block_ipv4_this_network_subnet",
			ipStr:     "0.1.2.3",
			wantClass: ipHostReserved,
		},
		{
			name:      "block_ipv4_rfc2544_benchmark",
			ipStr:     "198.18.0.1",
			wantClass: ipHostReserved,
		},
		{
			name:      "block_ipv4_reserved_240",
			ipStr:     "240.0.0.1",
			wantClass: ipHostReserved,
		},
		{
			name:      "block_ipv4_limited_broadcast",
			ipStr:     "255.255.255.255",
			wantClass: ipHostReserved,
		},
		{
			name:      "classify_ipv4_private_10",
			ipStr:     "10.0.0.1",
			wantClass: ipPrivate,
		},
		{
			name:      "classify_ipv4_private_172",
			ipStr:     "172.16.0.1",
			wantClass: ipPrivate,
		},
		{
			name:      "classify_ipv4_private_192",
			ipStr:     "192.168.1.1",
			wantClass: ipPrivate,
		},
		{
			name:      "classify_ipv4_cgnat",
			ipStr:     "100.64.0.1",
			wantClass: ipPrivate,
		},
		{
			name:      "block_ipv6_loopback",
			ipStr:     "::1",
			wantClass: ipHostReserved,
		},
		{
			name:      "block_ipv6_unspecified",
			ipStr:     "::",
			wantClass: ipHostReserved,
		},
		{
			name:      "block_ipv6_link_local",
			ipStr:     "fe80::1",
			wantClass: ipHostReserved,
		},
		{
			name:      "block_ipv6_site_local",
			ipStr:     "fec0::1",
			wantClass: ipHostReserved,
		},
		{
			name:      "classify_ipv6_nat64_embedded_private",
			ipStr:     "64:ff9b::10.0.0.1",
			wantClass: ipPrivate,
		},
		{
			name:      "classify_ipv6_6to4_embedded_private",
			ipStr:     "2002:0a00:0001::",
			wantClass: ipPrivate,
		},
		{
			name:      "classify_ipv6_v4compat_embedded_private",
			ipStr:     "::10.0.0.1",
			wantClass: ipPrivate,
		},
		{
			name:      "allow_public_ipv4",
			ipStr:     "8.8.8.8",
			wantClass: ipPublic,
		},
		{
			name:      "allow_public_ipv6",
			ipStr:     "2607:f8b0:4005:805::200e",
			wantClass: ipPublic,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ip := net.ParseIP(tc.ipStr)
			if ip == nil {
				t.Fatalf("failed to parse IP: %q", tc.ipStr)
			}
			got := classifyIP(ip)
			if got != tc.wantClass {
				t.Fatalf("classifyIP(%q) = %v; want %v", tc.ipStr, got, tc.wantClass)
			}
		})
	}
}

func TestAdversarialReadConnect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		rawReq    string
		wantHost  string
		wantPort  string
		errSubstr string
	}{
		{
			name:      "reject_non_connect_method",
			rawReq:    "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			errSubstr: "expected a CONNECT request",
		},
		{
			name:      "reject_missing_target",
			rawReq:    "CONNECT  HTTP/1.1\r\n\r\n",
			errSubstr: "malformed target",
		},
		{
			name:      "reject_malformed_target",
			rawReq:    "CONNECT example.com:443:80 HTTP/1.1\r\n\r\n",
			errSubstr: "malformed target",
		},
		{
			name:      "reject_empty_host",
			rawReq:    "CONNECT :443 HTTP/1.1\r\n\r\n",
			errSubstr: "empty target host",
		},
		{
			name:      "reject_null_byte_in_target",
			rawReq:    "CONNECT example.com\x00:443 HTTP/1.1\r\n\r\n",
			errSubstr: "control character",
		},
		{
			name:      "reject_ansi_escape_in_target",
			rawReq:    "CONNECT example.com\x1b[31m:443 HTTP/1.1\r\n\r\n",
			errSubstr: "malformed target",
		},
		{
			name:     "accept_valid_connect",
			rawReq:   "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n",
			wantHost: "api.example.com",
			wantPort: "443",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			conn := &mockConn{Buffer: *bytes.NewBufferString(tc.rawReq)}
			host, port, _, err := readConnect(conn)
			if tc.errSubstr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errSubstr) {
					t.Fatalf("expected error containing %q, got: %v", tc.errSubstr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected readConnect error: %v", err)
			}
			if host != tc.wantHost || port != tc.wantPort {
				t.Fatalf("readConnect = (%q, %q); want (%q, %q)", host, port, tc.wantHost, tc.wantPort)
			}
		})
	}
}

func TestAdversarialGatekeeperPanicsAndCancels(t *testing.T) {
	t.Parallel()

	// Gatekeeper that panics
	panickingGate := func(ctx context.Context, host, port string) bool {
		panic("gatekeeper unexpected explosion!")
	}

	p := New(nil, WithGatekeeper(panickingGate))
	admitted := p.callGate(context.Background(), "evil.com", "443")
	if admitted {
		t.Fatal("callGate must return false when gatekeeper panics")
	}
}

type mockConn struct {
	net.Conn
	bytes.Buffer
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	return m.Buffer.Read(b)
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (m *mockConn) Close() error {
	return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}
