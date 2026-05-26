package proxy

import (
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/spec"
)

func TestMatchHost(t *testing.T) {
	cases := []struct {
		rule, host string
		want       bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "api.example.com", false},
		{"*", "anything.example.com", true},
		{"*", "", true},
		{".example.com", "api.example.com", true},
		{".example.com", "deep.api.example.com", true},
		{".example.com", "example.com", false}, // suffix must include the dot
		{".example.com", "fakeexample.com", false},
		{"", "example.com", false},
		// Case insensitivity (DNS is case-insensitive).
		{"EXAMPLE.com", "example.com", true},
		{"example.com", "EXAMPLE.COM", true},
		{".Example.com", "API.Example.COM", true},
	}
	for _, c := range cases {
		got := matchHost(c.rule, c.host)
		if got != c.want {
			t.Errorf("matchHost(%q, %q) = %v, want %v", c.rule, c.host, got, c.want)
		}
	}
}

func TestIsValidHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
		why  string
	}{
		// Valid canonical forms
		{"example.com", true, "DNS name"},
		{"api.example.com", true, "subdomain"},
		{"_dmarc.example.com", true, "underscore DNS label"},
		{"127.0.0.1", true, "canonical IPv4"},
		{"::1", true, "canonical IPv6"},
		{"2001:db8::1", true, "IPv6"},
		{"a", true, "single-char DNS"},

		// Reject: empty / overlong
		{"", false, "empty"},
		{strings.Repeat("a", 254), false, "overlong"},

		// Reject: control characters and bypass payloads
		{"evil.com\x00.allowed.com", false, "null-byte bypass"},
		{"evil\rhost.com", false, "CR"},
		{"evil\nhost.com", false, "LF"},
		{"::1%eth0", false, "IPv6 zone ID"},
		{"::ffff:1.2.3.4%x.allowed.com", false, "zone ID bypass"},

		// Reject: non-canonical IPv4 (inet_aton bypass vectors)
		{"127.1", false, "dotted shorthand"},
		{"2852039166", false, "integer form (169.254.169.254)"},
		{"0x7f.0.0.1", false, "hex octet"},
		{"0177.0.0.1", false, "octal"},

		// Reject: malformed DNS
		{"host with spaces", false, "whitespace"},
		{"host;name", false, "semicolon"},
		{"-leading-dash.com", true, "regex allows; DNS spec would reject but our charset is permissive"},
	}
	for _, c := range cases {
		got := isValidHost(c.host)
		if got != c.want {
			t.Errorf("isValidHost(%q) = %v, want %v (%s)", c.host, got, c.want, c.why)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"Example.COM", "example.com"},
		{"example.com.", "example.com"}, // trailing dot
		{"127.0.0.1", "127.0.0.1"},      // IP unchanged
		{"::1", "::1"},                  // IPv6 unchanged
		{"", ""},
	}
	for _, c := range cases {
		if got := normalizeHost(c.in); got != c.want {
			t.Errorf("normalizeHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMatchPort(t *testing.T) {
	cases := []struct {
		rule string
		port int
		want bool
	}{
		{"443", 443, true},
		{"443", 80, false},
		{"*", 1, true},
		{"*", 65535, true},
		{"8000-9000", 8000, true},
		{"8000-9000", 9000, true},
		{"8000-9000", 8500, true},
		{"8000-9000", 7999, false},
		{"8000-9000", 9001, false},
		{"abc", 443, false},       // malformed
		{"100-bogus", 150, false}, // malformed range
		{"", 443, false},
	}
	for _, c := range cases {
		got := matchPort(c.rule, c.port)
		if got != c.want {
			t.Errorf("matchPort(%q, %d) = %v, want %v", c.rule, c.port, got, c.want)
		}
	}
}

func TestMatchPerm(t *testing.T) {
	perm := &spec.NetworkPerm{
		Rules: []spec.NetworkRule{
			{Host: "example.com", Port: "443"},
			{Host: ".github.com", Port: "443"},
			{Host: "*", Port: "8080"},
		},
	}
	cases := []struct {
		host string
		port int
		want bool
	}{
		{"example.com", 443, true},
		{"example.com", 80, false},    // wrong port
		{"api.github.com", 443, true}, // subdomain via .suffix
		{"github.com", 443, false},    // .github.com requires the dot prefix
		{"anything", 8080, true},      // wildcard host on 8080
		{"example.com", 8080, true},   // matches the wildcard rule even if specific rule has different port
	}
	for _, c := range cases {
		got := matchPerm(perm, c.host, c.port)
		if got != c.want {
			t.Errorf("matchPerm(%q, %d) = %v, want %v", c.host, c.port, got, c.want)
		}
	}

	if matchPerm(nil, "example.com", 443) {
		t.Error("matchPerm(nil, ...) should always be false")
	}
	if matchPerm(&spec.NetworkPerm{}, "example.com", 443) {
		t.Error("matchPerm with empty Rules should always be false")
	}
}
