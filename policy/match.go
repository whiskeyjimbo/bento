package policy

import "strings"

// Allows reports whether a connection to host:port is permitted by the rules.
//
// This is the runtime counterpart to the rule validation in Validate: the proxy
// calls it for every outbound connection a sandboxed script attempts. It lives
// with the domain because it is the meaning of a NetworkRule, and both the proxy
// and any future explainer must agree on that meaning exactly.
//
// An empty rule set denies everything, matching the manifest semantics that no
// `network:` block means no egress.
func Allows(rules []NetworkRule, host, port string) bool {
	host = normalizeHost(host)
	for _, r := range rules {
		if matchHost(r.Host, host) && matchPort(r.Port, port) {
			return true
		}
	}
	return false
}

// PortMatches reports whether a port matches a rule's port pattern (exact, "*",
// or "lo-hi"). The egress proxy's resolved-IP guard uses it to apply the same
// port semantics as Allows when deciding whether an explicit IP-literal rule
// authorizes a connection to a non-public address.
func PortMatches(pattern, port string) bool { return matchPort(pattern, port) }

// normalizeHost lowercases and strips a trailing dot (the DNS root label), so
// "API.Example.Com." and "api.example.com" compare equal.
//
// Folding is ASCII-only, deliberately not strings.ToLower: Unicode case-folding
// maps codepoints like U+212A (KELVIN SIGN) onto ASCII 'k', which would let a
// target host containing that codepoint match an ASCII-only rule while the proxy
// dials the raw bytes - the name checked and the name dialed would differ. Rule
// hosts are ASCII (isHostname), so a non-ASCII target simply fails to match, which
// is the safe result.
func normalizeHost(host string) string {
	return strings.TrimSuffix(asciiLower(host), ".")
}

// asciiLower lowercases only A-Z, leaving every other byte untouched. Operating
// per-byte is safe for UTF-8: no continuation or lead byte falls in the A-Z range.
func asciiLower(host string) string {
	b := []byte(host)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// matchHost applies one rule's host pattern to a connect target.
//
//   - "*"          matches any host.
//   - ".suffix"    matches a subdomain of suffix (api.example.com) but NOT the
//     bare domain (example.com); that asymmetry is deliberate, so granting
//     ".example.com" does not silently also grant the apex.
//   - literal      matches exactly.
func matchHost(pattern, host string) bool {
	// host is already normalized by Allows; normalize the pattern too so a rule
	// written with uppercase (DNS is case-insensitive) matches the same targets.
	pattern = normalizeHost(pattern)
	switch {
	case pattern == "*":
		return true
	case strings.HasPrefix(pattern, "."):
		return strings.HasSuffix(host, pattern)
	default:
		return pattern == host
	}
}

// matchPort applies one rule's port pattern to a connect target port.
//
//   - "*"       matches any port.
//   - "lo-hi"   matches a port within the inclusive range.
//   - literal   matches exactly.
func matchPort(pattern, port string) bool {
	switch {
	case pattern == "*":
		return true
	case strings.Contains(pattern, "-"):
		lo, hi, ok := strings.Cut(pattern, "-")
		n, nok := atoiPort(port)
		l, lok := atoiPort(lo)
		h, hok := atoiPort(hi)
		return ok && nok && lok && hok && n >= l && n <= h
	default:
		return pattern == port
	}
}

// atoiPort parses a port string without pulling in strconv's error handling for
// a hot path where the input was already validated at load time.
func atoiPort(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
		if n > 65535 {
			return 0, false
		}
	}
	return n, true
}
