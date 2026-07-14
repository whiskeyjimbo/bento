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

// normalizeHost lowercases and strips a trailing dot (the DNS root label), so
// "API.Example.Com." and "api.example.com" compare equal.
func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// matchHost applies one rule's host pattern to a connect target.
//
//   - "*"          matches any host.
//   - ".suffix"    matches a subdomain of suffix (api.example.com) but NOT the
//     bare domain (example.com); that asymmetry is deliberate, so granting
//     ".example.com" does not silently also grant the apex.
//   - literal      matches exactly.
func matchHost(pattern, host string) bool {
	switch {
	case pattern == "*":
		return true
	case strings.HasPrefix(pattern, "."):
		return strings.HasSuffix(host, pattern)
	default:
		return normalizeHost(pattern) == host
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
