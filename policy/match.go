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
//
// PRECONDITIONS, which this function does not restate and a caller must meet:
//
//   - rules have passed Validate, so every Host is canonical and every Port is plain
//     decimal.
//   - host and port come from a screened CONNECT target - no control bytes, and a
//     canonically spelled port.
//
// Neither is a formality. A target carrying a NUL ("evil.com\x00.example.com") matches
// the suffix rule ".example.com" here, while a resolver that truncates at the NUL dials
// evil.com - the name checked and the name dialed differ. bento's proxy rejects such a
// target when it parses the CONNECT line, which is why this is a precondition rather
// than a hole; a second caller that skips that screen reopens it.
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

// NormalizeHost is the host key Allows compares against, exported for an embedder that
// keys state of its own by host - a supervising wrapper remembering per-host decisions -
// and would otherwise hand-roll the fold. Its copy is what diverges: strings.ToLower is
// the obvious spelling and the wrong one, for the reason normalizeHost gives below.
func NormalizeHost(host string) string { return normalizeHost(host) }

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
//
// Comparison is textual, while the proxy's resolved-IP guard compares addresses with
// net.IP.Equal. The two cannot disagree about a rule, because validateHostPattern accepts
// an IP literal only in its canonical spelling and net.ParseIP("::ffff:10.0.0.1").String()
// is "10.0.0.1" - so a rule naming an address in v4-mapped form cannot be written at all.
// A v4-mapped TARGET simply does not match a v4 rule here, which is the safe direction:
// it denies rather than grants. Making this IP-aware would widen what a rule reaches
// beyond what its author wrote.
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
// a hot path where the input was already validated at load time. It is lenient about
// spelling where strconv would not be - "0443" parses as 443 - which is safe only
// because both the rule (validatePort) and the CONNECT target (the proxy's
// canonicalPort) are required to be plain decimal before they reach here. It affects
// only the range branch in any case: the literal branch compares the strings.
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
