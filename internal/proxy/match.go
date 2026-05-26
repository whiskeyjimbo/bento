package proxy

import (
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/whiskeyjimbo/bento/internal/grants"
	"github.com/whiskeyjimbo/bento/internal/spec"
)

// dnsLabelCharset accepts standard DNS labels plus dot (separator),
// hyphen (intra-label), and underscore (real-world records like
// _dmarc, _acme-challenge). Anything else is rejected outright — no
// whitespace, no control chars, no %, no NUL.
var dnsLabelCharset = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// isValidHost rejects host strings that are bypass vectors for our
// allowlist. See bento-609 for the threat model. Specifically refuses:
//
//   - empty / overlong (>253) inputs
//   - control characters (NUL, CR, LF) anywhere
//   - "%" anywhere (IPv6 zone-ID payloads like "::1%eth0")
//   - IP literals that aren't already in canonical form (rejects
//     "127.1", "2852039166", "0x7f.0.0.1")
//   - DNS-looking strings that don't match the DNS charset
//
// Stricter than canonicalize-then-compare: rather than parse permissive
// forms and translate, we refuse them. Legit scripts using "127.1"
// get a clear error and re-declare with "127.0.0.1".
func isValidHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if strings.ContainsAny(h, "\x00\r\n%") {
		return false
	}
	// Strip IPv6 brackets for ParseIP (it doesn't accept "[::1]").
	bare := h
	if strings.HasPrefix(bare, "[") && strings.HasSuffix(bare, "]") {
		bare = bare[1 : len(bare)-1]
	}
	if ip := net.ParseIP(bare); ip != nil {
		// Canonical form check: ParseIP normalizes (e.g. "::01" → "::1");
		// require the input already match that normalized form.
		// Note: ParseIP is strict — it returns nil for "127.1",
		// "0x7f.0.0.1", "2852039166", etc. Those fall through to the
		// DNS path below where the "letters required" rule catches
		// them.
		return ip.String() == bare
	}
	// Not a canonical IP — must look like a DNS hostname AND have at
	// least one letter in the last label. All-numeric labels are
	// reserved by DNS (RFC 1123) and are the failure mode for
	// inet_aton bypass attempts ("127.1", "2852039166", etc.).
	if !dnsLabelCharset.MatchString(bare) {
		return false
	}
	lastDot := strings.LastIndex(bare, ".")
	lastLabel := bare[lastDot+1:]
	return strings.ContainsAny(lastLabel, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

// normalizeHost lower-cases hostnames (DNS is case-insensitive) and
// strips an optional trailing dot ("example.com." → "example.com").
// Run on both the rule and the request host before comparison.
//
// IP literals are returned as-is — net.ParseIP's canonical form is
// already what isValidHost accepts.
func normalizeHost(h string) string {
	if h == "" {
		return h
	}
	if net.ParseIP(strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")) != nil {
		return h
	}
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

// matchPerm reports whether host:port is allowed by perm. Callers must
// have already validated host with isValidHost; matchPerm itself only
// handles the lookup, not the security check.
func matchPerm(perm *spec.NetworkPerm, host string, port int) bool {
	if perm == nil {
		return false
	}
	host = normalizeHost(host)
	for _, r := range perm.Rules {
		if matchHost(r.Host, host) && matchPort(r.Port, port) {
			return true
		}
	}
	return false
}

// matchHost: literal, "*", or ".suffix" (e.g. ".example.com" matches
// "api.example.com"). Both rule and host are normalized for
// case-insensitive comparison; DNS is case-insensitive.
func matchHost(rule, host string) bool {
	rule = normalizeHost(rule)
	host = normalizeHost(host)
	if rule == "*" || rule == host {
		return true
	}
	if strings.HasPrefix(rule, ".") && strings.HasSuffix(host, rule) {
		return true
	}
	return false
}

type defaultAuthorizer struct {
	perm       *spec.NetworkPerm
	grants     grants.Callback
	grantCache grants.DecisionCache
}

func (a *defaultAuthorizer) Authorize(host string, port int) (bool, string) {
	if matchPerm(a.perm, host, port) {
		return true, "ALLOW"
	}
	if a.grants == nil {
		return false, "DENY"
	}
	req := grants.Request{Kind: grants.KindNetwork, Host: host, Port: port}
	if a.grantCache != nil {
		if cached, ok := a.grantCache.Lookup(req); ok {
			if cached == grants.DecisionAllow {
				return true, "GRANTED-CACHED"
			}
			return false, "DENIED-CACHED"
		}
	}
	decision := a.grants(req)
	if a.grantCache != nil {
		a.grantCache.Store(req, decision)
	}
	if decision == grants.DecisionAllow {
		return true, "GRANTED"
	}
	return false, "DENIED-BY-USER"
}

// matchPort: "*", literal "443", or range "8000-9000".
func matchPort(rule string, port int) bool {
	if rule == "*" {
		return true
	}
	if loStr, hiStr, ok := strings.Cut(rule, "-"); ok {
		lo, err1 := strconv.Atoi(loStr)
		hi, err2 := strconv.Atoi(hiStr)
		if err1 != nil || err2 != nil {
			return false
		}
		return port >= lo && port <= hi
	}
	n, err := strconv.Atoi(rule)
	return err == nil && n == port
}
