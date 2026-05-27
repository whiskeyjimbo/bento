package proxy

import (
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/whiskeyjimbo/bento/internal/grants"
	"github.com/whiskeyjimbo/bento/internal/spec"
)

// dnsLabelCharset accepts DNS labels plus underscore (for _dmarc-style records).
var dnsLabelCharset = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// isValidHost rejects allowlist-bypass vectors: control chars, "%" (IPv6 zone
// IDs), non-canonical IP literals ("127.1", "2852039166", "0x7f.0.0.1"), and
// non-DNS-shaped strings. Stricter than canonicalize-then-compare.
func isValidHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if strings.ContainsAny(h, "\x00\r\n%") {
		return false
	}
	bare := h
	if strings.HasPrefix(bare, "[") && strings.HasSuffix(bare, "]") {
		bare = bare[1 : len(bare)-1] // ParseIP doesn't accept brackets
	}
	if ip := net.ParseIP(bare); ip != nil {
		// Require canonical form — reject "::01", which ParseIP would normalize.
		return ip.String() == bare
	}
	// RFC 1123: last label must contain a letter, which also rejects inet_aton bypasses.
	if !dnsLabelCharset.MatchString(bare) {
		return false
	}
	lastDot := strings.LastIndex(bare, ".")
	lastLabel := bare[lastDot+1:]
	return strings.ContainsAny(lastLabel, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

// normalizeHost lowercases and strips trailing dot. IP literals pass through.
func normalizeHost(h string) string {
	if h == "" {
		return h
	}
	if net.ParseIP(strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")) != nil {
		return h
	}
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

// matchPerm reports whether host:port is allowed by perm. Caller must have
// already validated host with isValidHost.
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

// matchHost: literal, "*", or ".suffix" wildcard. Case-insensitive.
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
