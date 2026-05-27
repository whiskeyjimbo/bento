package proxy

import (
	"net"
	"strconv"
	"strings"

	"github.com/whiskeyjimbo/bento/internal/grants"
	"github.com/whiskeyjimbo/bento/internal/spec"
)

// isValidHost rejects allowlist-bypass vectors at connect time. Concrete
// hosts only (no "*" or ".suffix" — those are rule patterns, not connect
// targets). Shares its canonicalization logic with spec.IsCanonicalHostPattern.
func isValidHost(h string) bool {
	if h == "" || h == "*" || strings.HasPrefix(h, ".") {
		return false
	}
	return spec.IsCanonicalHostPattern(h)
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
				return true, "ALLOW"
			}
			return false, "DENIED-CACHED"
		}
	}
	decision := a.grants(req)
	if a.grantCache != nil {
		a.grantCache.Store(req, decision)
	}
	if decision == grants.DecisionAllow {
		return true, "ALLOW"
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
