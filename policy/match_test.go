package policy

import "testing"

func TestAllows(t *testing.T) {
	rules := []NetworkRule{
		{Host: "api.github.com", Port: "443"},
		{Host: ".example.com", Port: "8000-9000"},
		{Host: ".Uppercase.Dev", Port: "443"}, // DNS is case-insensitive
		{Host: "10.0.0.1", Port: "*"},
		{Host: "*", Port: "22"},
	}

	cases := []struct {
		host, port string
		want       bool
	}{
		{"api.github.com", "443", true},   // exact
		{"api.github.com", "80", false},   // right host, wrong port
		{"API.GitHub.com", "443", true},   // case-insensitive
		{"api.github.com.", "443", true},  // trailing dot normalized
		{"sub.example.com", "8080", true}, // suffix + range
		{"sub.example.com", "9001", false},
		{"api.uppercase.dev", "443", true}, // uppercase suffix-wildcard rule still matches
		{"example.com", "8080", false},     // suffix must NOT match the apex
		{"evil-example.com", "8080", false},
		{"10.0.0.1", "5432", true},   // IP + any port
		{"anything.net", "22", true}, // any host + literal port
		{"anything.net", "23", false},
		{"github.com", "443", false}, // not a subdomain of a rule
	}
	for _, tc := range cases {
		if got := Allows(rules, tc.host, tc.port); got != tc.want {
			t.Errorf("Allows(%q, %q) = %v, want %v", tc.host, tc.port, got, tc.want)
		}
	}
}

func TestAllowsEmptyRulesDeniesEverything(t *testing.T) {
	if Allows(nil, "example.com", "443") {
		t.Error("no rules must deny all egress")
	}
}

func TestAllowsRejectsUnicodeFoldedHost(t *testing.T) {
	// U+212A KELVIN SIGN folds to ASCII 'k' under Unicode-aware lowercasing. The
	// rule host is ASCII and the proxy dials the target's raw bytes, so a name that
	// matches only after Unicode folding must be denied: otherwise the name checked
	// against the rule differs from the name actually dialed.
	rules := []NetworkRule{{Host: "bank.example.com", Port: "443"}}
	if Allows(rules, "banK.example.com", "443") {
		t.Error("a host matching only via Unicode case-folding must be denied")
	}
	// The ASCII form still matches, case-insensitively.
	if !Allows(rules, "BANK.example.com", "443") {
		t.Error("ASCII case-insensitive match must still hold")
	}
}

func TestMatchPortRangeBoundsInclusive(t *testing.T) {
	if !matchPort("8000-9000", "8000") || !matchPort("8000-9000", "9000") {
		t.Error("range bounds must be inclusive")
	}
	if matchPort("8000-9000", "7999") || matchPort("8000-9000", "9001") {
		t.Error("ports outside the range must not match")
	}
}

// matchHost compares hosts as text while the proxy's resolved-IP guard compares them as
// addresses. They cannot disagree about a RULE, and this pins the two halves of why: a
// v4-mapped spelling is refused at validation, so no rule can carry one; and a v4-mapped
// TARGET does not match a v4 rule, which denies rather than grants. If either half is
// ever relaxed, the textual comparison starts reaching addresses its author did not write.
func TestHostMatchingIsTextualByConstruction(t *testing.T) {
	if err := validateHostPattern("::ffff:10.0.0.1"); err == nil {
		t.Error("a v4-mapped rule spelling must be refused as non-canonical; matchHost's textual comparison depends on it")
	}
	if matchHost("10.0.0.1", normalizeHost("::ffff:10.0.0.1")) {
		t.Error("a v4-mapped target must not match a v4 rule textually")
	}
}

// Allows does not screen its input, and that is a precondition on its callers rather
// than a property they can discover. A target carrying a NUL matches a suffix rule here
// while a resolver truncating at the NUL dials evil.com, so the CONNECT parser has to
// reject it first - bento's does. This asserts the unscreened behavior deliberately: if
// someone adds screening inside Allows, this test fails and points at the doc comment
// that would then be wrong, rather than passing quietly either way.
func TestAllowsLeavesTargetScreeningToItsCaller(t *testing.T) {
	if !Allows([]NetworkRule{{Host: ".example.com", Port: "443"}}, "evil.com\x00.example.com", "443") {
		t.Error("Allows now screens its input; update its documented precondition and the proxy's CONNECT parser comment to match")
	}
}
