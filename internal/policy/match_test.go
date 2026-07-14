package policy

import "testing"

func TestAllows(t *testing.T) {
	rules := []NetworkRule{
		{Host: "api.github.com", Port: "443"},
		{Host: ".example.com", Port: "8000-9000"},
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
		{"example.com", "8080", false}, // suffix must NOT match the apex
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

func TestMatchPortRangeBoundsInclusive(t *testing.T) {
	if !matchPort("8000-9000", "8000") || !matchPort("8000-9000", "9000") {
		t.Error("range bounds must be inclusive")
	}
	if matchPort("8000-9000", "7999") || matchPort("8000-9000", "9001") {
		t.Error("ports outside the range must not match")
	}
}
