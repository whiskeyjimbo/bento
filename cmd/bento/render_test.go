package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/enforce"
	"github.com/whiskeyjimbo/bento-v2/policy"
)

func TestIsLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost":       true,
		"127.0.0.1":       true,
		"127.0.0.2":       true, // all of 127/8 is loopback
		"::1":             true,
		"example.com":     false,
		"10.0.0.1":        false,
		"169.254.169.254": false,
	} {
		if got := isLoopbackHost(host); got != want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestEgressHintFiresOnlyWhenRelevant(t *testing.T) {
	networked := &policy.Policy{Network: []policy.NetworkRule{{Host: "a.com", Port: "443"}}}
	noNetwork := &policy.Policy{}

	cases := []struct {
		name string
		p    *policy.Policy
		res  enforce.Result
		want bool
	}{
		{"likely bypass: network requested, failed, no proxy connections", networked, enforce.Result{ExitCode: 1, EgressConnections: 0}, true},
		{"used the proxy then failed for another reason", networked, enforce.Result{ExitCode: 1, EgressConnections: 3}, false},
		{"network run succeeded", networked, enforce.Result{ExitCode: 0, EgressConnections: 0}, false},
		{"no network requested", noNetwork, enforce.Result{ExitCode: 1, EgressConnections: 0}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			writeEgressHint(&b, tc.p, tc.res)
			got := strings.Contains(b.String(), "egress proxy")
			if got != tc.want {
				t.Errorf("hint emitted = %v, want %v (output: %q)", got, tc.want, b.String())
			}
		})
	}
}
