package main

import (
	"io"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/internal/manifest"
	"github.com/whiskeyjimbo/bento-v2/internal/policy"
)

func doc(approves string) *manifest.Document {
	p := &policy.Policy{Entrypoint: "./x", Read: []string{"/data"}}
	return &manifest.Document{Policy: p, Provenance: manifest.Provenance{Approves: approves}}
}

func TestCheckApproval(t *testing.T) {
	p := &policy.Policy{Entrypoint: "./x", Read: []string{"/data"}}
	cases := map[string]struct {
		approves string
		want     approvalState
	}{
		"no approval":   {"", approvalUnstamped},
		"matching":      {p.Fingerprint(), approvalCurrent},
		"changed since": {"a-stale-fingerprint", approvalStale},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := checkApproval(doc(tc.approves)); got != tc.want {
				t.Errorf("checkApproval = %v, want %v", got, tc.want)
			}
		})
	}
}

// --strict must fail on a stale or missing approval and pass on a current one;
// without --strict, none of them fail.
func TestReportApprovalStrictness(t *testing.T) {
	current := &policy.Policy{Entrypoint: "./x", Read: []string{"/data"}}

	cases := map[string]struct {
		doc        *manifest.Document
		strictFail bool
	}{
		"stale":     {doc("old"), true},
		"unstamped": {doc(""), true},
		"current":   {&manifest.Document{Policy: current, Provenance: manifest.Provenance{Approves: current.Fingerprint()}}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if err := reportApproval(io.Discard, tc.doc, false); err != nil {
				t.Errorf("non-strict must never fail; got %v", err)
			}
			err := reportApproval(io.Discard, tc.doc, true)
			if tc.strictFail && err == nil {
				t.Error("--strict should have failed")
			}
			if !tc.strictFail && err != nil {
				t.Errorf("--strict should have passed; got %v", err)
			}
		})
	}
}
