package main

import (
	"io"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/manifest"
	"github.com/whiskeyjimbo/bento-v2/policy"
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

// run refuses a manifest whose approval is not current by default, so a manifest
// edited after approval (drift) is caught at run time, not only by validate;
// --allow-unapproved opts out.
func TestRequireApproval(t *testing.T) {
	current := &policy.Policy{Entrypoint: "./x", Read: []string{"/data"}}
	approved := &manifest.Document{Policy: current, Provenance: manifest.Provenance{Approves: current.Fingerprint()}}

	if err := requireApproval(approved, false); err != nil {
		t.Errorf("a current approval must run; got %v", err)
	}
	for name, d := range map[string]*manifest.Document{"stale": doc("old"), "unstamped": doc("")} {
		if err := requireApproval(d, false); err == nil {
			t.Errorf("%s approval must be refused without --allow-unapproved", name)
		}
		if err := requireApproval(d, true); err != nil {
			t.Errorf("%s approval must run under --allow-unapproved; got %v", name, err)
		}
	}
}

// The approval binding depends on the fingerprint being checked on the manifest AS
// WRITTEN, before resolveManifestPaths rewrites its relative paths to absolute. This
// pins that ordering: resolution changes the fingerprint, so a check run after it
// would reject a validly-approved manifest - and a fingerprint stamped post-resolution
// would shift with the invocation directory. run.go checks approval first for exactly
// this reason.
func TestApprovalCheckedBeforePathResolution(t *testing.T) {
	p := &policy.Policy{Entrypoint: "run.py", Read: []string{"data"}} // relative on purpose
	stamped := p.Fingerprint()
	doc := &manifest.Document{Policy: p, Provenance: manifest.Provenance{Approves: stamped}}

	if got := checkApproval(doc); got != approvalCurrent {
		t.Fatalf("as-written approval = %v, want current", got)
	}
	resolveManifestPaths(p, "/work/proj/manifest.yaml")
	if p.Fingerprint() == stamped {
		t.Fatal("resolveManifestPaths must change the fingerprint, else the check ordering would not matter")
	}
	if got := checkApproval(doc); got != approvalStale {
		t.Fatalf("post-resolution approval = %v, want stale (so the check must precede resolution)", got)
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
