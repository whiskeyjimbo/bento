package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/manifest"
	"github.com/whiskeyjimbo/bento/policy"
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
// WRITTEN, before manifest.Resolve rewrites its relative paths to absolute. This
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
	manifest.Resolve(p, "/work/proj/manifest.yaml")
	if p.Fingerprint() == stamped {
		t.Fatal("manifest.Resolve must change the fingerprint, else the check ordering would not matter")
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

// approve rewrites the manifest others read, so a world-writable one gives away the
// only thing the stamp is worth: that the permissions cannot change without the
// approval going stale. It is written back with the shared write bits removed
// (bv2-w4n5).
func TestApproveDropsSharedWriteBits(t *testing.T) {
	path := writeManifest(t, &policy.Policy{Entrypoint: "./x"}, manifest.Provenance{})
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := runCapturingStdout(t, newApproveCmd(), path); err != nil {
		t.Fatalf("approve: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got&0o022 != 0 {
		t.Errorf("mode = %#o, want the group/world write bits cleared", got)
	}
}

// A manifest kept in a dotfiles repo and symlinked into place is ordinary. Renaming
// onto the link would replace it with a regular file and detach it from its source, so
// approve writes at the resolved location and the link survives.
func TestApproveWritesThroughASymlink(t *testing.T) {
	target := writeManifest(t, &policy.Policy{Entrypoint: "./x"}, manifest.Provenance{})
	link := filepath.Join(t.TempDir(), "link.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := runCapturingStdout(t, newApproveCmd(), link); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the symlink must survive approve; lstat = %v, %v", fi, err)
	}
	doc, _, err := loadDocument(target, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if checkApproval(doc) != approvalCurrent {
		t.Error("the stamp must land on the link's target, not on a file replacing the link")
	}
}

// The location approve writes at is the one its trust check inspected, so repointing the
// symlink after the check cannot redirect the stamp. Standing in for the race: whoever can
// replace the link gets to do it at a moment of their choosing, and this is that moment.
func TestWriteManifestAtomicallyIgnoresARepointedSymlink(t *testing.T) {
	target := writeManifest(t, &policy.Policy{Entrypoint: "./x"}, manifest.Provenance{})
	link := filepath.Join(t.TempDir(), "link.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	trust := trustOf(t, link)

	elsewhere := writeManifest(t, &policy.Policy{Entrypoint: "./elsewhere"}, manifest.Provenance{})
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Fatal(err)
	}
	if err := writeManifestAtomically(trust, []byte("entrypoint: ./y\n"), io.Discard); err != nil {
		t.Fatalf("writeManifestAtomically: %v", err)
	}

	if data, err := os.ReadFile(target); err != nil || string(data) != "entrypoint: ./y\n" {
		t.Errorf("the inspected target must get the write; got %q, %v", data, err)
	}
	if data, err := os.ReadFile(elsewhere); err != nil || string(data) == "entrypoint: ./y\n" {
		t.Errorf("the repointed target must not be written; got %q, %v", data, err)
	}
}

// A manifest replaced or unlinked between the open and the readlink leaves the kernel
// naming something the facts do not describe - "/w/m.yaml (deleted)", or another inode
// entirely. Concluding a location from either would send a rewrite somewhere unexamined.
func TestInspectManifestRefusesAManifestUnlinkedWhileOpen(t *testing.T) {
	path := writeManifest(t, &policy.Policy{Entrypoint: "./x"}, manifest.Provenance{})
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectManifest(f, path); err == nil {
		t.Error("an unlinked manifest has no location to judge, so it must fail")
	}
}

// A failed write must not leave a truncated manifest where a complete one was: the
// replacement goes through a temporary file and a rename, so the manifest is only ever
// the old bytes or the new ones - and no temp file is left behind.
func TestWriteManifestAtomicallyLeavesNoTempFiles(t *testing.T) {
	path := writeManifest(t, &policy.Policy{Entrypoint: "./x"}, manifest.Provenance{})
	dir := filepath.Dir(path)
	if err := writeManifestAtomically(trustOf(t, path), []byte("entrypoint: ./y\n"), io.Discard); err != nil {
		t.Fatalf("writeManifestAtomically: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".bento-") {
			t.Errorf("left a temporary file behind: %s", e.Name())
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "entrypoint: ./y\n" {
		t.Errorf("manifest = %q, want the new bytes", data)
	}
}

// A stamp is current as long as the policy has not changed, and the mode is no part of
// the fingerprint - so chmod after an approve leaves the stamp reading as current over
// permissions nobody attested. Reporting that as already approved would vouch for what
// it never checked, so the clamp runs regardless of the stamp.
func TestApproveClampsAnAlreadyApprovedManifest(t *testing.T) {
	path := writeManifest(t, &policy.Policy{Entrypoint: "./x"}, manifest.Provenance{})
	if _, err := runCapturingStdout(t, newApproveCmd(), path); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := runCapturingStdout(t, newApproveCmd(), path); err != nil {
		t.Fatalf("second approve: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got&0o022 != 0 {
		t.Errorf("mode = %#o, want the group/world write bits cleared", got)
	}
}
