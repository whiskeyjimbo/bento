package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/manifest"
	"github.com/whiskeyjimbo/bento/policy"
)

// stateHome points the journal at a directory this test owns. The environment is the seam:
// journalDir reads $XDG_STATE_HOME, so nothing here needs a filesystem interface.
func stateHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", dir)
	return dir
}

// editManifest rewrites a manifest in place the way an editor does - through a temporary
// file and a rename, which is what vim, emacs, gofmt -w and sed -i all do. The stamp is
// carried across deliberately: that is the drifted state the reader meets.
func editManifest(t *testing.T, path string, p *policy.Policy, prov manifest.Provenance) {
	t.Helper()
	data, err := manifest.Marshal(p, prov)
	if err != nil {
		t.Fatal(err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func stamped(t *testing.T, path string) *manifest.Document {
	t.Helper()
	doc, _, err := loadDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// The whole point of the journal: after a real approve, a re-approval of the same manifest
// can name the grant that was added rather than telling the reader to re-read everything.
// This is bv2-49sm's edit-run-fail loop.
func TestReapprovalNamesTheChangedGrants(t *testing.T) {
	stateHome(t)
	before := &policy.Policy{Entrypoint: "./x", Read: []string{"/data"}}
	path := writeManifest(t, before, manifest.Provenance{})
	if _, err := runCapturingStdout(t, newApproveCmd(), path, "--yes"); err != nil {
		t.Fatal(err)
	}

	// The edit that invalidates the stamp, through a rename as an editor would: the record
	// is keyed on the path and validated by the fingerprint, so replacing the file must not
	// cost the reader the diff.
	approved := stamped(t, path)
	after := &policy.Policy{Entrypoint: "./x", Read: []string{"/data"}, Write: []string{"/out"}}
	editManifest(t, path, after, approved.Provenance)

	out, err := runCapturingStdout(t, newApproveCmd(), path, "--yes")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "/out") {
		t.Errorf("the re-approval must name the added grant; got:\n%s", out)
	}
	if !strings.Contains(out, "+ ") {
		t.Errorf("the added line must be marked as added; got:\n%s", out)
	}
}

// Removals are namable too, which is what holding the whole approved shape buys over the
// per-line-hash design that was rejected: a dropped grant can only be counted there.
func TestReapprovalNamesRemovedGrants(t *testing.T) {
	stateHome(t)
	before := &policy.Policy{Entrypoint: "./x", Read: []string{"/data"}, Network: []policy.NetworkRule{{Host: "api.example.com", Port: "443"}}}
	path := writeManifest(t, before, manifest.Provenance{})
	if _, err := runCapturingStdout(t, newApproveCmd(), path, "--yes"); err != nil {
		t.Fatal(err)
	}

	approved := stamped(t, path)
	editManifest(t, path, &policy.Policy{Entrypoint: "./x", Read: []string{"/data"}}, approved.Provenance)

	out, err := runCapturingStdout(t, newApproveCmd(), path, "--yes")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "- - host: api.example.com") {
		t.Errorf("the re-approval must name the removed rule as removed; got:\n%s", out)
	}
}

// A stamp this host never wrote is the verdict a manifest-stored record could never
// produce, and it is worth more than a diff: it tells the reader the approval in front of
// them is somebody else's review.
func TestReapprovalSaysWhenTheStampIsNotOurs(t *testing.T) {
	stateHome(t)
	p := &policy.Policy{Entrypoint: "./x", Read: []string{"/data"}}
	doc := &manifest.Document{Policy: p, Provenance: manifest.Provenance{Approves: "a-stamp-from-elsewhere"}}

	var buf strings.Builder
	writeReapprovalNotice(&buf, "/nowhere/m.yaml", doc, approvalStale)
	out := buf.String()
	if !strings.Contains(out, "did not write") {
		t.Errorf("an absent record must say the stamp is not this host's; got:\n%s", out)
	}
	if strings.Contains(out, "+ ") || strings.Contains(out, "changed since then") {
		t.Errorf("an absent record must not produce a diff; got:\n%s", out)
	}
}

// A record that disagrees with the stamp the manifest now carries describes some other
// approval - re-stamped elsewhere, or the file swapped for a different manifest. Diffing
// against it would name lines that were never in the policy this stamp attests.
func TestReapprovalRefusesToDiffAgainstADisagreeingRecord(t *testing.T) {
	stateHome(t)
	before := &policy.Policy{Entrypoint: "./x", Read: []string{"/data"}}
	path := writeManifest(t, before, manifest.Provenance{})
	if _, err := runCapturingStdout(t, newApproveCmd(), path, "--yes"); err != nil {
		t.Fatal(err)
	}

	// The manifest keeps its policy but claims a stamp the record does not describe.
	doc := stamped(t, path)
	doc.Provenance.Approves = "some-other-approval"

	var buf strings.Builder
	writeReapprovalNotice(&buf, path, doc, approvalStale)
	out := buf.String()
	if !strings.Contains(out, "does not") {
		t.Errorf("a disagreeing record must be reported as such; got:\n%s", out)
	}
	if strings.Contains(out, "changed since then") {
		t.Errorf("a disagreeing record must not be diffed against; got:\n%s", out)
	}
}

// --yes is how CI stamps, and it is legitimate - but the one line saying nobody read the
// permissions went into a log weeks ago. The reviewer re-approving now is the last reader
// who can act on it, so the record carries it.
func TestReapprovalSaysWhenNobodyReadTheLastStamp(t *testing.T) {
	stateHome(t)
	before := &policy.Policy{Entrypoint: "./x", Read: []string{"/data"}}
	path := writeManifest(t, before, manifest.Provenance{})
	if _, err := runCapturingStdout(t, newApproveCmd(), path, "--yes"); err != nil {
		t.Fatal(err)
	}

	approved := stamped(t, path)
	editManifest(t, path, &policy.Policy{Entrypoint: "./x", Read: []string{"/data", "/more"}}, approved.Provenance)

	out, err := runCapturingStdout(t, newApproveCmd(), path, "--yes")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "nobody read it") {
		t.Errorf("a --yes stamp must be recorded as unreviewed and reported on re-approval; got:\n%s", out)
	}
}

// The journal is a convenience over a stamp that is authoritative without it. A state home
// that cannot be written must therefore cost the diff and nothing else - the alternative is
// that an unwritable directory stops people approving manifests.
func TestAnUnwritableJournalStillStamps(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(base, 0o700) })
	t.Setenv("XDG_STATE_HOME", base)

	p := &policy.Policy{Entrypoint: "./x", Read: []string{"/data"}}
	path := writeManifest(t, p, manifest.Provenance{})
	if _, err := runCapturingStdout(t, newApproveCmd(), path, "--yes"); err != nil {
		t.Fatalf("an unwritable state home must not fail the approval: %v", err)
	}
	if checkApproval(stamped(t, path)) != approvalCurrent {
		t.Error("the manifest must be stamped even though the journal could not be written")
	}
}

// A journal directory someone else can write is a forgeable diff, which defeats the whole
// reason the record is not kept in the manifest. Refusing the entry is right; refusing the
// approval is not.
func TestASharedJournalDirIsNotWritten(t *testing.T) {
	base := stateHome(t)
	dir := filepath.Join(base, "bento", "approvals")
	if err := os.MkdirAll(dir, 0o777); err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{Entrypoint: "./x", Read: []string{"/data"}}
	path := writeManifest(t, p, manifest.Provenance{})
	if _, err := runCapturingStdout(t, newApproveCmd(), path, "--yes"); err != nil {
		t.Fatalf("a shared journal dir must not fail the approval: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("no record may be written into a world-writable journal dir; found %d", len(entries))
	}
}

// The record is this host's own and holds a policy the reviewer already reads, but it is
// still the baseline a later diff is trusted against, so it is not left readable to others.
func TestJournalEntriesArePrivate(t *testing.T) {
	base := stateHome(t)
	p := &policy.Policy{Entrypoint: "./x", Read: []string{"/data"}}
	path := writeManifest(t, p, manifest.Provenance{})
	if _, err := runCapturingStdout(t, newApproveCmd(), path, "--yes"); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(base, "bento", "approvals")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("want one record, got %d", len(entries))
	}
	fi, err := os.Stat(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("record mode = %#o, want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("journal dir mode = %#o, want 0700", di.Mode().Perm())
	}
}

// The record must hold the fingerprint it stamped rather than only the shape: comparing it
// against the manifest's stamp is how a disagreeing entry is caught, and re-deriving it
// from the shape would answer that identically only while Fingerprint never changes.
func TestRecordStoresTheFingerprintItStamped(t *testing.T) {
	base := stateHome(t)
	p := &policy.Policy{Entrypoint: "./x", Read: []string{"/data"}}
	path := writeManifest(t, p, manifest.Provenance{})
	if _, err := runCapturingStdout(t, newApproveCmd(), path, "--yes"); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(base, "bento", "approvals")
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("want one record, got %v (%v)", len(entries), err)
	}
	data, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var rec approvalRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	doc := stamped(t, path)
	if rec.Fingerprint != doc.Provenance.Approves {
		t.Errorf("record fingerprint %q does not match the manifest's stamp %q", rec.Fingerprint, doc.Provenance.Approves)
	}
	if !strings.Contains(rec.Policy, "/data") {
		t.Errorf("record must hold the approved shape; got:\n%s", rec.Policy)
	}
	if rec.Reviewed {
		t.Error("a --yes stamp must be recorded as unreviewed")
	}
}

func TestDiffLines(t *testing.T) {
	cases := map[string]struct {
		before, after string
		want          []string
	}{
		"an added line": {
			"read:\n  - /data\n", "read:\n  - /data\n  - /more\n",
			[]string{"+   - /more"},
		},
		"a removed line": {
			"read:\n  - /data\n  - /more\n", "read:\n  - /data\n",
			[]string{"-   - /more"},
		},
		// A reordered list is not a rewrite: matching common lines in order is what keeps
		// the delta down to what actually moved, so the reader is not handed the whole
		// policy back as a diff.
		"a reordered list": {
			"read:\n  - /a\n  - /b\n", "read:\n  - /b\n  - /a\n",
			[]string{"-   - /a", "+   - /a"},
		},
		"no change": {
			"read:\n  - /data\n", "read:\n  - /data\n",
			nil,
		},
		// The indentation is the only thing saying a port belongs to the host above it, so
		// it survives into the diff. A flattened rendering leaves an orphan `port:` line.
		"a nested rule keeps its shape": {
			"network:\n  - host: a.example.com\n    port: \"443\"\n",
			"network:\n  - host: b.example.com\n    port: \"443\"\n",
			[]string{"-   - host: a.example.com", "+   - host: b.example.com"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var got []string
			for _, c := range diffLines(tc.before, tc.after) {
				got = append(got, string(c.sign)+" "+c.text)
			}
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Errorf("diff =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(tc.want, "\n"))
			}
		})
	}
}
