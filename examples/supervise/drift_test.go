package main

import (
	"os"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/manifest"
	"github.com/whiskeyjimbo/bento/policy"
)

// writeManifestAt marshals a policy to <script>.manifest.yaml, the path
// warnManifestDrift looks for.
func writeManifestAt(t *testing.T, script string, p *policy.Policy) {
	t.Helper()
	data, err := manifest.Marshal(p, manifest.Provenance{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script+".manifest.yaml", data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// When the store's remembered decisions match the manifest, there is no drift - the
// case a round-tripped export/import produces. This is the anti-false-alarm test.
func TestDriftSilentWhenStoreMatchesManifest(t *testing.T) {
	s := newTestStore()
	key := "sha256:aaaa"
	s.rememberPath(key, "read", "/data", allow, false)
	s.rememberNetwork(key, "example.com", "443", allow, false)

	script := t.TempDir() + "/agent.sh"
	writeManifestAt(t, script, &policy.Policy{
		Entrypoint: script, Interpreter: "sh",
		Read:    []string{"/data"},
		Network: []policy.NetworkRule{{Host: "example.com", Port: "443"}},
	})

	var out strings.Builder
	warnManifestDrift(&out, s, key, script)
	if out.Len() != 0 {
		t.Errorf("agreeing store and manifest must not warn; got %q", out.String())
	}
}

// Export must produce a self-contained manifest even when the app relies on a
// GLOBAL network allow, so a fresh export never drift-warns against itself. This is
// the populated-store analog of the agree test, and it guards the export path/network
// symmetry (paths already fold the global layer in).
func TestDriftSilentAfterExportingGlobalAllow(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	s, _ := loadStore()
	script := dir + "/agent.sh"
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	key, err := appKey(script)
	if err != nil {
		t.Fatal(err)
	}
	s.app(key).Entrypoint = script
	s.rememberNetwork(key, "cdn.example", "443", allow, true) // global allow, no per-app entry
	if err := s.save(); err != nil {
		t.Fatal(err)
	}

	var eout strings.Builder
	if rc := exportPerms(s, []string{shortKey(key), "-o", script + ".manifest.yaml"}, &eout); rc != 0 {
		t.Fatalf("export rc=%d out=%q", rc, eout.String())
	}
	var out strings.Builder
	warnManifestDrift(&out, s, key, script)
	if out.Len() != 0 {
		t.Errorf("a just-exported manifest must not drift; got %q", out.String())
	}
}

// A fresh store with a manifest present must not warn: a manifest entry the store
// has no opinion on prompts under supervise (not silent), so it is not drift. This
// is the case a symmetric set-diff would wrongly flag on every first run.
func TestDriftSilentWhenStoreEmpty(t *testing.T) {
	s := newTestStore()
	script := t.TempDir() + "/agent.sh"
	writeManifestAt(t, script, &policy.Policy{
		Entrypoint: script, Interpreter: "sh",
		Read:    []string{"/data", "/etc"},
		Network: []policy.NetworkRule{{Host: "example.com", Port: "443"}},
		Exec:    policy.ExecAll,
	})

	var out strings.Builder
	warnManifestDrift(&out, s, "sha256:unseen", script)
	if out.Len() != 0 {
		t.Errorf("an empty store must not warn against a manifest; got %q", out.String())
	}
}

// A manifest write grant confers read (bento binds writes read-write), so a store
// read-deny under a manifest write grant IS drift the manifest reads what supervise
// blocks - and a store read-allow under a write grant is NOT drift.
func TestDriftFoldsWriteGrantIntoReadCoverage(t *testing.T) {
	script := t.TempDir() + "/agent.sh"
	writeManifestAt(t, script, &policy.Policy{Entrypoint: script, Interpreter: "sh", Write: []string{"/data"}})

	// False negative guard: store denies /data/secret, manifest grants /data as write.
	sDeny := newTestStore()
	sDeny.rememberPath("k", "read", "/data/secret", deny, false)
	var denyOut strings.Builder
	warnManifestDrift(&denyOut, sDeny, "k", script)
	if !strings.Contains(denyOut.String(), "/data/secret") || !strings.Contains(denyOut.String(), "the manifest allows it, the store denies it") {
		t.Errorf("a read-deny under a manifest write grant must warn; got %q", denyOut.String())
	}

	// No false positive: store allows /data for read, manifest grants /data as write.
	sAllow := newTestStore()
	sAllow.rememberPath("k", "read", "/data", allow, false)
	var allowOut strings.Builder
	warnManifestDrift(&allowOut, sAllow, "k", script)
	if allowOut.Len() != 0 {
		t.Errorf("a read-allow under a manifest write grant must not warn; got %q", allowOut.String())
	}
}

// A global deny of a host the manifest allows is real drift: `bento run` would let
// the host through while supervise blocks it. The warning names the direction.
func TestDriftWarnsGlobalDenyVsManifestAllow(t *testing.T) {
	s := newTestStore()
	s.rememberNetwork("", "tracker.example", "443", deny, true) // global standing-deny

	script := t.TempDir() + "/agent.sh"
	writeManifestAt(t, script, &policy.Policy{
		Entrypoint: script, Interpreter: "sh",
		Network: []policy.NetworkRule{{Host: "tracker.example", Port: "443"}},
	})

	var out strings.Builder
	warnManifestDrift(&out, s, "sha256:aaaa", script)
	got := out.String()
	if !strings.Contains(got, "tracker.example") || !strings.Contains(got, "the manifest allows it, the store denies it") {
		t.Errorf("expected a manifest-allows/store-denies warning for the host; got %q", got)
	}
}

// A store host the manifest does not grant is drift the other way: supervise permits
// it, `bento run` blocks it.
func TestDriftWarnsStoreAllowVsManifestSilent(t *testing.T) {
	s := newTestStore()
	key := "sha256:aaaa"
	s.rememberNetwork(key, "extra.example", "443", allow, false)

	script := t.TempDir() + "/agent.sh"
	writeManifestAt(t, script, &policy.Policy{Entrypoint: script, Interpreter: "sh"}) // no network

	var out strings.Builder
	warnManifestDrift(&out, s, key, script)
	if !strings.Contains(out.String(), "the store allows it, the manifest does not") {
		t.Errorf("expected a store-allows/manifest-does-not warning; got %q", out.String())
	}
}

// A manifest wildcard that covers a concrete store host is NOT drift: exact-set
// comparison would false-alarm, but policy.Allows matches the wildcard.
func TestDriftSilentWhenManifestWildcardCoversStoreHost(t *testing.T) {
	s := newTestStore()
	key := "sha256:aaaa"
	s.rememberNetwork(key, "api.example", "443", allow, false)

	script := t.TempDir() + "/agent.sh"
	writeManifestAt(t, script, &policy.Policy{
		Entrypoint: script, Interpreter: "sh",
		Network: []policy.NetworkRule{{Host: ".example", Port: "443"}}, // suffix wildcard
	})

	var out strings.Builder
	warnManifestDrift(&out, s, key, script)
	if out.Len() != 0 {
		t.Errorf("a wildcard covering the store host must not warn; got %q", out.String())
	}
}

// Drift must compare what `bento run` would actually enforce, and it anchors a
// manifest's relative grant to the manifest's own directory. Judging the literal
// string instead matches nothing, so a hand-written manifest that agrees with the
// store warns on every line.
func TestDriftAnchorsRelativeManifestGrants(t *testing.T) {
	dir := t.TempDir()
	script := dir + "/agent.sh"
	s := newTestStore()
	key := "sha256:aaaa"
	s.rememberPath(key, "read", dir+"/data", allow, false)

	writeManifestAt(t, script, &policy.Policy{
		Entrypoint: script, Interpreter: "sh",
		Read: []string{"data"},
	})

	var out strings.Builder
	warnManifestDrift(&out, s, key, script)
	if out.Len() != 0 {
		t.Errorf("a relative grant naming the same file must not warn; got %q", out.String())
	}
}

// A standing deny is the one most likely to be spelled as a directory, and containment
// only ran manifest-grant-over-store-path - so a global read-deny on ~/.ssh above a
// manifest granting ~/.ssh/config went unreported, which is the exact divergence the
// warning's own comment names.
func TestDriftWarnsStoreDenyAboveAManifestGrant(t *testing.T) {
	s := newTestStore()
	key := "sha256:aaaa"
	s.rememberPath("", "read", "/home/u/.ssh", deny, true)

	script := t.TempDir() + "/agent.sh"
	writeManifestAt(t, script, &policy.Policy{
		Entrypoint: script, Interpreter: "sh",
		Read: []string{"/home/u/.ssh/config"},
	})

	var out strings.Builder
	warnManifestDrift(&out, s, key, script)
	if !strings.Contains(out.String(), "/home/u/.ssh") {
		t.Errorf("a store deny above a manifest grant must warn; got %q", out.String())
	}
}

// The widened check is re-decided rather than inherited, because a more specific store
// allow under the deny leaves the granted file permitted on both sides. Warning there
// would be a false alarm on the one message that exists to be believed.
func TestDriftSilentWhenAStoreAllowShadowsTheDeny(t *testing.T) {
	s := newTestStore()
	key := "sha256:aaaa"
	s.rememberPath("", "read", "/home/u/.ssh", deny, true)
	s.rememberPath("", "read", "/home/u/.ssh/config", allow, true)

	script := t.TempDir() + "/agent.sh"
	writeManifestAt(t, script, &policy.Policy{
		Entrypoint: script, Interpreter: "sh",
		Read: []string{"/home/u/.ssh/config"},
	})

	var out strings.Builder
	warnManifestDrift(&out, s, key, script)
	if out.Len() != 0 {
		t.Errorf("supervise permits the granted file too; got %q", out.String())
	}
}
