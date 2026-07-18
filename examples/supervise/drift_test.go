package main

import (
	"os"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/manifest"
	"github.com/whiskeyjimbo/bento-v2/policy"
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
