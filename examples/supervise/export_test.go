package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/manifest"
	"github.com/whiskeyjimbo/bento/policy"
)

// writeManifest marshals a policy to a temp manifest file and returns its path, so
// import tests exercise the real Load path rather than a hand-typed YAML string.
func writeManifest(t *testing.T, p *policy.Policy) string {
	t.Helper()
	data, err := manifest.Marshal(p, manifest.Provenance{})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "in.manifest.yaml")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// Export computes the EFFECTIVE deny-wins decision: a host the app allowed but a
// global rule denies must NOT leak into the manifest's allowlist, and the
// interpreter must be carried.
func TestExportExcludesGloballyDeniedHostAndCarriesInterpreter(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	s, _ := loadStore()
	key := "sha256:aaaa"
	a := s.app(key)
	a.Entrypoint = "/home/u/agent.py"
	a.Interpreter = "python3"
	s.rememberNetwork(key, "example.com", "443", allow, false)
	s.rememberNetwork(key, "tracker.example", "443", allow, false) // app allows
	s.rememberNetwork(key, "tracker.example", "443", deny, true)   // global denies
	if err := s.save(); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(dir, "out.yaml")
	var out strings.Builder
	if rc := exportPerms(s, []string{shortKey(key), "-o", outPath}, &out); rc != 0 {
		t.Fatalf("export rc=%d out=%q", rc, out.String())
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	yaml := string(got)
	if strings.Contains(yaml, "tracker.example") {
		t.Errorf("a globally-denied host leaked into the manifest:\n%s", yaml)
	}
	if !strings.Contains(yaml, "example.com") {
		t.Errorf("the allowed host is missing:\n%s", yaml)
	}
	if !strings.Contains(yaml, "interpreter: python3") {
		t.Errorf("the interpreter was not carried:\n%s", yaml)
	}

	// The store -> manifest -> runnable promise: the exported file must parse back
	// through the same Load a real `bento run` uses.
	f, err := os.Open(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := manifest.Load(f); err != nil {
		t.Errorf("the exported manifest does not load back: %v", err)
	}
}

// A manifest is a pure allowlist and cannot express a deny nested under an allowed
// dir; export must refuse rather than over- or under-grant.
func TestExportRefusesDenyUnderAllow(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	s, _ := loadStore()
	key := "sha256:bbbb"
	s.app(key).Entrypoint = "/home/u/agent.sh"
	s.rememberPath(key, "read", "/home/u/proj", allow, false)
	s.rememberPath(key, "read", "/home/u/proj/secret", deny, false)
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "out.yaml")
	var out strings.Builder
	if rc := exportPerms(s, []string{shortKey(key), "-o", outPath}, &out); rc == 0 {
		t.Errorf("export must refuse a deny under an allow; out=%q", out.String())
	}
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Error("a refused export must not write a manifest file")
	}
	if !strings.Contains(out.String(), "cannot export") {
		t.Errorf("expected a refusal message, got %q", out.String())
	}
}

// Import requires explicit consent: with no yes, it must seed nothing.
func TestImportWithoutConsentSeedsNothing(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	script := filepath.Join(t.TempDir(), "agent.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	mf := writeManifest(t, &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{"/data"}})

	s, _ := loadStore()
	var out strings.Builder
	importPerms(s, []string{mf}, strings.NewReader("n\n"), &out)
	if reloaded, _ := loadStore(); len(reloaded.Apps) != 0 {
		t.Error("import seeded the store despite no consent")
	}
}

// Exec is a third permission dimension that can hold a deny: a recorded ExecNone.
// Import must keep it, not flip it to allow on a manifest's exec: all - the same
// deny-preservation the path and network dimensions get.
func TestImportKeepsExecDeny(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	script := filepath.Join(t.TempDir(), "agent.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	key, err := appKey(script)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := loadStore()
	s.app(key).Exec = string(policy.ExecNone) // a recorded human exec deny
	if err := s.save(); err != nil {
		t.Fatal(err)
	}

	mf := writeManifest(t, &policy.Policy{Entrypoint: script, Interpreter: "sh", Exec: policy.ExecAll})
	s2, _ := loadStore()
	var out strings.Builder
	if rc := importPerms(s2, []string{mf}, strings.NewReader("y\n"), &out); rc != 0 {
		t.Fatalf("import rc=%d out=%q", rc, out.String())
	}
	reloaded, _ := loadStore()
	if reloaded.Apps[key].Exec != string(policy.ExecNone) {
		t.Errorf("import flipped a recorded exec deny to allow: Exec=%q", reloaded.Apps[key].Exec)
	}
	if !strings.Contains(out.String(), "kept the existing exec deny") {
		t.Errorf("import should report the kept exec deny; got %q", out.String())
	}
}

// Import seeds allows but must never flip a pre-existing per-app deny to allow;
// only forget clears a deny. A wildcard/range rule has no literal store key, so it
// is skipped and left to a runtime prompt.
func TestImportKeepsDenyAndSkipsWildcards(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	script := filepath.Join(t.TempDir(), "agent.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	key, err := appKey(script)
	if err != nil {
		t.Fatal(err)
	}

	// Pre-seed a per-app deny for a host the manifest will try to allow.
	s, _ := loadStore()
	s.rememberNetwork(key, "blocked.example", "443", deny, false)
	if err := s.save(); err != nil {
		t.Fatal(err)
	}

	mf := writeManifest(t, &policy.Policy{
		Entrypoint:  script,
		Interpreter: "sh",
		Network: []policy.NetworkRule{
			{Host: "blocked.example", Port: "443"},   // manifest allow of a stored deny
			{Host: "*", Port: "443"},                 // wildcard host
			{Host: "api.example", Port: "8000-9000"}, // port range
			{Host: "ok.example", Port: "443"},        // a clean literal
		},
	})

	s2, _ := loadStore()
	var out strings.Builder
	if rc := importPerms(s2, []string{mf}, strings.NewReader("y\n"), &out); rc != 0 {
		t.Fatalf("import rc=%d out=%q", rc, out.String())
	}
	reloaded, _ := loadStore()
	a := reloaded.Apps[key]
	if a == nil {
		t.Fatal("import did not seed the app")
	}
	if a.Network["blocked.example:443"] != deny {
		t.Error("import flipped a pre-existing deny to allow")
	}
	if a.Network["ok.example:443"] != allow {
		t.Error("import did not seed the clean literal rule")
	}
	if _, ok := a.Network["*:443"]; ok {
		t.Error("a wildcard host was seeded instead of skipped")
	}
	if _, ok := a.Network["api.example:8000-9000"]; ok {
		t.Error("a port range was seeded instead of skipped")
	}
	if !strings.Contains(out.String(), "skipped") || !strings.Contains(out.String(), "kept the existing deny") {
		t.Errorf("import should report the skipped and kept-deny rules; got %q", out.String())
	}
}

// Export is the one place a store decision leaves the wrapper's shielding: the
// exported manifest runs under plain `bento run`, with no approve() refusal and no
// enforced-run backstop behind it. A remembered allow covering the permission store
// therefore has to be refused here too, or it graduates into a real grant (bv2-yc8g).
func TestExportRefusesGrantCoveringTheStore(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	s, _ := loadStore()
	key := "sha256:bbbb"
	a := s.app(key)
	a.Entrypoint = "/home/u/agent.py"
	// Written straight into the record rather than through rememberPath: the routes
	// that record a decision now refuse such a path, so this is the store as an older
	// build (or a hand edit) could have left it.
	a.Read = map[string]decision{filepath.Join(s.dir, "permissions.json"): allow}
	if err := s.save(); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(dir, "out.yaml")
	var out strings.Builder
	if rc := exportPerms(s, []string{shortKey(key), "-o", outPath}, &out); rc == 0 {
		t.Fatalf("export must refuse a grant covering the store; out=%q", out.String())
	}
	if !strings.Contains(out.String(), "permission store") {
		t.Errorf("the refusal must say why: %q", out.String())
	}
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		got, _ := os.ReadFile(outPath)
		t.Errorf("a refused export must write no manifest; found:\n%s", got)
	}
}
