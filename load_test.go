package bento

import (
	"strings"
	"testing"
)

func TestLoadManifestGood(t *testing.T) {
	src := `
interpreter: python3
script: ./check.py
read:
  - /etc/hostname
network:
  rules:
    - host: api.example.com
      port: "443"
`
	m, err := LoadManifest(strings.NewReader(src))
	if err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
	if m.Interpreter != "python3" {
		t.Errorf("interpreter: got %q", m.Interpreter)
	}
	if len(m.Network.Rules) != 1 {
		t.Errorf("network rules: got %d", len(m.Network.Rules))
	}
}

func TestLoadManifestLegacyExecPromotesAllowExec(t *testing.T) {
	src := `
interpreter: python3
script: ./s.py
exec:
  - ls
  - rm
`
	m, err := LoadManifest(strings.NewReader(src))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !m.AllowExec {
		t.Error("legacy non-empty exec: should promote AllowExec to true")
	}
	if !m.LegacyExecField {
		t.Error("LegacyExecField should be set so callers can warn")
	}
	if len(m.Exec) != 0 {
		t.Errorf("Exec should be cleared after promotion, got %v", m.Exec)
	}
}

func TestLoadManifestAllowExecDirect(t *testing.T) {
	src := `
interpreter: python3
script: ./s.py
allow_exec: true
`
	m, err := LoadManifest(strings.NewReader(src))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !m.AllowExec {
		t.Error("allow_exec: true did not stick")
	}
	if m.LegacyExecField {
		t.Error("LegacyExecField should NOT be set for the new field")
	}
}

func TestLoadManifestNilReader(t *testing.T) {
	if _, err := LoadManifest(nil); err == nil {
		t.Fatal("nil reader should error")
	}
}

func TestLoadManifestBadYAML(t *testing.T) {
	src := `not a manifest: [unclosed bracket`
	_, err := LoadManifest(strings.NewReader(src))
	if err == nil {
		t.Fatal("malformed YAML should error")
	}
	if !strings.Contains(err.Error(), "yaml") {
		t.Errorf("error should mention 'yaml', got %v", err)
	}
}

func TestLoadManifestInvalidManifest(t *testing.T) {
	// Valid YAML, invalid manifest (missing required field).
	src := `script: foo.py`
	_, err := LoadManifest(strings.NewReader(src))
	if err == nil {
		t.Fatal("missing interpreter should error")
	}
	if !strings.Contains(err.Error(), "interpreter") {
		t.Errorf("error should name 'interpreter', got %v", err)
	}
}
