package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/policy"
)

// A bento write grant is read-write, so a read-deny nested under a write-allow is
// unenforceable - export must refuse it, the same as a read-deny under a read-allow.
func TestExportRefusesReadDenyUnderWriteAllow(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	s, _ := loadStore()
	key := "sha256:aaaa"
	s.app(key).Entrypoint = "/home/u/agent.sh"
	s.rememberPath(key, "write", "/data", allow, false)      // write-allow (implies read)
	s.rememberPath(key, "read", "/data/secret", deny, false) // read-deny beneath it
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "out.yaml")
	var out strings.Builder
	if rc := exportPerms(s, []string{shortKey(key), "-o", outPath}, &out); rc == 0 {
		t.Errorf("export must refuse a read-deny under a write-allow; out=%q", out.String())
	}
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Error("a refused export must not write a manifest")
	}
}

// The asymmetry must hold: a write-deny under a READ-allow is fine, because a read
// grant is read-only - the write-deny is already enforced (nothing under a read-only
// bind is writable). Export must NOT refuse this.
func TestExportAllowsWriteDenyUnderReadAllow(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	s, _ := loadStore()
	key := "sha256:bbbb"
	s.app(key).Entrypoint = "/home/u/agent.sh"
	s.rememberPath(key, "read", "/data", allow, false)        // read-allow (read-only)
	s.rememberPath(key, "write", "/data/secret", deny, false) // write-deny beneath it
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "out.yaml")
	var out strings.Builder
	if rc := exportPerms(s, []string{shortKey(key), "-o", outPath}, &out); rc != 0 {
		t.Fatalf("a write-deny under a read-allow must not block export; out=%q", out.String())
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Error("export should have written a manifest")
	}
}

// The read-deny can sit at the EXACT same path as the write-allow, not just beneath
// it: write /data = allow, read /data = deny. The write grant makes /data readable,
// so the read-deny is still unenforceable and export must refuse - otherwise it
// emits a manifest that instantly drift-warns against its own store.
func TestExportRefusesReadDenyAtSamePathAsWriteAllow(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	s, _ := loadStore()
	key := "sha256:cccc"
	s.app(key).Entrypoint = "/home/u/agent.sh"
	s.rememberPath(key, "write", "/data", allow, false)
	s.rememberPath(key, "read", "/data", deny, false)
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "out.yaml")
	var out strings.Builder
	if rc := exportPerms(s, []string{shortKey(key), "-o", outPath}, &out); rc == 0 {
		t.Errorf("export must refuse a read-deny at the same path as a write-allow; out=%q", out.String())
	}
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Error("a refused export must not write a manifest")
	}
}

// The interactive warning has the same coverage rule: a read-deny under an approved
// write grant is flagged as unenforceable.
func TestWarnFlagsReadDenyUnderWriteGrant(t *testing.T) {
	s := newTestStore()
	s.rememberPath("k", "read", "/data/secret", deny, false)
	final := &policy.Policy{Write: []string{"/data"}}
	var out strings.Builder
	warnDenyUnderAllow(newPrompter(strings.NewReader(""), &out), s, "k", final)
	if !strings.Contains(out.String(), "/data/secret") || !strings.Contains(out.String(), "cannot enforce the sub-deny") {
		t.Errorf("a read-deny under an approved write grant must be flagged; got %q", out.String())
	}
}

// And the asymmetry holds in the warning too: a write-deny under a read grant is
// already enforced (read-only bind), so it must NOT be flagged.
func TestWarnSilentForWriteDenyUnderReadGrant(t *testing.T) {
	s := newTestStore()
	s.rememberPath("k", "write", "/data/secret", deny, false)
	final := &policy.Policy{Read: []string{"/data"}}
	var out strings.Builder
	warnDenyUnderAllow(newPrompter(strings.NewReader(""), &out), s, "k", final)
	if out.Len() != 0 {
		t.Errorf("a write-deny under a read grant is already enforced; must not warn; got %q", out.String())
	}
}
