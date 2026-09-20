package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/shield"
)

// The clamp's gitdir walk is the third walk bound by shield.MaxWalkDepth, and it has to
// stop where the backend's does: a shallower bound fails closed on a subtree the run
// shields rule by rule, so the clamp withholds a write grant the run honors, and a deeper
// one walks past where the run stopped seeing and proposes a grant the run refuses.
//
// Measured at the cutoff rather than by comparing the two constants, which after the
// shared source would hold by construction. This is internal/linux's
// TestGitDirShieldsFailsClosedAtTheDepthCutoff over the clamp's own walk.
func TestClampGitDirShieldsFailClosedWhereTheBackendStops(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, ".git", "modules")
	cutoff := ""
	for i := 0; i <= shield.MaxWalkDepth; i++ {
		deep = filepath.Join(deep, "d")
		if i == shield.MaxWalkDepth {
			cutoff = deep
		}
	}
	if err := os.MkdirAll(filepath.Join(deep, "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "config"), []byte("[core]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	shielded := false
	for _, r := range gitDirShields(root) {
		if r.Path == cutoff && r.Deny == denylist.DenyWrite && r.Dir {
			shielded = true
		}
	}
	if !shielded {
		t.Errorf("the clamp's walk must fail closed at %q, where the backend's bound stops it", cutoff)
	}
}
