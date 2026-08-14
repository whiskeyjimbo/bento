package shield_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/shield"
)

// A built-in shield nested inside a caller deny used to be blamed in the InsideCallerShield
// sentence, which tells the author to take it up with whatever launched the run - while
// naming a dotfile the embedder never put in their deny list, so they cannot find it
// there. The verdict is right (a built-in a caller deny also covers is not opt-in-able,
// see OptIns), only the blamed path was wrong.
func TestCallerDenyOverABuiltinIsBlamedAtTheCallersOwnPath(t *testing.T) {
	home := t.TempDir()
	config := filepath.Join(home, ".config")
	if err := os.MkdirAll(filepath.Join(config, "gh"), 0o700); err != nil {
		t.Fatal(err)
	}
	deny := []denylist.Rule{{Path: config, Deny: denylist.DenyAll, Dir: true}}
	set := shield.Assemble(folding(false), []string{home}, denylist.RuntimeDir(), deny)

	grant := filepath.Join(config, "gh", "hosts.yml")
	r, got := set.Contains(grant, shield.Read, nil, nil)
	if got != shield.InsideCallerShield {
		t.Fatalf("read of %q inside a caller deny: got %v, want InsideCallerShield", grant, got)
	}
	if r.Path != config {
		t.Errorf("the sentence must name the caller's own deny %q, not %q", config, r.Path)
	}

	// A built-in with no caller deny over it keeps its own blame and the opt-in sentence.
	ssh := filepath.Join(home, ".ssh", "id_rsa")
	r, got = set.Contains(ssh, shield.Read, nil, nil)
	if got != shield.InsideShield {
		t.Fatalf("read of %q: got %v, want InsideShield", ssh, got)
	}
	if r.Path != filepath.Join(home, ".ssh") {
		t.Errorf("a built-in outside every caller deny must name itself; got %q", r.Path)
	}
}
