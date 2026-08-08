package shield_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/shield"
)

// A write grant that CONTAINS a DenyWrite shield used to return Honored: the above
// direction was answered for DenyAll only. It has to be a verdict of its own rather than
// AboveShield, because the two tiers answer it differently - under bwrap the shield's
// read-only bind lands after the grant and wins, and the Landlock-only tier has no bind
// and no way to carve a narrower right out of a granted tree.
//
// Which verdict comes back decides which sentence the author reads, so the ordering
// against the DenyAll verdicts is pinned here alongside it.
func TestWriteGrantContainingADenyWriteShield(t *testing.T) {
	home := t.TempDir()
	for _, d := range []string{".pyenv/shims", ".ssh"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	set := shield.Assemble(folding(false), []string{home}, denylist.RuntimeDir(), nil)
	pyenv := filepath.Join(home, ".pyenv")

	r, got := set.Contains(pyenv, shield.Write, nil, nil)
	if got != shield.AboveWriteShield {
		t.Fatalf("write grant of %q: got %v, want AboveWriteShield", pyenv, got)
	}
	if !strings.HasPrefix(r.Path, pyenv+"/") {
		t.Errorf("the refusal must name the shield it is about; got %q", r.Path)
	}

	// A grant above both kinds is refused in the DenyAll sentence: that one refuses on
	// every tier, so it is the one the author needs to act on.
	if _, got := set.Contains(home, shield.Write, nil, nil); got != shield.AboveShield {
		t.Errorf("a write grant above both kinds must be AboveShield; got %v", got)
	}

	// A read grant is untouched. Read: ~/.pyenv is the ordinary case - the shield leaves
	// its content readable and only the write surface is fenced.
	if _, got := set.Contains(pyenv, shield.Read, nil, nil); got != shield.Honored {
		t.Errorf("a read grant containing a DenyWrite shield must be honored; got %v", got)
	}

	// A grant AT the shield stays UnderWriteShield, which offers the accurate remedy
	// (there is no opt-in) rather than pointing at a narrower directory that does not
	// exist below it.
	shims := filepath.Join(pyenv, "shims")
	if _, got := set.Contains(shims, shield.Write, nil, nil); got != shield.UnderWriteShield {
		t.Errorf("a write grant at the shield must stay UnderWriteShield; got %v", got)
	}
}
