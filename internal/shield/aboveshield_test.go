package shield_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/shield"
)

// The dotfiles-farm shape: ~/.aws is a symlink into a farm directory the manifest grants
// write on, so the real credential store sits inside the grant while neither spelling of
// the link's own name does. The AboveShield loop answered the containment question for
// the link's name only, so this came back Honored while the byte-identical DenyWrite twin
// (~/.pyenv/shims relocated the same way) was refused AboveWriteShield.
//
// The farm directory is deliberately not named "dotfiles": that name is itself a
// DenyWrite rule, and a test using it passes on UnderWriteShield in an earlier loop
// without ever reaching this one.
func TestWriteGrantContainingARelocatedDenyAllShield(t *testing.T) {
	home := t.TempDir()
	farm := filepath.Join(home, "store")
	if err := os.MkdirAll(filepath.Join(farm, "aws"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(farm, "aws"), filepath.Join(home, ".aws")); err != nil {
		t.Fatal(err)
	}
	set := shield.Assemble(folding(false), []string{home}, denylist.RuntimeDir(), nil)

	r, got := set.Contains(farm, shield.Write, nil, nil)
	if got != shield.AboveShield {
		t.Fatalf("write grant of %q, which contains the store ~/.aws points at: got %v, want AboveShield", farm, got)
	}
	// The refusal names the path the deny-list built, not the target the link leads to:
	// that is the spelling the author can find in their own manifest.
	if want := filepath.Join(home, ".aws"); r.Path != want {
		t.Errorf("refusal names %q, want the deny-list's own path %q", r.Path, want)
	}

	// A read of the farm is untouched. The shield still binds over the store inside it,
	// and there is no name to replace, so the enclosing read is the ordinary case.
	if _, got := set.Contains(farm, shield.Read, nil, nil); got != shield.Honored {
		t.Errorf("a read grant containing a relocated shield must be honored; got %v", got)
	}
}
