package shield_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/shield"
)

// A relocation naming a home under the host's OTHER spelling for it (/home -> /var/home on
// an ostree host, GNUPGHOME=/var/home/u against HOME=/home/u) passes the deny-list's
// emit-time guard, which compares the anchors as configured. Resolved, it is the home, and
// a DenyAll there hides everything the policy granted - which is what the guard exists to
// stop. Dropping it is fail-open in nothing: the anchor-relative rules for that home stand.
func TestARelocationOntoAHomesOtherSpellingIsNotShielded(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "var", "home")
	if err := os.MkdirAll(filepath.Join(real, "u"), 0o700); err != nil {
		t.Fatal(err)
	}
	link(t, real, filepath.Join(root, "home"))

	home := filepath.Join(root, "home", "u")
	t.Setenv("GNUPGHOME", filepath.Join(real, "u"))

	set := shield.Assemble(shield.Host(), []string{home}, denylist.RuntimeDir(), nil)
	if shielded(set, filepath.Join(real, "u")) {
		t.Errorf("a DenyAll landed on the whole home %s", filepath.Join(real, "u"))
	}
}

// The other side of the same test: a store that IS one anchor while sitting inside another
// (HOME=/home/u/.aws beside a passwd home of /home/u) still carries its shield. The outer
// anchor's tree stays reachable, so this is not the swallow-everything case above, and
// refusing to shield it would leave the credential store itself open.
func TestAnAnchorNestedInsideAnotherAnchorIsStillShielded(t *testing.T) {
	outer := t.TempDir()
	inner := filepath.Join(outer, ".aws")
	if err := os.MkdirAll(inner, 0o700); err != nil {
		t.Fatal(err)
	}

	set := shield.Assemble(shield.Host(), []string{outer, inner}, denylist.RuntimeDir(), nil)
	if !shielded(set, inner) {
		t.Errorf("nested anchor %s lost its shield", inner)
	}
}
