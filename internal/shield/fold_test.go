package shield_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/shield"
)

// folding returns the host FS with SameFile answering the way a case-insensitive mount
// does: two names that differ only in case reach one file. The behaviour cannot be staged
// on a real ext4 temp directory - creating both spellings there makes two genuinely
// different files - so the mount's property is injected rather than built.
func folding(on bool) shield.FS {
	fs := shield.Host()
	fs.SameFile = func(a, b string) bool {
		// Existence is part of the behaviour, not a detail: a folding mount reaches one
		// file under two spellings, and a name with no file behind it reaches nothing.
		if !on || !strings.EqualFold(a, b) {
			return false
		}
		_, err := os.Lstat(a)
		return err == nil
	}
	return fs
}

// A read grant of the home tree is the ordinary, honored case: ~/.ssh sits inside it and
// the shield contains it. On a case-folding mount it does not - the shield is one
// byte-exact bind and ~/.SSH reaches the same directory beside it - so the same grant has
// to be refused instead of honored.
func TestGrantContainingAShieldIsRefusedWhereTheMountFoldsCase(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		fold bool
		want shield.Verdict
	}{
		{"case-sensitive mount", false, shield.Honored},
		{"case-folding mount", true, shield.FoldedShield},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set := shield.Assemble(folding(tc.fold), []string{home}, denylist.RuntimeDir(), nil)
			r, got := set.Contains(home, shield.Read, nil, nil)
			if got != tc.want {
				t.Fatalf("read grant of %q: got %v, want %v", home, got, tc.want)
			}
			if tc.want == shield.FoldedShield && !strings.HasSuffix(r.Path, ".ssh") {
				t.Errorf("the refusal must name the shield it is about; got %q", r.Path)
			}
		})
	}
}

// A grant INSIDE a shield stays InsideShield on a folding mount: that refusal offers the
// opt-in, and the folding one does not, so letting the later check win would withdraw a
// remedy the run still honors.
func TestGrantInsideAShieldKeepsItsOwnRefusalWhenTheMountFoldsCase(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	set := shield.Assemble(folding(true), []string{home}, denylist.RuntimeDir(), nil)

	if _, got := set.Contains(filepath.Join(home, ".ssh", "id_rsa"), shield.Read, nil, nil); got != shield.InsideShield {
		t.Errorf("got %v, want InsideShield", got)
	}
}

// The read opt-in survives a folding mount. It is the escape the other shield refusals
// point their reader at, and it binds the store's real content read-only - so a second
// spelling reaching that same content exposes nothing the author did not already ask for.
// Refusing it here would leave the folding refusal telling them to use a remedy it had
// just taken away.
func TestTheReadOptInSurvivesAFoldingMount(t *testing.T) {
	home := t.TempDir()
	ssh := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	set := shield.Assemble(folding(true), []string{home}, denylist.RuntimeDir(), nil)
	optIns := shield.Targets(set.OptIns([]string{ssh}))
	if len(optIns) == 0 {
		t.Fatal("a read naming the shield exactly must find a shield to opt into")
	}

	if _, got := set.Contains(ssh, shield.Read, optIns, nil); got != shield.Honored {
		t.Errorf("got %v, want Honored", got)
	}
	// The grant that CONTAINS the opted-into shield is honored for the same reason.
	if _, got := set.Contains(home, shield.Read, optIns, nil); got != shield.Honored {
		t.Errorf("a home grant with ~/.ssh opted in: got %v, want Honored", got)
	}
}
