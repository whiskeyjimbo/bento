package shield_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/shield"
	"github.com/whiskeyjimbo/bento/internal/shieldcorpus"
)

// folding is the host FS with identity answered the way a case-insensitive mount answers
// it. Taken from the corpus rather than built here, even though these cases are not corpus
// cases: a second definition of the mount property would let this package and the
// differential harness fold differently, which is the class of divergence the corpus
// exists to close.
func folding(on bool) shield.FS {
	return shieldcorpus.FS(shieldcorpus.Case{Folding: on})
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

// A DenyWrite shield is one byte-exact bind too, so on a folding mount a write spelled
// ~/.local/BIN reaches the same directory the shield binds at ~/.local/bin. On the
// degraded tier that leaves a plainly host-writable shim directory; under bwrap the shield
// binds one spelling while the grant binds the other.
func TestWriteUnderAReadOnlyShieldIsRefusedThroughAFoldedSpelling(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".local", "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	grant := filepath.Join(home, ".local", "BIN", "mytool")

	for _, tc := range []struct {
		name string
		fold bool
		want shield.Verdict
	}{
		// Off a folding mount the respelling is a different directory and the shield has
		// nothing to say about it.
		{"case-sensitive mount", false, shield.Honored},
		{"case-folding mount", true, shield.UnderWriteShield},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set := shield.Assemble(folding(tc.fold), []string{home}, denylist.RuntimeDir(), nil)
			r, got := set.Contains(grant, shield.Write, nil, nil)
			if got != tc.want {
				t.Fatalf("write grant of %q: got %v, want %v", grant, got, tc.want)
			}
			if tc.want == shield.UnderWriteShield && !strings.HasSuffix(r.Path, ".local/bin") {
				t.Errorf("the refusal must name the shield it is about; got %q", r.Path)
			}
		})
	}
}

// The same respelling against a DenyAll shield, where it is sharper still: nothing has to
// be writable for the store's content to leave, so this is the read that would have handed
// over a private key beside a byte-exact bind at ~/.ssh.
func TestReadInsideAShieldIsRefusedThroughAFoldedSpelling(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	grant := filepath.Join(home, ".SSH", "id_rsa")

	for _, tc := range []struct {
		name string
		fold bool
		want shield.Verdict
	}{
		{"case-sensitive mount", false, shield.Honored},
		{"case-folding mount", true, shield.InsideShield},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set := shield.Assemble(folding(tc.fold), []string{home}, denylist.RuntimeDir(), nil)
			if _, got := set.Contains(grant, shield.Read, nil, nil); got != tc.want {
				t.Fatalf("read grant of %q: got %v, want %v", grant, got, tc.want)
			}
		})
	}
}

// A whole-mount fold folds EVERY component, so an ancestor respelling reaches the store
// just as surely as the shield's own name does - vfat, exfat and ciopfs are the cases the
// deny-list leads with, and a rule that only ever folded the last component would leave
// all three open one directory up.
func TestAnAncestorRespellingIsRefusedWhereTheWholeMountFolds(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".local", "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	// .LOCAL is the respelled component; the shield's own name is spelled as it is.
	grant := filepath.Join(home, ".LOCAL", "bin", "mytool")

	for _, tc := range []struct {
		name string
		fold bool
		want shield.Verdict
	}{
		{"case-sensitive mount", false, shield.Honored},
		{"case-folding mount", true, shield.UnderWriteShield},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set := shield.Assemble(folding(tc.fold), []string{home}, denylist.RuntimeDir(), nil)
			if _, got := set.Contains(grant, shield.Write, nil, nil); got != tc.want {
				t.Fatalf("write grant of %q: got %v, want %v", grant, got, tc.want)
			}
		})
	}
}

// The other half of the same rule, and the reason each differing component is settled by
// asking the host rather than by which component it is. ext4's casefold is PER-DIRECTORY,
// so a home that does not fold makes ~/.LOCAL a genuinely different directory even where
// the shield's own parent folds - and refusing that grant would turn away a write that
// reaches no shielded store at all, in the DenyWrite sentence, which has no opt-in to
// offer the author as a way out.
func TestAnAncestorThatDoesNotFoldIsNotFoldedOntoTheShield(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".local", "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	// A host that folds inside ~/.local but nowhere above it.
	fs := shield.Host()
	fs.SameFile = func(a, b string) bool {
		return strings.HasPrefix(a, filepath.Join(home, ".local")+string(filepath.Separator)) &&
			shieldcorpus.FS(shieldcorpus.Case{Folding: true}).SameFile(a, b)
	}
	set := shield.Assemble(fs, []string{home}, denylist.RuntimeDir(), nil)

	grant := filepath.Join(home, ".LOCAL", "bin", "mytool")
	if _, got := set.Contains(grant, shield.Write, nil, nil); got != shield.Honored {
		t.Errorf("an ancestor the host says is a different directory must not be folded onto the shield; got %v", got)
	}
}

// The workspace shields are the second place a DenyWrite rule is matched, and they are the
// ones a checkout derives - a planted pre-commit runs on the host at the developer's next
// commit, so a folded spelling reaching them is worth as much to a run as one reaching a
// listed shield.
func TestAFoldedWriteIntoAWorkspaceShieldIsRefused(t *testing.T) {
	home := t.TempDir()
	hooks := filepath.Join(home, "proj", ".git", "hooks")
	if err := os.MkdirAll(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	workspace := []denylist.Rule{{Path: hooks, Deny: denylist.DenyWrite, Dir: true}}
	set := shield.Assemble(folding(true), []string{home}, denylist.RuntimeDir(), nil)

	grant := filepath.Join(home, "proj", ".git", "HOOKS", "pre-commit")
	if _, got := set.Contains(grant, shield.Write, nil, workspace); got != shield.UnderWriteShield {
		t.Errorf("write grant of %q: got %v, want UnderWriteShield", grant, got)
	}
}

// The containment direction has to fold too, or the two halves of the same question
// disagree. A write grant of ~/.CONFIG is above ~/.config/sops/age/keys.txt and reaches
// the shielded key on a folding mount, while every byte-exact test says the two paths have
// nothing to do with each other - and the grant is SHALLOWER than the shield, so the
// inside-direction check cannot see it either.
func TestAGrantAboveAShieldThroughARespelledAncestorIsRefused(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".config", "sops", "age"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".config", "sops", "age", "keys.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	grant := filepath.Join(home, ".CONFIG")

	for _, kind := range []shield.Kind{shield.Read, shield.Write} {
		set := shield.Assemble(folding(true), []string{home}, denylist.RuntimeDir(), nil)
		if _, got := set.Contains(grant, kind, nil, nil); got == shield.Honored {
			t.Errorf("grant %q above a shield on a folding mount must be refused; got Honored", grant)
		}
	}
	// And on a mount that folds nothing it is an ordinary grant of a directory that does
	// not exist, which nothing refuses.
	set := shield.Assemble(folding(false), []string{home}, denylist.RuntimeDir(), nil)
	if _, got := set.Contains(grant, shield.Write, nil, nil); got != shield.Honored {
		t.Errorf("off a folding mount %q reaches no shield; got %v", grant, got)
	}
}

// Two components respelled at once, which is what a whole-mount fold actually does. The
// corpus's own folding seam answered false for this pair while it respelled only the last
// component, so the case that needed the component walk was the one it could not express.
func TestEveryRespelledComponentFolds(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".local", "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	set := shield.Assemble(folding(true), []string{home}, denylist.RuntimeDir(), nil)

	grant := filepath.Join(home, ".LOCAL", "BIN", "mytool")
	if _, got := set.Contains(grant, shield.Write, nil, nil); got != shield.UnderWriteShield {
		t.Errorf("write grant of %q: got %v, want UnderWriteShield", grant, got)
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
