package shieldcorpus_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/shieldcorpus"
)

// Build is a fixture for four differential tests in three other packages, and none of them
// looks at the layout - they look at verdicts over it. So a Build that stops creating a
// file leaves every one of them green over a host that no longer matches what the cases
// describe, and the absent path silently becomes the only shape measured. These are the
// assertions that notice.
func TestBuildStagesTheLayoutTheCasesAreWrittenAgainst(t *testing.T) {
	home, err := shieldcorpus.Build(t.TempDir(), shieldcorpus.Case{})
	if err != nil {
		t.Fatal(err)
	}

	for _, d := range []string{".ssh", ".local/bin", "checkout/.git/hooks", "farm/ssh", "farm/keys", "gnupg-target"} {
		if fi, err := os.Stat(filepath.Join(home, d)); err != nil || !fi.IsDir() {
			t.Errorf("%s must be a directory: %v", d, err)
		}
	}
	for _, f := range []string{".ssh/config", "farm/ssh/known_hosts", "farm/keys/id_ed25519", "gnupg-target/notes"} {
		if fi, err := os.Stat(filepath.Join(home, f)); err != nil || fi.IsDir() {
			t.Errorf("%s must be a regular file: %v", f, err)
		}
	}
	// A credential FILE linked out of the store, a credential SUBDIRECTORY linked out of
	// it, and one link left dangling. The expansion walks from the ~/.ssh rule, so an
	// expansion that stops at files and one that does not walk at all are told apart only
	// while all three are present.
	for name, wantResolvable := range map[string]bool{
		".ssh/known_hosts": true,
		".ssh/keys":        true,
		".ssh/pending":     false,
	} {
		p := filepath.Join(home, name)
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s must be a symlink: %v", name, err)
			continue
		}
		if _, err := os.Stat(p); (err == nil) != wantResolvable {
			t.Errorf("%s resolvable = %v, want %v", name, err == nil, wantResolvable)
		}
	}

	// ShieldOntoHome covers every grant in the layout, so it is staged for its own case
	// alone and its absence everywhere else is what keeps one divergence from masking the
	// rest.
	if _, err := os.Lstat(filepath.Join(home, ".gnupg")); err == nil {
		t.Error(".gnupg must be staged only for a ShieldOntoHome case")
	}
	onHome, err := shieldcorpus.Build(t.TempDir(), shieldcorpus.Case{ShieldOntoHome: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(onHome, ".gnupg")); err != nil {
		t.Errorf("a ShieldOntoHome case must stage .gnupg: %v", err)
	}
}

// Whether a grant's path is on disk decides what several of the cases measure, and Build
// and Cases state it in two places that cannot see each other. This pins the pairing:
// every grant is staged unless it is one of the three the corpus deliberately leaves
// absent, each of which loses its point the moment something creates it.
func TestEveryCaseGrantIsStagedUnlessItIsDeliberatelyAbsent(t *testing.T) {
	absent := map[string]string{
		"farm/pending/id_rsa":  "behind a dangling link: a dotfiles tree checked out lazily",
		"farm/keys/id_absent": "the absent half of the pair inside a symlinked credential subdirectory",
		".local/bin/mytool":   "the tool a run would install into a DenyWrite shield, which is refused before anything is there to stat",
	}
	for _, c := range shieldcorpus.Cases {
		home, err := shieldcorpus.Build(t.TempDir(), c)
		if err != nil {
			t.Fatal(err)
		}
		_, err = os.Lstat(c.Path(home))
		_, wantAbsent := absent[c.Grant]
		if wantAbsent && err == nil {
			t.Errorf("%s: %q is meant to be absent (%s) but Build staged it", c.Name, c.Grant, absent[c.Grant])
		}
		if !wantAbsent && err != nil {
			t.Errorf("%s: Build does not stage %q, so the case is measured over a layout it does not describe", c.Name, c.Grant)
		}
	}
}

// FoldedPath is the corpus's whole definition of the mount property Build cannot stage,
// and all four differential tests fold through it. A FoldedPath that quietly stopped
// matching would turn every folding case into a non-folding one and leave them green.
func TestFoldedPathReachesTheEntryBesideIt(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if got := shieldcorpus.FoldedPath(filepath.Join(dir, "CONFIG")); got != filepath.Join(dir, "config") {
		t.Errorf("a respelling must reach the entry that is there; got %q", got)
	}
	// Nothing beside it, so nothing to reach: this is what keeps a shield that does not
	// exist from being reported as folding.
	absent := filepath.Join(dir, "id_rsa")
	if got := shieldcorpus.FoldedPath(absent); got != absent {
		t.Errorf("a name with no entry beside it must answer itself; got %q", got)
	}

	// The identity seam the two shield.FS sites take from here, over the same three names.
	folding := shieldcorpus.FS(shieldcorpus.Case{Folding: true}).SameFile
	if !folding(filepath.Join(dir, "config"), filepath.Join(dir, "CONFIG")) {
		t.Error("two spellings of an entry that is there must reach one file")
	}
	if folding(absent, filepath.Join(dir, "ID_RSA")) {
		t.Error("two spellings of an entry that is not there reach nothing, not each other")
	}
	if shieldcorpus.FS(shieldcorpus.Case{}).SameFile(filepath.Join(dir, "config"), filepath.Join(dir, "CONFIG")) {
		t.Error("off a folding mount the two spellings are two files")
	}
}
