package shield_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/shield"
)

// shielded reports whether the assembled set carries a DenyAll rule landing on path.
func shielded(set shield.Set, path string) bool {
	return slices.ContainsFunc(set.Shields(), func(a shield.Applied) bool {
		return a.Resolved == path && a.Rule.Deny == denylist.DenyAll
	})
}

func link(t *testing.T, target, name string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, name); err != nil {
		t.Fatal(err)
	}
}

// A directory read that fails PART WAY through still hands back the entries it got, and
// every link among them points somewhere the expansion has to cover. Dropping the whole
// expansion there leaves the farm target - which lives outside the store, so the DenyAll
// being expanded does not hide it - reachable by a read grant naming it.
func TestAPartiallyReadCredentialDirStillExpandsTheLinksItSaw(t *testing.T) {
	home := t.TempDir()
	store := filepath.Join(home, ".gnupg")
	target := filepath.Join(home, "dotfiles", "trustdb.gpg")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link(t, target, filepath.Join(store, "trustdb.gpg"))

	fs := shield.Host()
	host := fs.ListDir
	fs.ListDir = func(path string) (names, links []string, ok bool) {
		names, links, _ = host(path)
		if path == store {
			// An EIO or a truncated read on a network home: os.ReadDir returns what it
			// managed to read alongside the error.
			return names, links, false
		}
		return names, links, true
	}

	set := shield.Assemble(fs, []string{home}, denylist.RuntimeDir(), nil)
	if !shielded(set, target) {
		t.Errorf("farm target %s got no shield from a partially-read %s", target, store)
	}
}
