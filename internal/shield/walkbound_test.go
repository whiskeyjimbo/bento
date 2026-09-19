package shield_test

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/shield"
)

// nest builds depth real subdirectories under root and returns the deepest one.
func nest(t *testing.T, root string, depth int) string {
	t.Helper()
	dir := root
	for i := range depth {
		dir = filepath.Join(dir, "d"+strconv.Itoa(i))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A store nesting deeper than MaxWalkDepth is expanded only as far as the bound reaches,
// so a link below it keeps its farm target unshielded and a read grant on that target is
// Honored. The bound is the backend's git-directory scan's and stays where it is; what
// must not happen silently is the shortfall, so the set names the store it happened in.
func TestAStoreDeeperThanTheWalkBoundIsReported(t *testing.T) {
	home := t.TempDir()
	store := filepath.Join(home, ".password-store")
	deep := nest(t, store, 70)
	target := filepath.Join(home, "dotfiles", "secret.gpg")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link(t, target, filepath.Join(deep, "secret.gpg"))

	set := shield.Assemble(shield.Host(), []string{home}, denylist.RuntimeDir(), nil)

	// The premise: the bound really did leave this target unshielded. Without it the
	// report below would be about nothing.
	if shielded(set, target) {
		t.Fatalf("premise gone: %s past the walk bound is shielded after all", target)
	}
	if !slices.Contains(set.TruncatedStores(), store) {
		t.Errorf("store %s was walked only to the bound and did not say so; got %v", store, set.TruncatedStores())
	}
}

// The bound is the only reason to report a short walk. A store that fits inside it is
// covered whole, so naming it would tell an operator to look for a gap that is not there.
func TestAStoreInsideTheWalkBoundIsNotReported(t *testing.T) {
	home := t.TempDir()
	store := filepath.Join(home, ".password-store")
	deep := nest(t, store, 20)
	target := filepath.Join(home, "dotfiles", "secret.gpg")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link(t, target, filepath.Join(deep, "secret.gpg"))

	set := shield.Assemble(shield.Host(), []string{home}, denylist.RuntimeDir(), nil)
	if !shielded(set, target) {
		t.Fatalf("premise gone: %s inside the walk bound is unshielded", target)
	}
	if len(set.TruncatedStores()) != 0 {
		t.Errorf("a store the walk covered whole was reported truncated: %v", set.TruncatedStores())
	}
}

// Source is the environment variable that moved a built-in store, and the run report puts
// that variable next to the path it moved. A caller's deny has no variable behind it, so a
// Source it stamps would print as a relocation that never happened. It is diagnostic only,
// so dropping it at the boundary costs nothing enforced.
func TestACallerDenyCarriesNoRelocationSource(t *testing.T) {
	home := t.TempDir()
	store := filepath.Join(home, "proj", "store")
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	deny := []denylist.Rule{{Path: store, Deny: denylist.DenyAll, Dir: true, Source: "GNUPGHOME"}}
	set := shield.Assemble(shield.Host(), []string{home}, denylist.RuntimeDir(), deny)

	// Shields() is what the report renders from; CallerDenies() alone would go green
	// under a fix that cleared only the other copy of the caller's rules.
	var mounted bool
	for _, a := range set.Shields() {
		if a.Rule.Path != store {
			continue
		}
		mounted = true
		if a.Rule.Source != "" {
			t.Errorf("caller deny %s reached the report stamped as relocated by $%s", store, a.Rule.Source)
		}
	}
	if !mounted {
		t.Fatalf("premise gone: caller deny %s never reaches the report at all", store)
	}
	for _, r := range set.CallerDenies() {
		if r.Source != "" {
			t.Errorf("caller deny %s kept Source %q", r.Path, r.Source)
		}
	}
}
