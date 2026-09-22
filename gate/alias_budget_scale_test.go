//go:build unix

package gate

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/shield"
)

// budgetHome relocates HOME onto a temp tree whose one SSH key carries a second directory
// entry inside its own store, so the scan has a credential to want and walks the grants,
// while nothing outside the store aliases it. It returns the directory the grants go in,
// on the same device as the key so no walk is pruned by device.
func budgetHome(t *testing.T) (root, key string) {
	t.Helper()
	root = t.TempDir()
	store := filepath.Join(root, "home", ".ssh")
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	key = filepath.Join(store, "id_ed25519")
	if err := os.WriteFile(key, []byte("PRIVATE KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(key, key+".bak"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", filepath.Join(root, "home"))
	return root, key
}

// hostSet is the set Check builds, over whatever HOME the test has set: the scan resolves
// through it, so a zero set has nothing to resolve with.
func hostSet(t *testing.T) shield.Set {
	t.Helper()
	set, err := ShieldSet()
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func fill(t *testing.T, dir string, n int) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%d", i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// spent is what one scan of reads charges against an allowance it cannot exhaust. The
// passwd home is an anchor too and this host's is not the test's to arrange, so callers
// compare two spends rather than asserting one: the anchor share is the same in both.
func spent(t *testing.T, reads []string) int {
	t.Helper()
	const plenty = 1 << 30
	budget := plenty
	credentialAliasesWithin(hostSet(t), reads, nil, &budget)
	return plenty - budget
}

// A nested grant holds nothing its encloser's walk does not enumerate, and the allowance
// is one for the whole answer, so walking it again takes its entries out of the grants
// behind it. Asked in both orders because the manifest's order is the author's, and a
// dedup that only skips a root covered by an EARLIER one pays twice for read: ~/project
// listed above read: ~.
func TestNestedGrantsAreWalkedOnceInEitherOrder(t *testing.T) {
	root, _ := budgetHome(t)
	outer := filepath.Join(root, "work")
	inner := filepath.Join(outer, "project")
	fill(t, outer, 10)
	fill(t, inner, 50)

	alone := spent(t, []string{outer})
	for _, reads := range [][]string{{outer, inner}, {inner, outer}} {
		if got := spent(t, reads); got != alone {
			t.Errorf("grants %v spent %d entries; the enclosing grant alone spends %d", reads, got, alone)
		}
	}
}

// The bound has to hold whatever the host holds: a credential store is a few entries on
// one home and tens of thousands on another, and the anchor walk runs before there is
// anything to want. Asked at two sizes, since one size cannot tell a bounded walk from one
// that happened to fit - the spend must be the allowance at both, and every grant must be
// named as unwalked, because nothing they would be compared against was finished. With
// and without a credential already wanted when the allowance runs out: without one no
// grant is walked at all, and that answer comes back by a different return.
func TestTheAnchorWalkIsBoundedAtAnySize(t *testing.T) {
	for _, tc := range []struct {
		n      int
		wanted bool
	}{{200, true}, {2000, true}, {200, false}, {2000, false}} {
		t.Run(fmt.Sprintf("%d/wanted=%v", tc.n, tc.wanted), func(t *testing.T) {
			root, key := budgetHome(t)
			if !tc.wanted {
				if err := os.Remove(key + ".bak"); err != nil {
					t.Fatal(err)
				}
			}
			grant := filepath.Join(root, "work")
			fill(t, grant, 5)
			fill(t, filepath.Join(root, "home", ".gnupg"), tc.n)

			budget := 100
			_, short, partial := credentialAliasesWithin(hostSet(t), []string{grant}, nil, &budget)
			if budget != 0 {
				t.Errorf("a %d-entry store left %d of a 100-entry allowance; the walk must stop on it", tc.n, budget)
			}
			if !partial || !slices.Equal(short, []string{grant}) {
				t.Errorf("an anchor walk the allowance ran out on must name every grant as unwalked; got %v (partial %v)", short, partial)
			}
		})
	}
}

// The allowance is spent in grant order, so where it runs out says nothing about where an
// alias is likely to be: a module cache listed first scans nothing behind it. The answer
// has to say WHICH grants went unread, not only that some did, or a reader cannot tell a
// grant holding a real alias from one that was checked.
func TestTheGrantsTheBudgetRanOutBeforeAreNamed(t *testing.T) {
	root, key := budgetHome(t)
	cache := filepath.Join(root, "cache")
	fill(t, cache, 200)
	backup := filepath.Join(root, "backup")
	fill(t, backup, 0)
	if err := os.Link(key, filepath.Join(backup, "id_ed25519")); err != nil {
		t.Fatal(err)
	}
	anchors := spent(t, nil)

	scan := func(budget int, reads ...string) (int, []string) {
		found, short, _ := credentialAliasesWithin(hostSet(t), reads, nil, &budget)
		return len(found), short
	}
	if found, short := scan(anchors+50, cache, backup); found != 0 || !slices.Equal(short, []string{backup, cache}) {
		t.Errorf("the cache spent the allowance, so the backup behind it went unread and must be named; found %d, unwalked %v", found, short)
	}
	if found, short := scan(anchors+50, backup, cache); found != 1 || !slices.Equal(short, []string{cache}) {
		t.Errorf("the backup read whole before the cache ran the allowance out; found %d, unwalked %v", found, short)
	}
	if found, short := scan(anchors+1000, cache, backup); found != 1 || len(short) != 0 {
		t.Errorf("an allowance both trees fit inside leaves nothing unwalked; found %d, unwalked %v", found, short)
	}
}

// The scan anchors where the shield set says a store lands, so it resolves through the
// set's own FS rather than asking the host a second time: the two answering differently is
// the divergence internal/shield exists to prevent, and the set has already resolved most
// of the anchors while assembling. An FS that relocates ~/.ssh is only honored by a scan
// that asks it.
func TestTheAliasScanResolvesAsTheShieldSetDoes(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	elsewhere := filepath.Join(root, "elsewhere", ".ssh")
	fill(t, home, 0)
	fill(t, elsewhere, 0)
	key := filepath.Join(elsewhere, "id_ed25519")
	if err := os.WriteFile(key, []byte("PRIVATE KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(key, key+".bak"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	fs := shield.Host()
	hostResolve := fs.Resolve
	fs.Resolve = func(p string) string {
		if rest, ok := strings.CutPrefix(p, filepath.Join(home, ".ssh")); ok {
			return elsewhere + rest
		}
		return hostResolve(p)
	}
	set := shield.Assemble(fs, []string{home}, filepath.Join(root, "run"), nil)

	budget := 1 << 30
	want, _, _, _ := aliasableCredentials(set, nil, &budget)
	if len(want) == 0 {
		t.Error("the scan did not anchor on the store where the shield set's FS puts it")
	}
}
