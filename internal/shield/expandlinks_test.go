package shield

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/denylist"
)

// The expansion reads ExpandLinks and nothing else: a rule's callout bucket can be
// reworded, or a store reclassified, without moving what the sandbox binds. Both
// off-diagonal combinations are asserted because only they separate the flag from the
// bucket - every built-in rule agrees on the two today, so a set assembled from the deny
// list cannot tell which field the walk consulted.
//
// Internal test: the dissociation is not exhibitable from outside the package for exactly
// that reason, and inventing an exported seam to reach it would be a wider change than
// the invariant it checks.
func TestExpansionFollowsTheFlagNotTheBucket(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(home, "dotfiles", "secret")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name  string
		holds denylist.Holds
		flag  bool
	}{
		{"bulk store opted in", denylist.HoldsPrivateData, true},
		{"credential store opted out", denylist.HoldsCredentials, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := filepath.Join(home, tc.name)
			if err := os.MkdirAll(store, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(store, "secret")); err != nil {
				t.Fatal(err)
			}
			s := Set{fs: Host(), homes: []string{home}, atAnchor: map[string]bool{}}
			links := s.credentialLinks([]denylist.Rule{
				{Path: store, Deny: denylist.DenyAll, Dir: true, Holds: tc.holds, ExpandLinks: tc.flag},
			})
			got := slices.ContainsFunc(links, func(r denylist.Rule) bool { return r.Path == target })
			if got != tc.flag {
				t.Errorf("ExpandLinks=%v holds=%s: farm target expanded=%v, want %v",
					tc.flag, tc.holds.Code(), got, tc.flag)
			}
		})
	}
}
