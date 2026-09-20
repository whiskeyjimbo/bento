package credhunt

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/denylist"
)

// FuzzHuntNeverReportsAShieldedFile promotes TestIndexedHuntMatchesLinear from a table to a
// generator. Hunt prunes with a denylist.Index and the hand-written test checks the pruned
// answer against a linear denylist.Covers scan over the same rules, on one planted layout;
// this asks the same question of whatever layout the fuzzer plants. The direction is the
// one that matters: a finding already covered by a DenyAll shield is noise that buries the
// handful of paths the operator has to act on, and the index is the only thing standing
// between the walk and reporting thousands of them.
//
// The other two claims in Hunt's doc ride along free, because a differential that does not
// also pin the output's shape passes on a hunt that returns its findings twice: the results
// are sorted by path, and each path appears once.
//
// Every one of those is quantified over what Hunt returned, so a Hunt that returned nothing
// would satisfy them all. The canary is what makes them load-bearing: a fixed secret at a
// fixed path that must be reported on every exec, whatever the fuzzer planted beside it. Its
// oracle is a constant rather than a re-derivation of the sniff's own predicate, which would
// hold by construction. What the unbounded axis then buys is statable: no layout the fuzzer
// invents may suppress it - a planted .git carrying git's gitdir pointer prunes a real
// subtree, and the canary is where that would show.
func FuzzHuntNeverReportsAShieldedFile(f *testing.F) {
	f.Add(".ssh/id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\n")
	f.Add("secret_token.pem", "-----BEGIN PRIVATE KEY-----\n")
	f.Add(".gnupg/sub/trustdb.gpg", "\x00\x01binary")
	f.Add(".npmrc", "_authToken=abcdefghijklmnopqrstuvwxyz\n")
	f.Add(".env", "AWS_SECRET_ACCESS_KEY=abcdefghijklmnopqrstuvwxyz\n")
	// A link and a traversal, which the plant refuses rather than follows - but the
	// spellings are what the sanitizer has to keep out, so they belong in the corpus.
	f.Add("../escape", "token: abcdefghijklmnopqrstuvwxyz\n")
	f.Add(".ssh/../.ssh/id_ed25519", "-----BEGIN PRIVATE KEY-----\n")
	// The dotfile farm: the deny-list does not expand it and, before farmDirs, the sniff
	// did not reach it either. A permanent seed against the half that lands first.
	f.Add("dotfiles/config/acme/settings.json", "oauth_token: gho_0123456789abcdefghijklmnop\n")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, rel, content string) {
		home := t.TempDir()
		// Planted every exec because the file is the input; two directories and one file is
		// a walk of three entries, which is what keeps this inside the 30s budget.
		if err := os.Mkdir(filepath.Join(home, ".ssh"), 0o700); err != nil {
			t.Fatal(err)
		}
		plantIfInside(t, home, rel, content)
		canary := plantCanary(t, home)

		opts := benchOpts(home)
		found, _, _, _, err := Hunt(opts)
		if err != nil {
			t.Fatalf("Hunt: %v", err)
		}

		if !slices.Contains(paths(found), canary) {
			t.Fatalf("the canary %q holds a token and was not reported; findings=%v", canary, paths(found))
		}
		for _, fi := range found {
			// The linear answer, over the same rules the index was built from.
			if r, ok := denylist.Covers(fi.Path, opts.Rules); ok && r.Deny == denylist.DenyAll {
				t.Fatalf("finding %q is covered by the DenyAll shield %q; the index missed a prune the linear scan makes", fi.Path, r.Path)
			}
			if len(fi.Signals) == 0 {
				t.Fatalf("finding %q carries no signal, so nothing says why it was reported", fi.Path)
			}
			if len(fi.Signals) == 1 && fi.Signals[0] == SignalPrivateMode {
				t.Fatalf("finding %q rests on a private mode alone, which shapesOf declines to carry a finding on", fi.Path)
			}
		}
		if !slices.IsSortedFunc(found, func(a, b Finding) int { return strings.Compare(a.Path, b.Path) }) {
			t.Fatalf("findings are not sorted by path: %v", paths(found))
		}
		for i := 1; i < len(found); i++ {
			if found[i].Path == found[i-1].Path {
				t.Fatalf("path %q reported twice; a symlink within the home is the way that happens", found[i].Path)
			}
		}
	})
}

// plantCanary writes the fixed secret the target quantifies the forbidden direction over
// and returns its path. It goes at the home root, the one place no prune can reach - the
// checkout and machine-store prunes both exempt the root, so no name the fuzzer invents can
// hide it. Its own name trips nothing: the finding rests on the unconditional home-root
// sniff and the token shape, so a sniff that stopped reaching the root is what goes red
// here rather than a name-token change.
//
// Planted AFTER the fuzzer's file and skipped on error, because the same input can land on
// this path: os.WriteFile truncates, and an input like "canary.txt/x" turns the name into a
// directory.
func plantCanary(t *testing.T, home string) string {
	t.Helper()
	p := filepath.Join(home, "canary.txt")
	if err := os.WriteFile(p, []byte("oauth_token: gho_0123456789abcdefghijklmnopqrstuvwxyz\n"), 0o644); err != nil {
		t.Skip()
	}
	return p
}

// plantIfInside writes content at rel under home, skipping the exec if rel does not name a plain
// file inside it. Returning rather than failing: a traversal or an empty name is an input
// the fuzzer will produce constantly and it says nothing about Hunt, while planting outside
// the temporary home would have the walk reading the checkout it runs from.
func plantIfInside(t *testing.T, home, rel, content string) {
	t.Helper()
	abs := filepath.Join(home, rel)
	if abs == home || !strings.HasPrefix(abs, home+string(filepath.Separator)) || strings.ContainsRune(rel, 0) {
		return
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return
	}
	if err := os.WriteFile(abs, []byte(content), 0o600); err != nil {
		return
	}
}
