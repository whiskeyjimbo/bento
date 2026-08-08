//go:build unix

package gate_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/whiskeyjimbo/bento/gate"
	"github.com/whiskeyjimbo/bento/policy"
)

// aliasHome relocates HOME onto a temp tree holding one SSH key, and returns the home and
// the key's path. It is one t.TempDir for the whole case so the grant and the credential
// land on the same device - a hardlink cannot cross one, and neither can this test.
func aliasHome(t *testing.T) (home, key string) {
	t.Helper()
	root := t.TempDir()
	home = filepath.Join(root, "home")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	key = filepath.Join(home, ".ssh", "id_ed25519")
	if err := os.WriteFile(key, []byte("PRIVATE KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	return home, key
}

func runnableOver(t *testing.T, entrypoint string, read []string) gate.Runnability {
	t.Helper()
	return gate.Check(&policy.Policy{Entrypoint: entrypoint, Read: read})
}

// The gap this exists to close: a snapshot tool hardlinks against a live credential, a
// manifest grants read over the tree holding the snapshot, and the run refuses at its
// first step over an alias nothing before it mentioned. `cp -al` and `rsync --link-dest`
// both leave exactly this - a second directory entry for the key's inode.
func TestCheckReportsAHardlinkedCredential(t *testing.T) {
	home, key := aliasHome(t)
	backup := filepath.Join(filepath.Dir(home), "backup")
	if err := os.MkdirAll(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(backup, "id_ed25519")
	if err := os.Link(key, alias); err != nil {
		t.Fatal(err)
	}

	r := runnableOver(t, key, []string{backup})
	if len(r.CredentialAliases) != 1 {
		t.Fatalf("a hardlinked credential under a read grant must be reported; got %+v", r.CredentialAliases)
	}
	if got := r.CredentialAliases[0]; got.Path != alias || got.Credential != key {
		t.Errorf("the finding must name the alias and the credential it reaches; got %+v", got)
	}
	// Reported beside the verdict, never as it: the run's refusal is lifted by
	// --accept-alias, which is not in the manifest and so cannot be checked from here.
	if len(r.Refusals) != 0 {
		t.Errorf("an alias must not be refused here - a run naming the tree accepts it; got %v", r.Refusals)
	}
}

// The two answers that must stay quiet, because a note over either is one an operator
// learns to skim: an ordinary credential with a single directory entry cannot be
// hardlink-aliased at all, and a grant that does not cover the alias does not expose it.
func TestCheckIsQuietWithoutAReachableAlias(t *testing.T) {
	t.Run("no second name", func(t *testing.T) {
		home, _ := aliasHome(t)
		work := filepath.Join(filepath.Dir(home), "work")
		if err := os.MkdirAll(work, 0o700); err != nil {
			t.Fatal(err)
		}
		if r := runnableOver(t, work, []string{work}); len(r.CredentialAliases) != 0 {
			t.Errorf("a credential with one name aliases nothing; got %+v", r.CredentialAliases)
		}
	})

	t.Run("alias outside the grant", func(t *testing.T) {
		home, key := aliasHome(t)
		outside := filepath.Join(filepath.Dir(home), "elsewhere")
		if err := os.MkdirAll(outside, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(key, filepath.Join(outside, "id_ed25519")); err != nil {
			t.Fatal(err)
		}
		work := filepath.Join(filepath.Dir(home), "work")
		if err := os.MkdirAll(work, 0o700); err != nil {
			t.Fatal(err)
		}
		if r := runnableOver(t, work, []string{work}); len(r.CredentialAliases) != 0 {
			t.Errorf("an alias the policy grants nothing over is not reachable; got %+v", r.CredentialAliases)
		}
	})

	// The credential's own path is not a second name for itself. A grant containing the
	// store walks over it, and its identity is by definition the one being looked for.
	t.Run("the credential's own path", func(t *testing.T) {
		home, key := aliasHome(t)
		if err := os.Link(key, filepath.Join(filepath.Dir(key), "id_ed25519.bak")); err != nil {
			t.Fatal(err)
		}
		r := runnableOver(t, key, []string{filepath.Join(home, ".ssh")})
		for _, a := range r.CredentialAliases {
			if a.Path == key {
				t.Errorf("the shielded path was reported as an alias of itself; got %+v", r.CredentialAliases)
			}
		}
	})
}
