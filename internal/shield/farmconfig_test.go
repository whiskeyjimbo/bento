package shield_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/shield"
)

// stow, chezmoi and yadm manage ~/.config wholesale by replacing the tree with links into
// a farm directory, so a store there whose own deny-list comment names a password or a
// private key is reachable at the farm path unless the expansion follows the link. The
// stores named here are configuration, not bulk trees: their walk costs a handful of
// stats, which is the distinction bulkStoreDirs draws and the reason the whole bucket
// cannot simply be turned on.
func TestFarmManagedConfigStoresExpandTheirLinks(t *testing.T) {
	for _, store := range []string{".config/gajim", ".config/psi", ".config/Mumble", ".config/kdeconnect"} {
		t.Run(store, func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, "dotfiles", "secret")
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			link(t, target, filepath.Join(home, store, "secret"))

			set := shield.Assemble(shield.Host(), []string{home}, denylist.RuntimeDir(), nil)
			if !shielded(set, target) {
				t.Errorf("farm target %s of %s got no shield, so a read grant naming it is honored", target, store)
			}
		})
	}
}
