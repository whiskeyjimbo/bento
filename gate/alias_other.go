//go:build !unix

package gate

import (
	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/shield"
)

// credentialAliases finds nothing off unix, because the identity a hardlink shares with
// the file it aliases is a (device, inode) pair and there is none here to read. bento has
// no backend on such a host either, so the run this would have warned about cannot start -
// see Runnability.CredentialAliases for what an empty answer is worth.
func credentialAliases(shield.Set, []string, []string) []enforce.CredentialAlias {
	return nil
}
