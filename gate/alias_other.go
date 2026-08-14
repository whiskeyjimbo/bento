//go:build !unix

package gate

import (
	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/shield"
)

// credentialAliases finds nothing off unix, because the identity a hardlink shares with
// the file it aliases is a (device, inode) pair and there is none here to read. bento has
// no backend on such a host either, so the run this would have warned about cannot start.
//
// Reported partial rather than clean all the same: enforce.Enforcer is an interface and
// enforce builds for windows, so an embedder supplying its own can reach this - and a
// false there says on Runnability.CredentialAliasesPartial's own terms that the granted
// trees were read whole, when none was read at all.
func credentialAliases(shield.Set, []string, []string) ([]enforce.CredentialAlias, bool) {
	return nil, true
}
