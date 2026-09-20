package grantrefusal

import (
	"strings"
	"testing"
)

// shield.Contains raises FoldedShield for a grant containing a DenyWrite shield
// (~/.pyenv/shims) as readily as for one containing a DenyAll store (~/.ssh), so this
// sentence has to be true of both kinds. "always-shielded path" is denylist's noun for
// the DenyAll half alone - a DenyWrite shield leaves its content readable and fences the
// write surface - and naming it here tells an author their pyenv shims are hidden from
// the run when they are not.
//
// The two sentences are checked together because the noun is correct in WriteAboveShield:
// that refusal is raised over DenyAll shields only, so a kind-neutral sweep of the package
// would take a true sentence with the false one.
func TestFoldedShieldDoesNotClaimTheShieldHidesItsContent(t *testing.T) {
	folded := FoldedShield("/home/u/.pyenv", "/home/u/.pyenv/shims").Error()
	if strings.Contains(folded, "always-shielded") {
		t.Errorf("FoldedShield calls a shield always-shielded, which a DenyWrite shield is not: %s", folded)
	}
	if !strings.Contains(folded, `the shielded path "/home/u/.pyenv/shims"`) {
		t.Errorf("FoldedShield no longer names the shield it refuses over: %s", folded)
	}

	above := WriteAboveShield("/home/u", "/home/u/.ssh").Error()
	if !strings.Contains(above, "always-shielded") {
		t.Errorf("WriteAboveShield is raised over DenyAll shields alone and should keep denylist's noun: %s", above)
	}
}
