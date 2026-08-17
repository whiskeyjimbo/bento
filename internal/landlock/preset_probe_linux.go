//go:build linux && bentoprobe

package landlock

import (
	"fmt"

	ll "github.com/landlock-lsm/go-landlock/landlock"
)

// SetScopedIPCPreset swaps the scoped set the degraded tier requests, so a probe can
// apply the ruleset BestEffort would have built on an older kernel and assert what that
// kernel enforces. Without it the low-ABI arms of this package's expectation tables run
// only on a host old enough to have them - and the arm is then asserted positively (this
// residual IS open) rather than skipped.
//
// Behind a build tag because nothing that ships may weaken a handled set from outside the
// package: the shipped binary carries no way to reach this, and the probe is the only
// thing built with the tag.
//
// Only a preset at or below the host's ABI changes anything - BestEffort clamps down, so
// asking for a newer set yields the host's own. The interesting boundary is V6, the first
// preset that handles a scope at all: every preset below it applies an empty scoped set
// and reproduces the same pre-ABI-6 column, which is why V1 is left out as redundant
// rather than excluded for any hazard. RestrictScoped carries no rules, so nothing here
// touches refer or the filesystem handled set.
func SetScopedIPCPreset(name string) error {
	presets := map[string]ll.Config{"V2": ll.V2, "V3": ll.V3, "V4": ll.V4, "V5": ll.V5, "V6": ll.V6}
	c, ok := presets[name]
	if !ok {
		return fmt.Errorf("landlock: unknown scoped-IPC preset %q", name)
	}
	scopedIPC = c
	return nil
}
