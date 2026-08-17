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
	c, err := preset(name)
	if err != nil {
		return err
	}
	scopedIPC = c
	return nil
}

// SetTierPreset swaps every set the two tiers request - the filesystem handled sets and
// the network set - so a probe can apply the whole ruleset BestEffort would have built on
// an older kernel. SetScopedIPCPreset's reasons for existing and for being behind a build
// tag apply here unchanged; this covers the arms that one does not: the pre-ABI-3
// truncate difference on a read-only grant, and the pre-ABI-4 column where the net domain
// restricts nothing.
//
// The result is a HYBRID, and every assertion over it has to be true of the hybrid rather
// than of the kernel it names: withIoctlDev, withResolveUnix and referSupported ask
// LandlockGetABIVersion directly, so they keep answering for the REAL kernel while the
// handled sets come from the preset. A rule therefore still asks for ioctl_dev and
// resolve_unix at any preset; BestEffort intersects those away per rule below the ABI
// that handles them, which is the same thing the older kernel would have done, but the
// route there is not the same and a comment claiming "this is an ABI-2 kernel" would be
// wrong.
//
// V1 is excluded rather than merely uninteresting: refer is absent from its handled set,
// and refer is the one right go-landlock answers by collapsing the config to v0 and
// restricting nothing at all - so a V1 preset would confine nothing while reporting
// success, which is worse than no coverage.
func SetTierPreset(name string) error {
	c, err := preset(name)
	if err != nil {
		return err
	}
	handledFS, degradedFS, netTCP = c, c, c
	return nil
}

// preset resolves a preset name to a go-landlock Config. Only a preset at or below the
// host's ABI changes anything - BestEffort clamps down, so asking for a newer set yields
// the host's own.
func preset(name string) (ll.Config, error) {
	presets := map[string]ll.Config{
		"V2": ll.V2, "V3": ll.V3, "V4": ll.V4, "V5": ll.V5,
		"V6": ll.V6, "V7": ll.V7, "V8": ll.V8, "V9": ll.V9,
	}
	c, ok := presets[name]
	if !ok {
		return ll.Config{}, fmt.Errorf("landlock: unknown preset %q", name)
	}
	return c, nil
}
