package main

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/pathresolve"
	"github.com/whiskeyjimbo/bento/internal/shield"
	"github.com/whiskeyjimbo/bento/policy"
	"github.com/whiskeyjimbo/bento/profile"
)

// clampShieldedGrants drops read and write grants that fall at or inside a mandatory
// DenyAll home shield (~/.ssh, ~/.aws, ~/.gnupg, ...). Bento hides these on every run, so
// the profiler never proposes them automatically - the observer records the attempt (the
// consent surface) even though default-deny never mounted the path, and the user opts in
// by hand if the program genuinely needs it. A grant that names the shield exactly is
// honorable at run time (an explicit, warned opt-in); a grant strictly inside one is
// refused there. Either way it is dropped from the auto-proposal, so this is a proposal-
// quality filter, not a security check. A grant that merely CONTAINS a shield (read: ~
// with ~/.ssh shielded inside it) is legitimate and kept - only a grant at or under a
// shield goes.
func clampShieldedGrants(reads, writes []string) (keptReads, keptWrites []string, dropped []shieldGrant, writeShielded []string) {
	// The same set the enforcer applies and the gate predicts, so the proposal is clamped
	// against the shields the run will actually raise. The error means no anchor at all -
	// not merely an unusable $HOME, which drops to the passwd home - so there are no
	// shields to clamp against and the run this proposal feeds would be refused anyway.
	set, err := shieldSet()
	if err != nil {
		return reads, writes, nil, nil
	}
	// Two departures from what the run does, both deliberate and both in the direction of
	// a narrower proposal. A read that names a shield exactly is honored at run time as a
	// warned opt-in, and is still withheld here: an opt-in is a line a reviewer adds by
	// hand after reading the warning, not one a draft manifest arrives holding. And the
	// grant is judged where it LANDS as well as where it is spelled, because the observer
	// records resolved paths while the manifest may name the link.
	//
	// Asked as a READ even for the write grants, which is what leaves the above-shield
	// refusal to clampWriteShieldedGrants' own reasoning rather than dropping every grant
	// that encloses a shield.
	drop := func(g string) (denylist.Holds, bool) {
		for _, spelling := range []string{g, pathresolve.Existing(g)} {
			r, v := set.Contains(spelling, shield.Read, nil, nil)
			if v != shield.Honored {
				return r.Holds, true
			}
		}
		return denylist.HoldsUnknown, false
	}
	filter := func(grants []string) (kept []string) {
		for _, g := range grants {
			if holds, ok := drop(g); ok {
				dropped = append(dropped, shieldGrant{Path: g, Holds: holds})
			} else {
				kept = append(kept, g)
			}
		}
		return kept
	}
	keptReads = filter(reads)
	keptWrites, writeShielded = clampWriteShieldedGrants(set, filter(writes))
	return keptReads, keptWrites, dropped, writeShielded
}

// clampWriteShieldedGrants drops write grants at or inside a DenyWrite home shield
// (~/.local/bin, ~/.cargo/bin, ~/.rustup, ~/.bashrc, ...). checkWriteNotUnderReadOnlyShield
// hard-refuses these at run time and there is no opt-in, so proposing one would hand the
// reviewer a manifest that cannot be approved into a working run. Reads are untouched:
// a DenyWrite shield leaves its content readable, so a read grant there is honored.
//
// Unlike clampShieldedGrants this is not merely a proposal-quality filter - it is what
// keeps the profiler's output and the enforcer's refusal from disagreeing.
//
// A grant that merely CONTAINS a shield is kept, which the run refuses: the enforced run
// re-shields the interior, and dropping every enclosing grant would take the ordinary
// "write: the project directory" proposal with it. foreignHomeShields reports the case
// where that reasoning does not hold.
func clampWriteShieldedGrants(set shield.Set, writes []string) (kept, dropped []string) {
	for _, g := range writes {
		shielded := false
		for _, spelling := range []string{g, pathresolve.Existing(g)} {
			if _, v := set.Contains(spelling, shield.Write, nil, nil); v == shield.UnderWriteShield {
				shielded = true
				break
			}
		}
		if shielded {
			dropped = append(dropped, g)
		} else {
			kept = append(kept, g)
		}
	}
	return kept, dropped
}

// foreignHomeShields returns the proposed grants that reach a shielded path under a home
// directory other than the profiler's own. clampShieldedGrants drops grants inside the
// PROFILER's home shields, but a script that reaches a protected path under a different
// home - profiled under sudo (HOME=/root) touching /home/u/.ssh, or with HOME unset so
// the clamp is skipped - is not clamped and lands in the proposal. It is reported, not
// dropped: a home-shaped heuristic strong enough to drop on would also gut legitimate
// cross-home data grants (/home/u/project/data), so the reviewer decides.
//
// The match against denylist.Home(root) tests containment in EITHER direction: a grant
// at or under a shield (write: ~/.ssh/id_rsa), and - the case that matters most - a grant
// that ENCLOSES a shield (write: ~, which Synthesize produces by collapsing a file write
// to its directory, sweeping in ~/.ssh). For the profiler's own home clampShieldedGrants
// can safely keep an enclosing grant because the enforced run re-shields the interior;
// for a foreign home it cannot, since the run shields only the home it executes as, so
// both directions must warn. Both shield classes count - a foreign DenyWrite persistence
// path (~/.config/systemd/user) is unshielded at run time just like a DenyAll credential.
// A data path enclosing no shield still stays quiet.
//
// Only the root-anchored rules, never denylist.Relocated: an env relocation names one
// absolute path that belongs to the RUN, so the enforced run shields it wherever it lands
// - including under a foreign home - and a warning built from it would name a shield the
// run does carry. What this function looks for is the opposite, a shield the run has no
// rule for because it anchors on a different home.
func foreignHomeShields(grants []string) []string {
	// Every anchor the run shields on counts as "own", not just $HOME: under sudo -H the
	// two disagree, and treating the passwd home as foreign would warn about a store the
	// run shields anyway - noise the reviewer learns to skip past.
	anchors, _ := denylist.HomeAnchors()
	selves := map[string]bool{}
	for _, self := range anchors {
		selves[self] = true
		selves[pathresolve.Existing(self)] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, g := range grants {
		root, ok := homeRoot(g)
		if !ok || selves[root] || seen[g] {
			continue
		}
		for _, r := range denylist.Home(root) {
			if g == r.Path || policy.CoversResolved(r.Path, g) || policy.CoversResolved(g, r.Path) {
				seen[g] = true
				out = append(out, g)
				break
			}
		}
	}
	return out
}

// homeRoot reports the per-user home directory a path lives under, when the path sits
// beneath a conventional home root (/root, /home/<user>, /Users/<user>). It is a
// heuristic used only to warn, never to drop, so a home in an unconventional location
// (a container image or Silverblue's /var/home) simply yields no warning rather than a
// wrong one.
func homeRoot(path string) (string, bool) {
	// A cleaned absolute path splits to ["", "home", "u", ...] - segs[0] is empty.
	segs := strings.Split(filepath.Clean(path), "/")
	switch {
	case len(segs) >= 2 && segs[1] == "root":
		return "/root", true
	case len(segs) >= 3 && (segs[1] == "home" || segs[1] == "Users"):
		return "/" + segs[1] + "/" + segs[2], true
	default:
		return "", false
	}
}

// clampProposal filters a synthesized proposal for review, in an order that is
// load-bearing: drop grants inside a mandatory shield, then drop over-broad
// read and write grants, and ONLY THEN dedup reads a surviving write already covers.
// Deduping last is what keeps a read near a credential store (~/.ssh under a $HOME-level
// write) from being swallowed by a broad write before the shield clamp can surface it.
// The broad-read clamp is the read-side twin of the write clamp: a proposal of read: ~
// (or read: /) - which a script that lists its home or the root produces - would, once
// approved, bind the whole tree minus only the enumerated shields, re-exposing every
// credential the deny-list misses; the specific sub-paths the script read are proposed
// on their own, so dropping the umbrella loses nothing real. It mutates p and returns
// the shielded, over-broad read, and over-broad write paths to warn about.
func clampProposal(p *policy.Policy) (shielded []shieldGrant, writeShielded, broadReads, broadWrites []string) {
	p.Read, p.Write, shielded, writeShielded = clampShieldedGrants(p.Read, p.Write)
	p.Write, broadWrites = partitionBroad(p.Write)
	p.Read, broadReads = partitionBroad(p.Read)
	p.Read = profile.DropCovered(p.Read, p.Write)
	return shielded, writeShielded, broadReads, broadWrites
}

// partitionBroad splits grants into those safe to bind whole and those too broad
// (see isBroadDir), preserving order.
func partitionBroad(paths []string) (kept, dropped []string) {
	for _, p := range paths {
		if isBroadDir(p) {
			dropped = append(dropped, p)
		} else {
			kept = append(kept, p)
		}
	}
	return kept, dropped
}

// isBroadDir reports whether path is too broad to bind as a whole: the root, a
// top-level directory (a direct child of "/", such as /etc or /home), or the user's
// home directory itself. Binding any of these exposes far more than a profiled script
// needs - as an automatic read or write grant (partitionBroad) or as the discovery run's own
// script-directory grant (discoveryPolicy).
func isBroadDir(path string) bool {
	if path == "/" || filepath.Dir(path) == "/" {
		return true
	}
	// Every anchor counts, since either can be the home the script actually walked -
	// under sudo -H a proposal of the passwd home is just as broad as one of $HOME. The
	// values are already cleaned, which proposal paths are too (Synthesize), so a $HOME
	// carrying a trailing slash cannot slip the whole home tree through as non-broad.
	anchors, _ := denylist.HomeAnchors()
	return slices.Contains(anchors, path)
}
