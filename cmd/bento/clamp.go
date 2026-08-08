package main

import (
	"fmt"
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
//
// The set is the caller's, the same one the enforcer applies and the gate predicts, so the
// proposal is clamped against the shields the run will actually raise.
func clampShieldedGrants(set shield.Set, reads, writes []string) (keptReads, keptWrites []string, dropped []shieldGrant, writeShielded []string) {
	// Two departures from what the run does, both deliberate and both in the direction of
	// a narrower proposal. A read that names a shield exactly is honored at run time as a
	// warned opt-in, and is still withheld here: an opt-in is a line a reviewer adds by
	// hand after reading the warning, not one a draft manifest arrives holding. And the
	// grant is judged where it LANDS as well as where it is spelled, because the observer
	// records resolved paths while the manifest may name the link.
	//
	// Asked as a READ even for the write grants, which is what leaves the above-shield
	// refusal to clampWriteShieldedGrants' own reasoning rather than dropping every grant
	// that encloses a shield. The one enclosing verdict a read does earn is the
	// case-folding one, and dropping on it is right: the run refuses that grant outright,
	// for either kind.
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
	reaches := func(g string) bool {
		// Judged where it LANDS as well as how it is spelled, the same as the clamps
		// above: a link into another user's store (the target plants one in its own
		// directory) is otherwise a grant this predicate reads as belonging to no home at
		// all, and converge auto-accepts what it says nothing about.
		for _, spelling := range []string{g, pathresolve.Existing(g)} {
			root, ok := homeRoot(spelling)
			// The root is resolved against the anchors too, or the run's own home warns
			// whenever the grant is spelled through the link: on an ostree host the anchors
			// say /var/home/u while the stock /home symlink makes the same home /home/u.
			if !ok || selves[root] || selves[pathresolve.Existing(root)] {
				continue
			}
			for _, r := range denylist.Home(root) {
				if spelling == r.Path || policy.CoversResolved(r.Path, spelling) || policy.CoversResolved(spelling, r.Path) {
					return true
				}
			}
		}
		return false
	}
	seen := map[string]bool{}
	var out []string
	for _, g := range grants {
		if seen[g] || !reaches(g) {
			continue
		}
		seen[g] = true
		out = append(out, g)
	}
	return out
}

// homeRoot reports the per-user home directory a path lives under, when the path sits
// under /root or under one of the containers user homes live in (/home/<user>,
// /var/home/<user>, /Users/<user>).
//
// The containers come from profile rather than being listed again here: a root this
// misses is a home foreignHomeShields cannot warn about, and converge no longer only
// warns on that answer - it decides whether a grant is auto-accepted under [a]ll and
// whether a seeded grant is mounted on an approval stamp alone. A layout known to one
// package and not the other is then a consent gap, not a missing line of output.
func homeRoot(path string) (string, bool) {
	clean := filepath.Clean(path)
	if clean == "/root" || strings.HasPrefix(clean, "/root/") {
		return "/root", true
	}
	for _, c := range profile.HomeContainers() {
		rest, ok := strings.CutPrefix(clean, c+"/")
		if !ok {
			continue
		}
		user, _, _ := strings.Cut(rest, "/")
		if user == "" {
			continue
		}
		return c + "/" + user, true
	}
	return "", false
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
	// A set the host cannot anchor at all - not merely an unusable $HOME, which drops to
	// the passwd home - leaves the proposal unclamped: there are no shields to clamp
	// against, and the run this proposal feeds would be refused for that same reason.
	if set, err := commandShieldSet(); err == nil {
		p.Read, p.Write, shielded, writeShielded = clampShieldedGrants(set, p.Read, p.Write)
	}
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
	// Every anchor counts, since either can be the home the script actually walked -
	// under sudo -H a proposal of the passwd home is just as broad as one of $HOME. The
	// values are already cleaned, which proposal paths are too (Synthesize), so a $HOME
	// carrying a trailing slash cannot slip the whole home tree through as non-broad.
	anchors, _ := denylist.HomeAnchors()
	// Judged where it LANDS as well as how it is spelled, the same as the shield clamps
	// above, and on both sides of the comparison. A link is otherwise enough to steer a
	// whole tree past this: the target plants $scriptdir/link -> $HOME and the proposal
	// names the link, and on a host where /home is itself a symlink the observer records
	// /var/home/u while the anchor is spelled /home/u. Either way the grant binds the
	// home, which is precisely what this refuses to propose.
	for _, spelling := range []string{path, pathresolve.Existing(path)} {
		// A home container is every account at once, which /home and /Users happen to be
		// caught by as top-level directories and /var/home is not.
		if spelling == "/" || filepath.Dir(spelling) == "/" || slices.Contains(profile.HomeContainers(), spelling) {
			return true
		}
		for _, a := range anchors {
			if spelling == a || spelling == pathresolve.Existing(a) {
				return true
			}
		}
	}
	return false
}

// resolvedNote names where a grant lands when that differs from how it is spelled, for
// a message about a clamp that fired on the resolved name. Without it the line names a
// path the reviewer can look at and see nothing wrong with.
func resolvedNote(path string) string {
	if r := pathresolve.Existing(path); r != path {
		return fmt.Sprintf(" (it resolves to %q)", r)
	}
	return ""
}
