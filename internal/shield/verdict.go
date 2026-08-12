package shield

import (
	"cmp"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/policy"
)

// Verdict is what a shield set does to one grant. Each value maps to exactly one refusal
// sentence in internal/grantrefusal, and the mapping is the caller's to make: the wording
// belongs to the frontend that speaks to the author, while what is refused belongs here.
type Verdict int

const (
	// Honored means no shield refuses the grant.
	Honored Verdict = iota
	// InsideShield means the grant is at or inside a fully-shielded (DenyAll) path. A
	// read is refused in a sentence offering the opt-in; a write in one that does not,
	// because there is no write opt-in and naming one would send the author around a
	// loop.
	InsideShield
	// InsideCallerShield is InsideShield where the shield is a caller-supplied deny. It
	// is separate because that sentence's remedy - name the shield in a read grant - does
	// not exist here: the opt-in lifts bento's own built-ins, and an embedder's deny is a
	// trust domain the manifest must not talk its way out of.
	InsideCallerShield
	// UnderWriteShield means a write at or inside a read-only (DenyWrite) shield. There
	// is no read counterpart, because such a shield leaves its content readable, and no
	// opt-in at all: the content being readable already means an opt-in could grant
	// nothing but the plant.
	UnderWriteShield
	// AboveShield means a write that CONTAINS a fully-shielded path, which would make the
	// shield's own name replaceable in a directory the run can write.
	AboveShield
	// AboveWriteShield means a write that CONTAINS a read-only (DenyWrite) shield. It is
	// separate from AboveShield because only one tier is affected: under bwrap the
	// shield's ro-bind is emitted after the grant's bind and wins, so the shield holds,
	// while the Landlock-only tier has no binds and no way to carve a narrower right out
	// of a granted tree - Landlock takes the UNION of every matching rule - so the
	// shielded directory is plainly writable on the host there.
	AboveWriteShield
	// FoldedShield means a grant CONTAINS a fully-shielded path whose directory folds
	// case, so the byte-exact bind that shields it leaves the same file reachable under
	// another spelling. Unlike AboveShield it applies to reads as much as writes, because
	// what leaks is the content, not the name.
	FoldedShield
)

// Kind is the grant's kind. The two are not symmetric - the read opt-in has no write
// counterpart, and only a write can be refused for containing a shield - so the verdict
// cannot be answered without it.
type Kind int

const (
	Read Kind = iota
	Write
)

// Contains reports the first refusal a grant earns and the rule that raises it, or
// Honored with a zero rule.
//
// The order matches the order a run applies the checks in, so a grant tripping more than
// one (a write naming a shield exactly is both inside it and above it) is refused in the
// sentence the run would have printed rather than whichever rule happened to sort first.
//
// A write grant of "/" must be refused by the caller BEFORE it gets here. This reports
// AboveShield for it - every shield on the host is under it - and names whichever one
// sorts first, which is a true statement about a dotfile and a useless one about a grant
// that would hand over the whole filesystem.
//
// optIns are the resolved targets of the shields a READ opts into, from OptIns below;
// pass nil for a write, which is what keeps the opt-in read-only.
//
// workspace are the shields derived from the write grants themselves - a checkout's git
// hooks and editor task files - a runtime input rather than part of the assembled set,
// because they depend on the grants being judged. Two things about them are load-bearing.
// They are consulted in the INSIDE direction only: a self-derived shield sits strictly
// under its own grant, so refusing a grant that contains one would refuse every project
// write there is. And the caller must pass the union derived from EVERY write grant,
// derived without gating on the grant being an existing directory - the gate belongs on
// what is mounted, not on what is judged, because gating here admits a grant while its
// directory is still absent, lets the run create it, and refuses on the next pass with
// the artifact already on the host.
func (s Set) Contains(grant string, kind Kind, optIns []string, workspace []denylist.Rule) (denylist.Rule, Verdict) {
	for _, a := range s.applied {
		if a.Rule.Deny != denylist.DenyAll {
			continue
		}
		// A READ naming the shielded path itself is a deliberate, warned opt-in: the
		// enforcer skips the shield so the real content binds read-only. A grant strictly
		// inside one is refused either way - a shield cannot be partly lifted - so opting
		// one file in means naming the shielding directory and taking its siblings with it.
		// The folded spelling counts here too, and more sharply than anywhere else: a
		// DenyAll shield hides a credential store, so a read of ~/.SSH/id_rsa beside a
		// byte-exact bind at ~/.ssh hands over the key with nothing needing to be writable.
		// An opt-in is matched on the shield's own resolved path, so a grant that reaches
		// the store only by respelling it is not one and is refused - which is the right
		// way round, the opt-in being a path the author named deliberately.
		if s.covers(a.Resolved, grant) && !slices.Contains(optIns, a.Resolved) {
			if s.callerDenied(a.Resolved) {
				return a.Rule, InsideCallerShield
			}
			return a.Rule, InsideShield
		}
	}
	// Checked for both kinds and before the write-only verdicts, because a case-folding
	// mount defeats a shield for a plain read - the grant that reaches the second
	// spelling need not be able to write anything.
	//
	// An opted-into shield is passed over, as in the loop above. The opt-in already binds
	// that store's real content read-only, so a second spelling reaching the same content
	// exposes nothing the author did not ask for, and refusing here would withdraw the one
	// escape the other refusals point them at.
	for _, a := range s.applied {
		if a.Rule.Deny != denylist.DenyAll || slices.Contains(optIns, a.Resolved) {
			continue
		}
		if policy.CoversResolved(grant, a.Resolved) && s.foldsCase(a.Resolved) {
			return a.Rule, FoldedShield
		}
	}

	if kind == Read {
		return denylist.Rule{}, Honored
	}

	// Asked of the folded spelling too, for the reason the FoldedShield loop above exists:
	// a shield is one byte-exact bind, so where the mount folds case the same shim
	// directory is reached by writing ~/.pyenv/SHIMS while the shield binds ~/.pyenv/shims.
	// There is no opt-in to pass over here - a DenyWrite shield has none at all - so unlike
	// that loop this one is not conditional on the grant.
	for _, a := range s.applied {
		if a.Rule.Deny == denylist.DenyWrite && s.covers(a.Resolved, grant) {
			return a.Rule, UnderWriteShield
		}
	}
	for _, r := range workspace {
		if r.Deny == denylist.DenyWrite && s.covers(s.fs.Resolve(r.Path), grant) {
			return r, UnderWriteShield
		}
	}

	for _, a := range s.applied {
		if a.Rule.Deny != denylist.DenyAll {
			continue
		}
		// The tamperable entry is the shield's own NAME in the granted directory, so the
		// parent resolves and the name stays literal - the target of the link lies outside
		// the grant, but the link that would be replaced does not. Asked of the unresolved
		// spelling too, because where it is the SHIELD that moves out of the grant (a
		// symlinked home: the grant is /home while the shield lands in /data/u) the
		// containment is visible in no other namespace. A shield with no symlink above it
		// resolves to itself, so the two tests coincide everywhere else and the second
		// costs nothing.
		loc := filepath.Join(s.fs.Resolve(filepath.Dir(a.Rule.Path)), filepath.Base(a.Rule.Path))
		if policy.CoversResolved(grant, loc) || policy.CoversResolved(grant, a.Rule.Path) {
			return a.Rule, AboveShield
		}
	}

	// Last, so a grant that contains both kinds is refused in the DenyAll sentence: that
	// one refuses on every tier, and this one only on the tier with no binds.
	for _, a := range s.applied {
		if a.Rule.Deny != denylist.DenyWrite {
			continue
		}
		// Asked of the same three spellings the DenyAll loop above asks of, and for a
		// sharper reason: where the shield's own name is a symlink out of the grant (a
		// pyenv relocated to another disk), the resolved path escapes while the NAME the
		// host's $PATH walks through stays inside a writable tree, so the run replaces the
		// link with a directory of planted shims. That is the plant this refuses.
		loc := filepath.Join(s.fs.Resolve(filepath.Dir(a.Rule.Path)), filepath.Base(a.Rule.Path))
		if policy.CoversResolved(grant, a.Resolved) || policy.CoversResolved(grant, loc) || policy.CoversResolved(grant, a.Rule.Path) {
			return a.Rule, AboveWriteShield
		}
	}
	return denylist.Rule{}, Honored
}

// covers reports whether a shield at or above grant covers it, byte-exact or through a
// respelling the host's own mounts admit.
//
// The two folding cases the deny-list has to survive want opposite answers from a
// whole-path comparison, which is why this walks components instead. A whole-mount fold
// (vfat, exfat, ciopfs) folds EVERY component, so /home/U/.ssh/id_rsa is the shielded key
// and refusing it is the whole point. ext4's casefold is per-directory, so with +F on
// ~/.config alone, ~/.CONFIG/gh is a genuinely different path and refusing it would turn
// away a write grant that reaches no shielded store, in a sentence that offers no way out
// because a DenyWrite shield has no opt-in.
//
// So each component that differs is settled by asking the host, not by a rule about which
// component it is: the two spellings of the path SO FAR must be one file. That is the
// same question foldsCase asks, put to the pair actually in front of it, and it costs a
// syscall only where the spellings really differ - after the byte-exact test above has
// already declined, which on a host that folds nothing is where this stops.
//
// EqualFold and not a lowercased comparison, because what is being modelled is the
// filesystem's fold: ext4's casefold and vfat fold the whole Unicode range, where
// lowercasing the Kelvin sign and lowercasing "k" do not meet.
func (s Set) covers(shield, grant string) bool {
	if policy.CoversResolved(shield, grant) {
		return true
	}
	sp := strings.Split(filepath.Clean(shield), string(filepath.Separator))
	gp := strings.Split(filepath.Clean(grant), string(filepath.Separator))
	if len(gp) < len(sp) {
		return false
	}
	for i, name := range sp {
		if name == gp[i] {
			continue
		}
		if !strings.EqualFold(name, gp[i]) {
			return false
		}
		if !s.fs.SameFile(strings.Join(sp[:i+1], string(filepath.Separator)), strings.Join(gp[:i+1], string(filepath.Separator))) {
			return false
		}
	}
	return true
}

// foldsCase reports whether the directory holding path reaches path's content under a
// different spelling of its name - a case-insensitive mount (vfat, exfat, ciopfs) or a
// directory carrying ext4's casefold attribute. A shield is one byte-exact bind, so where
// this is true the store stays readable beside the shield under any other spelling.
//
// The flipped spelling is a DETECTOR, not an enumeration: a folding directory reaches the
// same inode under every mixture of cases, so there is no set of extra binds that would
// contain it. That is why the caller's only move is to refuse the grant.
//
// Only path's OWN base name is flipped, which bounds what this detects. The whole-mount
// cases fold every component, so the leaf is a sufficient detector for them. ext4's
// casefold is per-directory, and although a new subdirectory inherits it, a deliberate
// chattr -F on a child leaves a folding ancestor this answers false for: with +F on ~ but
// not on ~/.config, ~/.CONFIG/gh reaches the store beside a byte-exact shield at
// ~/.config/gh and no flip of gh says so. Widening it means walking every component
// between the grant and the shield, which the corpus cannot express until its Folding flag
// becomes per-component.
//
// A name with no letters cannot be respelled, so it answers false without a syscall. A
// shield that does not exist costs one and answers false too: it holds nothing to reach.
func (s Set) foldsCase(path string) bool {
	base := filepath.Base(path)
	flipped := strings.Map(func(r rune) rune {
		if unicode.IsUpper(r) {
			return unicode.ToLower(r)
		}
		return unicode.ToUpper(r)
	}, base)
	if flipped == base {
		return false
	}
	return s.fs.SameFile(path, filepath.Join(filepath.Dir(path), flipped))
}

// callerDenied reports whether a caller-supplied deny covers a resolved host path. Both
// sides are resolved because a caller names its store in its own spelling and the shield
// binds where that lands.
func (s Set) callerDenied(onHost string) bool {
	return slices.ContainsFunc(s.extraDeny, func(rp string) bool {
		return onHost == rp || policy.CoversResolved(rp, onHost)
	})
}

// OptIn is one shield a policy lifted by reading it: the grant's literal spelling, the
// store it actually binds, and what the lifted shield was hiding. The three travel
// together because a caller pairing separate slices by index reports one grant as
// reaching another's target the moment a symlink puts a store somewhere that sorts
// elsewhere.
type OptIn struct {
	Path   string
	OnHost string
	Holds  denylist.Holds
}

// OptIns finds the built-in shields a policy opts into by READING them - the
// caveat-emptor escape for a program that legitimately reads ~/.ssh with no source change.
// Deliberate scope:
//
//   - Reads only. A write to a credential store is the key-planting threat the deny-list
//     exists to stop, so passing anything but the policy's reads here defeats the point.
//   - A shield is opted into only when a read names its LITERAL deny-list path; a read
//     that merely resolves to the same place is a side-step the shield still refuses, so
//     the match is on the unresolved grant string.
//   - Built-ins only, never the caller's denies, and a built-in whose store a caller deny
//     also covers is not opt-in-able at all. Both sides match on a bare resolved path, so
//     without that exclusion an opt-in of the built-in would carry the caller's shield
//     away with it where the two land on the same host path.
//
// literalReads are the policy's own absolute, un-symlink-resolved read paths. Sorted by
// literal path, which is the order the reported opt-ins keep.
func (s Set) OptIns(literalReads []string) []OptIn {
	var out []OptIn
	for _, r := range s.builtin {
		if r.Deny != denylist.DenyAll || !slices.Contains(literalReads, r.Path) {
			continue
		}
		onHost := s.fs.Resolve(r.Path)
		if s.callerDenied(onHost) {
			continue
		}
		out = append(out, OptIn{Path: r.Path, OnHost: onHost, Holds: r.Holds})
	}
	slices.SortFunc(out, func(a, b OptIn) int { return cmp.Compare(a.Path, b.Path) })
	return out
}

// Targets are the opt-ins' resolved stores, the form Contains matches against.
func Targets(optIns []OptIn) []string {
	out := make([]string, 0, len(optIns))
	for _, o := range optIns {
		out = append(out, o.OnHost)
	}
	return out
}
