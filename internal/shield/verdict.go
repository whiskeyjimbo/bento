package shield

import (
	"cmp"
	"path/filepath"
	"slices"

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
		if policy.CoversResolved(a.Resolved, grant) && !slices.Contains(optIns, a.Resolved) {
			if s.callerDenied(a.Resolved) {
				return a.Rule, InsideCallerShield
			}
			return a.Rule, InsideShield
		}
	}
	if kind == Read {
		return denylist.Rule{}, Honored
	}

	for _, a := range s.applied {
		if a.Rule.Deny == denylist.DenyWrite && policy.CoversResolved(a.Resolved, grant) {
			return a.Rule, UnderWriteShield
		}
	}
	for _, r := range workspace {
		if r.Deny == denylist.DenyWrite && policy.CoversResolved(s.fs.Resolve(r.Path), grant) {
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
	return denylist.Rule{}, Honored
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
