package shield

import (
	"path/filepath"
	"slices"

	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/policy"
)

// maxWalkDepth bounds how deep the symlinked-credential expansion descends into real
// subdirectories. It bounds the walk, not any chain of links: a link's target is shielded
// at its own path and never re-walked, so no link ever costs depth. It is the depth the
// backend's git-directory scan uses, kept identical because the two walk the same host
// trees at the same shape and a shallower bound here would silently unshield a store the
// enforcer expands.
const maxWalkDepth = 64

// Set is the always-on shields for one run: assembled from the deny-list, expanded
// through the symlinks a credential store points out along, resolved to where each would
// really mount, and with the rules that mount nowhere dropped.
//
// Assembled once and asked many times. Every caller tests many grants against one set,
// and the expansion walks the credential stores on disk, so an assembly per question is
// the difference between a validate that runs in milliseconds and one that does not.
type Set struct {
	fs FS
	// homes are the run's anchors as the host's symlinks leave them, the form a moved
	// shield is compared against.
	homes []string
	// atAnchor are the paths of the deny-list's own anchor-relative rules that stand on
	// one of the run's anchors, keyed by the path as the deny-list spelled it. It is a
	// provenance record, not a set of places: a relocation resolving onto the same anchor
	// must NOT inherit the exemption those rules get - see nestedAnchor.
	atAnchor map[string]bool
	// applied is the set as the enforcer really mounts it. Every verdict derives from
	// this, so a rule the enforcer drops can never refuse a grant and blame a shield that
	// was never there.
	applied []Applied
	// rules is the whole assembled set before the drops, which is what the enforcer emits
	// mounts from and what the alias scan walks for credential roots.
	rules []denylist.Rule
	// builtin is the same set BEFORE the drops and before the caller's own denies: what a
	// read may opt into. Kept separately because the two questions have different answers
	// - an opt-in names a rule by the path the deny-list built, while a refusal is decided
	// at the path that rule lands on.
	builtin []denylist.Rule
	// extraDeny are the caller's denies, resolved. A grant inside one is refused in its
	// own sentence and can never be opted into: it belongs to the trust domain of whoever
	// launched the run, which the manifest being run must not be able to talk its way out
	// of.
	extraDeny []string
}

// Applied is a rule paired with where its shield actually mounts. The rule is kept whole
// because a refusal names the path the deny-list built (~/.gnupg), not the target the
// host's symlinks lead to.
type Applied struct {
	Rule     denylist.Rule
	Resolved string
}

// Assemble builds the run's shield set. homes are the deny-list's anchors as configured
// ($HOME and the passwd entry, which disagree legitimately under containers, sudo and
// nix), runtimeDir the host's XDG runtime directory, and extraDeny the caller-supplied
// shields an embedding program adds on top - empty for an ordinary run.
func Assemble(fs FS, homes []string, runtimeDir string, extraDeny []denylist.Rule) Set {
	s := Set{fs: fs, homes: make([]string, len(homes)), atAnchor: map[string]bool{}}
	for i, h := range homes {
		s.homes[i] = fs.Resolve(h)
	}

	var base []denylist.Rule
	for _, h := range homes {
		base = append(base, denylist.Home(h)...)
	}
	// Recorded over the anchor-relative pass ALONE, before any relocation exists to be
	// mistaken for one. The two spellings of a nested anchor need not match - a passwd home
	// of /home/u derives its .aws store as /home/u/.aws while the run configures that same
	// store as /var/home/u/.aws - so membership is decided where they do agree, at the
	// resolved path, and remembered against the spelling the rule carries.
	for _, r := range base {
		if slices.Contains(s.homes, fs.Resolve(r.Path)) {
			s.atAnchor[r.Path] = true
		}
	}
	// Once over the whole anchor set, not once per anchor: an env relocation names one
	// absolute path, so a per-anchor call would emit it twice and stamp the copies with
	// whichever anchor's Source came out first.
	base = append(base, denylist.Relocated(base, homes)...)
	base = append(base, denylist.Runtime(runtimeDir, homes...)...)

	// The symlink expansion is derived from the built-ins alone, and it is the built-ins
	// a read can opt into, so the two sets are the same set. A shield a policy cannot name
	// is one it can only be refused over, with no remedy in the sentence.
	links := s.credentialLinks(base)
	s.builtin = append(slices.Clone(base), links...)

	for _, r := range extraDeny {
		s.extraDeny = append(s.extraDeny, fs.Resolve(r.Path))
	}
	// Caller denies sit between the built-ins and the expansion, which is the order the
	// enforcer assembles them in. It decides blame, not outcome: where a caller deny and
	// an expanded link both cover a grant, the refusal names the caller's own path and
	// says the shield has no opt-in, rather than naming a dotfile the caller never
	// mentioned.
	s.rules = append(append(slices.Clone(base), extraDeny...), links...)
	s.applied = s.Mount(s.rules)
	return s
}

// Shields is the set as the enforcer mounts it, for the callers that have to emit or
// clean up the same shields they refuse grants over.
func (s Set) Shields() []Applied { return s.applied }

// Rules is the whole assembled set before the drops: the built-ins, the caller's denies,
// and the symlink expansion, in the order the enforcer applies them.
func (s Set) Rules() []denylist.Rule { return s.rules }

// Builtin is the assembled rules before the drops and before the caller's own denies:
// what a read may opt into, and what a report naming relocated shields describes.
func (s Set) Builtin() []denylist.Rule { return s.builtin }

// Mount resolves a rule list the same way the assembled set was resolved, dropping the
// rules that would mount nowhere. It exists for the one caller that shields more than the
// always-on set - the enforcer, which adds a workspace's own execution surface per write
// grant - so the rules it really mounts and the rules it refuses grants over cannot be
// resolved by two different pieces of code.
func (s Set) Mount(rules []denylist.Rule) []Applied {
	var out []Applied
	for _, r := range rules {
		if rp, ok := s.target(r.Path); ok {
			out = append(out, Applied{Rule: r, Resolved: rp})
		}
	}
	return out
}

// target resolves a deny-list path to where its shield would mount and reports whether it
// is applied at all. Two resolutions leave nothing to shield:
//
//   - the root, which a deny dotfile symlinked to "/" reaches: shielding it would swallow
//     the whole sandbox;
//   - a path that lands on a home or an ancestor of one, where the shield would hide
//     everything the policy granted rather than one store.
//
// The second test runs at every path, not only the ones resolution moved. Gating it on
// having moved deferred to denylist.Shieldable's emit-time guard, which does not compose
// with this one: that guard compares the anchors AS CONFIGURED while s.homes are resolved,
// so on a host spelling a home two ways (/home -> /var/home) a relocation naming the other
// spelling passes there, moves nowhere here, and lands a DenyAll on the whole home. Some
// of what it defers to never ran at all - denylist.Home is anchor-relative and calls
// Shieldable on nothing.
//
// nestedAnchor is what the deferral was really protecting: an anchor inside another anchor
// ($HOME=/home/u/.aws beside a passwd home of /home/u). Shieldable refuses it for equalling
// an anchor, but the outer anchor's tree stays reachable, so it is not the swallow-
// everything case - and unshielding it would open the credential store itself.
func (s Set) target(literal string) (string, bool) {
	rp := s.fs.Resolve(literal)
	if rp == "/" {
		return "", false
	}
	if !denylist.Shieldable(rp, s.homes) && !s.nestedAnchor(literal, rp) {
		return "", false
	}
	return rp, true
}

// nestedAnchor reports whether a rule stands on an anchor that sits strictly inside another
// anchor. Keyed on PROVENANCE, not on where the path resolves: only the deny-list's own
// anchor-relative rule gets the exemption. A relocation variable pointed at a symlink
// leading to that same anchor resolves identically and is the whole-home DenyAll this guard
// exists to drop - and its own spelling is nobody's anchor, so denylist.Relocated's
// emit-time guard never saw it either. Spelling cannot separate the two; where the rule came
// from can.
func (s Set) nestedAnchor(literal, rp string) bool {
	return s.atAnchor[literal] && slices.ContainsFunc(s.homes, func(h string) bool {
		return h != rp && policy.CoversResolved(h, rp)
	})
}

// credentialLinks is the symlinked-credential expansion: where a credential store's entry
// is a link into a dotfile farm IN THE HOME (stow, chezmoi and yadm all produce these),
// the target is shielded at its own path too, so the store cannot be reached by naming
// where it points.
//
// home-manager is EXCLUDED, not covered: its links point into /nix/store, outside every
// anchor by construction, so linksUnder's own skip takes every one of them. That is the
// right answer for a different reason than the skip's - a /nix/store path is world-readable
// and immutable, so shielding the target buys nothing the store's own DenyAll does not
// already have - but a reader auditing coverage on a nix host must not read it as handled.
func (s Set) credentialLinks(base []denylist.Rule) []denylist.Rule {
	var out []denylist.Rule
	for _, r := range base {
		if r.Deny != denylist.DenyAll || !r.Dir {
			continue
		}
		switch r.Holds {
		case denylist.HoldsCredentials, denylist.HoldsHistory, denylist.HoldsPersistence:
			out = append(out, s.linksUnder(r, r.Path, 0)...)
		case denylist.HoldsUnknown, denylist.HoldsPrivateData, denylist.HoldsServices:
			// No second spelling to chase: these buckets are directories of data and
			// sockets rather than the credential stores tools symlink into.
		}
	}
	return out
}

// linksUnder walks a shielded store for entries that are links out of it. Every real
// subdirectory is descended into, .git included: pass(1)'s store is a git repository by
// design, so its object store is the credential history under a second name and a link
// relocating it out of the store is exactly what this expansion exists to cover. The cost
// is walking the fanout directories, which hold no links and are bounded and setup-time -
// the same trade the backend's git-directory scan already makes.
func (s Set) linksUnder(r denylist.Rule, dir string, depth int) []denylist.Rule {
	if depth > maxWalkDepth || !s.fs.IsDir(dir) {
		return nil
	}
	names, links, ok := s.fs.ListDir(dir)
	if !ok && len(names)+len(links) == 0 {
		// Nothing came back, and unlike the backend's git walk there is no rule that fails
		// closed here. What an unreadable store exposes is its links' TARGETS, which live
		// OUTSIDE it - a farm path a read grant reaches - and they cannot be named without
		// reading the directory. Shielding the directory itself adds nothing: the DenyAll
		// being expanded already hides it. A partial read is not this case, and the
		// entries it did hand back are expanded below.
		return nil
	}
	var out []denylist.Rule
	for _, name := range links {
		p := filepath.Join(dir, name)
		rp, ok := s.target(p)
		if !ok || rp == p || !underAny(rp, s.homes) {
			// A target outside every home is not a dotfile farm. Stow, chezmoi and yadm all
			// keep theirs in the home by construction, while a link out of a store to
			// somewhere else is as often an ordinary file a grant already names - and
			// shielding one of those refuses a policy that has nothing to do with a
			// credential. Name the target in a read grant to reach it; it is shielded at
			// its own path and warns.
			continue
		}
		out = append(out, denylist.Rule{Path: rp, Deny: denylist.DenyAll, Dir: s.fs.IsDir(rp), Holds: r.Holds, Source: r.Source})
	}
	for _, name := range names {
		out = append(out, s.linksUnder(r, filepath.Join(dir, name), depth+1)...)
	}
	return out
}

func underAny(path string, roots []string) bool {
	return slices.ContainsFunc(roots, func(r string) bool { return policy.CoversResolved(r, path) })
}
