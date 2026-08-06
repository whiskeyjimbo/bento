package shield

import (
	"path/filepath"
	"slices"

	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/policy"
)

// maxLinkDepth bounds the symlinked-credential walk. It is the depth the backend's
// git-directory scan uses, kept identical because the two walk the same host trees and a
// shallower bound here would silently unshield a store the enforcer expands.
const maxLinkDepth = 64

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
	// applied is the set as the enforcer really mounts it. Every verdict derives from
	// this, so a rule the enforcer drops can never refuse a grant and blame a shield that
	// was never there.
	applied []Applied
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
	s := Set{fs: fs, homes: make([]string, len(homes))}
	for i, h := range homes {
		s.homes[i] = fs.Resolve(h)
	}

	var base []denylist.Rule
	for _, h := range homes {
		base = append(base, denylist.Home(h)...)
	}
	// Once over the whole anchor set, not once per anchor: an env relocation names one
	// absolute path, so a per-anchor call would emit it twice and stamp the copies with
	// whichever anchor's Source came out first.
	base = append(base, denylist.Relocated(base, homes)...)
	base = append(base, denylist.Runtime(runtimeDir, homes...)...)

	// The symlink expansion is derived from the built-ins alone, and it is the built-ins
	// a read can opt into, so the two sets are the same set. A shield a policy cannot name
	// is one it can only be refused over, with no remedy in the sentence.
	s.builtin = append(base, s.credentialLinks(base)...)

	for _, r := range extraDeny {
		s.extraDeny = append(s.extraDeny, fs.Resolve(r.Path))
	}
	for _, r := range append(append([]denylist.Rule{}, s.builtin...), extraDeny...) {
		if rp, ok := s.target(r.Path); ok {
			s.applied = append(s.applied, Applied{Rule: r, Resolved: rp})
		}
	}
	return s
}

// Applied is the set as the enforcer mounts it, for the callers that have to emit or
// clean up the same shields they refuse grants over.
func (s Set) Shields() []Applied { return s.applied }

// target resolves a deny-list path to where its shield would mount and reports whether it
// is applied at all. Two resolutions leave nothing to shield:
//
//   - the root, which a deny dotfile symlinked to "/" reaches: shielding it would swallow
//     the whole sandbox;
//   - a path that moved onto a home or an ancestor of one, where the shield would hide
//     everything the policy granted rather than one store. Only where resolution MOVED
//     it: denylist.Shieldable already guarded what it chose to emit and deliberately
//     exempts a store that IS an anchor ($HOME=/home/u/.aws beside a passwd home of
//     /home/u), which a blanket test here would silently unshield.
func (s Set) target(literal string) (string, bool) {
	rp := s.fs.Resolve(literal)
	if rp == "/" {
		return "", false
	}
	if rp != literal && !denylist.Shieldable(rp, s.homes) {
		return "", false
	}
	return rp, true
}

// credentialLinks is the symlinked-credential expansion: where a credential store's entry
// is a link into a dotfile farm (stow, chezmoi and home-manager all produce these), the
// target is shielded at its own path too, so the store cannot be reached by naming where
// it points.
func (s Set) credentialLinks(base []denylist.Rule) []denylist.Rule {
	var out []denylist.Rule
	for _, r := range base {
		if r.Deny != denylist.DenyAll || !r.Dir {
			continue
		}
		switch r.Holds {
		case denylist.HoldsCredentials, denylist.HoldsHistory, denylist.HoldsPersistence:
			out = append(out, s.linksUnder(r, r.Path, 0)...)
		}
	}
	return out
}

func (s Set) linksUnder(r denylist.Rule, dir string, depth int) []denylist.Rule {
	if depth > maxLinkDepth || !s.fs.IsDir(dir) {
		return nil
	}
	if filepath.Base(dir) == ".git" {
		return nil
	}
	names, links, ok := s.fs.ListDir(dir)
	if !ok {
		// Nothing to enumerate and nothing exposed either: the whole directory is hidden
		// by the DenyAll shield this is expanding.
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
