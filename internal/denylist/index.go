package denylist

import (
	"path/filepath"
)

// Index answers the same question as Covers, prepared once for many paths.
//
// Covers is a linear scan: it tests every rule, so a caller asking about one path pays
// the whole rule set. That is the right shape for the parity audit, which asks once per
// candidate over a rule set it builds for that call. It is the wrong shape for the
// credential hunt, which walks a whole home and asks about every file in it - there the
// same few hundred rules are re-tested tens of thousands of times.
//
// So this is not a second definition of coverage, and must never become one: Covers
// stays the reference, and TestIndexAgreesWithCovers drives both over the same paths -
// including uncleaned spellings of every rule path, which is where the two last came
// apart.
//
// This only reorganizes the same rules for a different access pattern - instead of
// testing every rule against one path, it looks the path and its ancestors up directly,
// which costs the path's depth rather than the rule count.
//
// It rests on rule paths being clean, absolute and free of a trailing separator, since
// the lookups compare them literally where Covers compares them through
// policy.CoversResolved. Every rule this package builds is spelled that way: the literal
// tables are compile-time constants, and every rule whose spelling comes from outside -
// GNUPGHOME, KUBECONFIG, the HISTFILE family, ZDOTDIR, CARGO_HOME, MAILCAPS, the XDG
// bases - is cleaned at its emit site. TestRulePathsAreIndexable pins both populations.
type Index struct {
	// exact holds the strictest rule at each path, whatever its Dir flag: a rule always
	// covers its own path.
	exact map[string]Rule
	// dirs holds the strictest DIRECTORY rule at each path - the only kind that reaches
	// a descendant. A file rule is absent here, so it can never cover anything below it.
	dirs map[string]Rule
}

// NewIndex prepares rules for repeated Covers queries. The rules are read once and not
// retained, so a later change to the slice does not silently change what the index says.
func NewIndex(rules []Rule) *Index {
	ix := &Index{exact: make(map[string]Rule, len(rules)), dirs: make(map[string]Rule, len(rules))}
	for _, r := range rules {
		// Two rules can name one path (the /run shields are built by more than one
		// helper). Keeping the strictest is what Covers's "when several match, the
		// strictest wins" means at a single path.
		if cur, ok := ix.exact[r.Path]; !ok || stricter(r, cur) {
			ix.exact[r.Path] = r
		}
		if r.Dir {
			if cur, ok := ix.dirs[r.Path]; !ok || stricter(r, cur) {
				ix.dirs[r.Path] = r
			}
		}
	}
	return ix
}

// Covers finds the rule shielding path, returning it and true: an exact match or an
// enclosing directory rule, strictest wins. It answers what the package's Covers
// answers, down to the same undefined choice among equally strict matches - only the
// returned Deny and Dir are specified.
func (ix *Index) Covers(path string) (Rule, bool) {
	// Once per query. Covers cleans too, but pays for it once per rule in the scan it
	// runs; here the cost is paid before any lookup and the maps can compare literally.
	path = filepath.Clean(path)

	best, found := ix.exact[path]
	// Walk to the root rather than stopping at the first hit: a nearer rule is not
	// necessarily the strictest one, and Covers judges over all of them.
	for dir := path; ; {
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
		if r, ok := ix.dirs[dir]; ok && (!found || stricter(r, best)) {
			best, found = r, true
		}
	}
	return best, found
}
