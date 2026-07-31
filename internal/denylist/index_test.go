package denylist

import (
	"path/filepath"
	"strings"
	"testing"
)

// auditRules is the rule set both the hunt and the audit build.
func auditRules() []Rule {
	rules := append(Home("/home/u"), Runtime("/run/user/1000", "/home/u")...)
	return append(rules, Workspace("/home/u/proj")...)
}

// The index compares rule paths literally where Covers compares them through
// policy.CoversResolved, so a rule spelled with a trailing separator or an uncleaned
// segment would be found by Covers and missed by the index - a shield that silently
// stops covering. Pin the property the index rests on rather than trusting it.
func TestRulePathsAreIndexable(t *testing.T) {
	var all []Rule
	all = append(all, auditRules()...)
	all = append(all, Runtime("/tmp/rt", "/home/u")...)
	for _, r := range all {
		if !filepath.IsAbs(r.Path) {
			t.Errorf("rule path %q is not absolute", r.Path)
		}
		if c := filepath.Clean(r.Path); c != r.Path {
			t.Errorf("rule path %q is not clean (Clean = %q)", r.Path, c)
		}
		if r.Path != "/" && strings.HasSuffix(r.Path, string(filepath.Separator)) {
			t.Errorf("rule path %q carries a trailing separator", r.Path)
		}
	}
}

// The index is an access-pattern change, not a second definition of coverage, so it must
// answer exactly what the linear Covers answers - rule, coverage and all. Covers is the
// reference here; this is what makes it safe to read the index in the credential hunt.
func TestIndexAgreesWithCovers(t *testing.T) {
	rules := auditRules()
	ix := NewIndex(rules)

	// Derived from the rules themselves rather than hand-listed, so a rule shape nobody
	// thought to write a case for is still covered. Hand-listing is what let the
	// file-rule divergence below go unnoticed: every uncleaned spelling in the first
	// version of this test happened to land on a DIRECTORY rule, which agreed.
	var paths []string
	for _, r := range rules {
		dir, base := filepath.Dir(r.Path), filepath.Base(r.Path)
		paths = append(paths,
			r.Path,
			r.Path+"/child",
			r.Path+"/a/b/c",
			dir,
			// The prefix-string trap, which an index keyed on components cannot fall
			// into but a careless one could.
			r.Path+"sibling",
			// Uncleaned spellings of this very rule's path. A DenyAll rule on a FILE is
			// reachable only through the exact match, so these are the shapes where a
			// raw equality and a cleaned enclosure test come apart.
			dir+"/./"+base,
			dir+"//"+base,
			r.Path+"/",
			dir+"/x/../"+base,
		)
	}
	paths = append(paths,
		"/home/u", "/home/u/", "/home/u/proj/src/main.go", "/home/u/.ssh/id_rsa",
		"/", "/tmp", "/run/user/1000/bus", "/var/run/docker.sock",
		"/home/u/proj/../.ssh/id_rsa", "/home/u//.ssh//id_rsa", "/home/u/./.gnupg",
		// Neither implementation covers a relative path; nothing pinned that before.
		"rel/path", ".", "..",
	)

	for _, p := range paths {
		wantRule, wantOK := Covers(p, rules)
		gotRule, gotOK := ix.Covers(p)
		if gotOK != wantOK {
			t.Errorf("Covers(%q): index covered = %v, linear = %v", p, gotOK, wantOK)
			continue
		}
		// Deny is the whole contract - it is all either caller reads, and Covers leaves
		// the choice among equally strict matches undefined, so comparing rule identity
		// here would pin an arbitrary tie-break neither side promises.
		if wantOK && gotRule.Deny != wantRule.Deny {
			t.Errorf("Covers(%q): index returned %+v, linear returned %+v", p, gotRule, wantRule)
		}
	}
}

// Two rules naming one path is a real shape (the /run shields are built by more than one
// helper), and the index must resolve it the way Covers does rather than by whichever
// one it happened to store last.
func TestIndexKeepsTheStrictestAtOnePath(t *testing.T) {
	for name, rules := range map[string][]Rule{
		"write first": {{Path: "/x", Deny: DenyWrite, Dir: true}, {Path: "/x", Deny: DenyAll, Dir: true}},
		"all first":   {{Path: "/x", Deny: DenyAll, Dir: true}, {Path: "/x", Deny: DenyWrite, Dir: true}},
	} {
		t.Run(name, func(t *testing.T) {
			for _, p := range []string{"/x", "/x/inside"} {
				got, ok := NewIndex(rules).Covers(p)
				if !ok || got.Deny != DenyAll {
					t.Errorf("Covers(%q) = %+v (%v), want the DenyAll rule", p, got, ok)
				}
			}
		})
	}
}
