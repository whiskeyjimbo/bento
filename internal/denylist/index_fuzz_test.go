package denylist

import (
	"path/filepath"
	"strings"
	"testing"
)

// parseFuzzRules reads a generated rule set: one rule per line, "<deny><dir><path>", where
// deny is any byte (even/odd picks DenyAll or DenyWrite) and dir is 'd' for a directory
// rule.
//
// Rule paths are cleaned and required absolute, and a line naming an unclean or relative
// path is dropped rather than repaired. That is not the fuzzer being made polite: the
// index compares rule paths literally where Covers goes through policy.CoversResolved, and
// the package guarantees every rule it builds is clean and absolute - TestRulePathsAreIndexable
// pins that separately. Feeding an unclean rule path here would report a divergence the
// callers cannot reach and bury the ones they can. The QUERY path is left untouched.
func parseFuzzRules(spec string) []Rule {
	var rules []Rule
	for _, line := range strings.Split(spec, "\n") {
		if len(line) < 3 {
			continue
		}
		p := line[2:]
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			continue
		}
		deny := DenyAll
		if line[0]%2 == 1 {
			deny = DenyWrite
		}
		rules = append(rules, Rule{Path: p, Deny: deny, Dir: line[1] == 'd'})
	}
	return rules
}

// Covers' own doc says it shares the stricter tie-break with Index "so the two cannot
// drift". That is a differential oracle stated in prose, and TestIndexAgreesWithCovers
// mechanizes it only over the shapes someone thought to write down - which is how the
// file-rule divergence it now pins got in.
//
// Only the specified half is compared. Covers leaves Source unspecified (a path can be
// reached by a default rule and a relocated one at once) and leaves the choice among two
// equally strict nested directory rules undefined, so rule identity is not an oracle.
// Deny and Dir are: the Dir tie-break among equally strict matches is promised, and the
// parity audit reads it to decide whether a shield was narrowed to a single file.
func FuzzCoversAgreesWithIndex(f *testing.F) {
	// The shapes the two last came apart on, and the state-grid cells for this area: a
	// DenyAll rule on a FILE is reachable only through the exact match, so an uncleaned
	// query is where a raw equality and a cleaned enclosure test diverge; a file rule and
	// a directory rule at one path are equally strict and only the tie-break decides; two
	// rules at one path is a real shape the /run shields produce; and a nearer rule is not
	// necessarily the strictest, so the index must walk to the root rather than stop.
	f.Add("0f/x/credentials.toml", "/x/./credentials.toml")
	f.Add("0f/x/credentials.toml", "/x//credentials.toml")
	f.Add("0f/x\n0d/x", "/x")
	f.Add("0d/x\n0f/x", "/x")
	f.Add("1d/x\n0d/x", "/x/inside")
	f.Add("0d/x\n1d/x/y", "/x/y/z")
	f.Add("1d/x\n0d/x/y", "/x/y/z")
	f.Add("0f/x", "/xsibling")
	f.Add("0d/x", "/x/")
	f.Add("0d/", "/anything")
	f.Add("0d/x", "rel/path")
	f.Add("", "/x")
	f.Fuzz(func(t *testing.T, spec, query string) {
		rules := parseFuzzRules(spec)
		wantRule, wantOK := Covers(query, rules)
		gotRule, gotOK := NewIndex(rules).Covers(query)
		if gotOK != wantOK {
			t.Fatalf("Covers(%q) over %+v: index covered = %v, linear = %v", query, rules, gotOK, wantOK)
		}
		if wantOK && (gotRule.Deny != wantRule.Deny || gotRule.Dir != wantRule.Dir) {
			t.Fatalf("Covers(%q) over %+v: index returned %+v, linear returned %+v", query, rules, gotRule, wantRule)
		}
	})
}
