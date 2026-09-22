//go:build linux

package linux

import (
	"fmt"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/denylist"
)

// projectSandbox is a fake checkout at /w holding config project config entries and
// nested checkouts, with a resolve seam that counts its calls. Resolves are the unit
// here because every rule comparison goes through one: a count that grows with the
// product of findings and rules in force is the quadratic these tests exist to catch,
// and unlike wall time it does not move between runs.
func projectSandbox(config, nested int) (sandbox, *int) {
	sb := testSandbox("/w/.git/HEAD", "/w/src/x")
	resolves := new(int)
	resolve := sb.resolve
	sb.resolve = func(p string) string { *resolves++; return resolve(p) }
	var cfg []denylist.Rule
	for i := range config {
		cfg = append(cfg, denylist.Rule{Path: fmt.Sprintf("/w/p%d/.claude", i), Deny: denylist.DenyWrite, Dir: true})
	}
	var ns []string
	for i := range nested {
		ns = append(ns, fmt.Sprintf("/w/n%d", i))
	}
	sb.projectConfig = map[string][]denylist.Rule{"/w": cfg}
	sb.nestedCheckouts = map[string][]string{"/w": ns}
	sb.shieldCache = &shieldMemo{}
	sb.workspaceShieldCache = map[string][]denylist.Rule{}
	return sb, resolves
}

// resolvesOf counts the resolves call makes, after the shield set is already assembled -
// that walk is shields()'s cost, memoized per run, and not what these tests measure.
func resolvesOf(sb sandbox, resolves *int, call func()) int {
	shields(sb)
	*resolves = 0
	call()
	return *resolves
}

// Each project config entry a write grant holds is compared against every rule already in
// force. Resolving those rules again for each entry made one derivation cost entries x
// rules - 954k resolves at 500 entries, and several derivations per launch - so an added
// entry must cost a constant number of resolves, not one per rule in force.
func TestDerivedWorkspaceRulesCostIsLinearInFindings(t *testing.T) {
	derive := func(config int) int {
		sb, n := projectSandbox(config, 2)
		return resolvesOf(sb, n, func() { derivedWorkspaceRules(sb, "/w", shields(sb).Rules(), map[string]bool{}) })
	}
	small, large := derive(10), derive(100)
	if perEntry := float64(large-small) / 90; perEntry > 4 {
		t.Errorf("each added project config entry costs %.0f resolves (%d at 10 entries, %d at 100); want a constant, not one per rule in force", perEntry, small, large)
	}
}

// Most write grants hold no project config and no nested checkout, and a derivation for
// one of those must not pay for resolving every rule in force to compare against nothing.
func TestDerivedWorkspaceRulesWithNothingFoundResolvesNothing(t *testing.T) {
	sb, n := projectSandbox(0, 0)
	if got := resolvesOf(sb, n, func() { derivedWorkspaceRules(sb, "/w", shields(sb).Rules(), map[string]bool{}) }); got > 2 {
		t.Errorf("a grant with nothing below it cost %d resolves", got)
	}
}
