//go:build linux

package linux

import (
	"fmt"
	"maps"
	"slices"
	"strings"
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

// denyArgs and createdShields both derive the run's shields, from compile and again from
// the launch preflight, with the same grants each time. After the first derivation the
// rest must be answered without redoing it.
func TestShieldRulesIsDerivedOncePerRun(t *testing.T) {
	sb, n := projectSandbox(10, 2)
	sb.shieldRulesCache = map[string][]denylist.Rule{}
	writes := []string{"/w", "/w/src"}
	shieldRules(sb, writes)
	if got := resolvesOf(sb, n, func() { shieldRules(sb, writes) }); got != 0 {
		t.Errorf("a second shieldRules with the same grants cost %d resolves", got)
	}
}

// The memo must not outlive what its answer was read from. checkShieldsCarvable derives
// the shields before prepareWriteDirs creates the granted directories, and a grant absent
// then is a checkout directory after: keyed on the grants alone, the memo would hand
// denyArgs the answer from before the mkdir, and the new directory's hooks and editor
// config would go unshielded under a write grant.
func TestShieldRulesMemoMissesAGrantCreatedSinceTheLastCall(t *testing.T) {
	files := map[string]bool{"/w/.git": true}
	sb := testSandbox()
	sb.exists = func(p string) bool { return files[p] }
	sb.isDir = func(p string) bool {
		return slices.ContainsFunc(slices.Collect(maps.Keys(files)), func(f string) bool { return strings.HasPrefix(f, p+"/") })
	}
	sb.shieldRulesCache = map[string][]denylist.Rule{}
	writes := []string{"/w/build"}
	if slices.Contains(rulePaths(shieldRules(sb, writes)), "/w/.vscode") {
		t.Fatal("an absent grant already derived workspace shields, so this cannot show the miss")
	}
	files["/w/build/out"] = true
	if !slices.Contains(rulePaths(shieldRules(sb, writes)), "/w/.vscode") {
		t.Error("after the grant's directory was created, its checkout's workspace shields are missing: the memo answered from before the mkdir")
	}
}

// probeCounts wraps a sandbox's existence and directory probes to count each by path. Each
// is a bounded host call - a goroutine and a timer in production - so the count is the
// cost, and a path probed twice within one pass is one probe too many.
func probeCounts(sb *sandbox) map[string]int {
	counts := map[string]int{}
	exists, isDir := sb.exists, sb.isDir
	sb.exists = func(p string) bool { counts["exists "+p]++; return exists(p) }
	sb.isDir = func(p string) bool { counts["isDir "+p]++; return isDir(p) }
	return counts
}

// denyArgs asks after a rule's path in the exposure pass, in shieldNeeded and in
// shieldMount. Nothing it does creates a path, so each probe has one answer for the call.
func TestDenyArgsProbesEachPathOnce(t *testing.T) {
	sb, _ := projectSandbox(100, 2)
	sb.shieldRulesCache = map[string][]denylist.Rule{}
	shieldRules(sb, []string{"/w"})
	counts := probeCounts(&sb)
	denyArgs(sb, []string{"/w", "/home/u"}, []string{"/w"}, nil)
	for probe, n := range counts {
		if n > 1 {
			t.Errorf("%s was asked %d times in one denyArgs", probe, n)
		}
	}
}

// A rule no grant reaches is skipped whatever the host says about its path, and deciding
// that needs no host at all - so a shield outside every grant must cost no probe.
func TestDenyArgsDoesNotProbeAShieldNoGrantReaches(t *testing.T) {
	sb, _ := projectSandbox(10, 0)
	sb.shieldRulesCache = map[string][]denylist.Rule{}
	shieldRules(sb, []string{"/w"})
	counts := probeCounts(&sb)
	denyArgs(sb, []string{"/w"}, []string{"/w"}, nil)
	var outside int
	for probe := range counts {
		if strings.Contains(probe, " /home/u") {
			outside++
		}
	}
	if outside > 0 {
		t.Errorf("denyArgs probed %d paths under the home, which no grant reaches", outside)
	}
}
