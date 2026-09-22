//go:build linux

package linux

import (
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/policy"
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

// A finding is dropped when a directory shield already in force encloses it, and that
// test ran over every directory rule in force for every finding - findings x rules again,
// one level below the resolves the test above pins. Timed rather than counted because the
// comparisons go through no seam: at ten times both the rules and the findings a pass
// linear in each costs about ten times as much, and one over their product about a hundred.
func TestDerivedWorkspaceRulesScreenIsLinearInRulesAndFindings(t *testing.T) {
	if testing.Short() {
		t.Skip("times two sizes of the derivation")
	}
	derive := func(rules, config int) time.Duration {
		sb, _ := projectSandbox(config, 0)
		var above []denylist.Rule
		for i := range rules {
			above = append(above, denylist.Rule{Path: fmt.Sprintf("/elsewhere/s%d", i), Deny: denylist.DenyWrite, Dir: true})
		}
		best := time.Duration(1 << 62)
		for range 7 {
			start := time.Now()
			if got := derivedWorkspaceRules(sb, "/w", above, map[string]bool{}); len(got) != config {
				t.Fatalf("every project config entry should be shielded; got %d of %d", len(got), config)
			}
			best = min(best, time.Since(start))
		}
		return best
	}
	small, large := derive(600, 100), derive(6000, 1000)
	t.Logf("600 rules x 100 entries %v, 6000 x 1000 %v", small, large)
	if ratio := float64(large) / float64(small); ratio > 30 {
		t.Errorf("ten times the rules and findings cost %.0fx the time (%v -> %v); a screen linear in each costs about 10x", ratio, small, large)
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

// Every derivation starts from the assembled set's own rules, and the memo keeps what each
// derivation built. Appending onto the set's slice would write into capacity another
// memoized answer already shares, handing one grant set another's workspace shields.
func TestShieldRulesMemoKeepsEachAnswerApart(t *testing.T) {
	sb := testSandbox("/w/.git/HEAD", "/w/x", "/v/.git/HEAD", "/v/x")
	sb.shieldCache = &shieldMemo{}
	sb.workspaceShieldCache = map[string][]denylist.Rule{}
	sb.shieldRulesCache = map[string][]denylist.Rule{}
	want := slices.Clone(rulePaths(shieldRules(sb, []string{"/w"})))
	shieldRules(sb, []string{"/v"})
	for _, p := range rulePaths(shieldRules(sb, []string{"/w"})) {
		if !slices.Contains(want, p) {
			t.Fatalf("after deriving /v's shields, the memoized answer for /w holds %s", p)
		}
	}
}

// Grants that share a checkout share its workspace shields, so the redirect check has one
// set to test however many of them there are.
func TestRedirectCheckTestsACheckoutsShieldsOnce(t *testing.T) {
	sb := testSandbox("/w/.git", "/w/.git/HEAD", "/w/a/x", "/w/b/x")
	sb.shieldCache = &shieldMemo{}
	sb.workspaceShieldCache = map[string][]denylist.Rule{}
	resolves := new(int)
	resolve := sb.resolve
	sb.resolve = func(p string) string { *resolves++; return resolve(p) }
	check := func(writes ...string) int {
		return resolvesOf(sb, resolves, func() {
			if err := checkWorkspaceShieldNotRedirected(sb, writes); err != nil {
				t.Fatal(err)
			}
		})
	}
	one, three := check("/w"), check("/w", "/w/a", "/w/b")
	if three > one+4 {
		t.Errorf("three grants in one checkout cost %d resolves against %d for one: the checkout's shields were tested per grant", three, one)
	}
}

// compile derives the shields in denyArgs and then asks after each applied one again, in
// shieldChecks and shieldsApplied, beside the write grants' own checks. Nothing in compile
// creates a path, so each probe has one answer for the whole call.
func TestCompileProbesEachPathOnce(t *testing.T) {
	sb, _ := projectSandbox(20, 2)
	sb.shieldRulesCache = map[string][]denylist.Rule{}
	counts := probeCounts(&sb)
	if _, _, err := compile(&policy.Policy{Write: []string{"/w"}}, enforce.Process{}, sb); err != nil {
		t.Fatalf("compile: %v", err)
	}
	total := 0
	for _, n := range counts {
		total += n
	}
	t.Logf("%d probes for %d distinct", total, len(counts))
	for probe, n := range counts {
		if n > 1 {
			t.Errorf("%s was asked %d times in one compile", probe, n)
		}
	}
}

// checkShieldsCarvable walks up from each mount point it finds to the deepest ancestor
// that exists and asks whether that one is writable. Sibling mount points share those
// ancestors, and the check creates nothing, so each probe has one answer for the call.
func TestCheckShieldsCarvableProbesEachPathOnce(t *testing.T) {
	sb, _ := projectSandbox(20, 2)
	// The walk up stops at the first ancestor that exists, which the fake's leaf-only
	// entries never name.
	exists := sb.exists
	sb.exists = func(p string) bool { return p == "/w" || exists(p) }
	sb.shieldRulesCache = map[string][]denylist.Rule{}
	counts := probeCounts(&sb)
	writable := sb.writable
	sb.writable = func(p string) bool { counts["writable "+p]++; return writable(p) }
	if err := checkShieldsCarvable(sb, []string{"/w"}, []string{"/w"}, nil); err != nil {
		t.Fatalf("checkShieldsCarvable: %v", err)
	}
	total := 0
	for _, n := range counts {
		total += n
	}
	t.Logf("%d probes for %d distinct", total, len(counts))
	for probe, n := range counts {
		if n > 1 {
			t.Errorf("%s was asked %d times in one checkShieldsCarvable", probe, n)
		}
	}
}

// createdShields is also called on its own, after the launch has created the granted
// directories, and its walk up from each absent mount point crosses the parents its
// siblings cross. Nothing it does creates a path, so each probe has one answer for the call.
func TestCreatedShieldsProbesEachPathOnce(t *testing.T) {
	sb, _ := projectSandbox(20, 2)
	sb.shieldRulesCache = map[string][]denylist.Rule{}
	counts := probeCounts(&sb)
	createdShields(sb, []string{"/w"}, []string{"/w"}, nil)
	total := 0
	for _, n := range counts {
		total += n
	}
	t.Logf("%d probes for %d distinct", total, len(counts))
	for probe, n := range counts {
		if n > 1 {
			t.Errorf("%s was asked %d times in one createdShields", probe, n)
		}
	}
}

// compile memoizes the existence and directory probes for its whole call, which holds only
// while nothing it reaches creates a host path. The shields it derives name mount points
// that are absent on the host until bwrap makes them, so a derivation that created one
// early would turn a memoized "absent" into a wrong answer - and the launch does create
// such paths, in the stages before compile, which is why the memo stops at its boundary.
func TestCompileCreatesNoHostPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", filepath.Join(dir, "home"))
	checkout := filepath.Join(dir, "checkout")
	for _, d := range []string{filepath.Join(dir, "home"), filepath.Join(checkout, ".git"), filepath.Join(checkout, "sub", ".git")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	entrypoint := filepath.Join(dir, "run.sh")
	if err := os.WriteFile(entrypoint, []byte("true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: entrypoint, Write: []string{checkout}}
	sb, cleanup, err := newSandbox(p, "bento-placeholder", false, nil, nil, true)
	if err != nil {
		t.Fatalf("newSandbox: %v", err)
	}
	defer cleanup()
	tree := func() []string {
		var paths []string
		if err := filepath.WalkDir(dir, func(path string, _ fs.DirEntry, err error) error {
			paths = append(paths, path)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return paths
	}
	before := tree()
	compileOrFail(t, p, sb)
	if after := tree(); !slices.Equal(before, after) {
		t.Errorf("compile changed the host tree:\nbefore %q\nafter  %q", before, after)
	}
}
