package denylist

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// insideDenyAllTree and underDenyAll are the linear screens denyAllTrees replaced, kept as
// the reference the index is held to - the same arrangement Index has with Covers.

func insideDenyAllTree(p string, rules []Rule) bool {
	for _, r := range rules {
		if r.Deny == DenyAll && r.Dir && strings.HasPrefix(p, r.Path+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func underDenyAll(p string, rules []Rule) bool {
	for _, r := range rules {
		if r.Deny != DenyAll {
			continue
		}
		if p == r.Path || (r.Dir && strings.HasPrefix(p, r.Path+string(filepath.Separator))) {
			return true
		}
	}
	return false
}

func TestDenyAllTreesAgreeWithTheLinearScreens(t *testing.T) {
	const home = "/home/u"
	rules := append(Home(home), Runtime("/run/user/1000", home)...)
	trees := newDenyAllTrees()
	trees.add(rules...)

	// Every rule's own path, a child of it, its parent, and a sibling sharing its bytes as
	// a prefix - the spelling a prefix test without the separator gets wrong.
	var paths []string
	for _, r := range rules {
		paths = append(paths, r.Path, r.Path+"/x", filepath.Dir(r.Path), r.Path+"2", r.Path+"2/x")
	}
	paths = append(paths, "/", home, "/srv/work")
	for _, p := range paths {
		if got, want := trees.covers(p), underDenyAll(p, rules); got != want {
			t.Errorf("covers(%q) = %v, the linear screen says %v", p, got, want)
		}
		if got, want := trees.encloses(p), insideDenyAllTree(p, rules); got != want {
			t.Errorf("encloses(%q) = %v, the linear screen says %v", p, got, want)
		}
	}
}

// Home's paths straddle the size Go keeps a concatenation on the stack for, so a screen
// that builds r.Path+"/" per rule allocates only once paths grow past it - invisible on a
// short fixture. The home here is long enough that every rule path is past it.
func TestDenyAllScreensDoNotAllocate(t *testing.T) {
	home := "/home/" + strings.Repeat("u", 40)
	trees := newDenyAllTrees()
	trees.add(Home(home)...)
	p := filepath.Join(home, "projects", "some-checkout", "src", "main.go")
	if n := testing.AllocsPerRun(100, func() { trees.covers(p) }); n != 0 {
		t.Errorf("covers allocated %v times per call", n)
	}
	if n := testing.AllocsPerRun(100, func() { trees.encloses(p) }); n != 0 {
		t.Errorf("encloses allocated %v times per call", n)
	}
}

// The XDG restatement derives an emitted rule from every default under .config, so the
// rules Relocated screens grow with the defaults it is handed, and a screen that scans
// both per rule is quadratic in the Home table - which grows every time a credential
// class is added. Timed rather than counted because the screen's work has no observable
// count short of instrumenting it: at ten times the defaults a linear pass costs about ten
// times as much and a quadratic one about a hundred, so the bound sits far from both.
func TestRelocatedScalesLinearlyInTheDefaults(t *testing.T) {
	if testing.Short() {
		t.Skip("times two sizes of Relocated")
	}
	for _, e := range relocationEnvs() {
		t.Setenv(e, "")
	}
	t.Setenv("XDG_CONFIG_HOME", "/xdg")
	anchors := []string{"/home/u"}
	defaults := func(n int) []Rule {
		out := make([]Rule, n)
		for i := range out {
			out[i] = Rule{Path: fmt.Sprintf("/home/u/.config/tool%d", i), Deny: DenyAll, Dir: true}
		}
		return out
	}
	// The minimum of several runs, which noise can only raise.
	fastest := func(d []Rule) time.Duration {
		best := time.Duration(1 << 62)
		for range 7 {
			start := time.Now()
			if got := Relocated(d, anchors); len(got) != len(d) {
				t.Fatalf("every default should be restated at the XDG base; got %d of %d", len(got), len(d))
			}
			best = min(best, time.Since(start))
		}
		return best
	}
	// Large enough that the small side is not dominated by map growth and GC pacing, which
	// at a few hundred defaults moved the ratio anywhere from 11x to 30x on an idle host.
	small, large := fastest(defaults(2000)), fastest(defaults(20000))
	t.Logf("2000 defaults %v, 20000 defaults %v", small, large)
	if ratio := float64(large) / float64(small); ratio > 30 {
		t.Errorf("ten times the defaults cost %.0fx the time (%v -> %v); a screen linear in them costs about 10x", ratio, small, large)
	}
}

// covered() has to see what Relocated has already emitted, not only the defaults: two file
// variables naming one target would otherwise both emit it, and the enclosure sweep at the
// end drops only rules INSIDE a DenyAll tree, never one equal to another.
func TestRelocatedScreensAgainstWhatItAlreadyEmitted(t *testing.T) {
	for _, e := range relocationEnvs() {
		t.Setenv(e, "")
	}
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/x/creds")
	t.Setenv("AWS_CONFIG_FILE", "/x/creds")
	var at []Rule
	for _, r := range Relocated(Home("/home/u"), []string{"/home/u"}) {
		if r.Path == "/x/creds" {
			at = append(at, r)
		}
	}
	if len(at) != 1 {
		t.Errorf("two variables naming one target emitted %d rules there, want 1: %+v", len(at), at)
	}
}

// BenchmarkRelocated measures the screen on the real Home table with an XDG base
// relocated, which is what makes the restatement emit a rule per .config default.
func BenchmarkRelocated(b *testing.B) {
	for _, e := range relocationEnvs() {
		b.Setenv(e, "")
	}
	b.Setenv("XDG_CONFIG_HOME", "/xdg/config")
	b.Setenv("XDG_DATA_HOME", "/xdg/data")
	anchors := []string{"/home/u"}
	defaults := Home("/home/u")
	b.ReportAllocs()
	for b.Loop() {
		Relocated(defaults, anchors)
	}
}
