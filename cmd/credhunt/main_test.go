package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/credhunt"
)

// XDG_CACHE_HOME is the only decision machineStores makes; the rest is a fixed list
// joined onto home, and restating it here would assert nothing the code does not say.
// A relative value is refused because these are compared against absolute walk paths -
// a relative entry would prune nothing and look like it had.
func TestMachineStoresTakesOnlyAnAbsoluteXDGCacheHome(t *testing.T) {
	const home = "/home/u"

	t.Setenv("XDG_CACHE_HOME", "/var/cache/u")
	if got := machineStores(home); !slices.Contains(got, "/var/cache/u") {
		t.Errorf("machineStores = %v, want an absolute XDG_CACHE_HOME pruned", got)
	}

	t.Setenv("XDG_CACHE_HOME", "relative/cache")
	for _, s := range machineStores(home) {
		if strings.Contains(s, "relative/cache") {
			t.Errorf("machineStores kept relative XDG_CACHE_HOME %q; it can never match a walk path, so it prunes nothing", s)
		}
	}
}

// Nothing is dropped: every finding is either listed as a lead or counted inside a dense
// tree. That is summarize's whole contract - a fold that loses findings is a silent
// suppression list, which is what this tool exists not to be.
func TestSummarizeAccountsForEveryFinding(t *testing.T) {
	const home = "/home/u"
	var found []credhunt.Finding
	for i := range denseTreeLimit + 5 {
		found = append(found, at(home+"/.local/share/tool/f"+strconv.Itoa(i)))
	}
	found = append(found, at(home+"/.netrc"), at(home+"/.aws/credentials"))

	leads, dense := summarize(home, found)

	total := len(leads)
	for _, d := range dense {
		total += d.count
	}
	if total != len(found) {
		t.Errorf("leads(%d) + dense counts(%d total) = %d, want %d; summarize must fold findings, never drop them", len(leads), total-len(leads), total, len(found))
	}
	if len(dense) != 1 || dense[0].count != denseTreeLimit+5 {
		t.Errorf("dense = %v, want one tree of %d", dense, denseTreeLimit+5)
	}
}

// A file directly at the home root is its own group, so it is always listed however many
// siblings it has. This pins the grouping, which is what delivers that: a prefixOf that
// took the dirname of a root file would put them all under one prefix and fold away the
// dotfiles and editor leavings this tool is most for.
func TestSummarizeNeverFoldsTheHomeRoot(t *testing.T) {
	const home = "/home/u"
	var found []credhunt.Finding
	for i := range denseTreeLimit + 5 {
		found = append(found, at(home+"/.rc"+strconv.Itoa(i)))
	}

	leads, dense := summarize(home, found)

	if len(dense) != 0 {
		t.Errorf("dense = %v, want none; the home root must not be folded", dense)
	}
	if len(leads) != len(found) {
		t.Errorf("leads = %d, want all %d listed", len(leads), len(found))
	}
}

// The limit is inclusive: a subtree at exactly denseTreeLimit still lists path by path,
// and one hit more folds. Either side of that boundary is where a reader stops seeing
// the paths, so it is the part worth pinning.
func TestSummarizeFoldsOnlyPastTheLimit(t *testing.T) {
	const home = "/home/u"
	for _, tc := range []struct {
		n         int
		wantDense bool
	}{{denseTreeLimit, false}, {denseTreeLimit + 1, true}} {
		var found []credhunt.Finding
		for i := range tc.n {
			found = append(found, at(home+"/.local/share/tool/f"+strconv.Itoa(i)))
		}
		leads, dense := summarize(home, found)
		if gotDense := len(dense) > 0; gotDense != tc.wantDense {
			t.Errorf("%d hits under one prefix: folded = %v, want %v (leads %d)", tc.n, gotDense, tc.wantDense, len(leads))
		}
	}
}

// run always reports 0, findings or none. The exit status is the contract that keeps this
// out of `make check`: a nonzero on leads is what would let somebody gate on a per-host
// shape scan, and the package doc says why that must not happen.
func TestRunReportsZeroWhetherOrNotItFindsAnything(t *testing.T) {
	empty := t.TempDir()
	withLead := t.TempDir()
	// 0600 plus a token-shaped assignment under a name no bento shield covers: the
	// several-signal lead the hunt is for.
	if err := os.WriteFile(filepath.Join(withLead, ".toolrc"), []byte("token = abcdef0123456789abcdef0123456789abcdef01\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out strings.Builder
	if code := run(&out, &out, []string{empty, withLead}); code != 0 {
		t.Errorf("run = %d, want 0; findings are leads to read, never a build verdict", code)
	}
	if !strings.Contains(out.String(), ".toolrc") {
		t.Errorf("the lead is missing from the report:\n%s", out.String())
	}
}

// A home that cannot be walked yields zero findings, which reads as a clean home - the
// silent wrong answer this tool exists to avoid. It is the one condition worth failing on.
func TestRunFailsOnAHomeItCannotWalk(t *testing.T) {
	var out strings.Builder
	if code := run(&out, &out, []string{filepath.Join(t.TempDir(), "absent")}); code == 0 {
		t.Error("run = 0 over an unwalkable home; zero findings there would read as a clean home")
	}
}

func at(path string) credhunt.Finding {
	return credhunt.Finding{Path: path, Mode: fs.FileMode(0o600), Signals: []string{credhunt.SignalPrivateMode}}
}

// Every path in the report is a name off the walked tree, and a filename carries whatever
// bytes whoever wrote it chose. This output is what a human reads in a terminal to decide
// whether a lead is a credential, so a name holding an escape sequence must arrive quoted
// rather than able to rewrite the lines around itself.
func TestRunEscapesHostileFilenames(t *testing.T) {
	home := t.TempDir()
	hostile := "\x1b[2K\rinnocent.txt"
	if err := os.WriteFile(filepath.Join(home, hostile), []byte("token = abcdef0123456789abcdef0123456789abcdef01\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out strings.Builder
	if code := run(&out, &out, []string{home}); code != 0 {
		t.Fatalf("run = %d, want 0", code)
	}
	if strings.ContainsRune(out.String(), 0x1b) {
		t.Errorf("a raw escape byte reached the report; the name can rewrite the terminal lines around it:\n%q", out.String())
	}
	if !strings.Contains(out.String(), `\x1b`) {
		t.Errorf("the hostile name is missing from the report entirely:\n%s", out.String())
	}
}
