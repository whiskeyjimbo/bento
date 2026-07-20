package audit

import (
	"testing"

	"github.com/whiskeyjimbo/bento-v2/internal/denylist"
)

func TestParseFirejailKeepsScopedShields(t *testing.T) {
	const content = `# a comment
blacklist ${HOME}/.ssh
read-only ${HOME}/.bashrc
blacklist ${HOME}/.*_history
blacklist ${RUNUSER}/bus
blacklist /sbin
blacklist ${PATH}/sudo
noblacklist ${HOME}/.config/foo
read-write ${HOME}/.local/share
include disable-common.local
rmenv GITHUB_TOKEN
`
	got := ParseFirejail(content, "/HOME", "/run/user/1000")

	want := []Candidate{
		{Path: "/HOME/.ssh", Deny: denylist.DenyAll},
		{Path: "/HOME/.bashrc", Deny: denylist.DenyWrite},
		{Path: "/HOME/.*_history", Deny: denylist.DenyAll, Glob: true},
		{Path: "/run/user/1000/bus", Deny: denylist.DenyAll},
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %d candidates, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].Path != w.Path || got[i].Deny != w.Deny || got[i].Glob != w.Glob {
			t.Errorf("candidate %d = %+v, want path=%q deny=%v glob=%v", i, got[i], w.Path, w.Deny, w.Glob)
		}
	}
}

func TestDiffCoverageAndClass(t *testing.T) {
	rules := []denylist.Rule{
		{Path: "/HOME/.ssh", Deny: denylist.DenyAll, Dir: true},
		{Path: "/HOME/.bashrc", Deny: denylist.DenyWrite},
		{Path: "/run", Deny: denylist.DenyAll, Dir: true},
	}
	candidates := []Candidate{
		{Path: "/HOME/.ssh/authorized_keys", Deny: denylist.DenyAll}, // covered by the .ssh dir shield
		{Path: "/run/user/1000/bus", Deny: denylist.DenyAll},        // covered by the /run dir shield
		{Path: "/HOME/.aws", Deny: denylist.DenyAll},                // missing entirely
		{Path: "/HOME/.bashrc", Deny: denylist.DenyAll},             // present but only DenyWrite -> weaker
	}

	gaps := Diff(candidates, rules)
	if len(gaps) != 2 {
		t.Fatalf("got %d gaps, want 2: %+v", len(gaps), gaps)
	}
	byPath := map[string]Gap{}
	for _, g := range gaps {
		byPath[g.Path] = g
	}
	if g, ok := byPath["/HOME/.aws"]; !ok || g.Weaker {
		t.Errorf(".aws should be a missing (not weaker) gap, got %+v ok=%v", g, ok)
	}
	if g, ok := byPath["/HOME/.bashrc"]; !ok || !g.Weaker {
		t.Errorf(".bashrc should be a weaker-class gap, got %+v ok=%v", g, ok)
	}
	if _, ok := byPath["/HOME/.ssh/authorized_keys"]; ok {
		t.Error("a file under a shielded dir must not be reported as a gap")
	}
}

func TestSplitByScopeUsesFirejailSections(t *testing.T) {
	gaps := []Gap{
		{Candidate: Candidate{Path: "/HOME/.aws", Section: "top secret"}},
		{Candidate: Candidate{Path: "/HOME/.config/autostart-scripts", Section: "X11 session autostart"}},
		{Candidate: Candidate{Path: "/HOME/.mozilla", Section: "gnome"}},                 // out: other-app
		{Candidate: Candidate{Path: "/HOME/.local/share/Trash", Section: "var"}},         // out
		{Candidate: Candidate{Path: "/HOME/.cargo/credentials", Section: "top secret"}},  // in
	}
	inScope, out := SplitByScope(gaps)
	if len(inScope) != 3 {
		t.Fatalf("in-scope = %d, want 3: %+v", len(inScope), inScope)
	}
	// Sorted by section then path: "X11 session autostart" < "top secret".
	if inScope[0].Section != "X11 session autostart" {
		t.Errorf("first in-scope section = %q, want X11 autostart", inScope[0].Section)
	}
	if out["gnome"] != 1 || out["var"] != 1 {
		t.Errorf("out-of-scope counts wrong: %+v", out)
	}
	if _, isIn := out["top secret"]; isIn {
		t.Error("a secret section must not be counted out-of-scope")
	}
}

// The parser and diff must run against bento's real shield list without panicking,
// and cover a path the list is known to shield (so a refactor that empties Home()
// does not silently make the audit pass by finding nothing to compare).
func TestDiffAgainstRealList(t *testing.T) {
	rules := append(denylist.Home("/HOME"), denylist.Runtime()...)
	c := []Candidate{{Path: "/HOME/.ssh/id_rsa", Deny: denylist.DenyAll}}
	if gaps := Diff(c, rules); len(gaps) != 0 {
		t.Errorf("~/.ssh/id_rsa should be covered by the real list, got gaps %+v", gaps)
	}
}
