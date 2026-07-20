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

// A commented-out directive or a mid-section note between a section header and its
// entries must not be mistaken for the section. firejail's X11-autostart block carries
// both, and the old last-comment-wins attribution pulled the entries under a disabled
// "# blacklist ${HOME}/.xpra" - out of bento's exec threat model - so .xinitrc and
// friends were only counted, never gated. The header, not the last comment, governs;
// and an intra-section blank line must not orphan the entries after it. Built from
// firejail syntax inline (not a vendored profile) so it exercises the real parser.
func TestParseFirejailAttributesSectionToHeaderNotLastComment(t *testing.T) {
	const content = `# Top secret
blacklist ${HOME}/.ssh

blacklist ${HOME}/.gnupg

# X11 session autostart
blacklist ${HOME}/.config/autostart
# disabled upstream, breaks nested X:
# blacklist ${HOME}/.xpra
#?HAS_X11: blacklist ${HOME}/.ICEauthority
blacklist ${HOME}/.xinitrc
blacklist ${HOME}/.config/i3
`
	byPath := map[string]Candidate{}
	for _, c := range ParseFirejail(content, "/HOME", "/run/user/1000") {
		byPath[c.Path] = c
	}

	for _, p := range []string{"/HOME/.config/autostart", "/HOME/.xinitrc", "/HOME/.config/i3"} {
		c, ok := byPath[p]
		if !ok {
			t.Fatalf("%s was not parsed: %+v", p, byPath)
		}
		if c.Section != "X11 session autostart" {
			t.Errorf("%s attributed to section %q, want the header \"X11 session autostart\"", p, c.Section)
		}
		if !inScopeSection(c.Section) {
			t.Errorf("%s (section %q) must classify in-scope - it is a host-exec vector", p, c.Section)
		}
	}
	// The intra-section blank between .ssh and .gnupg must not orphan .gnupg out of the
	// secret section it belongs to.
	for _, p := range []string{"/HOME/.ssh", "/HOME/.gnupg"} {
		if c := byPath[p]; c.Section != "Top secret" {
			t.Errorf("%s attributed to %q, want \"Top secret\"", p, c.Section)
		}
	}
}

// inScopeSection matches the distinctive words of bento's secret/exec sections, but a
// NEGATED header must not fool it: firejail's "Configuration files that do not allow
// arbitrary command execution but that..." names the exec keyword only to exclude
// itself. Suppression is scoped to that keyword, so a section that negates it while
// also matching another in-scope keyword still classifies in-scope.
func TestInScopeSectionRejectsNegatedHeaders(t *testing.T) {
	for _, s := range []string{
		"Arbitrary command execution",
		"Top secret",
		"X11 session autostart",
		"systemd",
		"systemd units that do not allow arbitrary command execution", // another keyword still counts
	} {
		if !inScopeSection(s) {
			t.Errorf("inScopeSection(%q) = false, want true", s)
		}
	}
	for _, s := range []string{
		"Configuration files that do not allow arbitrary command execution but that could otherwise be exploited",
		"gnome",
		"var",
	} {
		if inScopeSection(s) {
			t.Errorf("inScopeSection(%q) = true, want false", s)
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
