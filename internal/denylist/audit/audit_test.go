package audit

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/denylist"
)

func TestParseFirejailKeepsScopedShields(t *testing.T) {
	const content = `# a comment
blacklist ${HOME}/.ssh
read-only ${HOME}/.bashrc
blacklist-nolog ${HOME}/.*_history
blacklist-nolog ${HOME}/.viminfo
blacklist ${HOME}/.config/Ledger Live
blacklist ${HOME}/Applications # used for storing AppImages
?HAS_X11: blacklist ${HOME}/.ICEauthority
blacklist ${RUNUSER}/bus
blacklist /sbin
blacklist ${PATH}/sudo
noblacklist ${HOME}/.config/foo
read-write ${HOME}/.local/share
include disable-common.local
rmenv GITHUB_TOKEN
`
	got, _ := ParseFirejail(content, "/HOME", "/run/user/1000")

	want := []Candidate{
		{Path: "/HOME/.ssh", Deny: denylist.DenyAll},
		{Path: "/HOME/.bashrc", Deny: denylist.DenyWrite},
		// firejail's whole history/clipboard section uses blacklist-nolog, which shields
		// identically to blacklist - it must not parse as a no-op.
		{Path: "/HOME/.*_history", Deny: denylist.DenyAll, Glob: true},
		{Path: "/HOME/.viminfo", Deny: denylist.DenyAll},
		// firejail profiles carry paths with spaces, which taking the second field alone
		// truncates to a directory that does not exist. Reading the rest of the line
		// instead means a trailing comment would land in the path, so it is cut.
		{Path: "/HOME/.config/Ledger Live", Deny: denylist.DenyAll},
		{Path: "/HOME/Applications", Deny: denylist.DenyAll},
		// A live build-conditional directive. The condition decides whether firejail
		// applies it, not whether the path holds a credential, so it must be audited like
		// any other - dropping it leaves the whole conditional block reading as "firejail
		// shields nothing here", which is how a gap stays invisible.
		{Path: "/HOME/.ICEauthority", Deny: denylist.DenyAll},
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
	for _, c := range mustParse(ParseFirejail(content, "/HOME", "/run/user/1000")) {
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

// A reference note preceding the real header must not steal the section. firejail
// sometimes leads a section with a "# see #NNNN" note before the prose header; with
// plain first-comment-wins the note (out of bento's scope) captured the block and the
// real in-scope header was skipped, silently un-gating the entries (a wrong-OUT). A
// later in-scope header upgrades the out-of-scope note; the move is one-way, so it
// cannot un-gate anything the old rule gated.
func TestParseFirejailInScopeHeaderUpgradesLeadingNote(t *testing.T) {
	const content = `# see #3358
# X11 session autostart
blacklist ${HOME}/.xinitrc
blacklist ${HOME}/.config/autostart
`
	for _, c := range mustParse(ParseFirejail(content, "/HOME", "/run/user/1000")) {
		if c.Section != "X11 session autostart" {
			t.Errorf("%s attributed to %q, want the header \"X11 session autostart\"", c.Path, c.Section)
		}
		if !inScopeSection(c.Section) {
			t.Errorf("%s (section %q) must classify in-scope - it is a host-exec vector", c.Path, c.Section)
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

// The name classifier is what makes the header-less disable-programs.inc auditable, and
// its whole risk is over-matching: a token that also appears inside an ordinary app name
// would drag a privacy-scope directory into the hard-fail set, where the only ways out
// are shielding a path bento has no reason to shield or recording a bogus intentional
// exclusion. The negative cases here are the real near-misses in that profile - a Tetris
// clone, a session manager, and the messengers whose store is an encrypted message
// database, which are firejail's privacy scope rather than bento's secret scope.
func TestCredentialNameMatchesStoresNotLookalikes(t *testing.T) {
	for _, p := range []string{
		"/home/u/.keepassxc",
		"/home/u/.config/KeePassXCrc",
		"/home/u/.local/share/KeePass",
		"/home/u/.config/Bitwarden",
		"/home/u/.config/1Password",
		"/home/u/.lastpass",
		"/home/u/.cache/Enpass",
		"/home/u/.config/Authenticator",
		"/home/u/.smartgit/21.1/passwords",
		"/home/u/.config/kwalletrc",
		"/home/u/wallet.dat",
		"/home/u/.bitcoin",
		"/home/u/.electrum",
		"/home/u/.config/monero-project",
		"/home/u/.ethereum",
		"/home/u/.electron-cash", // the fork that dropped the "electrum" stem
		"/home/u/.config/Ledger Live",
		// Reaching firejail's .*coin glob needs the "coin" token, which also takes the
		// price ticker with it - accepted, since its config can hold exchange API keys.
		"/home/u/.config/cointop",
		"/home/u/.icedove", // Debian-rebranded Thunderbird
		"/home/u/.claws-mail",
		"/home/u/.config/remmina",
		"/home/u/.gist",
		"/home/u/.purple",
	} {
		if !credentialName(p) {
			t.Errorf("credentialName(%q) = false, want true", p)
		}
	}
	for _, p := range []string{
		"/home/u/.local/share/quadrapassel", // contains "pass", not "password"
		"/home/u/.config/gnome-session",
		"/home/u/.config/Signal",
		"/home/u/.local/share/signal-cli",
		"/home/u/.config/Session",
		"/home/u/.Atom",
	} {
		if credentialName(p) {
			t.Errorf("credentialName(%q) = true, want false", p)
		}
	}
}

// A profile with no usable section header (disable-programs.inc leads with an
// "overwritten during install" note) still has to surface its credential stores, and the
// report must not label them with that note. A name-classified gap is relabelled to say
// why it is in scope; an ordinary app dir in the same file stays out of scope and is only
// counted.
func TestSplitByScopeClassifiesHeaderlessProfileByName(t *testing.T) {
	gaps := []Gap{
		{Candidate: Candidate{Path: "/HOME/.keepassxc", Section: "This file is overwritten during software install."}},
		{Candidate: Candidate{Path: "/HOME/.Atom", Section: "This file is overwritten during software install."}},
	}
	inScope, out := SplitByScope(gaps, "/HOME")
	if len(inScope) != 1 || inScope[0].Path != "/HOME/.keepassxc" {
		t.Fatalf("the credential store must be in scope, got %+v", inScope)
	}
	if inScope[0].Section != credentialSection {
		t.Errorf("a name-classified gap must be relabelled, got section %q", inScope[0].Section)
	}
	if bySection(out)["This file is overwritten during software install."] != 1 {
		t.Errorf("the ordinary app dir must be reported out-of-scope, got %+v", out)
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
		{Path: "/run/user/1000/bus", Deny: denylist.DenyAll},         // covered by the /run dir shield
		{Path: "/HOME/.aws", Deny: denylist.DenyAll},                 // missing entirely
		{Path: "/HOME/.bashrc", Deny: denylist.DenyAll},              // present but only DenyWrite -> weaker
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

// Moving an entry from a directory list to the flat file list is a one-line diff - the
// same string, a different loop - that shrinks the shield from the whole tree to one
// inode. denylist.Covers answers the exact path match either way, which is right where it
// enforces and blind here, so the gate has to compare shapes.
func TestDiffReportsADirectoryShieldNarrowedToAFile(t *testing.T) {
	candidates := []Candidate{{Path: "/HOME/.gist", Deny: denylist.DenyAll, Dir: true}}

	tree := []denylist.Rule{{Path: "/HOME/.gist", Deny: denylist.DenyAll, Dir: true}}
	if gaps := Diff(candidates, tree); len(gaps) != 0 {
		t.Errorf("a directory rule covers a directory-shaped candidate; got %+v", gaps)
	}

	inode := []denylist.Rule{{Path: "/HOME/.gist", Deny: denylist.DenyAll}}
	gaps := Diff(candidates, inode)
	if len(gaps) != 1 || !gaps[0].Narrowed || gaps[0].Weaker {
		t.Errorf("a file rule under a directory-shaped candidate must report Narrowed; got %+v", gaps)
	}
}

func TestSplitByScopeUsesFirejailSections(t *testing.T) {
	gaps := []Gap{
		{Candidate: Candidate{Path: "/HOME/.aws", Section: "top secret"}},
		{Candidate: Candidate{Path: "/HOME/.config/autostart-scripts", Section: "X11 session autostart"}},
		{Candidate: Candidate{Path: "/HOME/.mozilla", Section: "gnome"}},                // out: other-app
		{Candidate: Candidate{Path: "/HOME/.local/share/Trash", Section: "var"}},        // out
		{Candidate: Candidate{Path: "/HOME/.cargo/credentials", Section: "top secret"}}, // in
	}
	inScope, out := SplitByScope(gaps, "/HOME")
	if len(inScope) != 3 {
		t.Fatalf("in-scope = %d, want 3: %+v", len(inScope), inScope)
	}
	// Sorted by section then path: "X11 session autostart" < "top secret".
	if inScope[0].Section != "X11 session autostart" {
		t.Errorf("first in-scope section = %q, want X11 autostart", inScope[0].Section)
	}
	if counts := bySection(out); counts["gnome"] != 1 || counts["var"] != 1 {
		t.Errorf("out-of-scope counts wrong: %+v", out)
	}
	if _, isIn := bySection(out)["top secret"]; isIn {
		t.Error("a secret section must not be counted out-of-scope")
	}
}

// bySection counts the out-of-scope gaps per section, the summary the tests above assert
// on. SplitByScope returns the entries themselves because a count is not diffable between
// runs; the count is still the right assertion for a fixture of three.
func bySection(gaps []Gap) map[string]int {
	counts := map[string]int{}
	for _, g := range gaps {
		counts[g.Section]++
	}
	return counts
}

// The name classifier reads the ${HOME}-relative remainder, not the absolute path. A home
// whose own directory name carries a token - /home/mailuser, a coin-something build agent -
// otherwise matches on every path beneath it, and the whole ~1300-entry privacy bucket
// moves into the hard-fail set with the gate reporting each as a credential store.
func TestSplitByScopeIgnoresTokensInTheHomeDirectoryName(t *testing.T) {
	gaps := []Gap{{Candidate: Candidate{Path: "/home/mailuser/.Atom", Section: "This file is overwritten during software install."}}}
	inScope, out := SplitByScope(gaps, "/home/mailuser")
	if len(inScope) != 0 || len(out) != 1 {
		t.Errorf("an ordinary app dir under a token-named home must stay out of scope; got inScope=%+v out=%+v", inScope, out)
	}
	// The classifier itself still has to work at that home.
	if in, _ := SplitByScope([]Gap{{Candidate: Candidate{Path: "/home/mailuser/.thunderbird", Section: "n/a"}}}, "/home/mailuser"); len(in) != 1 {
		t.Errorf("a real mail store under the same home must still classify in scope, got %+v", in)
	}
}

// The out-of-scope bucket is what a human diffs two runs of the audit on to notice a new
// upstream entry, so it has to carry the paths and come back in a stable order. Map
// iteration would reorder the sections on every run and bury the one line that changed.
func TestSplitByScopeOrdersOutOfScopeForDiffing(t *testing.T) {
	gaps := []Gap{
		{Candidate: Candidate{Path: "/HOME/.zzz", Section: "var"}},
		{Candidate: Candidate{Path: "/HOME/.mozilla", Section: "gnome"}},
		{Candidate: Candidate{Path: "/HOME/.aaa", Section: "var"}},
	}
	_, out := SplitByScope(gaps, "/HOME")
	var got []string
	for _, g := range out {
		got = append(got, g.Section+" "+g.Path)
	}
	want := []string{"gnome /HOME/.mozilla", "var /HOME/.aaa", "var /HOME/.zzz"}
	if !slices.Equal(got, want) {
		t.Errorf("out-of-scope order = %v, want %v", got, want)
	}
}

// The parser and diff must run against bento's real shield list without panicking,
// and cover a path the list is known to shield (so a refactor that empties Home()
// does not silently make the audit pass by finding nothing to compare).
func TestDiffAgainstRealList(t *testing.T) {
	rules := append(denylist.Home("/HOME"), denylist.Runtime("/run/user/1000", "/HOME")...)
	c := []Candidate{{Path: "/HOME/.ssh/id_rsa", Deny: denylist.DenyAll}}
	if gaps := Diff(c, rules); len(gaps) != 0 {
		t.Errorf("~/.ssh/id_rsa should be covered by the real list, got gaps %+v", gaps)
	}
}

// Audit ties parse -> diff -> scope -> exclusions together: it must surface only the
// in-scope firejail entries bento neither shields nor deliberately excludes. This is
// the machinery's real verification (the live-firejail test below skips where firejail
// is absent, which is most hosts).
func TestAuditReportsOnlyUnclassifiedInScopeGaps(t *testing.T) {
	const content = `# Top secret
blacklist ${HOME}/.ssh
blacklist ${HOME}/_vimrc
blacklist ${HOME}/.newsecret
blacklist ${HOME}/*.audittest

# History files
blacklist ${HOME}/.*_history

# gnome
blacklist ${HOME}/.audit_test_privacy_app
`
	unclassified, globs, out := Audit([]Source{{Content: content, Parse: ParseFirejail}}, "/HOME", "/run/user/1000")

	got := map[string]bool{}
	for _, g := range unclassified {
		got[g.Path] = true
	}
	// .ssh is shielded (no gap); _vimrc is an intentional exclusion (suppressed); the
	// reviewed .*_history glob goes to the review bucket; .newsecret (concrete) and the
	// UNREVIEWED *.audittest glob are genuine hard-fail gaps.
	if !got["/HOME/.newsecret"] {
		t.Errorf("an unshielded, unexcluded in-scope entry must surface; got %+v", unclassified)
	}
	if !got["/HOME/*.audittest"] {
		t.Errorf("an unreviewed glob must hard-fail, not become a note; got %+v", unclassified)
	}
	if got["/HOME/.ssh"] {
		t.Error(".ssh is shielded and must not surface as a gap")
	}
	if got["/HOME/_vimrc"] {
		t.Error("_vimrc is an intentional exclusion and must be suppressed")
	}
	if len(unclassified) != 2 {
		t.Errorf("want exactly two unclassified gaps (.newsecret, *.audittest), got %d: %+v", len(unclassified), unclassified)
	}
	// A REVIEWED glob is reported for periodic re-check, not hard-failed and never
	// silently dropped - leaving a whole class invisible is the chore this tool kills.
	if len(globs) != 1 || globs[0].Path != "/HOME/.*_history" {
		t.Errorf("the reviewed .*_history glob must surface as a glob for review, got %+v", globs)
	}
	// The gnome entry is firejail's other-app privacy scope: accounted for out-of-scope,
	// never a gap.
	if bySection(out)["gnome"] != 1 {
		t.Errorf("the out-of-scope gnome entry must be reported, got %+v", out)
	}
}

// An AcceptedWeaker record accepts one thing: that bento shields the path DenyWrite where
// firejail blacklists it. It says nothing about SHAPE, so a gap that is also Narrowed -
// upstream giving one of those files a tree-shaped directive, which bento's file rule
// leaves every child of exposed - has to survive the skip and be reported.
func TestAcceptedWeakerDoesNotSwallowACoOccurringNarrowed(t *testing.T) {
	const content = `# Top secret
blacklist ${HOME}/.zshenv/
`
	unclassified, _, _ := Audit([]Source{{Content: content, Parse: ParseFirejail}}, "/HOME", "/run/user/1000")

	var got *Gap
	for i, g := range unclassified {
		if g.Path == "/HOME/.zshenv" {
			got = &unclassified[i]
		}
	}
	if got == nil {
		t.Fatalf(".zshenv is accepted as weaker but not as narrowed; the tree-shaped directive must still surface, got %+v", unclassified)
	}
	if !got.Narrowed {
		t.Errorf("gap %+v surfaced without Narrowed set; the reporter's weaker-and-narrowed branch reads it", *got)
	}

	// The weaker-only case is what the record accepts, and it must still be cleared.
	weakerOnly, _, _ := Audit([]Source{{Content: "# Top secret\nblacklist ${HOME}/.zshenv\n", Parse: ParseFirejail}}, "/HOME", "/run/user/1000")
	for _, g := range weakerOnly {
		if g.Path == "/HOME/.zshenv" {
			t.Errorf("a weaker-only gap at an AcceptedWeaker path must stay suppressed, got %+v", g)
		}
	}
}

// The roots the gate expands the corpora's variables to. Both are constants, matching
// cmd/denylist-audit, because the rules are built from them and the audit only means
// something when the same host cannot reach a different verdict: the real $HOME is an
// ambient value that can COLLIDE with the runtime root, and Runtime's unconditional /run
// and /var/run directory rules then cover every expanded candidate. A home under /run -
// an ordinary rootless or container session - turned the whole comparison green.
const (
	gateHome    = "/home/u"
	gateRunUser = "/run/user/1000"
)

// The gate is a comparison only while its home is somewhere the rule set does not already
// shield wholesale. Runtime carries unconditional DenyAll DIRECTORY rules for /run and
// /var/run, so a home under either covers every expanded candidate whatever the corpora
// say, and the gate reports parity over a comparison it never made - 1926 directives, zero
// gaps, on any rootless or container session whose $HOME sits there.
//
// This pins the property rather than the constant, because the constant is not what went
// wrong: the home was read from the environment, where a value under /run is ordinary. A
// gateHome pointed back at an ambient read fails here instead of greening the gate.
func TestGateHomeIsNotShieldedWholesale(t *testing.T) {
	probe := filepath.Join(gateHome, ".audit-gate-probe")
	rules := append(denylist.Home(gateHome), denylist.Runtime(gateRunUser, gateHome)...)
	if r, ok := denylist.Covers(probe, rules); ok {
		t.Errorf("every candidate under the gate's home %s is already covered by %s (%v); the diff can only report parity, so the gate proves nothing", gateHome, r.Path, r.Deny)
	}
}

// hostCorpora are the upstream profiles the in-tree gate diffs against, read from this
// host: both projects' data is GPLv2 and used as a dev-time diff input only, never
// vendored to testdata. Each carries the same two health checks `make audit` applies to
// the fetched copy, because a corpus that arrives empty or stops parsing produces the
// identical green as a corpus with nothing left to find - and here it is a distro package
// rather than a fetch, so a partial or stale layout is the ordinary case rather than the
// exotic one.
//
// minCandidates and maxDropRatio duplicate cmd/denylist-audit's values rather than sharing
// them: those floor MASTER, these floor whatever the distro packaged, and a snapshot that
// legitimately carries fewer entries has to be lowerable here without weakening the
// fetching gate. The current Debian/Ubuntu packages parse to 342, 1301, 29 and 19
// candidates, so every floor has a third of its value in headroom.
var hostCorpora = []struct {
	dirEnv        string
	defaultDir    string
	file          string
	parse         func(content, home, runUser string) ([]Candidate, int)
	minCandidates int
	maxDropRatio  float64
}{
	// disable-common.inc carries the section headers the scope classification keys off;
	// disable-programs.inc is a flat per-application list with no headers, where the name
	// classifier is what picks the credential stores out of ~1300 ordinary app dirs.
	{"FIREJAIL_DIR", "/etc/firejail", "disable-common.inc", ParseFirejail, 250, 0.05},
	{"FIREJAIL_DIR", "/etc/firejail", "disable-programs.inc", ParseFirejail, 1000, 0.05},
	// The second corpus, and the only one whose directive shape reaches Diff's Narrowed
	// arm: firejail writes no trailing slash on a directory entry, so every one of its
	// candidates is file-shaped, while AppArmor's {,**} tail is explicit. Auditing it only
	// from the network-fetching `make audit` left that arm - and ParseAppArmor's behaviour
	// against a real abstraction - unexercised by every in-tree run.
	{"APPARMOR_DIR", "/etc/apparmor.d/abstractions", "private-files", ParseAppArmor, 20, 0.25},
	{"APPARMOR_DIR", "/etc/apparmor.d/abstractions", "private-files-strict", ParseAppArmor, 12, 0.25},
}

// corpusHealth reports why a parsed corpus cannot be diffed against, or nil when it can.
// Both halves say the same thing - this is not the corpus - about the two ways one goes
// quiet: it got shorter, or it kept its length behind a syntax the parser stopped
// reading. Either leaves entries out of the diff, which reads exactly like a corpus with
// nothing left to find.
//
// Order is load-bearing. An empty corpus divides zero by zero and NaN clears every
// ceiling, so the ratio alone waves through the one case the floor exists for.
func corpusHealth(kept []Candidate, dropped, minCandidates int, maxDropRatio float64) error {
	if len(kept) < minCandidates {
		return fmt.Errorf("parsed to %d in-scope directives, below the floor of %d; this is not the whole profile, so a green gate would be a comparison never made", len(kept), minCandidates)
	}
	if r := float64(dropped) / float64(len(kept)+dropped); r > maxDropRatio {
		return fmt.Errorf("left %d of %d directive(s) unparsed (%.0f%%, ceiling %.0f%%); the parser no longer reads this profile's syntax, so those entries left the diff without being compared", dropped, len(kept)+dropped, r*100, maxDropRatio*100)
	}
	return nil
}

// The floor is the check that has to hold for the empty corpus, and it is the one an
// ordering slip disables: NaN compares false against any ceiling, so a ratio-first
// version passes a file that parsed to nothing - the exact state the in-tree gate used to
// report as "0 out-of-scope entries in 0 section(s)".
func TestCorpusHealthRefusesAnEmptyCorpus(t *testing.T) {
	if err := corpusHealth(nil, 0, 250, 0.05); err == nil {
		t.Error("a corpus that parsed to nothing must be refused, not diffed against")
	}
	if err := corpusHealth(make([]Candidate, 300), 100, 250, 0.05); err == nil {
		t.Error("a corpus a quarter of which the parser could not read must be refused")
	}
	if err := corpusHealth(make([]Candidate, 300), 5, 250, 0.05); err != nil {
		t.Errorf("a healthy corpus must pass: %v", err)
	}
}

// The live parity gate: diff bento's shield list against the firejail and AppArmor
// profiles installed on this host. It skips where they are absent - the profile data is
// GPLv2 and cannot be vendored, so there is nothing to diff against and no honest verdict
// to reach - so on a host that has them it fails loudly listing any upstream in-scope path
// bento neither shields nor excludes, turning "remember to re-run the diff" into an
// enforced check. The enforced-everywhere gate is `make audit`, which fetches upstream.
func TestUpstreamCompleteness(t *testing.T) {
	var sources []Source
	var missing []string
	for _, c := range hostCorpora {
		dir, explicit := os.LookupEnv(c.dirEnv)
		if !explicit {
			dir = c.defaultDir
		}
		path := filepath.Join(dir, c.file)
		content, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			// An explicitly set dir is a caller asserting the profiles are there, so a
			// missing one is their error. Only the implicit default may go missing.
			if explicit {
				t.Fatalf("$%s names %s but it has no %s; the completeness gate cannot run against the directory you pointed it at", c.dirEnv, dir, c.file)
			}
			missing = append(missing, path)
			continue
		}
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		kept, dropped := c.parse(string(content), gateHome, gateRunUser)
		if err := corpusHealth(kept, dropped, c.minCandidates, c.maxDropRatio); err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		t.Logf("%s: %d candidates, %d unparsed", path, len(kept), dropped)
		sources = append(sources, Source{Name: c.file, Content: string(content), Parse: c.parse})
	}
	// A skipped completeness gate is a pass that proved nothing, and so is one run over
	// half its corpora: each is here because the other overlooks entries it catches.
	// BENTO_REQUIRE_TEST_DEPS is how a host that is supposed to have them installed - CI,
	// and `make test` - says so.
	if len(missing) > 0 {
		if os.Getenv("BENTO_REQUIRE_TEST_DEPS") != "" {
			t.Fatalf("no upstream profile at %v and BENTO_REQUIRE_TEST_DEPS is set; the completeness gate cannot run without every corpus", missing)
		}
		t.Logf("no upstream profile at %v (set $FIREJAIL_DIR/$APPARMOR_DIR); auditing the corpora present", missing)
	}
	if len(sources) == 0 {
		t.Skip("none of the upstream profiles are installed; the completeness gate needs at least one as a diff input")
	}

	unclassified, globs, outOfScope := Audit(sources, gateHome, gateRunUser)

	// Stale keywords are reported here, not failed on: the host corpus is whatever the
	// distro packaged, and in an older snapshot a section bento's keywords name may simply
	// not exist yet - firejail 0.9.72 has no IPC-socket block at all and confines
	// ssh-agent to /tmp, so both keywords classify nothing there while being live on
	// master. Against a downstream snapshot a missing section is indistinguishable from a
	// retitle, so only a current corpus can tell the two apart: the enforced ratchet is
	// `make audit`, which fetches master and exits nonzero on a stale keyword.
	if stale := StaleKeywords(sources, gateHome, gateRunUser); len(stale) > 0 {
		t.Logf("scope keyword(s) %v match no section in this corpus - expected on an older snapshot; `make audit` decides staleness against master", stale)
	}

	// Globs and out-of-scope totals are surfaced (not silently dropped) so a whole
	// class or the app/privacy scope stays visible for periodic manual review.
	for _, g := range globs {
		t.Logf("glob for review (bento covers by named instance - verify the set is current): %s [%s]", g.Path, g.Section)
	}
	t.Logf("%d out-of-scope upstream entries in %d section(s) (the upstreams' privacy/other-app/system scope, not enumerated by bento)", len(outOfScope), len(bySection(outOfScope)))

	if len(unclassified) == 0 {
		return
	}
	var b strings.Builder
	for _, g := range unclassified {
		weak := ""
		if g.Weaker {
			weak = " (bento has it DenyWrite; upstream denies reads)"
		}
		b.WriteString("\n  " + g.Path + " [" + g.Section + "]" + weak)
	}
	t.Errorf("the upstream corpora shield %d in-scope path(s) bento neither shields nor excludes - classify each (shield in denylist.go or add to IntentionalExclusions):%s", len(unclassified), b.String())
}

// The audit is a comparison of two lists and only means something when its own list is
// the same on every host: a rule the developer's shell adds can cover an upstream
// candidate and report a real gap as covered. Audit gets that by building from Home and
// Runtime alone - both take their paths as parameters, and every environment read this
// call graph could otherwise reach lives in Relocated, which Audit does not call - so the
// property is structural rather than a clearing step
// each call site has to remember. This pins it, because Audit reaching for Relocated
// would look like an improvement in coverage and would silently make the verdict the
// operator's.
func TestAuditVerdictIgnoresTheAmbientRelocations(t *testing.T) {
	sources := firejailSources([]string{"# Top secret\nblacklist ${HOME}/.audit-spike-store\n"})
	want, _, _ := Audit(sources, "/home/u", "/run/user/1000")
	if len(want) != 1 {
		t.Fatalf("the unshielded upstream path must report as a gap first, got %+v", want)
	}
	// Pointed at exactly the gap: were the relocations in the rule set, this would cover
	// it and the gap would vanish.
	for _, v := range denylist.RelocationVars() {
		t.Setenv(v, "/home/u/.audit-spike-store")
	}
	if got, _, _ := Audit(sources, "/home/u", "/run/user/1000"); len(got) != len(want) {
		t.Errorf("the ambient relocations changed the verdict: %d gap(s) with them set, %d without", len(got), len(want))
	}
}

// The exec half of the classifier claimed to cover "a plant that runs on the host later"
// while firejail's $PATH and portable-app sections sat in the out-of-scope bucket - the
// most direct instance of that threat there is. Both must now classify in scope, and the
// negated-exec header must still not.
func TestInScopeSectionAdmitsPathSections(t *testing.T) {
	for _, s := range []string{
		"Make directories commonly found in $PATH read-only",
		"Write-protection for portable apps",
	} {
		if !inScopeSection(s) {
			t.Errorf("%q holds host-exec plant targets and must be in scope", s)
		}
	}
	if inScopeSection("Configuration files that do not allow arbitrary command execution but that") {
		t.Error("the negated exec header must stay out of scope")
	}
}

// The Tier-2 vocabulary: each token names a store holding an account password or private
// key. The counter-cases matter as much - the classifier must not quietly widen into
// message content or into the synced document folders, and Signal/Session must stay out
// on the stated rule (their key lives in the OS keyring), not on the app's name.
func TestCredentialNameTierTwoTokens(t *testing.T) {
	for _, p := range []string{
		"/home/u/.local/share/dino", "/home/u/.config/gajim", "/home/u/.config/psi+",
		"/home/u/.config/profanity", "/home/u/.local/share/telepathy", "/home/u/.nicotine",
		"/home/u/.linphonerc", "/home/u/.config/Mumble", "/home/u/.config/kdeconnect",
		"/home/u/.parsec", "/home/u/.hashcat",
		// Electron messengers: a live account token recoverable from the local store,
		// which is the credential class regardless of the app's packaging.
		"/home/u/.config/discord", "/home/u/.config/discordcanary", "/home/u/.config/Slack",
		"/home/u/.config/skypeforlinux", "/home/u/.cache/ms-skype-online",
		"/home/u/.TelegramDesktop", "/home/u/.local/share/telegram-desktop",
	} {
		if !credentialName(p) {
			t.Errorf("%s holds an account password or private key and must classify as a credential store", p)
		}
	}
	for _, p := range []string{
		// Encrypted message databases whose key lives in the OS keyring: the stated
		// boundary is recoverable-credential vs key-held-elsewhere, not app shape.
		"/home/u/.config/Signal", "/home/u/.config/Session",
		// Cloud-sync: shielded by name in the denylist precisely so no token here
		// catches the synced document folders too.
		"/home/u/.config/Nextcloud", "/home/u/Nextcloud/Notes", "/home/u/.config/Seafile",
		// Ordinary app dirs that make up the bulk of the header-less profile.
		"/home/u/.config/vlc", "/home/u/.local/share/Steam",
	} {
		if credentialName(p) {
			t.Errorf("%s must stay out of the name classifier; widening it is a deliberate scope change", p)
		}
	}
}

// firejailSources wraps profile bodies as firejail-parsed sources, so the tests that
// predate the second corpus keep reading as one profile set rather than restating the
// parser at every call.
func firejailSources(contents []string) []Source {
	out := make([]Source, 0, len(contents))
	for _, c := range contents {
		out = append(out, Source{Content: c, Parse: ParseFirejail})
	}
	return out
}

// The AppArmor abstractions are written almost entirely as patterns and mode letters,
// so the parser's job is turning that into paths bento's rule list can be diffed
// against. Each case here is one way the format differs from firejail's.
func TestParseAppArmor(t *testing.T) {
	const content = `# vim:ft=apparmor
  abi <abi/5.0>,

  deny @{HOME}/.*history mrwkl,
  audit deny @{HOME}/bin/{,**} wl,
  audit deny @{HOME}/.config/ w,
  deny @{HOME}/.{,z}log{in,out} mrk,
  audit deny owner @{HOME}/.ssh/{,**} mrwkl,
  owner deny @{HOME}/.gnupg/{,**} mrwkl,
  audit deny @{run}/user/[0-9]*/keyring** mrwkl,
  deny /etc/shadow r,
  allow @{HOME}/.cache/{,**} rw,
`
	got := map[string]Candidate{}
	for _, c := range mustParse(ParseAppArmor(content, "/HOME", "/run/user/1000")) {
		got[c.Path] = c
	}

	// Alternation is finite, so it expands to concrete paths rather than being punted
	// to the glob review bucket.
	for _, p := range []string{"/HOME/.login", "/HOME/.logout", "/HOME/.zlogin", "/HOME/.zlogout"} {
		c, ok := got[p]
		if !ok {
			t.Errorf("brace alternation must expand to %s; got %v", p, keysOf(got))
			continue
		}
		if c.Glob {
			t.Errorf("%s is a concrete path, not a glob", p)
		}
	}
	// "and everything under it" is a bento directory rule, not a wildcard.
	if c, ok := got["/HOME/bin"]; !ok || c.Glob {
		t.Errorf("a /{,**} subtree rule must collapse to the directory itself; got %+v (ok=%v)", c, ok)
	}
	// A write-only rule on the directory itself guards creation; bento has no equivalent
	// and reporting it would demand shielding the whole of ~/.config.
	if _, ok := got["/HOME/.config"]; ok {
		t.Error("a write-only create-guard on a directory must not become a candidate")
	}
	// Mode letters carry the class: no r/m/k means writes only.
	if c := got["/HOME/bin"]; c.Deny != denylist.DenyWrite {
		t.Errorf("wl modes are DenyWrite; got %v", c.Deny)
	}
	// Either qualifier can sit on either side of "deny". Matching only one side silently
	// dropped the whole rule, so the path read as one upstream does not shield.
	if _, ok := got["/HOME/.gnupg"]; !ok {
		t.Errorf("a qualifier preceding deny must not drop the rule; got %v", keysOf(got))
	}
	if c := got["/HOME/.ssh"]; c.Deny != denylist.DenyAll {
		t.Errorf("mrwkl modes hide the content, so DenyAll; got %v", c.Deny)
	}
	// A real wildcard still reports as one.
	if c, ok := got["/HOME/.*history"]; !ok || !c.Glob {
		t.Errorf(".*history is a genuine wildcard and must report as a glob; got %+v (ok=%v)", c, ok)
	}
	// The runtime dir's uid wildcard resolves, or it could never match a bento rule.
	if _, ok := got["/run/user/1000/keyring**"]; !ok {
		t.Errorf("@{run}/user/[0-9]* must resolve to the runtime dir; got %v", keysOf(got))
	}
	// Out of bento's home/runtime scope, and the wrong polarity, respectively.
	if _, ok := got["/etc/shadow"]; ok {
		t.Error("a system path is outside bento's shield scope")
	}
	if _, ok := got["/HOME/.cache"]; ok {
		t.Error("an allow rule is not a shield; reading one as a deny inverts the corpus")
	}
}

// The parser must substitute @{HOME} before expanding alternation. Doing it the other
// way round consumes the variable's own braces as a one-branch group, leaving paths
// rooted at a literal "@HOME" that match no rule - which silently drops the entire
// corpus from the diff while the gate still reports a pass.
func TestParseAppArmorSubstitutesBeforeExpanding(t *testing.T) {
	got, _ := ParseAppArmor("  deny @{HOME}/.ssh/{,**} mrwkl,\n", "/HOME", "/run/user/1000")
	if len(got) != 1 || got[0].Path != "/HOME/.ssh" {
		t.Errorf("ParseAppArmor = %+v, want exactly /HOME/.ssh", got)
	}
}

// foo{,/**} expands to the bare path and then the subtree, both trimming to one path. The
// dedup must not keep the file branch's Dir=false: the diff reads Dir to decide whether
// bento's shield was narrowed, so a tree candidate recorded as a file reports no narrowing
// where there is one.
func TestParseAppArmorKeepsTheTreeBranchOfADuplicatedPath(t *testing.T) {
	for name, line := range map[string]string{
		"file branch first": "  deny @{HOME}/.ssh{,/**} mrwkl,\n",
		"tree branch first": "  deny @{HOME}/.ssh{/**,} mrwkl,\n",
	} {
		t.Run(name, func(t *testing.T) {
			got, _ := ParseAppArmor(line, "/HOME", "/run/user/1000")
			if len(got) != 1 || got[0].Path != "/HOME/.ssh" || !got[0].Dir {
				t.Errorf("ParseAppArmor = %+v, want exactly /HOME/.ssh as a directory", got)
			}
		})
	}
}

// seen dedups across lines too, where the modes CAN differ. Keeping whichever line came
// first makes the reference profile's claim about a path depend on its order in the file:
// the weaker Deny hides a gap from the Weaker check the same way the file branch hid one
// from the narrowing check.
func TestParseAppArmorMergesTheStrongestClaimAcrossLines(t *testing.T) {
	for name, profile := range map[string]string{
		"write first": "  deny @{HOME}/.foo w,\n  deny @{HOME}/.foo{,/**} mrwkl,\n",
		"read first":  "  deny @{HOME}/.foo{,/**} mrwkl,\n  deny @{HOME}/.foo w,\n",
	} {
		t.Run(name, func(t *testing.T) {
			got, _ := ParseAppArmor(profile, "/HOME", "/run/user/1000")
			if len(got) != 1 || got[0].Deny != denylist.DenyAll || !got[0].Dir {
				t.Errorf("ParseAppArmor = %+v, want one DenyAll directory candidate for /HOME/.foo", got)
			}
		})
	}
}

// Both abstractions exist only to enumerate sensitive $HOME entries, so their candidates
// are in scope by the source rather than by a header. Without this every AppArmor gap
// lands in the out-of-scope summary and the second corpus contributes nothing.
func TestAppArmorCandidatesAreInScope(t *testing.T) {
	gaps := []Gap{{Candidate: Candidate{Path: "/HOME/.newthing", Section: appArmorSection}}}
	inScope, out := SplitByScope(gaps, "/HOME")
	if len(inScope) != 1 {
		t.Errorf("an AppArmor candidate must be in scope; got inScope=%v out=%v", inScope, out)
	}
}

func keysOf(m map[string]Candidate) []string {
	return slices.Sorted(maps.Keys(m))
}

// A dormancy record is a claim about a section that EXISTS upstream and holds no
// home-relative path. StaleKeywords cannot check it - the keyword produces no candidate
// either way - so a section deleted outright leaves the record certifying nothing and the
// keyword silent forever, which is the state the ratchet exists to refuse.
func TestVanishedDormantKeywordsNoticesADeletedSection(t *testing.T) {
	var b strings.Builder
	for kw := range DormantKeywords {
		fmt.Fprintf(&b, "# %s\nblacklist /etc/%s\n\n", kw, strings.ReplaceAll(kw, " ", "-"))
	}
	live := b.String()

	if gone := VanishedDormantKeywords(firejailSources([]string{live})); len(gone) > 0 {
		t.Fatalf("VanishedDormantKeywords over a corpus carrying every dormant section = %v, want none - a section that is there is dormant, not vanished", gone)
	}

	deleted := strings.Replace(live, "# dm-crypt\nblacklist /etc/dm-crypt\n", "", 1)
	gone := VanishedDormantKeywords(firejailSources([]string{deleted}))
	if !slices.Contains(gone, "dm-crypt") {
		t.Errorf("VanishedDormantKeywords after upstream deleted the dm-crypt block = %v, want it to name \"dm-crypt\": the recorded reason for its silence is no longer true and nothing else would say so", gone)
	}
}

// inScopeSection fails open: a section whose title no longer matches any keyword bins its
// paths in the out-of-scope set, which the report only prints. The parity gate keys on the
// unclassified set, so it stays green over a comparison that silently stopped being made.
// StaleKeywords is what notices, so it has to fire on the retitle and stay quiet otherwise.
func TestStaleKeywordsNoticesARetitledSection(t *testing.T) {
	// Every non-dormant keyword present, so a clean corpus reports nothing stale and the
	// retitle below is the only variable.
	var b strings.Builder
	for _, kw := range ScopeKeywords {
		if _, dormant := DormantKeywords[kw]; dormant {
			continue
		}
		fmt.Fprintf(&b, "# %s\nblacklist ${HOME}/.%s-entry\n\n", kw, strings.ReplaceAll(kw, " ", "-"))
	}
	live := b.String()

	if stale := StaleKeywords(firejailSources([]string{live}), "/HOME", "/run/user/1000"); len(stale) > 0 {
		t.Fatalf("StaleKeywords over a corpus carrying every keyword = %v, want none", stale)
	}

	retitled := strings.Replace(live, "# top secret\n", "# Sensitive material\n", 1)
	stale := StaleKeywords(firejailSources([]string{retitled}), "/HOME", "/run/user/1000")
	if !slices.Contains(stale, "top secret") {
		t.Errorf("StaleKeywords after upstream retitled the top-secret section = %v, want it to name \"top secret\" - otherwise the block stops being compared and the gate stays green", stale)
	}

	// A dormant keyword names a real firejail section whose entries are all outside
	// ${HOME}, so it classifies nothing by construction and must never be reported.
	for kw := range DormantKeywords {
		if slices.Contains(stale, kw) {
			t.Errorf("%q is recorded dormant but was reported stale; the gate would red-fail on a corpus that is fine", kw)
		}
	}
}

// mustParse drops the parser's dropped-line count for the tests that assert only on the
// candidates. The count has tests of its own.
func mustParse(candidates []Candidate, _ int) []Candidate { return candidates }

// A drop is a directive that leaves the diff without being compared, and a corpus that
// quietly stops parsing reads exactly like one with nothing left to find. So the parser
// counts what it could not read - and does NOT count the drops that are deliberate, or
// the count is noise nobody can ratchet on.
func TestParseFirejailCountsWhatItCouldNotRead(t *testing.T) {
	const deliberate = `# Top secret
blacklist ${HOME}/.ssh
blacklist /etc/shadow
blacklist ${PATH}/sudo
noblacklist ${HOME}/.config/foo
read-write ${HOME}/.local/share
include disable-common.local
rmenv GITHUB_TOKEN
`
	kept, dropped := ParseFirejail(deliberate, "/HOME", "/run/user/1000")
	if len(kept) != 1 || dropped != 0 {
		t.Errorf("kept %d dropped %d, want 1 and 0: a system path, a ${PATH} entry and the non-shield directives are drops by design", len(kept), dropped)
	}

	// The three shapes that are NOT by design: a shield keyword with no path, a keyword
	// spelling this parser does not know, and a variable nobody has classified.
	const unread = `# Top secret
blacklist ${HOME}/.ssh
blacklist
bl@cklist ${HOME}/.gnupg
blacklist ${XDGDATA}/keyrings
`
	kept, dropped = ParseFirejail(unread, "/HOME", "/run/user/1000")
	if len(kept) != 1 || dropped != 3 {
		t.Errorf("kept %d dropped %d, want 1 and 3; an unreadable directive absent from both counts is one nobody can notice", len(kept), dropped)
	}
}

// firejail's build-condition token may be written with no space after the colon. Read as
// a directive keyword it matches nothing, so the whole conditional block would leave the
// diff - and before the drop count existed, leave it silently.
func TestParseFirejailReadsABuildConditionWithNoSpace(t *testing.T) {
	kept, dropped := ParseFirejail("# Top secret\n?HAS_X11:blacklist ${HOME}/.ICEauthority\n", "/HOME", "/run/user/1000")
	if len(kept) != 1 || kept[0].Path != "/HOME/.ICEauthority" {
		t.Fatalf("parsed %+v, want the .ICEauthority candidate: the space after the colon is optional in firejail's grammar", kept)
	}
	if dropped != 0 {
		t.Errorf("dropped = %d, want 0", dropped)
	}
}

// The AppArmor parser counts the same way, including the create-guards isCreateGuard
// suppresses by design - its own doc concedes that drop is a narrowing of the diff, and a
// count is what makes an upstream rewriting "foo/{,**}" as a bare "foo/ w" visible.
func TestParseAppArmorCountsWhatItCouldNotRead(t *testing.T) {
	const content = `# private files
deny @{HOME}/.ssh/{,**} mrwkl,
deny @{HOME}/.config/ w,
deny @{HOME}/ w,
deny @{XDG_DATA}/keyrings mrwkl,
deny /etc/shadow mrwkl,
deny @{HOME}/.netrc,
`
	kept, dropped := ParseAppArmor(content, "/HOME", "/run/user/1000")
	if len(kept) != 1 || kept[0].Path != "/HOME/.ssh" {
		t.Fatalf("parsed %+v, want only the .ssh candidate", kept)
	}
	// The create-guard, the rule that trims away to the home root, the unclassified
	// variable, and the deny rule carrying no mode token - four rules that left the diff
	// with nothing in it. /etc/shadow is out of scope by design and not among them, and a
	// line that is no deny rule at all was never this parser's to read.
	if dropped != 4 {
		t.Errorf("dropped = %d, want 4", dropped)
	}

	// A rule with a branch KEPT is the deliberate narrowing, not a rule that left: the
	// create-guard branch of "bin/{,**}" is dropped and the subtree branch is audited, so
	// counting the branch would put a permanent floor under every ratchet built on this.
	kept, dropped = ParseAppArmor("deny @{HOME}/bin/{,**} w,\n", "/HOME", "/run/user/1000")
	if len(kept) != 1 || dropped != 0 {
		t.Errorf("kept %d dropped %d, want 1 and 0: a rule half-dropped by design still reaches the diff", len(kept), dropped)
	}
}
