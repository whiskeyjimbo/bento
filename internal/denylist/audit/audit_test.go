package audit

import (
	"os"
	"path/filepath"
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
	got := ParseFirejail(content, "/HOME", "/run/user/1000")

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
	for _, c := range ParseFirejail(content, "/HOME", "/run/user/1000") {
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
	inScope, out := SplitByScope(gaps)
	if len(inScope) != 1 || inScope[0].Path != "/HOME/.keepassxc" {
		t.Fatalf("the credential store must be in scope, got %+v", inScope)
	}
	if inScope[0].Section != credentialSection {
		t.Errorf("a name-classified gap must be relabelled, got section %q", inScope[0].Section)
	}
	if out["This file is overwritten during software install."] != 1 {
		t.Errorf("the ordinary app dir must be counted out-of-scope, got %+v", out)
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

func TestSplitByScopeUsesFirejailSections(t *testing.T) {
	gaps := []Gap{
		{Candidate: Candidate{Path: "/HOME/.aws", Section: "top secret"}},
		{Candidate: Candidate{Path: "/HOME/.config/autostart-scripts", Section: "X11 session autostart"}},
		{Candidate: Candidate{Path: "/HOME/.mozilla", Section: "gnome"}},                // out: other-app
		{Candidate: Candidate{Path: "/HOME/.local/share/Trash", Section: "var"}},        // out
		{Candidate: Candidate{Path: "/HOME/.cargo/credentials", Section: "top secret"}}, // in
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
	unclassified, globs, out := Audit([]string{content}, "/HOME", "/run/user/1000")

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
	if out["gnome"] != 1 {
		t.Errorf("the out-of-scope gnome entry must be counted, got %+v", out)
	}
}

// The live completeness gate: diff bento's shield list against the firejail profiles
// installed on this host (or FIREJAIL_DIR). It skips where firejail is absent - the
// profile data is GPLv2 and read only as a dev-time diff input, never vendored - so on
// a host with firejail it fails loudly listing any upstream in-scope path bento neither
// shields nor excludes, turning "remember to re-run the diff" into an enforced check.
func TestFirejailCompleteness(t *testing.T) {
	// An explicitly set FIREJAIL_DIR is a caller asserting the profiles are there, so a
	// missing one is their error and fails. Only the implicit default may skip: firejail
	// is genuinely absent on plenty of dev boxes and CI images, the profile data is GPLv2
	// and cannot be vendored to testdata, so there is nothing to diff against and no
	// honest verdict to reach. The enforced gate is `make audit`, which fetches upstream
	// rather than reading the host.
	dir, explicit := os.LookupEnv("FIREJAIL_DIR")
	if !explicit {
		dir = "/etc/firejail"
	}
	// disable-common.inc carries the section headers the scope classification keys off;
	// disable-programs.inc is a flat per-application list with no headers, where the
	// name classifier is what picks the credential stores out of ~1300 ordinary app dirs.
	// disable-common.inc is the gate's floor - without it there is nothing to diff.
	// disable-programs.inc is additive: a partial install that lacks it still gets the
	// headed profile audited rather than losing the gate entirely.
	var contents []string
	for i, name := range []string{"disable-common.inc", "disable-programs.inc"} {
		path := filepath.Join(dir, name)
		content, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			if i == 0 {
				if explicit {
					t.Fatalf("FIREJAIL_DIR names %s but it has no %s; the completeness gate cannot run against the directory you pointed it at", dir, name)
				}
				t.Skipf("no firejail profile at %s (set FIREJAIL_DIR); the completeness gate needs firejail as a diff input", path)
			}
			t.Logf("no profile at %s; auditing the profiles present", path)
			continue
		}
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		contents = append(contents, string(content))
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	unclassified, globs, outBySection := Audit(contents, home, "/run/user/1000")

	// Globs and out-of-scope totals are surfaced (not silently dropped) so a whole
	// class or the app/privacy scope stays visible for periodic manual review.
	for _, g := range globs {
		t.Logf("glob for review (bento covers by named instance - verify the set is current): %s [%s]", g.Path, g.Section)
	}
	total := 0
	for _, n := range outBySection {
		total += n
	}
	t.Logf("%d out-of-scope firejail entries in %d section(s) (firejail's privacy/other-app/system scope, not enumerated by bento)", total, len(outBySection))

	if len(unclassified) == 0 {
		return
	}
	var b strings.Builder
	for _, g := range unclassified {
		weak := ""
		if g.Weaker {
			weak = " (bento has it DenyWrite; firejail blacklists it)"
		}
		b.WriteString("\n  " + g.Path + " [" + g.Section + "]" + weak)
	}
	t.Errorf("firejail shields %d in-scope path(s) bento neither shields nor excludes - classify each (shield in denylist.go or add to IntentionalExclusions):%s", len(unclassified), b.String())
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
