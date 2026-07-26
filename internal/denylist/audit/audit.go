// Package audit cross-references bento's shield list against two upstream corpora -
// firejail's disable-common/disable-programs profiles and AppArmor's private-files
// abstractions - so a path they shield but bento does not surfaces as a candidate rather
// than waiting for an adversarial review to find it.
//
// The formats share no syntax, so each carries its own parser (ParseFirejail,
// ParseAppArmor) and Audit takes a Source per profile. They were chosen to be
// independently maintained and deny-shaped: a deny list states what must not be reached,
// which is bento's own polarity, whereas an allow-shaped confinement profile would have
// to be inverted to say anything here.
//
// It is a dev-time check, not part of the sandbox: the mapping from upstream
// directives to bento's DenyAll/DenyWrite classes is a hint, and the final
// classification (per the credential-vs-exec rule in the denylist package) stays a human
// call. Both corpora are GPLv2; this reads them as reference/diff input and never
// vendors them into the binary.
//
// WHAT A GREEN RUN MEANS, since the shape invites reading more into it: this establishes
// PARITY WITH ITS CORPORA, not completeness. A store none of them lists cannot surface
// here no matter how squarely it sits in bento's own credential/exec model, because each
// corpus's coverage is shaped by that project's scope rather than bento's.
//
// A second corpus narrows that, and does not close it. Both sources are DESKTOP
// APPLICATION sandboxes, which is the shared blind spot: the developer token stores
// (.terraformrc, .m2/settings.xml, .gradle/gradle.properties, .npmrc, .composer/auth.json)
// are outside firejail's list and AppArmor's alike. The 21 paths shielded for bv2-2k6y
// were all found by hand while this audit was green, and re-measuring against AppArmor
// put its recall on that same set at 2 of 21 - so the class that motivated the second
// corpus is still the class neither corpus covers.
//
// What the second source does buy is the failure mode a single source cannot detect at
// all: an entry one project overlooks now has a second chance to surface. Adding it
// found .local/share/thumbnailers, .config/upstart, .init, .gnome2_private, ~/.evolution,
// .mozilla-thunderbird and the legacy KDE KMail stores. Treat a clean run as "no
// upstream-known gap", and keep hunting the developer-tool class by review.
package audit

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/whiskeyjimbo/bento/internal/denylist"
)

// Source is one upstream profile's content paired with the parser for its format.
// Formats differ enough that a single parser cannot serve both - firejail's scope comes
// from section headers, AppArmor's from mode letters and the file's purpose - so each
// corpus carries its own, and Audit diffs their combined candidates against one rule
// list. A plain function value rather than an interface: there is one method's worth of
// behavior here, and both parsers already have this shape.
type Source struct {
	Content string
	Parse   func(content, home, runUser string) []Candidate
}

// Candidate is one upstream directive mapped into bento's terms.
type Candidate struct {
	// Path is the shielded path with the source format's variables expanded.
	Path string
	// Deny is the class the directive maps to: firejail's blacklist and
	// blacklist-nolog, and any AppArmor rule denying reads, become DenyAll; firejail's
	// read-only and a write-only AppArmor rule become DenyWrite.
	Deny denylist.Deny
	// Glob reports that the source directive used a wildcard, which bento does not
	// express (it shields directories instead). A glob candidate needs a human to
	// decide the covering directory shield, so it is reported separately.
	Glob bool
	// Section is what scope classification keys off: firejail's section-header comment
	// for a headed profile, or a constant naming the source where the format has no
	// headers. It separates bento's secret/exec threat model from an upstream's broader
	// privacy and other-app scope.
	Section string
	// Raw is the original upstream line, for the report.
	Raw string
}

// inScopeSection reports whether a section is within bento's host-exec / secret-read
// threat model - as opposed to an upstream's broader privacy, other-app, and
// system-hardening scope, which bento's empty-root default already covers and
// deliberately does not enumerate. Matching is by substring on the distinctive words of
// firejail's secret and exec sections; an unrecognised section is out of scope, so an
// upstream reorganization can only make the audit quieter, never silently in-scope.
func inScopeSection(section string) bool {
	s := strings.ToLower(section)
	// The AppArmor abstractions are wholly in scope by construction: both files exist
	// only to enumerate sensitive $HOME entries, so there is nothing to separate. That
	// is a property of the source, which is why ParseAppArmor stamps one section on
	// every candidate instead of reading the surrounding prose as a header.
	if section == appArmorSection {
		return true
	}
	for _, kw := range []string{
		// secret / credential sections
		"top secret", "cloud provider", "ssh-agent", "remote access", "pass utility",
		"mail directories", "dm-crypt", "luks", "veracrypt", "truecrypt", "zulucrypt",
		"intrusion detection", "history files",
		// host-exec sections (a plant that runs on the host later)
		"arbitrary command execution", "startup files", "autostart", "session manager",
		"systemd", "openrc", "desktop entries", "terminal emulator", "ipc socket",
		// Directories on $PATH and the portable-app tree: planting a binary in one is run
		// by the next bare command name that resolves to it, which is the same
		// plant-that-runs-on-the-host-later model the exec keywords above cover. These sat
		// in the out-of-scope bucket while the classifier claimed to cover exec.
		"$path", "portable apps",
	} {
		if strings.Contains(s, kw) && !negatedKeyword(s, kw) {
			return true
		}
	}
	return false
}

// credentialSection is the synthetic section given to a gap classified in-scope by name
// rather than by its firejail section header, so the report reads sensibly for a profile
// whose real "section" is boilerplate.
const credentialSection = "credential store (name-classified)"

// credentialName reports whether a path names a known secret store. It exists for
// firejail's disable-programs.inc, a flat ~1300-entry list of per-application directories
// with no section headers at all, where inScopeSection has nothing to key off and would
// bin real credential stores (keepassxc, Bitwarden, 1Password) with the browser and
// media-player dirs that make up the rest of the file.
//
// Matching is per path component and case-insensitive, so a token catches an app's
// variants and its future spellings (keepass -> .keepassx, .config/keepassxc,
// .local/share/KeePass) without enumerating paths. The vocabulary mirrors the classes
// inScopeSection already admits for a headed profile - password/top-secret stores, mail
// directories, remote access, cloud providers - so the two classifiers decide the same
// way whether or not a profile carries headers. Browsers and per-app caches stay out, as
// they are under inScopeSection.
//
// Chat and VoIP clients are the one place this goes further than inScopeSection, which
// names no messaging class: the ones matched here keep an account password, a private
// key, or both in plaintext on disk, which is the credential class by bento's own rule.
//
// The boundary is drawn at the CLIENT'S OWN account credential and at whether the store
// yields it without a key the host holds elsewhere - not at message content, and not at
// the app's shape. Discord, Slack, Skype, and Telegram Desktop are in on that rule: each
// keeps a live account token recoverable from the local store, which is the browser
// session-cookie class bento already shields wholesale, so an app being a large Electron
// tree is not a reason to leave its credential exposed. (An earlier version of this
// comment excluded them as "browser-shaped Electron scope"; that drew the line at the
// packaging rather than the credential, and did not survive being written down.)
//
// Signal and Session stay out, and the rule says why rather than the app name: their
// store is an encrypted message database whose key lives in the OS keyring, so the files
// alone yield neither messages nor a usable account credential - and the keyring itself
// is shielded. The line is therefore recoverable-credential vs key-held-elsewhere, which
// is checkable against a new client instead of being a list of decisions.
//
// This trades away one guarantee that inScopeSection has: a header-less file cannot make
// "unrecognised = in-scope" work, since that would hard-fail on the ~1300 ordinary app
// dirs. So a genuinely new credential app whose name contains no known token falls out of
// scope silently, and the ratchet here is only as good as the vocabulary. That is
// intrinsic to the profile's shape, not a gap to be closed; re-read the token list when a
// new password manager becomes common.
//
// One boundary this mechanism cannot express: a token matches a path COMPONENT, so it
// cannot separate a cloud-sync client's config tree from its synced document folder -
// "nextcloud" catches both .config/Nextcloud (account tokens, a credential store) and
// ~/Nextcloud plus ~/Nextcloud/Notes (user documents, which bento does not shield). Those
// config trees are therefore shielded by name in the denylist and given no token here,
// which keeps the documents out of scope instead of forcing a decision on them.
func credentialName(path string) bool {
	for comp := range strings.SplitSeq(strings.ToLower(path), "/") {
		for _, tok := range []string{
			// password managers and secret stores
			"keepass", "bitwarden", "1password", "lastpass", "enpass", "gopass",
			"pwsafe", "password", "passwd", "credential", "keyring", "keychain",
			"gnupg", "vault", "sinew", // sinew.in / Sinew Software Systems: Enpass's vendor name
			// crypto-currency wallets: private keys, the same class as an ssh key.
			// "coin" covers the Core wallets (bitcoin, litecoin, dogecoin); the forks
			// that dropped the stem need their own token.
			"wallet", "coin", "electrum", "electron-cash", "ethereum", "monero",
			"dashcore", "exodus", "ledger live",
			// one-time-password / 2FA stores
			"authenticator",
			// mail stores: saved IMAP/SMTP passwords and message bodies, the class
			// inScopeSection admits as "mail directories" and bento shields for mutt,
			// Thunderbird, and Evolution.
			"mail", "thunderbird", "icedove", "sylpheed", "balsa", "pinerc",
			"neomutt", "evolution", "geary", "smime",
			// remote-access clients: saved RDP/VNC passwords, recoverable because the
			// key sits beside them ("remote access" in inScopeSection).
			"remmina", "anydesk",
			// hosting and cloud-storage tokens, the class bento shields for rclone
			"gdfuse", "gist", "filezilla",
			// chat clients that keep account passwords in plaintext on disk (and, for
			// pidgin, OTR private keys). Messengers whose store is an encrypted message
			// database - Signal, Session - are firejail's privacy scope and stay out.
			"purple", "weechat", "xchat", "irssi", "mcabber", "coyim",
			"dino", "profanity", "psi", "gajim", "telepathy", "nicotine",
			// Electron messengers: a live account token recoverable from the local
			// store. "psi" above already matches nothing of theirs, so each needs its
			// own token; measured against upstream, these four match exactly the nine
			// store paths and nothing else.
			"discord", "slack", "skype", "telegram",
			// SIP/VoIP account passwords, a client certificate INCLUDING its private key,
			// and a device-pairing RSA key: key material, not message history.
			"linphone", "mumble", "kdeconnect",
			// remote-desktop saved credentials, the class remmina/anydesk already covers
			"parsec",
			// hashcat's potfile is recovered plaintext passwords - the cracked output
			"hashcat",
		} {
			if strings.Contains(comp, tok) {
				return true
			}
		}
	}
	return false
}

// negatedKeyword reports whether the section names kw only to exclude it. firejail has
// a header "Configuration files that do not allow arbitrary command execution but
// that..." which contains the exec keyword yet is deliberately out of the exec threat
// model, so a bare substring match on it is a false positive. Suppression is scoped to
// that keyword: a section that negates it while also matching another in-scope keyword
// still classifies in-scope.
func negatedKeyword(s, kw string) bool {
	return kw == "arbitrary command execution" && strings.Contains(s, "not allow "+kw)
}

// Gap is a firejail candidate bento does not fully cover.
type Gap struct {
	Candidate
	// Weaker is set when bento shields the path but only as DenyWrite while firejail
	// blacklists it (DenyAll) - the content is still readable, a possible
	// misclassification rather than a missing entry.
	Weaker bool
}

// ParseFirejail maps the blacklist/blacklist-nolog/read-only directives of a firejail profile into
// candidates, expanding ${HOME} and ${RUNUSER} and keeping only home- and
// runtime-scoped paths - bento's shield scope. System paths (/etc, /sbin, /usr),
// ${PATH} entries, and the non-shield directives (noblacklist, read-write, include,
// mkdir, rmenv, whitelist) are dropped: those are outside bento's home/runtime
// threat model, which its empty-root default already covers.
func ParseFirejail(content, home, runUser string) []Candidate {
	var out []Candidate
	var section string
	headerCaptured := false
	for line := range strings.SplitSeq(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			// A blank line opens a new block: the next header comment replaces the
			// section. The prior section is kept until then, so an intra-section blank
			// (firejail spaces related entries) does not orphan the entries after it.
			headerCaptured = false
			continue
		}
		if after, ok := strings.CutPrefix(line, "#"); ok {
			// The first comment of a block is its section header, with one monotonic
			// exception: a later in-scope header upgrades an out-of-scope note that
			// preceded it (firejail sometimes leads a section with a reference note like
			// "# see #3358" before "# X11 session autostart"). The reclassification only
			// ever moves a block out-of-scope -> in-scope, never the reverse, so it can
			// only reduce wrong-OUT (an in-scope entry silently left un-gated) - the
			// dangerous direction. That is why it does not reintroduce the last-comment-
			// wins bug, which was itself a wrong-OUT: a commented-out
			// "# blacklist ${HOME}/.xpra" pulling the X11-autostart entries out of scope.
			// A commented-out directive is skipped and is never in-scope, so it can never
			// win here.
			text := strings.TrimSpace(after)
			if !isCommentedDirective(text) && (!headerCaptured || (!inScopeSection(section) && inScopeSection(text))) {
				section = text
				headerCaptured = true
			}
			continue
		}
		// A directive may be gated on a firejail build condition by a leading "?COND:"
		// token ("?HAS_X11: blacklist ${HOME}/.ICEauthority"). The condition decides
		// whether FIREJAIL applies it, not whether the path holds a credential, so the
		// entry is audited like any other; without this the whole conditional block is
		// silently absent from the diff and reads as "firejail shields nothing here".
		// isCommentedDirective looks past the same token for the same reason.
		line = strings.TrimSpace(strings.TrimPrefix(line, buildCondition(line)))
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		var deny denylist.Deny
		switch fields[0] {
		case "blacklist", "blacklist-nolog":
			// blacklist-nolog shields exactly as blacklist does; firejail only suppresses
			// the access log for it, which is nothing bento models.
			deny = denylist.DenyAll
		case "read-only":
			deny = denylist.DenyWrite
		default:
			continue
		}
		// The path is the rest of the line, not the second field: firejail profiles carry
		// paths with spaces in them ("${HOME}/.config/Ledger Live", "${HOME}/.Wolfram
		// Research"), and taking one field truncates those to a directory that does not
		// exist - which then diffs as covered-by-nothing against a name bento will never
		// shield. A directive may end in a comment ("${HOME}/Applications # AppImages"),
		// so cut that first; a '#' at the start of a line is a comment and never reaches
		// here, and firejail's paths do not contain one.
		raw := strings.TrimSpace(strings.TrimPrefix(line, fields[0]))
		if i := strings.IndexByte(raw, '#'); i >= 0 {
			raw = strings.TrimSpace(raw[:i])
		}
		path, ok := expand(raw, home, runUser)
		if !ok {
			continue
		}
		out = append(out, Candidate{Path: path, Deny: deny, Glob: strings.ContainsAny(raw, "*?"), Section: section, Raw: line})
	}
	return out
}

// firejailDirectives are the leading keywords of firejail profile directives. A
// comment whose first token is one of these is a directive firejail disabled by
// prefixing '#', not a section header: it must not become the section the entries
// below it are attributed to. A real header is prose ("Top secret", "History files"),
// so its first token is not a lowercase directive keyword.
var firejailDirectives = map[string]bool{
	"blacklist": true, "blacklist-nolog": true, "read-only": true, "read-write": true, "noblacklist": true,
	"whitelist": true, "nowhitelist": true, "include": true, "mkdir": true,
	"mkfile": true, "rmenv": true,
}

// isCommentedDirective reports whether a comment's body is a commented-out firejail
// directive rather than a section header.
func isCommentedDirective(comment string) bool {
	fields := strings.Fields(strings.TrimPrefix(comment, buildCondition(comment)))
	return len(fields) > 0 && firejailDirectives[fields[0]]
}

// buildCondition returns the leading "?COND:" build-condition token of a directive
// line, or "" when it has none. firejail gates a directive on a compile-time feature
// with it ("?HAS_X11: blacklist ${HOME}/.ICEauthority"); both the parser and the
// commented-directive check must look past it to the directive keyword, and they read
// it here so the two cannot diverge on the syntax again.
func buildCondition(line string) string {
	fields := strings.Fields(line)
	if len(fields) > 0 && strings.HasPrefix(fields[0], "?") && strings.HasSuffix(fields[0], ":") {
		return fields[0]
	}
	return ""
}

// expand resolves the firejail variables bento cares about and reports whether the
// path is in scope. Only ${HOME}- and ${RUNUSER}-rooted paths are in scope; anything
// else (system paths, ${PATH}, ${CFG}, a bare absolute path) is out of scope.
func expand(raw, home, runUser string) (string, bool) {
	switch {
	case strings.HasPrefix(raw, "${HOME}/"):
		return filepath.Join(home, strings.TrimPrefix(raw, "${HOME}/")), true
	case raw == "${HOME}":
		return home, true
	case strings.HasPrefix(raw, "${RUNUSER}/"):
		return filepath.Join(runUser, strings.TrimPrefix(raw, "${RUNUSER}/")), true
	case raw == "${RUNUSER}":
		return runUser, true
	default:
		return "", false
	}
}

// Diff returns the candidates bento does not fully cover. A candidate is covered when
// a rule shields it exactly, or a directory rule encloses it (bento's dir shields
// cover unborn children, so firejail's per-file entries under a shielded dir are
// covered). A glob candidate is covered only when a directory rule encloses its
// parent, since bento cannot express the wildcard itself. A candidate bento shields
// as DenyWrite while firejail blacklists it is reported as Weaker, not missing.
func Diff(candidates []Candidate, rules []denylist.Rule) []Gap {
	var gaps []Gap
	for _, c := range candidates {
		covering, ok := cover(c.Path, rules)
		if !ok {
			gaps = append(gaps, Gap{Candidate: c})
			continue
		}
		if c.Deny == denylist.DenyAll && covering.Deny == denylist.DenyWrite {
			gaps = append(gaps, Gap{Candidate: c, Weaker: true})
		}
	}
	return gaps
}

// SplitByScope partitions gaps into the ones inside bento's secret/exec threat model
// (returned sorted by section, ready to list) and a count-by-section of the rest -
// firejail's privacy/other-app/system scope, which bento does not enumerate. A gap is
// in scope by its firejail section, or - for the header-less profiles where that says
// nothing - by naming a known secret store. The out-of-scope set is summarized rather
// than dropped so it stays accountable.
func SplitByScope(gaps []Gap) (inScope []Gap, outBySection map[string]int) {
	outBySection = map[string]int{}
	for _, g := range gaps {
		switch {
		case inScopeSection(g.Section):
			inScope = append(inScope, g)
		case credentialName(g.Path):
			g.Section = credentialSection
			inScope = append(inScope, g)
		default:
			outBySection[g.Section]++
		}
	}
	sort.SliceStable(inScope, func(i, j int) bool {
		if inScope[i].Section != inScope[j].Section {
			return inScope[i].Section < inScope[j].Section
		}
		return inScope[i].Path < inScope[j].Path
	})
	return inScope, outBySection
}

// IntentionalExclusions are firejail in-scope entries bento deliberately does NOT
// shield, keyed by their ${HOME}-relative path with the reason. The audit subtracts
// these so it flags only genuinely-new, unclassified entries.
//
// The bar is deliberately narrow: an exclusion means bento INTRINSICALLY never needs
// to shield the path - the name is dead on this platform, or the same value is shielded
// under a different real name. A path that is a real gap - even one blocked on a fix -
// is NOT excluded; it must surface for triage. "Covered elsewhere" is only an exclusion
// when that coverage is verified in denylist.go, never asserted. A wrong exclusion
// permanently blinds the audit to a real gap, the exact failure this tool exists to
// prevent.
var IntentionalExclusions = map[string]string{
	"_vimrc":  "a Windows-only vim rc name, dead on Linux where the real names (.vimrc, .gvimrc, .exrc) are shielded",
	"_gvimrc": "a Windows-only gvim rc name, dead on Linux",
	"_exrc":   "a Windows-only ex rc name, dead on Linux",
}

// AcceptedWeaker are paths an upstream hides outright while bento deliberately shields
// them DenyWrite, keyed by ${HOME}-relative path with the reason bento's weaker class is
// the right one. Without this the diff reports each as a candidate DenyAll forever,
// which is a standing instruction to make a change that was already considered and
// rejected.
//
// Every entry here is one scope difference, not many: AppArmor's private-files is
// explicitly a privacy abstraction, so it denies READING a shell startup file, while
// bento's model treats those as a plant-that-runs-later surface and keeps reads open
// because a sandboxed build legitimately sources them (see the writeOnly block in the
// denylist package). Hiding them would break ordinary runs to close a channel bento
// does not claim to close.
//
// The residual is real and stated rather than papered over: a user who pastes an
// export SECRET=... into .zshenv has put a secret somewhere a sandboxed run can read.
// That is the accepted cost of the readable-rc decision, not an oversight of it.
//
// Only paths an upstream has actually reported concretely are listed. Siblings that
// today reach the diff inside a wildcard (.bash_profile under .bash*) are deliberately
// absent: pre-silencing a finding no one has seen in that form is how an exclusion list
// starts hiding real gaps, which is the warning IntentionalExclusions carries too.
var AcceptedWeaker = map[string]string{
	".inputrc": "readline init: a macro binding is the plant; reading it exposes no secret",
	".login":   "csh login script: same plant-not-read rule as the other shell startup files",
	".logout":  "csh logout script: same plant-not-read rule",
	".zlogin":  "zsh login script: same plant-not-read rule",
	".zlogout": "zsh logout script: same plant-not-read rule",
	".zshenv":  "read on EVERY zsh invocation; shielded DenyWrite so a build can still source it",
}

// ReviewedGlobs are firejail wildcard directives a human has already decided about,
// keyed by ${HOME}-relative pattern with how the class is covered. bento cannot express
// a wildcard shield, so a glob cannot be diffed against the rule list mechanically. A
// glob listed here is reported for periodic re-check but does not fail the gate; a glob
// NOT listed hard-fails, so a new upstream wildcard (e.g. a bare *.key or *.kdbx in the
// top-secret section) forces an explicit decision instead of scrolling past as a note -
// the ratchet that keeps an inexpressible-but-real credential class from silently
// passing once the concrete-path backlog is cleared.
var ReviewedGlobs = map[string]string{
	".*_history":        "covered by shielding the named history instances (.bash_history, .zsh_history, .sh_history, ...) as DenyAll files",
	".*_history_*":      "rotated/suffixed variants of the same named history instances; the suffix is not expressible as a concrete path",
	".cache/greenclip*": "greenclip clipboard store; the named instance .cache/greenclip.history is shielded DenyAll and the sibling variants are not expressible as concrete paths",
	// KeePass databases and bare key files dropped at an arbitrary spot in $HOME. bento
	// cannot express a home-wide wildcard and shields the known credential stores by name;
	// a .kdbx is an encrypted database (useless without its master password), and a key
	// file placed at a self-chosen path is outside the concrete-path model. Re-check if a
	// new upstream wildcard names a plaintext-secret class that a named store would miss.
	"*.kdb":  "arbitrary-location KeePass 1.x database; bento shields named credential stores and cannot express a home-root wildcard",
	"*.kdbx": "arbitrary-location KeePass 2.x database; bento shields named credential stores and cannot express a home-root wildcard",
	"*.key":  "arbitrary-location key file; bento shields named key/credential stores, not a home-wide wildcard it cannot express",
	// firejail write-protects per-host .Xdefaults-<hostname> variants; bento shields the
	// base .Xdefaults (DenyWrite) and cannot express the wildcard, so the host variants are
	// a reviewed accepted residual rather than a hard fail.
	".Xdefaults-*": "per-host xrdb resource variant; the base .Xdefaults is shielded DenyWrite and the hostname suffix is not expressible as a concrete path",
	// Wallet and token stores whose concrete instances are shielded by name; the
	// wildcard stands for an open-ended set of forks and per-account files, which is
	// what bento cannot express - not any single one of them.
	".electrum*":   "Electrum wallet data dirs; the base .electrum is shielded DenyAll, but the suffixed fork set (.electrum-ltc and successors) is open-ended",
	".*coin":       "altcoin Core wallets; .bitcoin is shielded DenyAll, but the coin set (.litecoin, .dogecoin, .namecoin, ...) is open-ended and its members are only knowable from the wildcard",
	".sendgmail.*": "per-sender sendgmail credential files; the .config/sendgmail store and the suffix-less .sendgmail.json are shielded DenyAll, and the per-sender suffix is not expressible as a concrete path",

	// AppArmor's abstractions are written almost entirely as patterns, so its half of
	// the diff arrives here rather than as concrete paths. Each is covered by bento
	// shielding the named instances the pattern stands for.
	".*rc":        "any dotfile rc; bento shields the named rc files it models (.bashrc, .zshrc, .muttrc, .fetchmailrc, .inputrc, ...) and cannot express a home-root wildcard",
	".*history":   "unprefixed history variants of the .*_history class already reviewed above; the named instances are shielded DenyAll",
	".bash*":      "bash startup and history files; .bashrc, .bash_profile, .bash_login, .bash_aliases, .bash_logout and .bash_history are each shielded by name",
	".profile*":   "the base .profile is shielded DenyWrite; the suffixed variants are not expressible as concrete paths",
	".zprofile*":  "the base .zprofile is shielded DenyWrite; the suffixed variants are not expressible as concrete paths",
	".fetchmail*": "fetchmail state and rc; .fetchmailrc, which holds the account password, is shielded DenyAll",
	".viminfo*":   ".viminfo is shielded DenyAll; the .viminfo.tmp/.viminfo-<n> siblings vim writes are not expressible as concrete paths",
	".mutt**":     "the .mutt tree is shielded DenyAll, which covers everything the pattern reaches",

	// Editor leavings of ANY dotfile: a .swp of ~/.ssh/config or a .bak of
	// ~/.aws/credentials holds the same secret as the original under a name bento
	// cannot enumerate. The stores themselves are directory shields, so a temp file
	// written BESIDE the original inside one is already covered; what is not is a copy
	// an editor leaves at the home root. Named here so the residual is on the record
	// rather than implied - re-check if a shape-based scan (see the hunting-tool bead)
	// makes the class enumerable.
	".*~":    "editor backup of an arbitrary dotfile; covered inside shielded directories, not at the home root, and not expressible as a concrete path",
	".*~1~":  "numbered emacs backup, same class as .*~",
	".*.swp": "vim swap file of an arbitrary dotfile, same class as .*~",
	".*.bak": "generic backup copy of an arbitrary dotfile, same class as .*~",
}

// excluded reports whether path is an intentional exclusion at the given home.
func excluded(path, home string) bool {
	return relLookup(path, home, IntentionalExclusions)
}

// reviewedGlob reports whether a glob path has a recorded coverage decision.
func reviewedGlob(path, home string) bool {
	return relLookup(path, home, ReviewedGlobs)
}

func relLookup(path, home string, m map[string]string) bool {
	rel, ok := strings.CutPrefix(path, strings.TrimSuffix(home, "/")+"/")
	if !ok {
		return false
	}
	_, ok = m[rel]
	return ok
}

// Audit reads firejail profile contents, diffs them against bento's full shield list
// (Home + Runtime), and partitions the in-scope gaps into: unclassified - concrete
// paths bento neither shields nor excludes PLUS any glob without a recorded coverage
// decision, the hard-fail set a human must resolve; and globs - wildcard directives
// listed in ReviewedGlobs, reported for periodic re-check but not hard-failed. An
// unreviewed glob hard-fails rather than becoming a note, so an inexpressible credential
// class (a bare *.key/*.kdbx in the top-secret section) cannot silently pass once the
// concrete backlog clears. outBySection summarizes the out-of-scope firejail sections
// bento does not enumerate, so they stay accountable. home and runUser expand firejail's
// ${HOME}/${RUNUSER}; the profile files are a dev-time diff input, never vendored.
func Audit(sources []Source, home, runUser string) (unclassified, globs []Gap, outBySection map[string]int) {
	var candidates []Candidate
	for _, s := range sources {
		candidates = append(candidates, s.Parse(s.Content, home, runUser)...)
	}
	rules := append(denylist.Home(home), denylist.Runtime()...)
	inScope, outBySection := SplitByScope(Diff(candidates, rules))
	for _, g := range inScope {
		if excluded(g.Path, home) {
			continue
		}
		// A recorded weaker-class decision clears only the Weaker report. If the same
		// path later goes missing entirely, that is a different finding and still fails.
		if g.Weaker && relLookup(g.Path, home, AcceptedWeaker) {
			continue
		}
		if g.Glob && reviewedGlob(g.Path, home) {
			globs = append(globs, g)
		} else {
			unclassified = append(unclassified, g)
		}
	}
	return unclassified, globs, outBySection
}

// cover finds a rule that shields path, returning it and true. An exact match wins;
// otherwise a directory rule whose path encloses it covers it.
func cover(path string, rules []denylist.Rule) (denylist.Rule, bool) {
	var best denylist.Rule
	found := false
	for _, r := range rules {
		if r.Path == path || (r.Dir && under(path, r.Path)) {
			// Prefer the strictest covering rule, so a DenyAll dir shield is not
			// reported Weaker because a DenyWrite rule also matched.
			if !found || r.Deny < best.Deny {
				best, found = r, true
			}
		}
	}
	return best, found
}

// under reports whether path is strictly inside dir.
func under(path, dir string) bool {
	return strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/")
}
