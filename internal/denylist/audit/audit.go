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
// are outside firejail's list and AppArmor's alike. The 21 developer token stores bento
// shields for that class were all found by hand while this audit was green, and
// re-measuring against AppArmor put its recall on that same set at 2 of 21 - so the class
// that motivated the second corpus is still the class neither corpus covers.
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
	"unicode"

	"github.com/whiskeyjimbo/bento/internal/denylist"
)

// Source is one upstream profile's content paired with the parser for its format.
// Formats differ enough that a single parser cannot serve both - firejail's scope comes
// from section headers, AppArmor's from mode letters and the file's purpose - so each
// corpus carries its own, and Audit diffs their combined candidates against one rule
// list. A plain function value rather than an interface: there is one method's worth of
// behavior here, and both parsers already have this shape.
//
// A parser returns what it DROPPED alongside what it kept: every drop is a directive that
// leaves the diff without being compared, and a corpus that quietly stops parsing reads
// exactly like a corpus with nothing left to find. Name is what the report calls the
// profile when it says so.
type Source struct {
	Name    string
	Content string
	Parse   func(content, home, runUser string) ([]Candidate, int)
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
	// Dir reports that the upstream directive was directory-shaped - firejail's trailing
	// slash, AppArmor's {,**} tail - so covering it takes a rule that shields the tree.
	// Carried because denylist.Covers answers an exact path match whatever the rule's
	// Dir is, which is right for enforcement and blind here: it is what lets the same
	// entry move from a directory list to the flat file list, narrowing the shield from
	// the whole tree to one inode with the ratchet still green.
	Dir bool
	// Section is what scope classification keys off: firejail's section-header comment
	// for a headed profile, or a constant naming the source where the format has no
	// headers. It separates bento's secret/exec threat model from an upstream's broader
	// privacy and other-app scope.
	Section string
	// Raw is the original upstream line, for the report.
	Raw string
}

// ScopeKeywords are the distinctive words of firejail's secret and exec section headers.
// They are the whole of what decides whether a headed profile's block is compared at all,
// which is why StaleKeywords exists to notice when one stops matching upstream. Exported
// beside DormantKeywords so the gates can name the set they are ratcheting.
var ScopeKeywords = []string{
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
}

// DormantKeywords are the ScopeKeywords that classify nothing in the current upstreams,
// each with the reason it is expected to stay silent. They name a firejail section whose
// entries are all outside ${HOME}/${RUNUSER}, so the parser produces no candidate for the
// diff to attribute to them - which is not the same as the keyword having gone stale, and
// StaleKeywords must not report them.
//
// Recorded rather than pruned: each names a class bento would want compared the moment
// firejail adds a home-relative path to it, and deleting the keyword is how that arrival
// would go unnoticed. A dormant keyword waking up is not a failure.
var DormantKeywords = map[string]string{
	"dm-crypt":            "the dm-crypt/LUKS block shields /dev/mapper and /etc paths only",
	"luks":                "same block as dm-crypt",
	"intrusion detection": "the IDS block shields /etc and /var config, no home entries",
	"session manager":     "the session-manager block shields system paths only",
	"openrc":              "the openrc block shields /etc/init.d and /run service state",
	"terminal emulator":   "the terminal-escape block shields system paths only",
}

// StaleKeywords reports the ScopeKeywords that match no section in the parsed upstreams
// and are not recorded dormant - the signal that an upstream retitled a section out from
// under the classifier.
//
// It exists because inScopeSection fails open: a retitled section bins its paths in the
// out-of-scope set, which the report only prints, so the parity gate stays green over a
// comparison that silently stopped being made. Quieter is the dangerous direction for a
// ratchet. SplitByScope's credentialName fallback catches part of that - a path matching a
// credential token still lands in scope - so a retitle goes fully silent only for the
// paths matching no token either; this closes the rest.
//
// It is deliberately not part of Audit: Audit runs against synthetic corpora in tests,
// where almost no keyword matches and staleness means nothing. Only the gates that read a
// real upstream call this.
func StaleKeywords(sources []Source, home, runUser string) []string {
	sections := map[string]bool{}
	for _, s := range sources {
		candidates, _ := s.Parse(s.Content, home, runUser)
		for _, c := range candidates {
			sections[strings.ToLower(c.Section)] = true
		}
	}
	var stale []string
	for _, kw := range ScopeKeywords {
		if _, dormant := DormantKeywords[kw]; dormant {
			continue
		}
		matched := false
		for s := range sections {
			if strings.Contains(s, kw) && !negatedKeyword(s, kw) {
				matched = true
				break
			}
		}
		if !matched {
			stale = append(stale, kw)
		}
	}
	sort.Strings(stale)
	return stale
}

// VanishedDormantKeywords reports the DormantKeywords whose word appears nowhere in the
// raw upstream text, sorted.
//
// A dormancy record is a claim about an upstream section that exists and happens to hold
// no home-relative path. It stops being self-certifying the moment upstream deletes that
// section: the keyword then matches nothing for a reason the record does not state, and
// the audit is exactly as quiet as it would be if the keyword had gone stale - the state
// StaleKeywords exists to refuse. Dormancy through CANDIDATES is unobservable, but
// through the raw text it is not.
//
// Deletion is what it catches, not a retitle: several of these words also appear in the
// section's own directive paths (/etc/dm-crypt, /run/openrc), so the block can be renamed
// with the word still present. StaleKeywords cannot see a dormant keyword either, so a
// retitled dormant section is the residual - accepted because the record's own subject is
// a section holding nothing bento would compare. Presence is checked across all sources
// rather than the one the record names, for the same reason: what is being tested is
// whether the word still means anything upstream, not which file carries it.
//
// A note rather than a gate: nothing is unshielded when a record goes vague, and the
// upstream word may legitimately survive in prose the classifier never reads. What the
// operator needs is to be told the record is no longer certifying anything.
func VanishedDormantKeywords(sources []Source) []string {
	var gone []string
	for kw := range DormantKeywords {
		present := false
		for _, s := range sources {
			if strings.Contains(strings.ToLower(s.Content), kw) {
				present = true
				break
			}
		}
		if !present {
			gone = append(gone, kw)
		}
	}
	sort.Strings(gone)
	return gone
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
	for _, kw := range ScopeKeywords {
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
// Matching is per component of the ${HOME}-relative path and case-insensitive, so a token
// catches an app's
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
func credentialName(rel string) bool {
	for comp := range strings.SplitSeq(strings.ToLower(rel), "/") {
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
	// Narrowed is set when the upstream directive covers a tree and bento's rule covers
	// only the path itself, so every child - including one a sandboxed run creates -
	// stays exposed.
	Narrowed bool
}

// ParseFirejail maps the blacklist/blacklist-nolog/read-only directives of a firejail profile into
// candidates, expanding ${HOME} and ${RUNUSER} and keeping only home- and
// runtime-scoped paths - bento's shield scope. System paths (/etc, /sbin, /usr),
// ${PATH} entries, and the non-shield directives (noblacklist, read-write, include,
// mkdir, rmenv, whitelist) are dropped: those are outside bento's home/runtime
// threat model, which its empty-root default already covers.
//
// The second return is the number of SHIELD directives - blacklist, blacklist-nolog,
// read-only - the parser could not turn into a candidate, which is a different thing from
// the deliberate drops above. A directive the parser does not understand leaves the diff
// silently, so an upstream that moves a block behind a spelling this parser misses reads
// as a corpus with fewer entries rather than as one that stopped being read.
func ParseFirejail(content, home, runUser string) ([]Candidate, int) {
	var out []Candidate
	dropped := 0
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
			// A shield keyword with no path is a line this parser was meant to read and
			// could not; anything else here is a directive with no argument, which shields
			// nothing under any spelling.
			if len(fields) == 1 && shieldKeyword(fields[0]) {
				dropped++
			}
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
			// The known non-shield directives (noblacklist, whitelist, include, mkdir...)
			// are a deliberate drop. A token that is none of them is a spelling this
			// parser does not recognise - a "?HAS_FOO:blacklist" with no space after the
			// colon is the cheapest live example - and one of those carrying a whole block
			// away is exactly what the count exists to make visible.
			if !firejailDirectives[fields[0]] {
				dropped++
			}
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
			// A system path or a ${PATH}/${CFG} entry is out of bento's scope by design and
			// not a drop worth counting - most of the corpus is that. An UNRECOGNISED
			// variable is: firejail renaming or adding one moves home-relative entries
			// behind a spelling expand answers "out of scope" to, and that answer is
			// indistinguishable here from the one /etc gets.
			if v := leadingVar(raw); v != "" && !knownFirejailVars[v] {
				dropped++
			}
			continue
		}
		out = append(out, Candidate{Path: path, Deny: deny, Glob: strings.ContainsAny(raw, "*?"), Dir: strings.HasSuffix(raw, "/"), Section: section, Raw: line})
	}
	return out, dropped
}

// knownFirejailVars are the profile variables whose scope is already decided: expand
// resolves the first two, and the rest name system locations bento's empty-root default
// covers. A variable outside this set is one nobody has classified, which is what the
// parser's dropped count exists to surface.
var knownFirejailVars = map[string]bool{
	"${HOME}": true, "${RUNUSER}": true, "${PATH}": true, "${CFG}": true, "${DESKTOP}": true,
}

// leadingVar returns the "${...}" token a directive's path starts with, or "" when it
// starts with anything else.
func leadingVar(raw string) string {
	if !strings.HasPrefix(raw, "${") {
		return ""
	}
	if i := strings.IndexByte(raw, '}'); i > 0 {
		return raw[:i+1]
	}
	return ""
}

// shieldKeyword reports whether a firejail directive keyword is one that shields a path -
// the directives this parser maps into candidates, as opposed to the ones it drops by
// design.
func shieldKeyword(k string) bool {
	return k == "blacklist" || k == "blacklist-nolog" || k == "read-only"
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
//
// The space after the colon is optional in firejail's grammar, so the token is cut at the
// colon rather than at the whitespace: "?HAS_X11:blacklist ..." otherwise reads as a
// directive keyword nothing recognises, and the whole conditional block leaves the diff.
func buildCondition(line string) string {
	if !strings.HasPrefix(line, "?") {
		return ""
	}
	i := strings.IndexByte(line, ':')
	if i < 0 || strings.ContainsFunc(line[:i], unicode.IsSpace) {
		return ""
	}
	return line[:i+1]
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
// covered). A glob candidate is passed to Covers as the literal pattern string - nothing
// here is glob-aware, since bento cannot express a wildcard rule - so a
// "${HOME}/.ssh/*"-shaped pattern is covered when a directory rule encloses its parent,
// which falls out of prefix matching, and one with a wildcard mid-path is covered by
// nothing. An unreviewed glob hard-fails, so the narrowness shows up as noise rather than
// as a silent pass.
//
// A candidate bento shields as DenyWrite while firejail blacklists it is reported as
// Weaker, not missing. A directory-shaped candidate covered only by a rule on the path
// itself is reported as
// Narrowed: Covers answers the exact match whatever the rule's Dir is, so without this
// moving an entry from a directory list to the flat file list - the same string, a
// different loop - shrinks the shield to one inode and the ratchet stays green.
func Diff(candidates []Candidate, rules []denylist.Rule) []Gap {
	var gaps []Gap
	for _, c := range candidates {
		covering, ok := denylist.Covers(c.Path, rules)
		if !ok {
			gaps = append(gaps, Gap{Candidate: c})
			continue
		}
		weaker := c.Deny == denylist.DenyAll && covering.Deny == denylist.DenyWrite
		narrowed := c.Dir && !covering.Dir
		if weaker || narrowed {
			gaps = append(gaps, Gap{Candidate: c, Weaker: weaker, Narrowed: narrowed})
		}
	}
	return gaps
}

// SplitByScope partitions gaps into the ones inside bento's secret/exec threat model and
// the rest - firejail's privacy/other-app/system scope, which bento does not enumerate.
// A gap is in scope by its firejail section, or - for the header-less profiles where that
// says nothing - by naming a known secret store. home is what the name classifier reads
// against: a token in the home DIRECTORY's own name says nothing about the paths beneath
// it, and classifying the absolute path put every gap under a /home/mailuser in the
// hard-fail set. The out-of-scope set is returned in full
// rather than counted, because a count cannot be read: the great majority of it is
// attributed to one file-header comment that classifies nothing, so a newly-added
// credential path there moves a number by one and is invisible even against a previous
// run. Both halves come back sorted by section then path so two runs diff.
func SplitByScope(gaps []Gap, home string) (inScope, outOfScope []Gap) {
	for _, g := range gaps {
		switch {
		case inScopeSection(g.Section):
			inScope = append(inScope, g)
		case credentialName(homeRel(g.Path, home)):
			g.Section = credentialSection
			inScope = append(inScope, g)
		default:
			outOfScope = append(outOfScope, g)
		}
	}
	bySectionThenPath(inScope)
	bySectionThenPath(outOfScope)
	return inScope, outOfScope
}

// bySectionThenPath orders gaps for a report that has to be diffable between runs: map
// iteration order is randomized, so anything grouped by section has to be sorted before
// it is printed or the diff is noise.
func bySectionThenPath(gaps []Gap) {
	sort.SliceStable(gaps, func(i, j int) bool {
		if gaps[i].Section != gaps[j].Section {
			return gaps[i].Section < gaps[j].Section
		}
		return gaps[i].Path < gaps[j].Path
	})
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

// homeRel returns the ${HOME}-relative remainder of a path, or the path itself when it is
// not under home. A runtime path is the only thing that reaches the fallback: runUser is
// /run/user/<uid>, whose components carry no classifier token, so there is nothing above
// it worth stripping and no home component to misread.
func homeRel(path, home string) string {
	if rel, ok := strings.CutPrefix(path, strings.TrimSuffix(home, "/")+"/"); ok {
		return rel
	}
	return path
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
// concrete backlog clears. outOfScope lists the gaps in the upstream scopes bento does
// not enumerate, so they stay accountable and a new entry among them is readable. home
// and runUser expand firejail's ${HOME}/${RUNUSER}; the profile files are a dev-time diff
// input, never vendored.
func Audit(sources []Source, home, runUser string) (unclassified, globs, outOfScope []Gap) {
	var candidates []Candidate
	for _, s := range sources {
		parsed, _ := s.Parse(s.Content, home, runUser)
		candidates = append(candidates, parsed...)
	}
	rules := append(denylist.Home(home), denylist.Runtime(runUser, home)...)
	inScope, outOfScope := SplitByScope(Diff(candidates, rules), home)
	for _, g := range inScope {
		if excluded(g.Path, home) {
			continue
		}
		// A recorded weaker-class decision clears only the Weaker report. If the same
		// path later goes missing entirely, that is a different finding and still fails -
		// and so is a co-occurring Narrowed, which is why the skip requires the gap to be
		// nothing BUT weaker. Upstream rewriting one of these files as a tree-shaped
		// directive is the live shape: bento's file rule then leaves every child exposed,
		// and the record that accepted the class says nothing about the shape.
		if g.Weaker && !g.Narrowed && relLookup(g.Path, home, AcceptedWeaker) {
			continue
		}
		if g.Glob && reviewedGlob(g.Path, home) {
			globs = append(globs, g)
		} else {
			unclassified = append(unclassified, g)
		}
	}
	return unclassified, globs, outOfScope
}
