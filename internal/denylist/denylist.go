// Package denylist declares the paths Bento shields no matter what a policy
// grants.
//
// The list is data, not code: it is platform-independent and testable on its
// own, while the backend decides how to enforce a rule (bind mounts on Linux,
// the only backend today). A policy that grants a broad path - say all of $HOME -
// must never expose these.
//
// # Adding a tool
//
// A tool integration is a category, not a path, and it has arrived in pieces every time
// it has been added ad hoc. mise took three commits: a whole-tree shield too broad to
// live with, then the actual trust record, then the file-shaped knobs that bypass it.
// Every tool since has had the same five parts. Walk them before adding the first rule:
//
//  1. The directory store - where the tool keeps state. Usually the obvious one, and
//     usually the only part that gets found without looking.
//  2. File-shaped config and trust knobs. A setting that pre-trusts a path, auto-answers
//     a trust prompt, or points at an extra config read with no trust check makes a
//     shield on the store alone bounded-looking and not bounded.
//  3. Env-var relocations of both. Anything the tool will read from a path named in the
//     environment belongs in the relocation table; a store shielded only where it sits by
//     default is one variable away from unshielded.
//  4. Any cache holding resolved exec paths. A cache of what to exec is a persistence
//     surface even when the config it came from is shielded.
//  5. Whether shielding it breaks ordinary in-sandbox use of the tool. DenyWrite has no
//     opt-out, so a store the tool writes on every routine invocation cannot be
//     write-shielded without making the tool unusable inside the sandbox. This is the
//     trap that produced mise's first commit: narrow to the record, or leave it and file
//     the residual.
//
// Item 5 is a real fork, not a rubber stamp - where it says no, the answer is a narrower
// rule plus a filed residual, not a broader one.
//
// This does not make new rules arrive less often. The set of tools is open-world, and
// the firejail/AppArmor parity audit measures 2-of-21 recall on developer token stores;
// the checklist only stops a tool that is already being added from landing in thirds.
package denylist

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/whiskeyjimbo/bento/policy"
)

// ManagedMounts are the pseudo-filesystems the sandbox mounts fresh for every run: a
// hardened procfs, a minimal devtmpfs, and a tmpfs, plus the fresh tmpfs (/dev/shm) and
// devpts (/dev/pts) that bwrap's --dev sets up implicitly underneath /dev. A grant
// naming one of these whole would --ro-bind the host's version over the sandbox's (bwrap
// applies mounts in argv order, last wins), re-exposing host /proc/<pid>/environ, the
// full host device set, or other processes' shared-memory or temp files.
//
// Data rather than a backend detail because both the run and the CI gate that predicts
// it have to agree on the set, and they are compiled for different platforms.
var ManagedMounts = []string{"/proc", "/dev", "/dev/shm", "/dev/pts", "/tmp"}

// IsProcessPath reports whether a resolved path is a per-process procfs directory or
// something inside one (/proc/<pid>/...). /proc itself and its system-wide files
// (/proc/cpuinfo) are not: those bind fine, and /proc whole is a ManagedMounts refusal.
//
// Here for the reason ManagedMounts is: the run and the CI gate that predicts it both
// refuse this shape, and they are compiled for different platforms.
func IsProcessPath(path string) bool {
	rel, err := filepath.Rel("/proc", path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return false
	}
	first, _, _ := strings.Cut(rel, "/")
	return first != "" && strings.IndexFunc(first, func(r rune) bool { return r < '0' || r > '9' }) < 0
}

// Deny is how completely a rule shields its path.
type Deny int

const (
	// DenyAll hides the path entirely: it cannot be read, written, or created.
	// Used for credentials and private keys, which a sandboxed script has no
	// business reading at all.
	DenyAll Deny = iota
	// DenyWrite leaves the path readable but not writable or creatable. Used for
	// files that are legitimately read (a shell profile, ~/.gitconfig) but whose
	// modification would give an attacker persistence or code execution.
	DenyWrite
)

// Rule is one shielded path.
type Rule struct {
	// Path is absolute.
	Path string
	// Deny is how completely the path is shielded.
	Deny Deny
	// Dir reports whether Path is a directory, in which case the rule covers
	// everything under it - including files that do not exist yet. Shielding the
	// directory rather than each known filename is what closes the "plant a new
	// credential file" hole.
	Dir bool
	// Holds is what the path contains, for the callouts that tell a reviewer what
	// lifting the shield exposes. Set on DenyAll rules only: a write shield cannot be
	// lifted by a grant, so no callout has to describe one.
	Holds Holds
	// Source names the environment variable that put the shield at this path, and is
	// empty for a rule at its default location.
	//
	// A relocation variable accepts any absolute path, so HISTFILE=/usr/bin/python3
	// blanks the interpreter and the run then fails with an ENOENT or a link error
	// attributed to the target. Bounding the target is not possible - there is no
	// principled rule for which paths a user may keep a history file at - so the
	// answer is to be able to say which variable caused it, which nothing could
	// reconstruct after the fact from the path alone.
	//
	// Diagnostic only. Nothing about how a rule is enforced may read it, or an
	// operator's environment would be deciding what the sandbox binds.
	Source string
}

// Holds names what a shielded path contains. The deny rules are all enforced the same
// way, so this exists purely for the sentence a reviewer reads while deciding whether to
// approve a grant that lifts the shield - which is the sentence that has to say what is
// behind it. Keyed on the rule and not on the reader so that every callout says the same
// thing about the same path.
type Holds int

const (
	// HoldsUnknown is the zero value, so a rule built without a classification reads as
	// vague rather than as a credential store it may not be. Callouts fall back to
	// naming it an always-shielded path, which is never wrong.
	HoldsUnknown Holds = iota
	// HoldsCredentials is key material: private keys, tokens, keyrings, vaults.
	HoldsCredentials
	// HoldsPrivateData is a store of the user's own content - saved logins, session
	// cookies, mail, wallets - too large to enumerate.
	HoldsPrivateData
	// HoldsHistory is a record of what was typed, pasted, or edited.
	HoldsHistory
	// HoldsPersistence is a path the host runs code from at the next login or session.
	HoldsPersistence
	// HoldsServices is the host's service control sockets: a directory of them (/run,
	// XDG_RUNTIME_DIR) or a single socket file (~/.zuluCrypt-socket).
	HoldsServices
)

// Code is the machine-readable spelling, for the surfaces that carry the bucket past a
// package boundary: the enforce seam (enforce.ShieldedGrant.Holds, which cannot name a
// type from internal/) and the JSON a gate switches on. Stable - the nouns above are
// prose and get reworded, these do not.
func (h Holds) Code() string {
	switch h {
	case HoldsCredentials:
		return "credentials"
	case HoldsPrivateData:
		return "private-data"
	case HoldsHistory:
		return "history"
	case HoldsPersistence:
		return "persistence"
	case HoldsServices:
		return "services"
	case HoldsUnknown:
		// Named so the exhaustive check holds, and left to fall through: the answer below
		// is HoldsUnknown's as much as it is an out-of-range value's.
	}
	return "unknown"
}

// HoldsByCode reads a Code back, for a frontend turning what a backend reported into the
// prose of Noun and Exposure. An unrecognized code reads as HoldsUnknown, whose wording
// is true of every shielded path.
func HoldsByCode(code string) Holds {
	for _, h := range []Holds{HoldsCredentials, HoldsPrivateData, HoldsHistory, HoldsPersistence, HoldsServices} {
		if h.Code() == code {
			return h
		}
	}
	return HoldsUnknown
}

// Noun names the store, for a sentence about one path.
func (h Holds) Noun() string {
	switch h {
	case HoldsCredentials:
		return "credential store"
	case HoldsPrivateData:
		return "private data store"
	case HoldsHistory:
		return "history store"
	case HoldsPersistence:
		return "host-startup path"
	case HoldsServices:
		// Not "directory": the bucket also holds single socket files, and a noun naming a
		// directory sends a reader looking for contents that are not there.
		return "service socket path"
	case HoldsUnknown:
	}
	return "always-shielded path"
}

// Exposure completes a sentence about lifting the shield: "... which lets the script
// <Exposure>". It is carried beside the noun because the callouts name a consequence as
// well as a store, and a consequence written for credentials ("read the credentials in
// it") misdescribes the other buckets exactly as the noun does.
func (h Holds) Exposure() string {
	switch h {
	case HoldsCredentials:
		return "read the credentials in it"
	case HoldsPrivateData:
		// Hedged rather than enumerated: the bucket runs from browser cookie jars to
		// mail to wallets to a decrypted home, so a clause naming three of those
		// misdescribes the rest the way "credentials" misdescribed this bucket - but
		// several of them do hold a password or a key, and the sentence must not read
		// as softer than the credential one for the stores where it is the same thing.
		return "read the private data in it, which for many of these stores includes saved passwords and keys"
	case HoldsHistory:
		return "read what was typed, pasted, and edited on this host"
	case HoldsPersistence:
		return "read the session layout the host runs code from at the next login"
	case HoldsServices:
		// Hedged with "such as" rather than enumerated, because the bucket runs from a
		// directory of every session socket down to one tool's IPC socket, and a clause
		// listing three daemons misdescribes the single-socket end of it.
		return "reach the host services behind it, such as the container daemon, the session bus, and the agent sockets"
	case HoldsUnknown:
	}
	return "read what bento shields there"
}

// HomeAnchors returns the home directories the shields anchor on: $HOME and the passwd
// entry for the running uid, cleaned and deduplicated, $HOME first.
//
// Anchoring on $HOME alone lets the environment decide where the shields land, and a
// caller that chooses it (a CI job, an agent supervisor) can move them off the real
// credential stores just by exporting HOME=/ - the run still reports shields, they just
// cover nothing. Anchoring on passwd alone breaks the hosts where $HOME is the truth:
// containers, nix shells, sudo -H, CI images with no passwd entry for the uid. The union
// costs a handful of extra bind mounts, and where both answer, neither anchor can be
// dodged by moving the other.
//
// Where only one answers the union is one anchor wide, and on a host with no passwd entry
// that anchor is the environment's. So HOME=/ is refused outright rather than accepted as
// the anchor of last resort: an anchor at the root is not a home whose stores are covered
// but a home whose rules land on /bin, /Applications and the mail spool - which the
// degraded tier's Landlock enforces for real. Both sources are held to it: dropping "/"
// leaves the passwd entry as the anchor where that answers something else, and no anchors
// at all where it does not, which is the refusal below. Shieldable refuses "/" as a rule TARGET for the same reason; this is the
// same refusal one level up, at the anchor.
//
// It lives here, beside the rules it anchors, because every consumer has to agree on the
// answer: a profiler that clamps its proposal against a different home than the enforcer
// shields drafts manifests the enforcer then refuses.
//
// The passwd lookup must not route through libc NSS, where LD_PRELOAD would put it back
// under the caller's control - the shipped builds pass -tags osusergo for exactly that.
func HomeAnchors() ([]string, error) {
	var homes []string
	// os.UserHomeDir returns $HOME verbatim, which a caller can leave unset or set to a
	// relative path. The shields join onto it, so a relative home yields relative
	// Rule.Path values that a backend would apply at the wrong (or no) location, silently
	// leaving the real credential dirs exposed - so an unusable value is dropped rather
	// than shielding air.
	home, err := os.UserHomeDir()
	if err == nil && filepath.IsAbs(home) && filepath.Clean(home) != "/" {
		homes = append(homes, filepath.Clean(home))
	}

	if pw := PasswdHome(); pw != "" && pw != "/" && !slices.Contains(homes, pw) {
		homes = append(homes, pw)
	}
	if len(homes) == 0 {
		// Nothing left to anchor on, so there would be no credential shields at all. That
		// is the one case worth refusing over: a run with no shields is not the boundary
		// bento claims, and it is indistinguishable at the report from a run whose grants
		// simply reached none.
		return nil, fmt.Errorf("denylist: no usable home directory: $HOME is %q and the passwd database gives %q for uid %d", home, PasswdHome(), os.Getuid())
	}
	return homes, nil
}

// PasswdHome returns the home directory the passwd database gives the running uid, or
// "" when there is none to be had.
//
// A uid with no passwd entry is normal (an LDAP/SSS host whose module is not loaded, a
// container running an unmapped uid), and refusing to run there would break hosts that
// $HOME alone shields correctly - so HomeAnchors degrades to $HOME rather than aborting.
// That costs the one anchor the caller cannot move, which is why doctor reports whether
// this answered: the operator cannot tell from the shield count alone.
func PasswdHome() string {
	u, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil || !filepath.IsAbs(u.HomeDir) {
		return ""
	}
	return filepath.Clean(u.HomeDir)
}

// RuntimeDir returns the host's XDG runtime directory, or "" when the environment
// names none usable. It is resolved here, beside the rules it feeds, for the same
// reason HomeAnchors is: Runtime takes the resolved value so every consumer shields the
// same directory, and so the completeness audit's rule set does not depend on the
// environment of whoever runs it.
//
// A relative value is dropped: the shield is an absolute bind, so it cannot cover a path
// it cannot name, and shielding a relative path would silently bind at the wrong place.
func RuntimeDir() string {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if !filepath.IsAbs(dir) {
		return ""
	}
	return filepath.Clean(dir)
}

// UnshieldableRuntimeDir returns XDG_RUNTIME_DIR as the environment spells it when the
// variable is set but no shield can follow it there, and "" otherwise - including when it
// is unset, where there is nothing to shield and nothing to say.
//
// Two values reach that state and RuntimeDir cannot tell them apart from an unset one,
// because it answers with a path and both of these have none to give: a RELATIVE value
// (hand-rolled container entrypoints write these), which an absolute bind cannot cover,
// and a value at or above a home anchor, where the rule would hide the whole grant
// surface. Either way the run keeps only /run and /var/run, and the rule count alone reads
// exactly like an ordinary host's - so the caller that reports it needs the raw spelling
// and needs to know the variable was set at all.
//
// Not a refusal: XDG_RUNTIME_DIR=$HOME is normal on the minimal containers bento runs in.
func UnshieldableRuntimeDir(homes []string) string {
	raw := os.Getenv("XDG_RUNTIME_DIR")
	if raw == "" {
		return ""
	}
	if dir := RuntimeDir(); dir == "" || !Shieldable(dir, homes) {
		return raw
	}
	return ""
}

// Shieldable reports whether a relocation target can carry a deny rule at all, given the
// run's home anchors.
//
// A target that is the root, one of the homes, or an ancestor of one cannot be shielded:
// the rule would hide or ro-bind the entire grant surface, so nothing the policy granted
// stays reachable and every other rule is subsumed by this one. The consumers already
// drop a rule resolving to "/" for the same reason (see the Linux backend's denyArgs),
// and the ZDOTDIR relocation declines the home itself; this applies the rule to the
// credential relocations too, where a stray GNUPGHOME=$HOME would otherwise replace the
// whole deny-list with one DenyAll on the home - which also silently nullifies the
// completeness audit, since it leaves no per-store rule left to compare against
// firejail's.
//
// The test is lexical - it compares the spellings it is handed and resolves nothing - so
// an alias for a home (/home a symlink to /export/home, or a plain symlink to $HOME)
// passes here while naming the very tree the test exists to protect. Callers that
// ENFORCE a rule close that themselves by re-testing the resolved path against the
// resolved homes (see the Linux backend's denyArgs), which is the only place the two
// spellings are both known. Callers that only READ the rule set - the parity audit, the
// credential hunt - are safe for a different reason: they compare lexically too, and a
// rule that cannot lexically enclose an anchor cannot lexically cover anything walked
// from one, so the worst case is an inert rule. Teaching a reader to resolve without
// teaching it to re-test here would turn that inert rule into a shield over a whole home.
func Shieldable(p string, homes []string) bool {
	if p == "/" {
		return false
	}
	for _, h := range homes {
		if p == h || strings.HasPrefix(h, p+string(filepath.Separator)) {
			return false
		}
	}
	return true
}

// Home returns the mandatory rules for a user's home directory.
//
// A credential store that is a directory is shielded whole on purpose. Naming
// individual files (~/.ssh/id_rsa) leaves siblings exposed (~/.ssh/my_deploy_key)
// and cannot stop a script from creating a new file in the directory. The file
// entries below are the stores that are genuinely one file, whose parent holds
// unrelated content the tool needs - there is no directory to take.
//
// These are anchor-relative and nothing else: a run with two home anchors calls this
// once per anchor and gets two sets of paths, which is the point. The rules an
// environment variable relocates to an ABSOLUTE path belong to the run rather than to
// an anchor, so they come from Relocated, which a caller runs once over the whole
// anchor set.
func Home(home string) []Rule {

	dirGroups := []struct {
		holds Holds
		dirs  []string
	}{
		{HoldsCredentials, credentialAnchorDirs},
		{HoldsPrivateData, bulkStoreDirs},
		{HoldsHistory, historyDirs},
		{HoldsPersistence, persistenceDirs},
		{HoldsServices, serviceDirs},
	}
	credentialFiles := []string{
		".git-credentials",
		".config/git/credentials", // XDG location for the same
		".netrc",
		".npmrc",
		".pypirc",
		".my.cnf",      // MySQL client option file, commonly holds a plaintext password
		".mylogin.cnf", // mysql_config_editor login paths; obfuscated, not encrypted, and read by default
		".gem/credentials",
		".cargo/credentials.toml",
		".vault-token",
		".pgpass",         // PostgreSQL passwords
		".s3cfg",          // s3cmd keys
		".boto",           // legacy AWS/GCP credentials
		".databrickscfg",  // Databricks tokens
		".smbcredentials", // SMB/CIFS mount credentials
		".config/hub",     // hub CLI OAuth token
		// Coding-agent credential files. Their trees are DenyWrite above so the agent can
		// still read its own configuration; the token inside must not be readable, and
		// denyArgs emits DenyWrite before DenyAll so this hide lands after that bind.
		".claude/.credentials.json",        // Claude Code OAuth token
		".codex/auth.json",                 // Codex CLI OAuth token
		".gemini/oauth_creds.json",         // Gemini CLI OAuth token
		".gemini/google_accounts.json",     // the account identities beside it
		".gemini/mcp-oauth-tokens-v2.json", // per-MCP-server OAuth tokens
		".codeium/config.json",             // the Codeium/Windsurf plugin's API key
		// goose keeps provider API keys in the OS keyring where there is one and falls back
		// to this file where there is not - a headless host, or GOOSE_DISABLE_KEYRING, which
		// is the shape a sandbox runs on. The tree around it is DenyWrite with the other
		// agent config trees, so the agent still reads its own settings.
		".config/goose/secrets.yaml",
		// opencode splits the two: the config is under .config/opencode, DenyWrite with
		// the other agent config trees, and the provider tokens land here.
		".local/share/opencode/auth.json",
		// Claude Code keeps its account/OAuth block in the SAME file as the global
		// configuration, so the tree-DenyWrite/credential-DenyAll split above cannot
		// separate them. Hidden rather than write-denied: the secret wins over the config
		// read, the .msmtprc/.muttrc precedent. A sandboxed claude loses its own settings,
		// which is the trade - the alternative hands a broad read grant a live token.
		// The CLI also writes backups beside it holding the same block. The suffix-less
		// one has a concrete name and is shielded; the .claude.json.backup.<epoch>
		// siblings do not, and stay the same residual class as an editor leaving at the
		// home root. Enumerating them here is not the missing piece: these rules are
		// pure path arithmetic that the profiler's clamp, the credential hunt and the
		// firejail audit each derive independently, and a host read would make all four
		// disagree. Nor would enumeration close the class - bwrap binds concrete paths
		// at launch over a live home, so a backup the host CLI writes mid-run appears
		// inside the sandbox unshielded whatever the rule list said.
		".claude.json",
		".claude.json.backup",
		// ollama generates an ed25519 keypair to identify the host to a model registry.
		// Only the keys are named, not the whole ~/.ollama: the tree's bulk is pulled
		// models, which a sandboxed run may legitimately read, and the walletKeyPaths
		// entries make the same narrowing for the same reason.
		".ollama/id_ed25519",
		".ollama/id_ed25519.pub",
		// Mail/registry configs whose dominant content is a plaintext credential and
		// whose tool is rarely a sandboxed target: hidden (not just write-denied) so a
		// sandboxed run cannot read the secret, which also neutralizes their exec knobs
		// (msmtp passwordeval, mutt source-pipe). Matches the .netrc/.npmrc precedent.
		".msmtprc",    // SMTP passwords (msmtp enforces 600 and refuses a readable one)
		".muttrc",     // often holds plaintext imap_pass
		".yarnrc.yml", // yarn 2+ stores npmAuthToken here (like .npmrc)
		// R loads .Renviron (name=value) into the session env at startup; it routinely
		// holds plaintext API keys and DB passwords. Hidden, not just write-denied, so a
		// broad read grant cannot read the secret - which also neutralizes its exec knob
		// (a line can point R_PROFILE_USER at a writable file). R is rarely a sandboxed
		// target, so hiding it is unlikely to break a real in-sandbox workflow. The
		// sibling .Rprofile stays DenyWrite: it is R code R sources, the .vimrc analog.
		".Renviron",

		// Build-tool credential files. Each sits inside a directory whose bulk is a
		// package cache a sandboxed build legitimately reads, so the FILE is shielded and
		// the tree is left alone - shielding ~/.m2 or ~/.gradle wholesale would break
		// ordinary in-sandbox builds to hide one file. firejail lists none of these, so
		// the completeness ratchet cannot surface them.
		".terraformrc",              // credentials blocks with Terraform Cloud/Enterprise tokens
		".m2/settings.xml",          // Maven <server> passwords, often plaintext
		".gradle/gradle.properties", // signing keys and repository credentials
		".composer/auth.json",       // Composer registry/VCS tokens
		".bundle/config",            // bundler stores gem-source and push credentials here
		".nuget/NuGet/NuGet.Config", // NuGet apikeys (the ~/.nuget/packages cache stays readable)
		".ivy2/.credentials",        // Ivy resolver credentials (the ~/.ivy2 cache stays readable)
		".sbt/.credentials",         // sbt's conventional credentials file, same shape

		// Credential files various tools read by default.
		// The age private key sops reads by default: it decrypts every sops-encrypted file
		// in the user's repos, so the ciphertext a run can already read is worth nothing
		// without it and everything with it. The .config/sops tree beside it is ordinary
		// config, so the file is shielded on its own.
		".config/sops/age/keys.txt",
		// Pulumi Cloud access token, the .terraform.d/credentials.tfrc.json analog; the
		// rest of ~/.pulumi is plugins and workspace state an in-sandbox run reads.
		".pulumi/credentials.json",
		".fetchmailrc",       // fetchmail account password
		".davfs2/secrets",    // davfs2 mount credentials
		".cargo/credentials", // legacy cargo registry token (pre-credentials.toml)
		".passwd-s3fs",       // s3fs password file
		".s3cmd",             // s3cmd state firejail blacklists (the .s3cfg config file is shielded above)

		// Mail-client config files whose dominant content is an account password.
		".gist",                  // defunkt/gist stores the GitHub OAuth token as the file's whole content
		".mcabberrc",             // mcabber XMPP config, holds the account password
		".pinerc",                // pine/alpine config, which carries the account password inline
		".pinercex",              // its per-host companion
		".config/mailtransports", // Akonadi SMTP transports, incl. stored passwords
		"wallet.dat",             // Bitcoin Core wallet at the home root: the spending keys

		// The X11 display-access cookie: reading it grants control of the live X session
		// (keylog, screenshot, inject events), so it is a credential, not a config. Hidden,
		// not merely read-only as firejail has it - a bento sandbox has no X display to
		// authenticate to, so there is no legitimate in-sandbox read.
		".Xauthority",
		// Credential files various tools read by default, the .netrc class one tool out.
		// Each is hidden rather than write-denied for the reason .netrc and .npmrc are: the
		// dominant content is a plaintext secret, and hiding it also neutralizes whatever
		// command the same file names.
		".authinfo",     // Emacs auth-source, the documented sibling default of .netrc
		".authinfo.gpg", // the encrypted spelling; still key material, still no in-sandbox read need
		// Mercurial's user config at both spellings it reads. [auth] holds plaintext
		// passwords and [hooks]/[extensions] name host commands; git is otherwise the only
		// VCS shielded.
		".hgrc",
		".config/hg/hgrc",
		".ansible/galaxy_token",      // the token only: the collections cache beside it is what an in-sandbox ansible reads
		".curlrc",                    // --user user:pass lives here and curl reads it by default
		".config/curlrc",             // the XDG spelling curl has read since 7.73
		".wgetrc",                    // password= lives here, same
		".ansible.cfg",               // galaxy_token, plus the library/roles_path/vault_password_file exec knobs
		".config/pypoetry/auth.toml", // registry tokens when no keyring is available
		".bunfig.toml",               // [install] registry token, the .npmrc/.yarnrc.yml case
		".dbt/profiles.yml",          // warehouse passwords, the .pgpass class

		// The ICE session-manager cookie is the same capability for the session-management
		// channel (a client authenticating with it can drive session restart/shutdown and
		// talk to session peers), and a sandbox has no session to join either.
		".ICEauthority",
	}

	// The user's own content rather than key material: mail bodies, the addresses an
	// account sends as, the local search index over them.
	privateDataFiles := []string{
		// Password-manager and wallet CONFIG files, hidden alongside the stores they point
		// at: each names the vault's location and its recently-opened entries. That is
		// reconnaissance, not key material - the secret itself lives in the shielded store -
		// so a callout promising the credentials in it sends a reviewer after something
		// that is not there.
		".config/KeePassXCrc",
		".config/kwalletrc",
		".config/plasmavaultrc",        // names the vaults whose store is shielded above
		".kde/share/config/kwalletrc",  // legacy KDE location
		".kde4/share/config/kwalletrc", // KDE4 location

		// KMail's general config: account structure and identity pointers. The passwords
		// live in KWallet and .config/mailtransports, which are shielded on their own.
		".config/kmail2rc",
		".config/emaildefaults",
		".config/emailidentities",
		".config/kmailsearchindexingrc",
		".config/specialmailcollectionsrc",
		".pine-interrupted-mail", // an interrupted draft: message body on disk

		// Mail message stores and identity. mutt's default mailbox files/dirs and the
		// signature; message bodies carry reset links and 2FA codes, and a signature can
		// carry a PGP fingerprint or contact PII. The maildir roots ~/Mail and ~/mail are
		// shielded as directories above.
		"postponed",  // mutt default postponed-message mbox at ~/postponed
		"sent",       // mutt sent-mail mbox at ~/sent
		".signature", // outgoing-mail signature
	}

	// zuluCrypt's IPC control socket, a channel to the daemon that manages encrypted
	// volumes (the .zuluCrypt store dir is shielded above).
	serviceFiles := []string{".zuluCrypt-socket"}

	// Graphical-session scripts and generated startup configs firejail blacklists: each
	// is read or executed at login and a planted line runs on the host. Hidden to match
	// firejail and the WM trees above.
	// Graphical-login scripts (X11) belong here too: shell code run at graphical login,
	// hidden rather than merely write-denied because there is no in-sandbox read need and
	// hiding blocks both planting and reconnaissance. (Wayland persistence routes through
	// the systemd/autostart dirs above.)
	persistenceFiles := []string{
		// Remote-login trust: the contents name the hosts and users allowed in without a
		// password, so a planted line is host login at the attacker's convenience. Not key
		// material - the callout would send a reviewer looking for a secret that is not
		// there - and sshd treats these as security-sensitive for the same reason.
		".rhosts",
		".shosts",

		".xprofile",
		".xinitrc",
		".xsession",
		".xsessionrc",                          // sourced by the Debian/Ubuntu Xsession startup, like .xsession
		".Xresources",                          // xrdb-loaded resources (read at login)
		".Xsession",                            // capitalized X session script variant
		".gnomerc",                             // sourced at GNOME login
		".xserverrc",                           // startx-run X server launch script
		".config/lxsession/LXDE/autostart",     // LXDE session autostart commands
		".config/startupconfig",                // KDE generated startup config
		".config/startupconfigkeys",            // KDE generated startup keys
		".kde/share/config/startupconfig",      // legacy KDE generated startup config
		".kde/share/config/startupconfigkeys",  // legacy KDE generated startup keys
		".kde4/share/config/startupconfig",     // KDE4 generated startup config
		".kde4/share/config/startupconfigkeys", // KDE4 generated startup keys
	}

	historyFiles := []string{
		// Shell and REPL history: command lines and pasted secrets. Shielded as files
		// (not their parent dir) so a sibling config the tool also reads stays available.
		".lesshst",
		".histfile",
		".python_history",          // CPython's default readline REPL history (underscore is the real name)
		".python-history",          // dash-spelled variant some REPLs write
		".pythonhist",              // bpython history
		".cache/greenclip.history", // greenclip clipboard-manager history: holds pasted secrets
		".mupdf.history",
		".cache/mupdf.history",
		".mutthistory",
		".ammonite/history",
		".local/share/fish/fish_history",
		".viminfo", // holds registers and search history, which can carry yanked secrets
		// The named instances of firejail's ${HOME}/.*_history glob, which a concrete-path
		// shield cannot express. Database-client histories are the sharpest: a password
		// typed into a SQL/redis session lands here in the clear.
		".bash_history",
		".zsh_history",
		".history",     // tcsh's default history file (histfile unset); .cshrc/.tcshrc are shielded, so the shell is in scope
		".sh_history",  // ksh's default HISTFILE; .kshrc/.mkshrc are shielded
		".php_history", // php -a interactive shell readline history
		".mysql_history",
		".psql_history",
		".sqlite_history",
		".node_repl_history",
		".rediscli_history",
		".irb_history",
		".scala_history",
	}
	// Modifying any of these grants persistence or code execution on the host the
	// next time the user opens a shell or runs git. Reads stay allowed: git
	// legitimately reads ~/.gitconfig, and blinding it breaks real work.
	writeOnly := []string{
		// Shell startup and shutdown files: read when a shell starts or exits. The
		// default .bashrc sources .bash_aliases, which is usually absent and so
		// plantable (a write grant creates it and the next bash runs it).
		".bashrc",
		".bash_profile",
		".bash_login", // bash login shells read the first of bash_profile/bash_login/.profile
		".bash_aliases",
		".bash_logout",
		// The bash-completion package's main script, sourced unconditionally by the
		// distro /etc/bash.bashrc for every interactive shell. Usually absent, so the
		// same plantable-because-absent case as .bash_aliases above.
		".bash_completion",
		// sensible-editor and select-editor source this and run $SELECTED_EDITOR, so a
		// planted value runs at the next `git commit`, `crontab -e` or `visudo` on a host
		// with no $EDITOR set. The .mailcap analog: a config that names a command.
		".selected_editor",
		".zshenv", // zsh reads this for EVERY invocation, including non-interactive
		".zshrc",
		".zprofile",
		".zlogin",
		".zlogout",
		".profile",
		// PAM login environment: pam_env can set LD_PRELOAD/PATH for the whole session
		// from here. Deprecated and default-off on modern Linux-PAM (user_readenv
		// defaults off since 1.4.0), but still present and live on older hosts, so
		// shield it cheaply.
		".pam_environment",
		// Tool configs that define a command run on a common host action.
		".gitconfig",
		".config/git/config", // XDG location git reads the same as ~/.gitconfig
		".cargo/config.toml", // cargo build/run honors build.rustc-wrapper, target runners, [target] linker
		".cargo/config",      // legacy (pre-1.39) cargo config filename, still read
		".cargo/env",         // shell script rustup makes .profile source; runs on next shell
		// `go env -w GOFLAGS=-toolexec=...` writes this file, and every later host `go
		// build` then execs the named binary. No script and no approval record in between.
		".config/go/env",
		".vimrc",               // sourced when vim opens a file
		".exrc",                // vim also sources this (ex/vi rc) on startup
		".gvimrc",              // gvim rc, sourced on gvim startup
		".emacs",               // elisp run at emacs startup
		".emacs.el",            // alternate emacs init filename
		".screenrc",            // GNU screen runs commands from it
		".gdbinit",             // executed by gdb on startup
		".tmux.conf",           // run-shell hooks execute on tmux start
		".direnvrc",            // legacy direnv global rc (XDG dir shielded below)
		".mailcap",             // maps MIME types to commands run on attachment open
		".yarnrc",              // yarn-path names a binary yarn execs (classic; rarely holds a token)
		".config/pip/pip.conf", // index-url can redirect installs to a malicious registry; readable but not writable
		".pip/pip.conf",        // legacy per-user pip config, also read by default (same index-url redirect)
		".config/uv/uv.toml",   // uv's index url/extra-index-url, pip.conf's redirect in the newer installer
		".aider.conf.yml",      // aider's config names the editor and test/lint commands it runs
		".xscreensaver",        // names programs run as screensavers
		".psqlrc",              // \! runs a shell command when psql starts
		".Rprofile",            // R sources it at startup (.Renviron holds the secrets and is DenyAll above)
		".mcp.json",
		// Subversion's config names diff-cmd/editor-cmd helper binaries. It carries no
		// secret of its own - those are under the .subversion/auth shield - so it is
		// readable and plant-denied rather than hidden, the .gitconfig treatment.
		".subversion/config",

		// Additional shell startup files: read when the matching shell starts or a login
		// session opens; a planted or modified line runs on the host next time.
		".cshrc",       // csh/tcsh rc
		".tcshrc",      // tcsh rc
		".kshrc",       // ksh rc
		".mkshrc",      // mksh rc
		".login",       // csh login shell
		".logout",      // csh logout
		".zshrc.local", // sourced by ~/.zshrc on several distros
		".forward",     // a leading "|command" line runs on local mail delivery
		".inputrc",     // readline init: a macro binding runs a command on a keypress

		// Files a shell rc sources by name, planted by the installer that appended the
		// source line. The rc itself is write-denied above; the file it reaches for is not
		// covered by that, and is usually absent on a host that never ran the installer -
		// the .bash_aliases case, one layer out.
		".p10k.zsh",  // powerlevel10k config, sourced verbatim by the line its wizard writes
		".zpreztorc", // prezto's rc, sourced by the .zshrc its installer links
		".fzf.zsh",   // fzf's installer appends `[ -f ~/.fzf.zsh ] && source ~/.fzf.zsh`
		".fzf.bash",  // the bash half of the same

		// Tool configs that name or run a command on a routine action.
		".caffrc",                // caff/gpg options
		".config/ncmpcpp/config", // execute_on_song_change runs a shell command
		".pythonrc.py",           // sourced at interactive python startup (PYTHONSTARTUP convention)
		".config/mimeapps.list",  // default-application map; redirects an open to a planted .desktop
		".config/user-dirs.dirs", // sourced by xdg-user-dirs-update; a shell-injection line runs

		// Read-only in firejail: single init/config files whose modification redirects a
		// later action (a browser profile pointer, an editor rc) or whose write-protection
		// prevents tampering. Readable, plant/tamper-denied.
		".nanorc",                  // nano rc (include/syntax directives)
		".iscreenrc",               // iscreen rc
		".reportbugrc",             // Debian reportbug config
		".config/user-dirs.locale", // locale for xdg user-dirs (write-protected against redirection)
		// .Xdefaults only, though .Xresources is the same xrdb resource format: upstream
		// blacklists that one and merely write-protects this one, and the audit ratchet
		// holds bento to it. So a read: grant on .Xresources is refused where the same grant
		// on .Xdefaults is honored, which is upstream's distinction rather than a slip here.
		".Xdefaults",
		// Public finger(1) info files: not secrets and not executed, so left readable, but
		// write-protected so a broad home write grant cannot tamper with published info.
		".plan",
		".project",
		".pgpkey",
	}

	// Directories whose contents run on the host at the next login, shell start, or
	// editor/tool invocation. Reads stay allowed (a script may legitimately inspect
	// them); creating or modifying an entry is what grants persistence, so writes are
	// denied. These are shielded as whole directories because their autoloaded/plugin
	// files cannot be pre-enumerated - a not-yet-created entry is still plantable, the
	// same reason git hooks are shielded as a directory.
	writeOnlyDirs := []string{
		".bashrc.d", // Fedora/RHEL default .bashrc sources ~/.bashrc.d/*.sh; a planted entry runs on next shell (.bashrc itself is write-shielded, but the loop only checks the dir exists)
		".local/share/bash-completion/completions", // per-command completion scripts, sourced the first time the user tab-completes that command name; planting `git` here runs on the host at the next git
		".config/environment.d",                    // systemd user-session env (LD_PRELOAD, PATH, ...)
		".config/fish",                             // config.fish, conf.d/*.fish, autoloaded functions/*.fish (planting ls.fish hijacks `ls`)
		".config/nushell",                          // config.nu/env.nu and autoloads
		".vim",                                     // plugin/, autoload/, after/plugin/ are auto-sourced
		".config/nvim",                             // init.{vim,lua}, lua/, plugin/, after/
		".emacs.d",                                 // init.el and site-lisp
		".config/emacs",                            // XDG location for the same
		".config/gdb",                              // gdb 11+ reads gdbinit/gdbearlyinit here
		".config/tmux",                             // XDG location for tmux.conf
		".config/direnv",                           // direnvrc, sourced on cd for direnv users, and direnv.toml's [whitelist] skips the allow check entirely
		".local/share/direnv/allow",                // authorization records: an entry pre-approves a workspace .envrc
		// mise is direnv's shape: an in-tree mise.toml is inert until trusted, and a
		// symlink under state/trusted-configs is the per-host record of that trust. Deny
		// the record and every workspace config mise would have auto-executed is covered
		// at once, including workspaces this run never touched.
		//
		// Both halves are needed. The config directory holds the settings that bypass the
		// record - trusted_config_paths pre-trusts a path outright, and `yes` auto-answers
		// the trust prompt - so shielding the record alone leaves a bounded-looking shield
		// that is not. The three file-shaped knobs that do the same are in
		// startupDefaultEnvs, which is where a config mise reads with no trust check at
		// all belongs.
		//
		// The cost, which is the point of the shield rather than a side effect: a run that
		// meets a workspace mise.toml nobody has trusted yet cannot trust it, and every
		// mise call there then fails rather than degrading. Exporting
		// MISE_TRUSTED_CONFIG_PATHS for the run itself is the in-sandbox way through, and
		// it grants nothing on the host.
		//
		// The record is the trusted-configs directory rather than the state tree around
		// it, which is the ~/.m2 and ~/.gradle line: mise writes a symlink under
		// state/tracked-configs on every ordinary `mise x` or `mise install`, and a
		// DenyWrite shield has no opt-out, so taking the tree makes every in-sandbox mise
		// invocation warn twice about a directory it cannot create. It degrades rather
		// than failing, which is exactly why it is not worth the noise: tracked-configs
		// grants no trust. The config directory IS taken whole, because both spellings
		// mise reads settings from (config.toml and settings.toml) carry the bypass.
		//
		// The cache is the third half, and it is .cache/pre-commit's shape rather than
		// ~/.cargo/registry's: ~/.cache/mise/<tool>/<version>/bin_paths-*.msgpack.z is the
		// resolved list of directories mise puts on $PATH, read with NO trust check once a
		// config is trusted. Rewriting one made `mise x -- jq` run a planted jq in an
		// already-trusted project against mise 2026.7.18, reaching neither the record nor
		// the config directory above. A cache read back by a build stays writable; this one
		// decides which binary executes.
		//
		// Taken whole because the bin_paths files sit at <tool>/<version>/, a wildcard no
		// Rule can express - the same reason sdkman's candidates/*/current/bin is left as a
		// residual below.
		//
		// The cost is larger than the record's and is the .cache/pre-commit trade: with the
		// cache read-only `mise install` fails outright ("Permission denied (os error 13)")
		// and lands nothing. The shims shield alone does not stop it - an unshielded cache
		// leaves a usable tool installed - so this is where in-sandbox installing ends.
		// `mise x`, `mise env` and `mise ls` on an already-installed tool are unaffected.
		// Run the installs outside bento, the same line the $PATH shims block takes.
		//
		// Residual: mise also takes cache_dir from a settings key in .config/mise, which no
		// env table can follow, so a host that relocates its cache that way is unshielded
		// there. Not a bypass - .config/mise is write-shielded, so no run can plant it.
		".local/state/mise/trusted-configs",
		".config/mise",
		".cache/mise",
		// pre-commit clones each hook repo here and the installed .git/hooks/pre-commit
		// executes it on the host at the developer's next commit. The hook entry point is
		// shielded by Workspace, but the cache it runs FROM is where the code actually
		// lives, so without this a run under a home write grant poisons an installed hook
		// without touching .git.
		//
		// The cost is the .cargo/bin trade above: a DenyWrite shield has no opt-out, so
		// `pre-commit install-hooks` and a first `pre-commit run` cannot populate the cache
		// in-sandbox. Deliberate, and the line ~/.cargo/registry and ~/.m2 sit on the other
		// side of - those are read back by a build, this one is EXECUTED on the host.
		".cache/pre-commit",
		// bento's own approval journal: each entry is this host's record of the permissions a
		// human approved, and re-approval names the changed lines by diffing against it. A
		// sandboxed run that could write one would author its own baseline, so the next
		// reviewer is told an added grant is old news. Shielded at the bento directory so a
		// later state file is covered without a second entry.
		//
		// Write-denied rather than hidden, which is the weaker of the two and a deliberate
		// choice: it holds no key material, so hiding it would buy only that a sandboxed run
		// cannot enumerate the paths and grants of other manifests approved on this host.
		// That is real reconnaissance and an argument for DenyAll, but the callouts that
		// describe a lifted shield all call what they name a credential store - approve's
		// prompt, validate's note and footer, the post-run exposure warning, and the
		// proposal filter. Hiding the journal would make every one of them say something
		// false at the moment a reviewer is deciding whether to stamp, which costs more than
		// the disclosure buys. Widening that vocabulary is the precondition for revisiting
		// it, and not the only cost to weigh then: DenyAll also flips a read grant strictly
		// inside the journal from honored to refused, leaving an exact-name opt-in as the
		// only way for bento-adjacent tooling to read its own records.
		".local/state/bento",
		".config/Code", // VS Code User/settings.json (git.path, interpreter paths) run commands
		".vscode",      // extensions/ load on startup
		// The sibling spellings of the same editor: each is a separate install with its own
		// settings.json carrying the same git.path/alternateTools exec knobs, so shielding
		// only the Microsoft build leaves the fork plantable.
		".config/Code - Insiders",
		".config/Cursor",
		".config/VSCodium",
		".config/Windsurf",
		".config/zed",    // tasks.json and the language-server settings name host command lines
		".codeium",       // the plugin's own tree: the language server it execs (its API key is a credential file, hidden)
		".vscode-server", // Remote's extension host, with its own data/Machine/settings.json
		".vscode-oss",
		".vscode-insiders", // the home-level extension tree of the Insiders build
		// JetBrains IDEs: options/*.xml declares external tools and run configurations, both
		// command lines the IDE runs on the host - the global half of what Workspace shields
		// per repo as .idea.
		// The password safe writes a c.kdbx under the same tree when no native keyring is
		// available; it sits behind a per-product-version directory name, so it cannot be
		// named as a concrete DenyAll path and stays readable under this write shield.
		".config/JetBrains",
		".local/share/JetBrains",
		".config/mpv",    // scripts/*.lua autoloaded on launch
		".xmonad",        // xmonad.hs is compiled and executed
		".config/xmonad", // XDG location for xmonad.hs (0.17+)
		".oh-my-zsh",     // framework: plugins/ and themes/ are sourced on shell start
		".antigen",       // zsh antigen-managed plugins, sourced on shell start
		".zfunc",         // autoloaded zsh functions (planting one hijacks a command)
		".zsh.d",         // sourced zsh config fragments
		// The rest of the zsh framework and plugin-manager roots, the same class as
		// .oh-my-zsh: every file under them is sourced on shell start, and which files
		// exist is decided by the plugin list, so the tree is the only expressible shield.
		".zprezto",
		".zplug",
		".zinit",
		".zi", // the z-shell/zi fork, whose default root differs from zinit's below
		".zgen",
		".zgenom",
		".local/share/zinit",
		// tmux's plugin manager: .tmux.conf is write-denied above, but the line it runs is
		// `run ~/.tmux/plugins/tpm/tpm`, and every plugin tpm loads lives beside it.
		".tmux/plugins",
		// fzf's stub does two things: prepends ~/.fzf/bin to $PATH and sources
		// ~/.fzf/shell/*.zsh, so shielding the stub alone leaves the same plant one level
		// down.
		".fzf",
		// The conventional ZDOTDIR, shielded unconditionally beside .config/fish and
		// .config/nushell. The ZDOTDIR relocation block below cannot cover it: the variable
		// is set in a zsh startup file, so it exists only inside zsh and bento launched from
		// any other parent sees it unset while ~/.config/zsh/.zshrc still runs at next login.
		".config/zsh",
		".config/nsxiv/exec",        // nsxiv key-handler scripts run on keypress
		".config/pkcs11",            // pkcs11 module configs load shared objects (code)
		".local/share/applications", // .desktop entries whose Exec= runs on launch
		// A .service file here carries an Exec= the session bus activates on demand, which
		// is .local/share/applications' surface without even a launch to wait for.
		".local/share/dbus-1/services",
		// Extension JS is loaded straight into the compositor process at login.
		".local/share/gnome-shell/extensions",
		".config/menus", // XDG menu definitions pointing at .desktop entries
		".gnome/apps",   // legacy GNOME menu entries

		// Read-only in firejail: config/data trees whose entries run or load code on a later
		// invocation (an editor rc, an imported library, a browser profile), so a planted
		// entry is the threat; reads stay allowed as a build may legitimately inspect them.
		".cache/deno",                  // Deno cache holds compiled modules that run
		".deno",                        // legacy Deno dir
		".config/nano",                 // nanorc (syntax/include directives)
		".nano",                        // nano state/history dir
		".elinks",                      // ELinks config (exec knobs)
		".w3m",                         // w3m config (external-command mappings)
		".dotfiles",                    // dotfile-manager checkout, symlinked/sourced into $HOME
		"dotfiles",                     // same, non-hidden ~/dotfiles checkout
		".homesick",                    // homesick dotfile-manager castles
		".local/lib",                   // user libraries imported at runtime (pip --user, etc.)
		".local/share/cool-retro-term", // terminal-emulator config
		".local/share/fish",            // fish functions/completions (fish_history inside is DenyAll above)
		".local/share/mime",            // compiled MIME db: redirects which handler opens a file type
		".csh_files",                   // csh startup-file collection firejail write-protects
		".zsh_files",                   // zsh startup-file collection firejail write-protects

		// Coding-agent configuration trees. Their settings declare hooks and MCP servers -
		// command lines the agent runs on the HOST on a later invocation - so a planted
		// entry is host code execution, the same threat .mcp.json is shielded for above and
		// the same shape as .config/Code's git.path. Reads stay allowed: an agent running
		// inside the sandbox may legitimately consult its own configuration. Any credential
		// inside is shielded DenyAll separately below, which lands after this bind.
		".claude",
		".codex",
		".cursor",
		".gemini", // settings.json declares MCP servers, the same host-exec knob
		".config/opencode",
		".config/goose", // its extensions are command lines goose spawns on the host

		// Directories the distro default profile prepends to $PATH when they exist
		// (/etc/skel/.profile does this for both). A binary planted here is run by the
		// user's next shell under any bare command name it shadows - squarely the
		// plant-that-runs-on-the-host-later model, and the sibling .local/lib is already
		// shielded above for the import-time version of it. firejail write-protects these
		// under a section bento's scope classifier does not admit, so the ratchet is blind
		// to them.
		".local/bin",
		"bin",
		// The same $PATH prepend from the two user-level package managers that ship it in
		// their own profile snippet rather than /etc/skel: nix's per-user profile link and
		// flatpak's exported wrappers, both on $PATH on a stock distro that has either.
		".nix-profile/bin",
		".local/share/flatpak/exports/bin",
		// The rest of the $PATH-resident binary directories firejail write-protects: each
		// holds executables or shims a later shell resolves a bare command name to, so a
		// planted file runs on the host under a name the user already types.
		//
		// These are whole trees, matching firejail, and the cost is real: a DenyWrite
		// shield has no opt-out (the read opt-in covers DenyAll shields only, see
		// shieldNeeded), so `rustup update`, `nvm install`, `npm i -g`, `gem install
		// --user-install` and `cargo install` cannot run in-sandbox at all - a policy
		// granting write here is refused outright by checkWriteNotUnderReadOnlyShield
		// rather than being honored in argv and then losing to the shield. That is the
		// intended trade - each of those
		// mutates the host's $PATH from inside a sandbox - but it is a trade, not a free
		// shield; run them outside bento. The registry and
		// build caches (~/.cargo/registry, ~/.m2, ~/.gradle) are deliberately NOT here, so
		// an ordinary build still writes what it needs.
		".bin",
		".cargo/bin",
		".gem", // gem-installed binaries (the .gem/credentials file inside is DenyAll above)
		".local/share/coursier/bin",
		".luarocks",
		".npm-packages",
		".nvm",
		".rustup",
		// AppImages and other portable binaries launched by name from the file manager or
		// a desktop entry; firejail write-protects this for the same reason.
		"Applications",

		// The same class from the toolchains firejail does not carry, so the ratchet
		// cannot surface them: each is a directory an installer or distro puts on $PATH,
		// where a planted file runs on the host under a bare command name the user already
		// types.
		//
		// Only the bin/shim directories are named, not the version manager's whole tree the
		// way .nvm and .rustup are shielded. The install prefix under one of these holds the
		// interpreter a policy may legitimately run (write: ~/.pyenv over a versions/ tree is
		// a supported shape, see the Linux backend's interpreter re-bind), and a DenyWrite
		// shield has no opt-in - taking the tree would refuse that grant outright.
		//
		// Sparing the prefix keeps the interpreter re-bind working; it does not make
		// installing in-sandbox clean. A shimming manager writes the shim on every install,
		// so it meets the shield: against mise 2026.7.18, `mise reshim` fails outright.
		// `mise install` does not reach the shim write at all, because the cache shield
		// above refuses its lockfile first. Same trade as .nvm and .rustup, arrived at from
		// the other direction - run the installs outside bento.
		//
		// Not expressible as concrete paths, so left as a residual: sdkman's
		// ~/.sdkman/candidates/*/current/bin and opam's non-default switches, both of which
		// carry a name chosen at install time.
		"go/bin", // GOBIN's default, and `go install` puts every user-installed tool here
		".pyenv/bin",
		".pyenv/shims",
		".rbenv/bin",
		".rbenv/shims",
		".asdf/bin",
		".asdf/shims",
		".nodenv/bin",
		".nodenv/shims",
		".rvm/bin",
		".rvm/scripts",                // sourced by the line rvm's installer appends to the rc
		".opam/default/bin",           // the switch every non-project opam install lands in
		".ghcup/bin",                  // haskell toolchain shims
		".cabal/bin",                  // cabal install's target, beside it
		".volta/bin",                  // volta's node/npm shims
		".bun/bin",                    // the rest of ~/.bun is an install cache
		".local/share/mise/shims",     // mise keeps its installs beside the shims
		".krew/bin",                   // kubectl plugins, resolved as `kubectl <name>`
		".dotnet/tools",               // dotnet global tools
		".config/composer/vendor/bin", // composer global package binaries
		".composer/vendor/bin",        // the legacy root, which composer prefers when it exists
		".foundry/bin",                // forge/cast/anvil
		".pub-cache/bin",              // dart/flutter global activate
		".mix/escripts",               // elixir escripts
		// Archives are code mix loads on every invocation, not just on a bare command
		// name, so a planted one runs under the developer's next mix command.
		".mix/archives",
		".local/share/pnpm", // pnpm's global bindir
		// The per-user gem tree, taken whole the way .gem above is: the bindir under it
		// carries the ruby ABI version in its name, so no concrete path reaches it.
		".local/share/gem/ruby",
		".yarn/bin", // yarn global add
		".config/yarn/global/node_modules/.bin",

		// Gradle runs every .gradle script in init.d before each build, so a planted file
		// executes on the next build with the developer's privileges. The credential file
		// beside it (gradle.properties) is DenyAll above; the caches stay readable.
		".gradle/init.d",
	}

	// The same buckets as dirGroups, for the stores that are genuinely one file. Keyed
	// per group rather than stamped HoldsCredentials wholesale, so that a shell history
	// reads as a history store here and not just where an env var relocates it.
	fileGroups := []struct {
		holds Holds
		files []string
	}{
		{HoldsCredentials, credentialFiles},
		{HoldsPrivateData, privateDataFiles},
		{HoldsHistory, historyFiles},
		{HoldsPersistence, persistenceFiles},
		{HoldsServices, serviceFiles},
	}

	nFiles := 0
	for _, g := range fileGroups {
		nFiles += len(g.files)
	}
	rules := make([]Rule, 0, nFiles+len(writeOnly)+len(writeOnlyDirs))
	emit := func(entry string, r Rule) {
		r.Path = filepath.Join(home, entry)
		rules = append(rules, r)
	}
	for _, g := range dirGroups {
		for _, d := range g.dirs {
			emit(d, Rule{Deny: DenyAll, Dir: true, Holds: g.holds})
		}
	}
	for _, g := range fileGroups {
		for _, f := range g.files {
			emit(f, Rule{Deny: DenyAll, Holds: g.holds})
		}
	}
	for _, f := range writeOnly {
		emit(f, Rule{Deny: DenyWrite})
	}
	for _, d := range writeOnlyDirs {
		emit(d, Rule{Deny: DenyWrite, Dir: true})
	}

	return rules
}

// Relocated returns the rules an environment variable moves off a default location, for
// the run's whole set of home anchors at once.
//
// They are not anchor-relative: a variable names one absolute path, so emitting them
// inside Home - which runs once per anchor - produced the same rule twice on a two-anchor
// host and stamped the second copy with whichever anchor's Source lost the race. Every
// default a target is compared against is therefore tested under EVERY anchor, which is
// also what keeps a relocation onto a sibling anchor's default store from being reported
// as a relocation at all.
//
// defaults are the anchor-relative rules for the same anchors (Home over each), needed
// because a relocation landing under a rule that already hides the subtree must be
// dropped rather than emitted - see underDenyAll.
func Relocated(defaults []Rule, anchors []string) []Rule {
	var rules []Rule
	// Both halves: the defaults, and what this pass has already emitted. It sees only what
	// came before, and no block ordering makes that enough: the XDG restatement has to run
	// first, because its rules were part of defaults when Home emitted them, yet dirEnvs'
	// whole-tree DenyAll can land on top of what it just emitted. The sweep at the end of
	// this function is what closes that, once every encloser is known.
	covered := func(p string) bool { return underDenyAll(p, defaults) || underDenyAll(p, rules) }
	shieldable := func(p string) bool { return Shieldable(p, anchors) }
	// isDefault reports whether an absolute target is just a restatement of the
	// home-relative default, at any of the run's anchors. Keyed on one anchor it would
	// call a sibling anchor's own default store a relocation, and the Source stamp would
	// then tell an operator a variable put a shield where the anchor list already had one.
	isDefault := func(p, rel string) bool {
		for _, h := range anchors {
			if p == filepath.Join(h, rel) {
				return true
			}
		}
		return false
	}

	// A relocated XDG base moves a whole class of entries at once, so it is derived from
	// the defaults rather than from a list of its own: every rule Home placed under an
	// anchor's .config/ (etc.) is restated at the base's target. Both copies stand - a
	// tool that honors the variable reads from the target, one that ignores it from the
	// default.
	//
	// The target does not depend on the anchor, so the whole anchor set collapses onto one
	// rule per entry; seen drops the copies the per-anchor defaults would otherwise
	// contribute. It runs before the blocks below because those rules were part of
	// defaults when Home emitted them, and covered() must still see them.
	seen := map[string]bool{}
	for _, d := range defaults {
		for _, h := range anchors {
			rel, ok := strings.CutPrefix(d.Path, h+string(filepath.Separator))
			if !ok {
				continue
			}
			for _, b := range xdgBases {
				sub, ok := strings.CutPrefix(rel, b.prefix)
				if !ok {
					continue
				}
				// A relative base is invalid per the spec and ignored by conforming tools,
				// which fall back to the default location - already shielded by Home.
				base := os.Getenv(b.env)
				if base == "" || !filepath.IsAbs(base) || isDefault(filepath.Clean(base), b.def) {
					continue
				}
				// The same two guards every block below runs. sub is non-empty by
				// construction, so an emitted path is never the base itself, and shieldable
				// fires only on the contrived layouts that put an anchor under one;
				// covered is the half a plausible host reaches - an XDG base pointed at an
				// already-hidden tree (XDG_CACHE_HOME=$HOME/.ssh) puts an interior rule
				// inside a DenyAll, which survives an opt-in matching only the enclosing
				// rule. Held in common with the other blocks so a widening here inherits
				// them rather than having to rediscover them.
				p := filepath.Join(base, sub)
				if seen[p] || covered(p) || !shieldable(p) {
					continue
				}
				seen[p] = true
				r := d
				r.Path, r.Source = p, b.env
				rules = append(rules, r)
			}
		}
	}

	// A tool-specific env var can move a whole credential directory off its default
	// path, the same way an XDG base does. When one is set to an absolute location that
	// differs from the default (already shielded above), the shield follows to the
	// target too. A relative value is dropped: the shield is an absolute bwrap bind, so
	// a relative target cannot be shielded at the place the tool would actually read it.
	for _, de := range dirEnvs {
		base := os.Getenv(de.env)
		if base == "" || !filepath.IsAbs(base) {
			continue
		}
		if c := filepath.Clean(base); !isDefault(c, de.def) && !covered(c) && shieldable(c) {
			rules = append(rules, Rule{Path: c, Deny: DenyAll, Dir: true, Holds: HoldsCredentials, Source: de.env})
		}
	}

	// The variables that relocate a DIRECTORY but whose sensitive content is one named
	// file inside it. dirEnvs' whole-tree DenyAll is the wrong shape for these: the
	// directory also holds content the tool legitimately reads in-sandbox (dbt's project
	// config beside profiles.yml), and for CURL_HOME the directory is a home. So the file
	// is shielded on its own and the directory is left alone.
	for _, de := range dirFileEnvs {
		base := os.Getenv(de.env)
		if !filepath.IsAbs(base) {
			continue
		}
		if c := filepath.Clean(base); !isDefault(c, de.def) {
			if p := filepath.Join(c, de.file); !covered(p) && shieldable(p) {
				rules = append(rules, Rule{Path: p, Deny: DenyAll, Holds: HoldsCredentials, Source: de.env})
			}
		}
	}

	// Some tools relocate individual credential files rather than a whole directory.
	// The default files sit inside a directory already shielded above (~/.kube, ~/.aws),
	// but the env can point the file anywhere, and a relocated target lands outside every
	// shield - exposed under a broad read grant at enforce time. Shield the target file
	// itself. KUBECONFIG is a colon-separated search list; each entry is a separate file.
	// Relative and empty entries are dropped for the same reason as a relative directory
	// relocation: an absolute bind cannot cover a path the shield cannot name. A target at
	// or under its default store (a common redundant restatement, e.g. KUBECONFIG=~/.kube/
	// config) is dropped too: the whole-directory shield already covers it, and emitting an
	// interior file rule would blank the file out from under a `read: ~/.kube` opt-in that
	// matches only the directory.
	//
	// The store is tested under EVERY anchor. Keyed on one alone, a KUBECONFIG under a
	// SIBLING anchor's ~/.kube would land as an interior file rule that no `read: ~/.kube`
	// opt-in matches: it survives the opt-in and the user gets a zero-byte kubeconfig, a
	// silent wrong answer rather than a refusal. That anchor's own Home pass emits the
	// directory shield covering the path, so dropping it here loses no coverage.
	//
	// Only KUBECONFIG is a search list. The rest name one file, and a path may legally
	// contain a colon, so splitting them would shield two halves of a name and leave the
	// real file exposed.
	underStore := func(p, store string) bool {
		for _, h := range anchors {
			s := filepath.Join(h, store)
			if p == s || strings.HasPrefix(p, s+string(filepath.Separator)) {
				return true
			}
		}
		return false
	}
	for _, fe := range fileEnvs {
		v := os.Getenv(fe.env)
		targets := []string{v}
		if fe.list {
			targets = filepath.SplitList(v)
		}
		for _, p := range targets {
			if p == "" || !filepath.IsAbs(p) {
				continue
			}
			p = filepath.Clean(p)
			// The store itself is relocatable (CLOUDSDK_CONFIG moves ~/.config/gcloud), and a
			// target inside the RELOCATED store is covered by the directory rule the dirEnvs
			// block just emitted - which underStore, keyed on the default path under each
			// anchor, cannot see. An interior file rule there is the same silent wrong answer
			// the store check exists to prevent: it survives a `read:` opt-in on the directory
			// and hands back a zero-byte file.
			if underStore(p, fe.store) || covered(p) || !shieldable(p) {
				continue
			}
			rules = append(rules, Rule{Path: p, Deny: DenyAll, Holds: HoldsCredentials, Source: fe.env})
		}
	}

	// Env vars that relocate a single credential/history FILE whose default is a named
	// file rather than a whole store directory. HISTFILE moves the shell history (typed
	// passwords, pasted tokens) off ~/.bash_history / ~/.zsh_history; it has no single
	// default (the name is shell-specific and the defaults are shielded individually), so
	// any absolute target is shielded, and /dev/null - the idiom for disabling history -
	// is left alone. The tool-specific *_HISTFILE / history vars move an already-shielded
	// history file off its default; NPM_CONFIG_USERCONFIG moves ~/.npmrc (auth tokens), and
	// R_ENVIRON_USER moves ~/.Renviron (plaintext API keys/DB passwords) - both credential
	// configs, hidden for the same reason as the histories. A value equal to the named
	// default is already covered and dropped; relative values cannot be bound.
	for _, fe := range fileDenyAllEnvs {
		v := os.Getenv(fe.env)
		if !filepath.IsAbs(v) {
			continue
		}
		c := filepath.Clean(v)
		// underDenyAll for the reason the fileEnvs loop above tests it: the def compare
		// only catches the DEFAULT spelling, so a target inside an already-hidden tree
		// (a relocated store, or plain ~/.ssh) would get an interior rule that survives an
		// opt-in on that tree and hands back a zero-byte file.
		if c == "/dev/null" || (fe.def != "" && isDefault(c, fe.def)) || covered(c) || !shieldable(c) {
			continue
		}
		rules = append(rules, Rule{Path: c, Deny: DenyAll, Holds: fe.holds, Source: fe.env})
	}

	// HGRCPATH REPLACES mercurial's config search path with a colon-separated list, so
	// every entry is a file hg reads instead of ~/.hgrc - and [auth] there holds plaintext
	// passwords while [hooks]/[extensions] name host commands. Hidden, matching the two
	// defaults. The colon-split shape is MAILCAPS', which is why it is a block rather than
	// a fileDenyAllEnvs row: there is no single default to compare against, and both
	// spellings hg would otherwise read are already DenyAll, so covered() drops a
	// restatement of either.
	//
	// Residual: an entry may name a DIRECTORY, where hg reads every *.rc inside it. The
	// rule is emitted as a file either way, because this package is path arithmetic with
	// no host reads - so a directory entry gets an empty file bound over it and hg finds
	// no config there. Degraded rather than exposed, and the same direction every other
	// mis-shaped relocation fails in.
	for _, p := range filepath.SplitList(os.Getenv("HGRCPATH")) {
		if !filepath.IsAbs(p) {
			continue
		}
		if c := filepath.Clean(p); !covered(c) && shieldable(c) {
			rules = append(rules, Rule{Path: c, Deny: DenyAll, Holds: HoldsCredentials, Source: "HGRCPATH"})
		}
	}

	// A startup file relocated by an env var is a persistence-planting target the
	// default DenyWrite shields above miss: ZDOTDIR points zsh at a different
	// directory for its whole startup group, and GIT_CONFIG_GLOBAL at a different
	// file git reads instead of ~/.gitconfig. Follow the shield to the relocation so
	// a write grant there cannot plant a file the host runs on the next shell or git
	// call. A relative value is dropped (an absolute bind cannot cover it), as is the
	// default location (already shielded); git's /dev/null "no config" idiom is dropped by
	// addWriteShield along with every other source's.
	//
	// A relocation landing at or under a DenyAll rule is skipped: the DenyAll rule
	// already hides the whole subtree, so a DenyWrite there grants nothing further and
	// only adds a redundant rule for a backend to enforce and a reader to reconcile.
	//
	// /dev/null is skipped for every source rather than at the call sites that remembered
	// to: INPUTRC=/dev/null and MAILCAPS=/dev/null are documented ways to disable a config,
	// and there is nothing to plant in a device node. The rule is inert under bwrap, where
	// a ro-bind does not deny writes to one, but the Landlock-only degraded tier enforces
	// it - and every "> /dev/null" inside the sandbox then fails.
	addWriteShield := func(p, source string) {
		if p != "/dev/null" && !covered(p) && shieldable(p) {
			rules = append(rules, Rule{Path: p, Deny: DenyWrite, Source: source})
		}
	}
	if zdotdir := os.Getenv("ZDOTDIR"); filepath.IsAbs(zdotdir) && !isDefault(filepath.Clean(zdotdir), "") {
		// .zshrc.local is sourced by the widely-copied grml zshrc from ${ZDOTDIR:-$HOME},
		// so it relocates with the rest of the group (the default is shielded above).
		for _, f := range []string{".zshenv", ".zshrc", ".zshrc.local", ".zprofile", ".zlogin", ".zlogout"} {
			addWriteShield(filepath.Join(zdotdir, f), "ZDOTDIR")
		}
	}
	if gc := os.Getenv("GIT_CONFIG_GLOBAL"); filepath.IsAbs(gc) {
		if c := filepath.Clean(gc); !isDefault(c, ".gitconfig") {
			addWriteShield(c, "GIT_CONFIG_GLOBAL")
		}
	}
	// Env vars that relocate a single startup file the host runs, the DenyWrite analog of
	// the block above. BASH_ENV is sourced by every non-interactive bash (why sudo strips
	// it); ENV by interactive POSIX sh/ksh/mksh/dash, and it is how ~/.kshrc / ~/.mkshrc
	// get designated. Both name a file with no default path to compare against.
	for _, env := range startupFileEnvs {
		if v := os.Getenv(env); filepath.IsAbs(v) {
			addWriteShield(filepath.Clean(v), env)
		}
	}
	// Env vars that each relocate a single startup/config file whose conventional default
	// is shielded above, so a value equal to that default is already covered and dropped.
	// INPUTRC (readline macros run on a keypress), PYTHONSTARTUP (interactive python init),
	// SCREENRC (GNU screen runs its commands), PSQLRC (psql \! runs a shell command), and
	// R_PROFILE_USER (.Rprofile is R code evaluated at startup) name a file the host runs.
	// R_ENVIRON_USER is not here: .Renviron holds plaintext secrets, so its relocation is a
	// DenyAll target in the fileDenyAllEnvs block above (which also neutralizes the same
	// R_PROFILE_USER exec knob).
	for _, de := range startupDefaultEnvs {
		if v := os.Getenv(de.env); filepath.IsAbs(v) {
			if c := filepath.Clean(v); !isDefault(c, de.def) {
				addWriteShield(c, de.env)
			}
		}
	}
	// PIP_CONFIG_FILE names the single pip.conf pip reads (index-url can redirect installs to
	// a malicious registry), the DenyWrite analog of the single-default loop but with TWO
	// conventional defaults, both shielded above. A value equal to either is already covered
	// and dropped; a relative value cannot be bound.
	if v := os.Getenv("PIP_CONFIG_FILE"); filepath.IsAbs(v) {
		if c := filepath.Clean(v); !isDefault(c, ".config/pip/pip.conf") && !isDefault(c, ".pip/pip.conf") {
			addWriteShield(c, "PIP_CONFIG_FILE")
		}
	}
	// MAILCAPS is a colon-separated list of mailcap files (MIME-type -> command run on
	// attachment open); when set it replaces the default search path, so every listed file is
	// one the host acts on. Shield each entry DenyWrite, the fileEnvs colon-split shape but
	// routed through addWriteShield so an entry under a DenyAll rule is not re-exposed. The
	// ~/.mailcap default is already shielded, so a matching entry is dropped, as are relative
	// and empty entries.
	for _, p := range filepath.SplitList(os.Getenv("MAILCAPS")) {
		if !filepath.IsAbs(p) {
			continue
		}
		if c := filepath.Clean(p); !isDefault(c, ".mailcap") {
			addWriteShield(c, "MAILCAPS")
		}
	}
	// CARGO_HOME relocates BOTH severity classes at once: the registry tokens
	// (credentials{,.toml}, hidden) and the build configs (config{,.toml}, env - each
	// names a rustc-wrapper/linker/runner the host executes, readable but not writable)
	// sit side by side under it. The dirEnvs table cannot express that split (it is
	// DenyAll-only), so emit the mixed set explicitly, re-based on the relocation. The
	// third default ~/.cargo rule - the bin directory `cargo install` writes and rustup's
	// env puts on $PATH - is a directory shield, so it rides in writeOnlyDirEnvs below
	// rather than here, where every rule is file-shaped. The DenyAll files go in first so
	// addWriteShield's collision guard sees them; a write grant over the relocated dir is
	// refused upstream for containing the credential shields, as for the default ~/.cargo.
	if base := os.Getenv("CARGO_HOME"); filepath.IsAbs(base) {
		if c := filepath.Clean(base); !isDefault(c, ".cargo") {
			for _, f := range []string{"credentials.toml", "credentials"} {
				if p := filepath.Join(c, f); !covered(p) && shieldable(p) {
					rules = append(rules, Rule{Path: p, Deny: DenyAll, Holds: HoldsCredentials, Source: "CARGO_HOME"})
				}
			}
			for _, f := range []string{"config.toml", "config", "env"} {
				addWriteShield(filepath.Join(c, f), "CARGO_HOME")
			}
		}
	}
	// STEPPATH moves step-cli's whole tree, but only secrets/ under it is shielded at the
	// default - the certificates and config beside it are what an in-sandbox step reads.
	// dirEnvs is the wrong table for that: its DenyAll takes the relocated tree whole and
	// would hide the certificates the default deliberately spares. The contexts layout
	// recorded beside the default entry is the same residual once relocated.
	if base := os.Getenv("STEPPATH"); filepath.IsAbs(base) {
		if c := filepath.Clean(base); !isDefault(c, ".step") {
			if p := filepath.Join(c, "secrets"); !covered(p) && shieldable(p) {
				rules = append(rules, Rule{Path: p, Deny: DenyAll, Dir: true, Holds: HoldsCredentials, Source: "STEPPATH"})
			}
		}
	}
	// GOPATH is a colon-separated list, and only its FIRST element supplies the bindir
	// `go install` writes - the one $PATH carries and the host's next bare tool name
	// resolves to. GOBIN overrides it outright when set, and has its own row below, so the
	// GOPATH bindir is only a target where GOBIN is unset. The remaining elements hold
	// module sources and caches an in-sandbox build legitimately writes.
	//
	// `go env -w` persists either variable to ~/.config/go/env, which the process
	// environment does not carry, so a host that set them that way keeps the default
	// go/bin shield while `go install` writes elsewhere - a recorded residual. Reading
	// that file is what the .claude.json comment above rules out for every rule here:
	// the clamp, the credential hunt and the firejail audit each derive these paths
	// independently, and a host read would make them disagree. GOENV relocates the file
	// in turn, so following it would be a read chased by another read.
	if gobin := os.Getenv("GOBIN"); gobin == "" {
		if gopath := filepath.SplitList(os.Getenv("GOPATH")); len(gopath) > 0 && filepath.IsAbs(gopath[0]) {
			if c := filepath.Clean(gopath[0]); !isDefault(c, "go") {
				if p := filepath.Join(c, "bin"); !covered(p) && shieldable(p) {
					rules = append(rules, Rule{Path: p, Deny: DenyWrite, Dir: true, Source: "GOPATH"})
				}
			}
		}
	}
	// The write-shielded directories a tool-specific variable relocates. addWriteShield is
	// the wrong emitter here - it produces a file rule, which would bind an empty file over
	// a directory and leave every entry beside it plantable. Same guards otherwise,
	// /dev/null included (nothing is plantable in a device node, and the degraded tier
	// enforces the rule it would otherwise emit), and last so a DenyAll target from any
	// block above already sits in covered().
	for _, de := range writeOnlyDirEnvs {
		base := os.Getenv(de.env)
		if !filepath.IsAbs(base) {
			continue
		}
		c := filepath.Clean(base)
		if isDefault(c, de.def) {
			continue
		}
		if p := filepath.Join(c, de.sub); p != "/dev/null" && !covered(p) && shieldable(p) {
			rules = append(rules, Rule{Path: p, Deny: DenyWrite, Dir: true, Source: de.env})
		}
	}

	// The rules an encloser emitted later than they were shields nothing further, and a
	// DenyWrite or interior file rule among them survives an opt-in matching only the
	// enclosing tree - see underDenyAll. Dropped here rather than by tightening covered(),
	// which cannot see forward.
	// A fresh slice: the screen reads the whole rule set, so filtering in place would let an
	// already-written entry stand in for an encloser the tail still has to be tested against.
	kept := make([]Rule, 0, len(rules))
	for _, r := range rules {
		if !insideDenyAllTree(r.Path, defaults) && !insideDenyAllTree(r.Path, rules) {
			kept = append(kept, r)
		}
	}
	return kept
}

// insideDenyAllTree reports whether a DenyAll DIRECTORY rule strictly encloses p. It
// ignores a rule at p itself, which is what lets a set be screened against itself without
// a pair of equal paths cancelling each other out.
func insideDenyAllTree(p string, rules []Rule) bool {
	for _, r := range rules {
		if r.Deny == DenyAll && r.Dir && strings.HasPrefix(p, r.Path+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// underDenyAll reports whether an already-emitted DenyAll rule covers p. A rule landing
// there shields nothing further: it is redundant when it is another DenyAll, and when it
// is a DenyWrite or an interior file rule it is worse than redundant, because it survives
// an opt-in that matches only the enclosing rule.
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

// Runtime returns the mandatory rules for the host's runtime state directories.
//
// runtimeDir is the host's resolved XDG runtime directory (see RuntimeDir), and homes the
// run's anchors. On an ordinary host it is /run/user/<uid>, already inside the /run shield
// below, and no extra rule comes out. It is a parameter rather than an environment read so
// that the completeness audit - which builds this same rule set - does not vary with the
// environment of whoever runs it, the same reason Home takes a resolved anchor.
//
// /run holds the control sockets of the host's services - the docker/podman
// daemon, the session bus, gpg-agent, the display server - and a unix socket is a
// read-write channel to whatever is on the other end no matter how the path is
// mounted: the kernel refuses a write to a read-only bind only for regular files,
// directories, and symlinks, so connect() on a socket succeeds through a --ro-bind
// (verified on kernel 6.8). A network namespace does not fence them either, since a
// path-named socket is scoped by the filesystem rather than by netns. So a policy
// granting read over /run - which "read: /" does - hands out the docker daemon,
// which has host networking and can mount the host root: a read grant would confer
// host root. The whole directory is shielded rather than each known socket, for the
// same reason credential stores are: naming docker.sock leaves the session bus and
// the next daemon's socket exposed.
//
// Not covered, because a socket is only reachable if some grant exposes its
// directory and no list of paths can name them all (a documented residual): a
// service socket outside /run, such as a distribution that puts the MySQL socket in
// /var/lib/mysql, or one a host process creates during the run. Sockets under $HOME
// are covered where they sit in a shielded credential store (~/.gnupg, ~/.docker,
// ~/.git-credential-cache); elsewhere under a granted home directory they are not.
func Runtime(runtimeDir string, homes ...string) []Rule {
	rules := []Rule{
		{Path: "/run", Deny: DenyAll, Dir: true, Holds: HoldsServices},
		// A symlink to /run on most hosts (resolved before it is shielded, so it
		// costs nothing there), a real directory on those that predate the merge.
		{Path: "/var/run", Deny: DenyAll, Dir: true, Holds: HoldsServices},
	}
	// A host that points XDG_RUNTIME_DIR somewhere other than /run (a container, a
	// session manager that parks it under /tmp) keeps the same contents there: the
	// podman/skopeo auth.json, the gpg-agent socket, the dbus and wayland sockets. The
	// /run shield names none of them at that location, so `read: /tmp` - or `read: /` -
	// would hand them out. Follow the shield to wherever the variable points.
	if runtimeDir == "" || policy.CoversResolved("/run", runtimeDir) || policy.CoversResolved("/var/run", runtimeDir) || !Shieldable(runtimeDir, homes) {
		return rules
	}
	return append(rules, Rule{Path: runtimeDir, Deny: DenyAll, Dir: true, Holds: HoldsServices, Source: "XDG_RUNTIME_DIR"})
}

// Covers finds the rule shielding path, returning it and true. A rule matches either
// exactly or as a directory enclosing the path, and among the matches the STRICTEST wins -
// exact and enclosing compete on strictness rather than exact taking precedence, so an
// enclosing DenyAll directory rule beats an exact DenyWrite file rule and a path inside a
// DenyAll directory does not read as merely write-shielded.
//
// It lives here rather than in each consumer because "is this path shielded" is a
// question about Rule, and the parity audit and the credential hunt both have to answer
// it the same way - a second copy is how they would come to disagree about what bento
// covers.
// The returned rule's Deny and Dir are specified; nothing else is. Among equally strict
// matches a directory rule wins, because a caller asking whether the shield extends past
// this one path (the parity audit's Narrowed verdict) would otherwise get the answer from
// whichever equally strict rule the slice happened to list first. Beyond that - two
// nested directory shields of the same class - which rule comes back is not defined.
//
// Strength is two-dimensional and one rule cannot report both halves of a composite
// shield: a DenyAll file rule beside a DenyWrite directory rule loses the Dir, since Deny
// is compared first. A tree candidate then reads as narrowed although the directory rule
// does cover the tree, more weakly. That is the safe direction - a spurious gap the audit
// surfaces, never a missed one - and a caller needing both halves wants every match, not a
// third tie-break.
//
// Source is likewise unspecified. A path can be reached by a default rule and by a
// relocated one at once, and naming whichever the scan reached first would attribute the
// shield to an arbitrary variable - so a surface that tells an operator which variable
// put a shield somewhere must read the rules, not ask this.
func Covers(path string, rules []Rule) (Rule, bool) {
	// Cleaned once, so the exact match below judges the same spelling the enclosing-
	// directory match does. Without this the two disagree: a DenyAll rule on a FILE (the
	// cargo credentials store, the fileEnvs rules) is reachable only through the equality,
	// so "/x/./credentials.toml" missed a shield that "/x/credentials.toml" hit.
	path = filepath.Clean(path)

	var best Rule
	found := false
	for _, r := range rules {
		if r.Path == path || (r.Dir && policy.CoversResolved(r.Path, path)) {
			if !found || stricter(r, best) {
				best, found = r, true
			}
		}
	}
	return best, found
}

// stricter reports whether a shields more than b: a lower Deny, or the same Deny over a
// tree rather than a single path. Shared with Index so the two cannot drift on the
// tie-break Covers promises.
func stricter(a, b Rule) bool {
	if a.Deny != b.Deny {
		return a.Deny < b.Deny
	}
	return a.Dir && !b.Dir
}

// Workspace returns the rules that apply inside a directory a policy grants
// write access to. A script with write access to a repository must not be able
// to install a git hook or an editor task that runs on the host the next time
// the user opens the project.
//
// The editor config directories are shielded whole, not file-by-file: .vscode holds
// settings.json (git.path, go.alternateTools, python.defaultInterpreterPath - each
// names a binary the editor runs) alongside tasks.json and launch.json, and .idea holds
// runConfigurations/*.xml and *.iml beside workspace.xml. Naming individual files leaves
// their siblings plantable, the same reason .git/hooks is a directory shield. Writes are
// denied but reads stay allowed, so a build that consults the config still works.
func Workspace(dir string) []Rule {
	join := func(p string) string { return filepath.Join(dir, p) }
	return []Rule{
		{Path: join(".git/hooks"), Deny: DenyWrite, Dir: true},
		{Path: join(".git/config"), Deny: DenyWrite},
		{Path: join(".git/config.worktree"), Deny: DenyWrite}, // honored under extensions.worktreeConfig
		{Path: join(".vscode"), Deny: DenyWrite, Dir: true},
		{Path: join(".idea"), Deny: DenyWrite, Dir: true},
		// config{,.toml} here names a rustc-wrapper, linker or target runner the host
		// execs on the developer's next cargo command - the ~/.cargo/config.toml case one
		// level in, and the one toolchain surface with no approval record that an agent
		// has no ordinary reason to write. Both filenames, since the legacy extensionless
		// one is still read, and shielded whether or not they exist yet, because an absent
		// one is exactly what a plant creates.
		//
		// Named as files rather than taking the .cargo directory, matching how the
		// CARGO_HOME relocation is shielded: a workspace-local cargo home
		// (CARGO_HOME=<repo>/.cargo, routine in CI) keeps its registry and git checkouts
		// under here, and a directory shield would EROFS an ordinary build - or, where the
		// directory does not exist yet, tmpfs the downloads and lose them silently.
		//
		// Residual: cargo searches every ancestor of the CWD, so a config under a nested
		// crate (crates/foo/.cargo/) is read when the developer runs cargo from there and
		// is not covered by a shield anchored at the checkout.
		{Path: join(".cargo/config.toml"), Deny: DenyWrite},
		{Path: join(".cargo/config"), Deny: DenyWrite},
	}
}

// WorkspaceGitfile returns Workspace's rules for a checkout whose .git is a FILE rather
// than a directory - a linked worktree or a submodule working tree, both of which keep
// a "gitdir: <path>" pointer there instead. The hooks and config that execute on the
// host live in the gitdir it names, which is outside the checkout and so outside the
// write grant already. What is newly plantable is the gitfile itself: rewriting it
// repoints the worktree at another gitdir, which the developer's next git command in
// that worktree honors. So the .git children are dropped for a shield on .git.
//
// Dropping them is not just tidiness. bwrap shields by binding and cannot create a
// mount point under a regular file, so emitting .git/hooks here kills sandbox setup and
// the run refuses to attest. The children are found by prefix rather than listed, so a
// .git rule added to Workspace later cannot leak through this path.
func WorkspaceGitfile(dir string) []Rule {
	gitfile := filepath.Join(dir, ".git")
	rules := []Rule{{Path: gitfile, Deny: DenyWrite}}
	for _, r := range Workspace(dir) {
		if !strings.HasPrefix(r.Path, gitfile+string(filepath.Separator)) {
			rules = append(rules, r)
		}
	}
	return rules
}

// A relocated XDG base moves the real credential/config stores out from under the
// default ~/.config etc., so a config/data/cache-relative entry is shielded at
// BOTH its default location and the XDG one - a tool that honors XDG_CONFIG_HOME
// reads from there, a tool that ignores it from the default, and both are covered.
var xdgBases = []struct{ prefix, env, def string }{
	{".config/", "XDG_CONFIG_HOME", ".config"},
	{".local/share/", "XDG_DATA_HOME", ".local/share"},
	{".local/state/", "XDG_STATE_HOME", ".local/state"},
	{".cache/", "XDG_CACHE_HOME", ".cache"},
}

// location is one absolute path an entry must be shielded at, carrying the variable that
// put it there so a relocated copy can be told apart from the default it sits beside.
type location struct {
	path   string
	source string
}

// homeLocations expands a home-relative deny entry to every absolute path it must be
// shielded at: its default location, plus the XDG one when the relevant base is
// relocated.
func homeLocations(home, entry string) []location {
	join := func(p string) string { return filepath.Join(home, p) }
	for _, b := range xdgBases {
		if rel, ok := strings.CutPrefix(entry, b.prefix); ok {
			out := []location{{path: join(entry)}}
			// A relative XDG base is invalid per the spec and ignored by conforming
			// tools, which fall back to the default location - already shielded via
			// join(entry). Emitting a relative Rule.Path here would shield nothing at
			// the intended place, so drop it and rely on the default shield.
			if base := os.Getenv(b.env); base != "" && filepath.IsAbs(base) && filepath.Clean(base) != join(b.def) {
				out = append(out, location{filepath.Join(base, rel), b.env})
			}
			return out
		}
	}
	return []location{{path: join(entry)}}
}

// AliasAnchors returns the absolute paths whose files identify a credential, for detecting
// a second readable name for one. It is narrower than the full set of hidden directories:
// see credentialAnchorDirs for which stores count and why, and walletKeyPaths for the
// full-node clients that anchor only their key subtree.
//
// It takes every home anchor the run has, not one, for the reason Home does: a store
// relocated out of the homes altogether belongs to the run and not to whichever anchor the
// caller happened to pass first.
func AliasAnchors(homes ...string) []string {
	anchors := slices.Concat(credentialAnchorDirs, walletKeyPaths)
	out := make([]string, 0, len(anchors)*len(homes))
	for _, home := range homes {
		for _, d := range anchors {
			// An anchor is a place to look for a second readable name, so a relocated copy
			// counts the same as the default and the variable that moved it does not.
			for _, l := range homeLocations(home, d) {
				out = append(out, l.path)
			}
		}
	}
	// A tool-specific relocation moves a whole store off the XDG bases homeLocations knows
	// about, so GNUPGHOME=/srv/keys is shielded (Home follows it) but would anchor nothing -
	// leaving a second readable name for those keys undetectable. Skipping the target when
	// it is at or above an anchor matches the shield: the scan would otherwise walk a whole
	// home looking for aliases of it.
	for _, de := range dirEnvs {
		base := os.Getenv(de.env)
		if !filepath.IsAbs(base) {
			continue
		}
		if c := filepath.Clean(base); Shieldable(c, homes) && !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out
}

var fileEnvs = []struct {
	env, store string
	list       bool
}{
	{env: "KUBECONFIG", store: ".kube", list: true},
	{env: "AWS_SHARED_CREDENTIALS_FILE", store: ".aws"},
	{env: "AWS_CONFIG_FILE", store: ".aws"},
	// The service-account JSON private key, the canonical GCP credential. It is always
	// an absolute path and has no default filename, so the variable is the only thing
	// that names it.
	{env: "GOOGLE_APPLICATION_CREDENTIALS", store: ".config/gcloud"},
	{env: "AWS_WEB_IDENTITY_TOKEN_FILE", store: ".aws"},
	// podman/skopeo/buildah's registry auth.json. Its primary default is under
	// XDG_RUNTIME_DIR, which Runtime shields; this is the pointer that moves it out.
	{env: "REGISTRY_AUTH_FILE", store: ".config/containers"},
}

var fileDenyAllEnvs = []struct {
	env, def string
	holds    Holds
}{
	{"HISTFILE", "", HoldsHistory},
	{"NPM_CONFIG_USERCONFIG", ".npmrc", HoldsCredentials},
	{"R_ENVIRON_USER", ".Renviron", HoldsCredentials},
	{"LESSHISTFILE", ".lesshst", HoldsHistory},
	{"MYSQL_HISTFILE", ".mysql_history", HoldsHistory},
	{"PSQL_HISTORY", ".psql_history", HoldsHistory},
	{"SQLITE_HISTORY", ".sqlite_history", HoldsHistory},
	{"REDISCLI_HISTFILE", ".rediscli_history", HoldsHistory},
	{"NODE_REPL_HISTORY", ".node_repl_history", HoldsHistory},
	// Both name a single config file whose default is shielded above and whose content
	// is a credential (a Terraform Cloud token, a galaxy_token) beside an exec knob
	// (ANSIBLE_CONFIG's library/roles_path/vault_password_file).
	{"TF_CLI_CONFIG_FILE", ".terraformrc", HoldsCredentials},
	{"PGPASSFILE", ".pgpass", HoldsCredentials},
	{"WGETRC", ".wgetrc", HoldsCredentials},
	{"ANSIBLE_CONFIG", ".ansible.cfg", HoldsCredentials},
	{"SOPS_AGE_KEY_FILE", ".config/sops/age/keys.txt", HoldsCredentials},
}

// The single startup files a variable designates with no default path to compare against.
// BASH_ENV is sourced by every non-interactive bash (why sudo strips it); ENV by
// interactive POSIX sh/ksh/mksh/dash, and it is how ~/.kshrc / ~/.mkshrc get designated.
var startupFileEnvs = []string{"BASH_ENV", "ENV"}

// The variables that each relocate one startup/config file the host RUNS, whose
// conventional default is shielded by name.
var startupDefaultEnvs = []struct{ env, def string }{
	{"INPUTRC", ".inputrc"},
	{"PYTHONSTARTUP", ".pythonrc.py"},
	{"SCREENRC", ".screenrc"},
	{"PSQLRC", ".psqlrc"},
	{"R_PROFILE_USER", ".Rprofile"},
	{"GOENV", ".config/go/env"},
	// mise's three file-shaped config knobs, the half of its category-1 completeness the
	// directory table cannot express. Each names a config mise reads with NO trust check
	// at all - verified: a [tasks] entry in a MISE_GLOBAL_CONFIG_FILE or a
	// MISE_SYSTEM_CONFIG_FILE runs on `mise run` with no prompt and no record, and a
	// MISE_ENV_FILE's assignments land in `mise env` the same way. So a host that points
	// one of these at a dotfile repo has the shield on the trust record buying nothing:
	// the file it reads instead is trusted implicitly.
	//
	// The system config's default is /etc/mise/config.toml, outside every home anchor and
	// so outside bento's scope; MISE_ENV_FILE has no default at all. Both get the empty
	// def, which no absolute value matches, so any value they carry is shielded.
	{"MISE_GLOBAL_CONFIG_FILE", ".config/mise/config.toml"},
	{"MISE_SYSTEM_CONFIG_FILE", ""},
	{"MISE_ENV_FILE", ""},
}

// The variables read by name rather than from a table above: each relocates a group or
// carries an idiom the table shape cannot express.
var loneEnvs = []string{
	"ZDOTDIR",
	"GIT_CONFIG_GLOBAL",
	"PIP_CONFIG_FILE",
	"MAILCAPS",
	"CARGO_HOME",
	"HGRCPATH",
	"GOPATH",
	"STEPPATH",
	"XDG_RUNTIME_DIR",
}

// RelocationVars returns every environment variable the rule set reads, so a caller that
// must not have its answer depend on the ambient environment can clear them.
//
// The completeness audit is that caller: it builds this rule set for a fixed home and
// diffs it against an upstream corpus, so a GNUPGHOME or an XDG_CONFIG_HOME in the
// developer's shell adds a rule CI does not have, which can cover an upstream candidate
// and turn a real gap green. Home and Runtime document that invariant already; nothing
// but this makes it reachable, because the reads are spread over a dozen tables.
//
// Assembled from those tables rather than restated, so a variable added to one is covered
// here by construction. The by-name group is the residue that no table holds, and
// TestRelocationVarsNamesEveryEnvRead reads this file to prove it is complete.
func RelocationVars() []string {
	out := make([]string, 0, 48)
	for _, b := range xdgBases {
		out = append(out, b.env)
	}
	for _, e := range dirEnvs {
		out = append(out, e.env)
	}
	for _, e := range dirFileEnvs {
		out = append(out, e.env)
	}
	for _, e := range writeOnlyDirEnvs {
		out = append(out, e.env)
	}
	for _, e := range fileEnvs {
		out = append(out, e.env)
	}
	for _, e := range fileDenyAllEnvs {
		out = append(out, e.env)
	}
	for _, e := range startupDefaultEnvs {
		out = append(out, e.env)
	}
	return append(append(out, startupFileEnvs...), loneEnvs...)
}

// The tool-specific variables that relocate a DIRECTORY whose sensitive content is one
// named file inside it, so dirEnvs' whole-tree DenyAll cannot express them: the target
// also holds content an in-sandbox run legitimately reads. Not in AliasAnchors either -
// the anchor set is stores whose files identify a credential, and these targets are
// mostly not that.
var dirFileEnvs = []struct{ env, def, file string }{
	// dbt's profiles.yml holds the warehouse passwords; the directory beside it carries
	// the project config dbt also reads.
	{"DBT_PROFILES_DIR", ".dbt", "profiles.yml"},
	// curl reads $CURL_HOME/.curlrc ahead of ~/.curlrc, and --user user:pass lives in it.
	// The variable names a home directory, so the default to compare against is the anchor
	// itself and the empty def gets there via filepath.Join.
	{"CURL_HOME", "", ".curlrc"},
	// PULUMI_HOME moves the whole tree; only credentials.json in it is a secret, and the
	// plugins and workspace state beside it are what an in-sandbox `pulumi` reads.
	{"PULUMI_HOME", ".pulumi", "credentials.json"},
	// gradle.properties carries the signing keys and repository passwords; the caches and
	// wrapper distributions beside it are what an in-sandbox build reads. init.d under the
	// same variable is write-shielded in writeOnlyDirEnvs, the other half of the split.
	{"GRADLE_USER_HOME", ".gradle", "gradle.properties"},
}

// The tool-specific variables that move a whole write-shielded DIRECTORY off its default
// path - the DenyWrite analog of dirEnvs. Without them a shield on the default location
// is worth nothing on a host that sets the variable: the tool reads the record or the
// config from the relocation, and the run plants it there.
//
// sub is the shielded subdirectory of the relocated base, empty where the base is the
// shielded directory itself. MISE_DATA_DIR needs it because the data tree carries the
// interpreter installs a policy may legitimately write, and only shims/ is shielded.
// Sparing the installs does not make `mise install` succeed in-sandbox - the cache shield
// stops it first - and following the relocation widens who hits the shim shield.
var writeOnlyDirEnvs = []struct{ env, def, sub string }{
	// The third half of the CARGO_HOME split the explicit block in Home cannot emit: the
	// bin directory `cargo install` writes and rustup's env line puts on $PATH, so a
	// planted file there runs on the host under a name the user already types. The
	// registry and build caches beside it stay writable, as at the default ~/.cargo.
	{"CARGO_HOME", ".cargo", "bin"},
	// direnv.toml's [whitelist] skips the allow check the ~/.local/share/direnv/allow
	// shield rests on, so relocating the config directory disarms both.
	{"DIRENV_CONFIG", ".config/direnv", ""},
	// mise's trust record and the settings that bypass it, each with its own variable.
	// Only the record moves with the state dir; the tracked-configs beside it is written
	// by ordinary use and deliberately left alone, as at the default location.
	{"MISE_STATE_DIR", ".local/state/mise", "trusted-configs"},
	{"MISE_CONFIG_DIR", ".config/mise", ""},
	{"MISE_DATA_DIR", ".local/share/mise", "shims"},
	// The resolved bin_paths the host's next `mise x` reads with no trust check.
	{"MISE_CACHE_DIR", ".cache/mise", ""},
	// The cloned hook repos the host executes at the next commit.
	{"PRE_COMMIT_HOME", ".cache/pre-commit", ""},

	// The $PATH-resident binary and shim directories Home shields at their defaults. Each
	// variable is the tool's own documented relocation, so a shield left at the default
	// buys nothing on a host that sets it: the shim the host's next bare command name
	// resolves to is written at the relocation, and that is where a run plants it.
	//
	// The version managers keep the two-row bin/shims shape rather than taking the root,
	// for the reason the default rules give: the install prefix under the root holds the
	// interpreter a policy may legitimately write, and DenyWrite has no opt-in, so a root
	// rule would refuse that grant outright.
	//
	// GOPATH is colon-separated and so cannot go through a filepath.Join of one base. It
	// gets a block of its own above: the SplitList that HGRCPATH and MAILCAPS use, but
	// shielding the FIRST element only, because only that one supplies a bindir.
	{"GOBIN", "go/bin", ""},
	{"RUSTUP_HOME", ".rustup", ""},
	{"NVM_DIR", ".nvm", ""},
	{"NPM_CONFIG_PREFIX", ".npm-packages", ""},
	{"PYENV_ROOT", ".pyenv", "bin"},
	{"PYENV_ROOT", ".pyenv", "shims"},
	{"RBENV_ROOT", ".rbenv", "bin"},
	{"RBENV_ROOT", ".rbenv", "shims"},
	{"NODENV_ROOT", ".nodenv", "bin"},
	{"NODENV_ROOT", ".nodenv", "shims"},
	// asdf splits the two: the checkout with its own bin/asdf moves with ASDF_DIR, the
	// shims with ASDF_DATA_DIR, and either can be set alone.
	{"ASDF_DIR", ".asdf", "bin"},
	{"ASDF_DATA_DIR", ".asdf", "shims"},
	{"rvm_path", ".rvm", "bin"},
	{"rvm_path", ".rvm", "scripts"},
	{"VOLTA_HOME", ".volta", "bin"},
	{"BUN_INSTALL", ".bun", "bin"},
	{"KREW_ROOT", ".krew", "bin"},
	{"PUB_CACHE", ".pub-cache", "bin"},
	{"CABAL_DIR", ".cabal", "bin"},
	{"FOUNDRY_DIR", ".foundry", "bin"},
	{"COMPOSER_HOME", ".config/composer", "vendor/bin"},
	{"MIX_HOME", ".mix", "escripts"},
	{"MIX_HOME", ".mix", "archives"},
	// Gradle runs every script in init.d before each build. The credential file beside it
	// (gradle.properties) is file-shaped, so it follows the relocation from dirFileEnvs.
	{"GRADLE_USER_HOME", ".gradle", "init.d"},
	// The default bindir carries the ruby ABI version in its name, so there is no
	// home-relative default to compare against and the empty def only spares $HOME
	// itself; a GEM_HOME left at its default emits a rule inside the tree already
	// shielded there, which is redundant rather than wrong.
	{"GEM_HOME", "", "bin"},
	// pnpm's variable names the global bindir itself, not a tree above it.
	{"PNPM_HOME", ".local/share/pnpm", ""},
	// ghcup installs to $VAR/.ghcup and the variable defaults to $HOME, so the default to
	// compare against is the anchor - the empty-def shape dirFileEnvs' CURL_HOME uses.
	{"GHCUP_INSTALL_BASE_PREFIX", "", ".ghcup/bin"},
	// dotnet's global tools land under $VAR/.dotnet, the same anchor-defaulting shape.
	{"DOTNET_CLI_HOME", "", ".dotnet/tools"},
}

// The tool-specific variables that move a whole credential directory off its default path.
// Shared between the rule that follows the shield there and the alias scan that anchors on
// it: a store the two disagree about is one that is hidden but whose second readable name
// nothing looks for.
var dirEnvs = []struct{ env, def string }{
	{"GNUPGHOME", ".gnupg"},
	{"PASSWORD_STORE_DIR", ".password-store"},
	{"DOCKER_CONFIG", ".docker"},
	{"CLOUDSDK_CONFIG", ".config/gcloud"},
	{"GH_CONFIG_DIR", ".config/gh"},
	{"AZURE_CONFIG_DIR", ".azure"},
	// The container-host client key, the DOCKER_CONFIG shape for the other toolchain;
	// LXD_CONF is the legacy variable incus still honors.
	{"INCUS_CONF", ".config/incus"},
	{"LXD_CONF", ".config/lxc"},
	// The sync encryption key and the shell history it decrypts move together.
	{"ATUIN_DATA_DIR", ".local/share/atuin"},
}

// The hidden home directories, split by what the contents ARE. Every bucket is shielded
// identically - DenyAll, the whole tree; the split exists so the alias scan knows which
// files can IDENTIFY a credential (see AliasAnchors), and so that adding a deny entry
// forces that judgement instead of leaving it to a second list that silently drifts.

// credentialAnchorDirs hold key material: private keys, tokens, keyrings, vaults. They
// are small enough to enumerate on every launch, which is what lets them anchor the
// alias scan.
var credentialAnchorDirs = []string{
	".ssh",           // private keys, authorized_keys
	".aws",           // credentials, config
	".config/gcloud", // application-default credentials, tokens
	".azure",         // access tokens
	".kube",          // cluster credentials
	".docker",        // registry auth
	// auth.json here is podman/skopeo/buildah's documented fallback registry auth store
	// (the XDG_RUNTIME_DIR primary is covered by Runtime) - the same content .docker
	// holds for the other toolchain. The tree also carries containers.conf's
	// helper_binaries_dir/hooks_dir and registries.conf mirrors, which redirect a later
	// host invocation to attacker binaries or registries; hiding it covers both.
	".config/containers",
	".gnupg",           // secret keyrings
	".terraform.d",     // credentials.tfrc.json
	".config/gh",       // GitHub CLI tokens
	".local/share/gh",  // GitHub CLI tokens
	".config/rclone",   // remote storage tokens
	".oci",             // Oracle Cloud keys
	".config/doctl",    // DigitalOcean tokens
	".config/op",       // 1Password CLI
	".config/keybase",  // Keybase keys and tokens
	".pki",             // NSS certificate/key databases
	".local/share/pki", // XDG location for the same
	".minisign",        // minisign secret keys
	".config/mutt",     // XDG mutt config (imap_pass, exec knobs)
	".config/msmtp",    // XDG msmtp config
	".mutt",            // ~/.mutt/muttrc and sourced files
	".subversion/auth", // SVN stores plaintext passwords under auth/svn.simple/
	// step-cli keeps the CA and provisioner private keys here; the certificates and the
	// config beside them under ~/.step are what a sandboxed step run reads, so only the
	// secrets directory is taken - the .subversion/auth narrowing.
	//
	// With contexts enabled step keeps each authority's keys at authorities/<name>/secrets
	// instead, under a name chosen at init time, so no concrete path reaches them and this
	// is left as a residual - the sdkman candidates/*/current/bin class. Taking ~/.step
	// whole would reach it, which is what the narrowing above exists to avoid.
	".step/secrets",
	".config/openstack", // clouds.yaml / secure.yaml hold passwords and app-cred secrets
	".config/glab-cli",  // GitLab CLI host tokens, the .config/gh analog
	".config/helm",      // repository basic-auth and OCI registry auth (caches live under .cache/.local)
	// The client certificate and key authenticating to a container host, where creating a
	// privileged container with / bound in is root on that host - the .docker precedent,
	// one rung sharper. The legacy lxc path is where the same key sits after an upgrade,
	// which incus does not remove.
	".config/incus",
	".config/lxc",
	// Found by the shape hunt (internal/credhunt) rather than by either upstream corpus -
	// its sessions/*/.cache/KEYREGISTRY holds the CLI's stored git-host credentials.
	".local/share/GitKrakenCLI",

	// pass(1) is genuinely key-bearing and anchors, but it is also a git repo by design.
	// The alias scan skips VCS object stores inside an anchor separately, so a
	// `git clone --local` of the store does not read as an alias. Both narrowings are
	// load-bearing: this one decides the store counts, that one decides its blobs do not.
	".password-store",

	// OS secret stores: the master keyring behind saved passwords and tokens.
	".local/share/keyrings",    // GNOME Keyring
	".local/share/kwalletd",    // KDE Wallet
	".gnome2/keyrings",         // GNOME Keyring (legacy path)
	".gnome2_private",          // legacy GNOME private store, the sibling of .gnome2/keyrings above
	".kde/share/apps/kwallet",  // KDE Wallet (legacy path)
	".kde4/share/apps/kwallet", // KDE Wallet (legacy KDE4 path)
	".git-credential-cache",    // git credential-cache helper socket dir
	".cache/git/credential",    // modern git credential-cache socket location

	// atuin replaces the shell history files shielded by name above, and keeps beside that
	// history the key that decrypts the user's synced copy of it. Taken whole rather than
	// per-file, the way the shell histories are hidden rather than write-denied: it costs
	// in-sandbox atuin its recording, which is the same trade a hidden ~/.bash_history
	// already makes for every other shell.
	".local/share/atuin",

	".cert",             // NetworkManager / 802.1X / VPN client certificates and private keys
	".config/borg/keys", // borg repository keys (the repo caches beside them stay readable)

	// Crypto containers: headers, config, and wrapped passphrases. The encrypted and
	// decrypted home trees themselves are bulk and live in the other bucket.
	".TrueCrypt",
	".VeraCrypt",
	".zuluCrypt",
	".ecryptfs",                 // ecryptfs config and wrapped passphrase
	".fscrypt",                  // fscrypt policies and protectors
	".local/share/plasma-vault", // KDE Plasma Vault
	".vaults",                   // generic encrypted vault store
	".caff",                     // caff (GnuPG) signing material
	".nyx",                      // nyx Tor controller (control-port password)

	// Password managers and OTP stores: the local vault database, plus the caches and
	// per-app config that record its path and recently-opened entries.
	".keepass",
	".keepassx",
	".keepassxc",
	".config/keepass",
	".config/keepassx",
	".config/keepassxc",
	".config/KeePass",  // the .NET KeePass uses the capitalized name
	".cache/keepassxc", // last-opened database paths and search history
	".local/share/keepass",
	".local/share/KeePass",
	".config/Bitwarden",
	".config/1Password",
	".lastpass",
	".local/share/Enpass",
	".cache/Enpass",
	".config/Authenticator", // GNOME Authenticator: TOTP seeds
	".cache/Authenticator",
	".local/share/authenticator-rs", // authenticator-rs: TOTP seeds
	// SmartGit keeps the passwords for its configured remotes under a per-version
	// subdirectory (~/.smartgit/<version>/passwords), so the version is not expressible
	// as a concrete path and the whole tree is shielded instead.
	".smartgit",

	// Wallets whose directory is the keys. The full-node clients, whose directory is
	// mostly chain data, are shielded as bulk and anchored at their wallet subdir only.
	".electrum",
	".electron-cash", // Electrum's BCH fork, same seed-file layout
	".config/monero-project",
	"Monero/wallets",
	".config/Exodus",
	// Ledger Live is the exception in this block: it is a hardware-wallet frontend, so the
	// spending keys stay on the device and its config holds account xpubs and metadata. An
	// xpub discloses the full transaction history and every future address of the account,
	// which is the reconnaissance half of the same threat and is why it is shielded here.
	".config/Ledger Live",
	".config/cointop", // portfolio tracker: exchange API keys

	// Mail and messaging CONFIG (not message stores): the file is a credential.
	".config/neomutt", // same imap_pass class as the .mutt configs above
	".config/sendgmail",
	".alpine-smime", // alpine's S/MIME certificate and private-key store
	// Enpass ships its config under the vendor name rather than the product's.
	".config/Sinew Software Systems",
	".config/sinew.in",

	// Remote-access clients: the saved RDP/VNC/SSH passwords are recoverable, because
	// the key that encrypts them sits beside them in the same tree.
	".remmina",
	".config/remmina",
	".local/share/remmina",
	".anydesk",

	// Hosting and cloud-storage tokens, the class already shielded for rclone.
	".gdfuse", // google-drive-ocamlfuse OAuth tokens
	".config/gdfuse",
	".cache/gdfuse",
	".local/share/gdfuse",
	".local/share/emailidentities", // per-identity signature data, one dir per identity
	".filezilla",                   // sitemanager.xml stores passwords base64-encoded
	".config/filezilla",

	// Chat clients that keep account passwords in plaintext on disk. pidgin also holds
	// OTR private keys. Messengers whose store is an encrypted message database (Signal,
	// Session) are firejail's privacy scope and stay out.
	".purple",
	".weechat",
	".config/hexchat", // servlist.conf holds plaintext server passwords
	".config/xchat",
	".irssi",
	".mcabber",
	".config/coyim",
}

// walletKeyPaths are the narrow locations holding spending keys inside a full-node
// client's data directory. The parent is shielded as a bulk store - a synced node's
// blocks/ and chainstate/ run to tens of thousands of files, which the alias scan must
// not enumerate on every launch - so only the key material itself anchors it.
//
// Both the modern and the legacy layout are named: Bitcoin Core moved wallets into a
// wallets/ subdirectory in 0.16, and a host upgraded from an older version keeps the
// wallet where it was, at the top of the data directory. Anchoring only the modern path
// would leave the older layout shielded but undetectable behind an alias.
var walletKeyPaths = []string{
	".bitcoin/wallets",
	".bitcoin/wallet.dat", // pre-0.16 layout, kept in place across upgrades
	".config/Bitcoin/wallets",
	".config/Bitcoin/wallet.dat",
	".ethereum/keystore", // geth: the encrypted spending keys
	".dashcore/wallets",
	".dashcore/wallet.dat",
}

// bulkStoreDirs are shielded because they hold secrets, but hold far too many files to
// enumerate on every launch - and some are routinely hardlinked by the tools that manage
// them (mail sync deduplicates identical messages), which would trip the alias scan on a
// message rather than a credential. A saved mail password or browser login inside one of
// these is therefore not an alias anchor; the tree is still hidden from the sandbox.
//
// The split is by what the alias scan can enumerate, not by severity, so the bucket is
// mixed on that axis: chain data and mail sit beside stores whose whole point is a saved
// password (~/.config/gajim, ~/.config/Mumble's client certificate). The callouts name
// the bucket, so HoldsPrivateData's exposure clause carries that floor rather than
// promising the reader nothing here is a credential.
var bulkStoreDirs = []string{
	// Mail clients: saved IMAP/SMTP passwords in the profile store, and message bodies
	// that carry reset links and 2FA codes.
	".thunderbird",
	".config/evolution",
	".evolution", // pre-3.6 Evolution store, still present on upgraded systems
	".mail",      // mutt/notmuch maildir; message bodies and cached credentials
	".Mail",      // same, capitalized variant used by some setups
	"Mail",       // mutt default mail folder at ~/Mail (no leading dot)
	"mail",       // mutt default mail folder at ~/mail
	".icedove",
	".mozilla-thunderbird", // Debian's legacy Thunderbird profile root, same saved-password store
	".cache/icedove",
	".cache/thunderbird",
	".claws-mail",
	".cache/claws-mail",
	".fossamail",
	".cache/fossamail",
	".sylpheed-2.0",
	".balsa",
	".nylas-mail",
	".config/Nylas Mail",
	".config/electron-mail",
	".local/share/local-mail",
	".local/share/kmail2", // KMail/Akonadi message store
	".cache/kmail2",
	// Legacy KDE/KDE4 KMail stores, the pre-Akonadi siblings of .local/share/kmail2.
	// The KDE-era autostart paths beside them are already shielded, so the mail store
	// at the same roots being readable was an inconsistency rather than a decision.
	".kde/share/apps/kmail",
	".kde/share/apps/kmail2",
	".kde4/share/apps/kmail",
	".kde4/share/apps/kmail2",
	".cache/mutt", // cached message bodies
	".local/share/evolution",
	".cache/evolution",
	".config/geary",
	".local/share/geary",
	".cache/geary",

	// Chat and VoIP clients that keep account passwords, private keys, or both in
	// plaintext on disk - the same rule that admits pidgin/weechat/irssi above, applied to
	// the protocols they do not cover. Hidden whole rather than per-file: each store also
	// carries the message archive, and there is no in-sandbox need for either half.
	".local/share/dino",                 // XMPP: OMEMO identity keys plus account passwords
	".config/profanity",                 // XMPP console client account config
	".local/share/profanity",            // its account/OTR key store
	".config/gajim",                     // XMPP: saved account passwords
	".local/share/gajim",                //
	".cache/gajim",                      //
	".config/psi",                       // XMPP (Psi/Psi+): account passwords and OTR keys
	".config/psi+",                      //
	".local/share/psi",                  //
	".local/share/psi+",                 //
	".local/share/Psi",                  // firejail carries both spellings; Qt picked either
	".cache/psi",                        //
	".cache/Psi",                        //
	".local/share/telepathy",            // accounts.cfg holds the connection-manager passwords
	".config/telepathy-account-widgets", //
	".cache/telepathy",                  //
	".nicotine",                         // Soulseek client: the account password in its config
	".linphonerc",                       // SIP account auth password
	".linphone-history.db",              // call history alongside it
	".config/linphone",                  //
	".local/share/linphone",             //
	".config/Mumble",                    // Mumble client certificate INCLUDING its private key
	".local/share/Mumble",               //
	".local/share/data/Mumble",          // legacy Qt location for the same
	".config/kdeconnect",                // device pairing RSA key and trusted-device list
	".parsec",                           // remote-desktop client, the class remmina/anydesk already covers
	// hashcat's potfile is recovered plaintext passwords - the cracked output, which is
	// as sensitive as any store above.
	".hashcat",
	".local/share/hashcat",
	".cache/hashcat",

	// Cloud-sync client CONFIGURATION: the account tokens the client authenticates with.
	// Only the config and state trees, never the synced document folders (~/Nextcloud,
	// ~/Seafile) - those are user data, not secrets, and bento does not shield documents.
	// Deliberately not given a credentialName token: the classifier matches on path
	// components, and every token that catches .config/Nextcloud also catches ~/Nextcloud,
	// so the boundary cannot be drawn there (see the note on credentialName).
	".config/Nextcloud",
	".local/share/Nextcloud",
	".config/Seafile",
	".dropbox",
	".dropbox-dist",

	// Browser profiles: cookies, session tokens, and saved-password databases.
	".mozilla",               // Firefox
	".config/mozilla",        // XDG Firefox profile location (cookies, key4.db, logins.json)
	".zen",                   // Zen (Firefox fork): same profile store contents
	".config/google-chrome",  // Chrome
	".config/chromium",       // Chromium
	".config/BraveSoftware",  // Brave
	".config/microsoft-edge", // Edge

	// Electron messenger stores. Each keeps the client's own auth token - the credential
	// that authenticates the account, not the message history - recoverable in plaintext
	// or under a key sitting beside it, which is the same class as a browser's session
	// cookie store above and the standard infostealer target set. Shielded whole for the
	// usual reason: naming the token file leaves siblings exposed and does not stop a new
	// one being created. Signal and Session are still out - see credentialName for where
	// the line falls and why these fall on this side of it.
	".config/discord",
	".config/discordcanary",
	".config/discordptb",
	".config/Slack",
	".config/skypeforlinux",
	".cache/ms-skype-online",
	".TelegramDesktop",
	".local/share/TelegramDesktop",
	".local/share/telegram-desktop",

	// Encrypted-home trees: the whole home in either form, so bulk by construction.
	".Private", // ecryptfs private directory (encrypted underlay)
	"Private",  // ecryptfs DECRYPTED mount point at ~/Private: holds cleartext when mounted

	// Full-node wallet clients: the spending keys anchor via walletKeyPaths, but the data
	// directory as a whole is chain data.
	".bitcoin",
	".config/Bitcoin",
	".ethereum",
	".dashcore",
}

// historyDirs record what was typed, pasted, or edited. They can hold a secret that
// passed through them, which is why they are hidden rather than merely write-denied, but
// they hold no credential a tool would look for by name - so a grant lifting one exposes
// a record of the user's session, not a key. Under bento's default-deny a program that
// legitimately needs its own history opts in per-path.
var historyDirs = []string{
	".adobe",      // Flash local storage (LSO)
	".macromedia", // Flash local storage (legacy)
	".ne",         // ne editor state, incl. history
	// nvim's state tree holds shada (registers plus command/search history, the .viminfo
	// equivalent), undo files (full prior contents of edited files), swap (live buffer
	// contents, including unsaved edits, of every open file), and backup. Pre-0.8 nvim
	// kept the same stores under stdpath('data'), and an upgraded host keeps the
	// abandoned files - nvim never migrates or deletes them - so the legacy location
	// holds the same secrets. Both trees are shielded whole rather than per-store: the
	// write-only alternative left the secrets readable, and nvim's own plugin trees live
	// under the data dir, so a sandboxed nvim reads neither. That costs in-sandbox nvim
	// its plugins and state; a session that needs them opts in per-path.
	".local/state/nvim",
	".local/share/nvim",
	".cache/xfce4/clipman",             // clipboard history
	".kde/share/apps/klipper",          // clipboard history
	".kde4/share/apps/klipper",         // clipboard history (KDE4)
	".local/share/klipper",             // clipboard history (KDE5+)
	".local/share/ibus-typing-booster", // learned typing history
}

// serviceDirs hold an agent's control socket. A unix socket is a read-write channel to
// whatever is on the other end no matter how the path is mounted - the kernel refuses a
// write through a read-only bind only for regular files, directories and symlinks, so
// connect() succeeds through one (see Runtime, where the same reasoning takes all of
// /run). The directory is shielded rather than the socket by name, for the reason Runtime
// gives: naming today's socket leaves the next one beside it exposed. They hold no key
// material - that is the point, the key stays in the vault - so they anchor nothing.
var serviceDirs = []string{
	// The 1Password SSH agent's default socket directory on Linux. Reachable, it signs
	// with the user's keys on demand: a sandboxed run gets live SSH authentication to
	// every host those keys reach without the private key ever leaving the vault. The
	// .config/1Password and .config/op stores are shielded above; this is the channel
	// that makes shielding them insufficient on its own.
	".1password",
}

// persistenceDirs run code on the host at the next login or session. Hiding them (not
// merely denying writes) both blocks planting and keeps a sandboxed run from reading a
// session layout that aids a later attack; firejail blacklists them and there is no
// in-sandbox need to read them. They hold no key material, so they anchor nothing.
var persistenceDirs = []string{
	".config/autostart",    // XDG autostart .desktop entries
	".config/systemd",      // systemd --user units/timers (whole tree: user/ and drop-ins)
	".local/share/systemd", // systemd --user timer/service state
	".config/upstart",      // Upstart user session jobs, run at login where Upstart is the session init
	".init",                // Upstart user jobs at the legacy location
	// A thumbnailer is a .desktop-shaped file carrying an Exec= line that the file
	// manager runs, unprompted, the moment a directory holding a matching file is
	// browsed - the same plant-and-wait surface as .local/share/applications.
	".local/share/thumbnailers",
	// Window-manager and desktop-session trees firejail blacklists: their config runs
	// commands at session start (i3/sway `exec`, awesome rc.lua, openbox autostart), so
	// they are host-exec persistence surfaces.
	".blackbox",                 // Blackbox WM
	".config/autostart-scripts", // KDE autostart scripts
	".config/awesome",           // awesome rc.lua (Lua run at start)
	".config/i3",                // i3 config `exec` lines
	".config/openbox",           // openbox autostart + rc.xml
	".config/plasma-workspace",  // KDE Plasma env/ and autostart scripts
	".config/sway",              // sway config `exec` lines
	".fluxbox",                  // Fluxbox startup/apps
	".kde/Autostart",            // legacy KDE autostart
	".kde/env",                  // legacy KDE login env scripts
	".kde/share/autostart",      // legacy KDE autostart
	".kde/shutdown",             // legacy KDE shutdown scripts
	".kde4/Autostart",           // KDE4 autostart
	".kde4/env",                 // KDE4 login env scripts
	".kde4/share/autostart",     // KDE4 autostart
	".kde4/shutdown",            // KDE4 shutdown scripts
	".local/share/autostart",    // XDG autostart .desktop entries (data dir)
	".local/share/xorg",         // Xorg session logs/state
}
