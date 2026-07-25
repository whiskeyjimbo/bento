// Package denylist declares the paths Bento shields no matter what a policy
// grants.
//
// The list is data, not code: it is platform-independent and testable on its
// own, while each backend decides how to enforce a rule (bind mounts on Linux,
// SBPL rules on macOS). A policy that grants a broad path - say all of $HOME -
// must never expose these.
package denylist

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
)

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
}

// Home returns the mandatory rules for a user's home directory.
//
// Credential stores are shielded as whole directories on purpose. Naming
// individual files (~/.ssh/id_rsa) leaves siblings exposed (~/.ssh/my_deploy_key)
// and cannot stop a script from creating a new file in the directory.
func Home(home string) []Rule {
	join := func(p string) string { return filepath.Join(home, p) }

	dirs := slices.Concat(credentialAnchorDirs, bulkStoreDirs, persistenceDirs)
	files := []string{
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

		// Remote-login trust: writable would grant persistence, and the contents name
		// trusted hosts/users; sshd treats these as security-sensitive.
		".rhosts",
		".shosts",

		// Graphical-login scripts (X11): shell code run at graphical login. firejail
		// blacklists them; hidden here rather than merely write-denied, matching the
		// autostart/systemd persistence trees above - there is no in-sandbox read need and
		// hiding blocks both planting and reconnaissance. (Wayland persistence routes through
		// the systemd/autostart dirs above.)
		".xprofile",
		".xinitrc",
		".xsession",
		".xsessionrc", // sourced by the Debian/Ubuntu Xsession startup, like .xsession

		// Credential files various tools read by default.
		".fetchmailrc",       // fetchmail account password
		".davfs2/secrets",    // davfs2 mount credentials
		".cargo/credentials", // legacy cargo registry token (pre-credentials.toml)
		".passwd-s3fs",       // s3fs password file
		".s3cmd",             // s3cmd state firejail blacklists (the .s3cfg config file is shielded above)

		// Password-manager and wallet config files, hidden alongside the stores they
		// point at: each names the vault's location and its recently-opened entries,
		// which is reconnaissance for an attacker even where the secret itself lives
		// in the shielded store.
		".config/KeePassXCrc",
		".config/kwalletrc",
		".config/plasmavaultrc", // names the vaults whose store is shielded above
		// Mail-client config and identity files: account passwords (or the pointers to
		// where they are stored) and the addresses the account sends as.
		".gist",      // defunkt/gist stores the GitHub OAuth token as the file's whole content
		".mcabberrc", // mcabber XMPP config, holds the account password
		".pinerc",    // pine/alpine config
		".pinercex",  // its per-host companion
		".config/emaildefaults",
		".config/emailidentities",
		".config/mailtransports", // Akonadi SMTP transports, incl. stored passwords
		".config/kmail2rc",
		".config/kmailsearchindexingrc",
		".config/specialmailcollectionsrc",
		".pine-interrupted-mail",       // an interrupted draft: message body on disk
		".kde/share/config/kwalletrc",  // legacy KDE location
		".kde4/share/config/kwalletrc", // KDE4 location
		"wallet.dat",                   // Bitcoin Core wallet at the home root: the spending keys

		// Mail message stores and identity. mutt's default mailbox files/dirs and the
		// signature; message bodies carry reset links and 2FA codes, and a signature can
		// carry a PGP fingerprint or contact PII. The maildir roots ~/Mail and ~/mail are
		// shielded as directories above.
		"postponed",  // mutt default postponed-message mbox at ~/postponed
		"sent",       // mutt sent-mail mbox at ~/sent
		".signature", // outgoing-mail signature

		// The X11 display-access cookie: reading it grants control of the live X session
		// (keylog, screenshot, inject events), so it is a credential, not a config. Hidden,
		// not merely read-only as firejail has it - a bento sandbox has no X display to
		// authenticate to, so there is no legitimate in-sandbox read.
		".Xauthority",

		// zuluCrypt's IPC control socket, a channel to the daemon that manages encrypted
		// volumes (the .zuluCrypt store dir is shielded above).
		".zuluCrypt-socket",

		// Graphical-session scripts and generated startup configs firejail blacklists: each
		// is read or executed at login and a planted line runs on the host. Hidden to match
		// firejail and the WM trees above.
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
		".config/git/config",   // XDG location git reads the same as ~/.gitconfig
		".cargo/config.toml",   // cargo build/run honors build.rustc-wrapper, target runners, [target] linker
		".cargo/config",        // legacy (pre-1.39) cargo config filename, still read
		".cargo/env",           // shell script rustup makes .profile source; runs on next shell
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
		".xscreensaver",        // names programs run as screensavers
		".psqlrc",              // \! runs a shell command when psql starts
		".Rprofile",            // R sources it at startup (.Renviron holds the secrets and is DenyAll above)
		".mcp.json",

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
		".Xdefaults",               // xrdb resources read at login
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
		".bashrc.d",                 // Fedora/RHEL default .bashrc sources ~/.bashrc.d/*.sh; a planted entry runs on next shell (.bashrc itself is write-shielded, but the loop only checks the dir exists)
		".config/environment.d",     // systemd user-session env (LD_PRELOAD, PATH, ...)
		".config/fish",              // config.fish, conf.d/*.fish, autoloaded functions/*.fish (planting ls.fish hijacks `ls`)
		".config/nushell",           // config.nu/env.nu and autoloads
		".vim",                      // plugin/, autoload/, after/plugin/ are auto-sourced
		".config/nvim",              // init.{vim,lua}, lua/, plugin/, after/
		".emacs.d",                  // init.el and site-lisp
		".config/emacs",             // XDG location for the same
		".config/gdb",               // gdb 11+ reads gdbinit/gdbearlyinit here
		".config/tmux",              // XDG location for tmux.conf
		".config/direnv",            // direnvrc, sourced on cd for direnv users
		".local/share/direnv/allow", // authorization records: an entry pre-approves a workspace .envrc
		".config/Code",              // VS Code User/settings.json (git.path, interpreter paths) run commands
		".vscode",                   // extensions/ load on startup
		".config/mpv",               // scripts/*.lua autoloaded on launch
		".xmonad",                   // xmonad.hs is compiled and executed
		".config/xmonad",            // XDG location for xmonad.hs (0.17+)
		".oh-my-zsh",                // framework: plugins/ and themes/ are sourced on shell start
		".antigen",                  // zsh antigen-managed plugins, sourced on shell start
		".zfunc",                    // autoloaded zsh functions (planting one hijacks a command)
		".zsh.d",                    // sourced zsh config fragments
		".config/nsxiv/exec",        // nsxiv key-handler scripts run on keypress
		".config/pkcs11",            // pkcs11 module configs load shared objects (code)
		".local/share/applications", // .desktop entries whose Exec= runs on launch
		".config/menus",             // XDG menu definitions pointing at .desktop entries
		".gnome/apps",               // legacy GNOME menu entries

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
	}

	locations := func(entry string) []string { return homeLocations(home, entry) }

	rules := make([]Rule, 0, len(dirs)+len(files)+len(writeOnly)+len(writeOnlyDirs))
	emit := func(entry string, deny Deny, dir bool) {
		for _, p := range locations(entry) {
			rules = append(rules, Rule{Path: p, Deny: deny, Dir: dir})
		}
	}
	for _, d := range dirs {
		emit(d, DenyAll, true)
	}
	for _, f := range files {
		emit(f, DenyAll, false)
	}
	for _, f := range writeOnly {
		emit(f, DenyWrite, false)
	}
	for _, d := range writeOnlyDirs {
		emit(d, DenyWrite, true)
	}

	// A relocation target that is the root, the home itself, or an ancestor of it
	// cannot be shielded: the rule would hide or ro-bind the entire grant surface, so
	// nothing the policy granted stays reachable and every other rule is subsumed by
	// this one. The consumers already drop a rule resolving to "/" for the same reason
	// (see the Linux backend's denyArgs), and the ZDOTDIR relocation below already
	// declines the home itself; this applies the rule to the credential relocations
	// too, where a stray GNUPGHOME=$HOME would otherwise replace the whole deny-list
	// with one DenyAll on the home - which also silently nullifies the completeness
	// audit, since it leaves no per-store rule left to compare against firejail's.
	shieldable := func(p string) bool {
		return p != "/" && p != home && !strings.HasPrefix(home, p+string(filepath.Separator))
	}

	// A tool-specific env var can move a whole credential directory off its default
	// path, the same way an XDG base does. When one is set to an absolute location that
	// differs from the default (already shielded above), the shield follows to the
	// target too. A relative value is dropped: the shield is an absolute bwrap bind, so
	// a relative target cannot be shielded at the place the tool would actually read it.
	dirEnvs := []struct{ env, def string }{
		{"GNUPGHOME", ".gnupg"},
		{"PASSWORD_STORE_DIR", ".password-store"},
		{"DOCKER_CONFIG", ".docker"},
		{"CLOUDSDK_CONFIG", ".config/gcloud"},
		{"GH_CONFIG_DIR", ".config/gh"},
		{"AZURE_CONFIG_DIR", ".azure"},
	}
	for _, de := range dirEnvs {
		base := os.Getenv(de.env)
		if base == "" || !filepath.IsAbs(base) {
			continue
		}
		if c := filepath.Clean(base); c != join(de.def) && shieldable(c) {
			rules = append(rules, Rule{Path: c, Deny: DenyAll, Dir: true})
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
	fileEnvs := []struct{ env, store string }{
		{"KUBECONFIG", ".kube"},
		{"AWS_SHARED_CREDENTIALS_FILE", ".aws"},
		{"AWS_CONFIG_FILE", ".aws"},
	}
	for _, fe := range fileEnvs {
		store := join(fe.store)
		for _, p := range filepath.SplitList(os.Getenv(fe.env)) {
			if p == "" || !filepath.IsAbs(p) {
				continue
			}
			p = filepath.Clean(p)
			if p == store || strings.HasPrefix(p, store+string(filepath.Separator)) || !shieldable(p) {
				continue
			}
			rules = append(rules, Rule{Path: p, Deny: DenyAll})
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
	fileDenyAllEnvs := []struct{ env, def string }{
		{"HISTFILE", ""},
		{"NPM_CONFIG_USERCONFIG", ".npmrc"},
		{"R_ENVIRON_USER", ".Renviron"},
		{"LESSHISTFILE", ".lesshst"},
		{"MYSQL_HISTFILE", ".mysql_history"},
		{"PSQL_HISTORY", ".psql_history"},
		{"SQLITE_HISTORY", ".sqlite_history"},
		{"REDISCLI_HISTFILE", ".rediscli_history"},
		{"NODE_REPL_HISTORY", ".node_repl_history"},
	}
	for _, fe := range fileDenyAllEnvs {
		v := os.Getenv(fe.env)
		if !filepath.IsAbs(v) {
			continue
		}
		c := filepath.Clean(v)
		if c == "/dev/null" || (fe.def != "" && c == join(fe.def)) || !shieldable(c) {
			continue
		}
		rules = append(rules, Rule{Path: c, Deny: DenyAll})
	}

	// A startup file relocated by an env var is a persistence-planting target the
	// default DenyWrite shields above miss: ZDOTDIR points zsh at a different
	// directory for its whole startup group, and GIT_CONFIG_GLOBAL at a different
	// file git reads instead of ~/.gitconfig. Follow the shield to the relocation so
	// a write grant there cannot plant a file the host runs on the next shell or git
	// call. A relative value is dropped (an absolute bind cannot cover it), as is the
	// default location (already shielded) and git's /dev/null "no config" idiom.
	//
	// A relocation landing at or under a DenyAll rule is skipped: emitting a DenyWrite
	// there would stack a readable ro-bind after the DenyAll hide, and bwrap's
	// last-wins ordering would expose the credential the DenyAll rule is hiding (see
	// the ordering note in the Linux backend's denyArgs).
	underDenyAll := func(p string) bool {
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
	addWriteShield := func(p string) {
		if !underDenyAll(p) && shieldable(p) {
			rules = append(rules, Rule{Path: p, Deny: DenyWrite})
		}
	}
	if zdotdir := os.Getenv("ZDOTDIR"); filepath.IsAbs(zdotdir) && filepath.Clean(zdotdir) != home {
		// .zshrc.local is sourced by the widely-copied grml zshrc from ${ZDOTDIR:-$HOME},
		// so it relocates with the rest of the group (the default is shielded above).
		for _, f := range []string{".zshenv", ".zshrc", ".zshrc.local", ".zprofile", ".zlogin", ".zlogout"} {
			addWriteShield(filepath.Join(zdotdir, f))
		}
	}
	if gc := os.Getenv("GIT_CONFIG_GLOBAL"); filepath.IsAbs(gc) {
		if c := filepath.Clean(gc); c != join(".gitconfig") && c != "/dev/null" {
			addWriteShield(c)
		}
	}
	// Env vars that relocate a single startup file the host runs, the DenyWrite analog of
	// the block above. BASH_ENV is sourced by every non-interactive bash (why sudo strips
	// it); ENV by interactive POSIX sh/ksh/mksh/dash, and it is how ~/.kshrc / ~/.mkshrc
	// get designated. Both name a file with no default path to compare against.
	for _, env := range []string{"BASH_ENV", "ENV"} {
		if v := os.Getenv(env); filepath.IsAbs(v) {
			addWriteShield(filepath.Clean(v))
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
	for _, de := range []struct{ env, def string }{
		{"INPUTRC", ".inputrc"},
		{"PYTHONSTARTUP", ".pythonrc.py"},
		{"SCREENRC", ".screenrc"},
		{"PSQLRC", ".psqlrc"},
		{"R_PROFILE_USER", ".Rprofile"},
	} {
		if v := os.Getenv(de.env); filepath.IsAbs(v) {
			if c := filepath.Clean(v); c != join(de.def) {
				addWriteShield(c)
			}
		}
	}
	// PIP_CONFIG_FILE names the single pip.conf pip reads (index-url can redirect installs to
	// a malicious registry), the DenyWrite analog of the single-default loop but with TWO
	// conventional defaults, both shielded above. A value equal to either is already covered
	// and dropped; a relative value cannot be bound.
	if v := os.Getenv("PIP_CONFIG_FILE"); filepath.IsAbs(v) {
		if c := filepath.Clean(v); c != join(".config/pip/pip.conf") && c != join(".pip/pip.conf") {
			addWriteShield(c)
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
		if c := filepath.Clean(p); c != join(".mailcap") {
			addWriteShield(c)
		}
	}
	// CARGO_HOME relocates BOTH severity classes at once: the registry tokens
	// (credentials{,.toml}, hidden) and the build configs (config{,.toml}, env - each
	// names a rustc-wrapper/linker/runner the host executes, readable but not writable)
	// sit side by side under it. The dirEnvs table cannot express that split (it is
	// DenyAll-only), so emit the mixed set explicitly, re-based on the relocation and
	// mirroring the default ~/.cargo rules. The DenyAll files go in first so
	// addWriteShield's collision guard sees them; a write grant over the relocated dir is
	// refused upstream for containing the credential shields, as for the default ~/.cargo.
	if base := os.Getenv("CARGO_HOME"); filepath.IsAbs(base) {
		if c := filepath.Clean(base); c != join(".cargo") {
			for _, f := range []string{"credentials.toml", "credentials"} {
				rules = append(rules, Rule{Path: filepath.Join(c, f), Deny: DenyAll})
			}
			for _, f := range []string{"config.toml", "config", "env"} {
				addWriteShield(filepath.Join(c, f))
			}
		}
	}
	return rules
}

// Runtime returns the mandatory rules for the host's runtime state directory.
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
func Runtime() []Rule {
	return []Rule{
		{Path: "/run", Deny: DenyAll, Dir: true},
		// A symlink to /run on most hosts (resolved before it is shielded, so it
		// costs nothing there), a real directory on those that predate the merge.
		{Path: "/var/run", Deny: DenyAll, Dir: true},
	}
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
	}
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

// homeLocations expands a home-relative deny entry to every absolute path it must be
// shielded at: its default location, plus the XDG one when the relevant base is
// relocated.
func homeLocations(home, entry string) []string {
	join := func(p string) string { return filepath.Join(home, p) }
	for _, b := range xdgBases {
		if rel, ok := strings.CutPrefix(entry, b.prefix); ok {
			out := []string{join(entry)}
			// A relative XDG base is invalid per the spec and ignored by conforming
			// tools, which fall back to the default location - already shielded via
			// join(entry). Emitting a relative Rule.Path here would shield nothing at
			// the intended place, so drop it and rely on the default shield.
			if base := os.Getenv(b.env); base != "" && filepath.IsAbs(base) && filepath.Clean(base) != join(b.def) {
				out = append(out, filepath.Join(base, rel))
			}
			return out
		}
	}
	return []string{join(entry)}
}

// AliasAnchors returns the absolute paths whose files identify a credential, for detecting
// a second readable name for one. It is narrower than the full set of hidden directories:
// see credentialAnchorDirs for which stores count and why, and walletKeyPaths for the
// full-node clients that anchor only their key subtree.
func AliasAnchors(home string) []string {
	anchors := slices.Concat(credentialAnchorDirs, walletKeyPaths)
	out := make([]string, 0, len(anchors))
	for _, d := range anchors {
		out = append(out, homeLocations(home, d)...)
	}
	return out
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
	// (the XDG_RUNTIME_DIR primary is covered by Runtime()) - the same content .docker
	// holds for the other toolchain. The tree also carries containers.conf's
	// helper_binaries_dir/hooks_dir and registries.conf mirrors, which redirect a later
	// host invocation to attacker binaries or registries; hiding it covers both.
	".config/containers",
	".gnupg",            // secret keyrings
	".terraform.d",      // credentials.tfrc.json
	".config/gh",        // GitHub CLI tokens
	".local/share/gh",   // GitHub CLI tokens
	".config/rclone",    // remote storage tokens
	".oci",              // Oracle Cloud keys
	".config/doctl",     // DigitalOcean tokens
	".config/op",        // 1Password CLI
	".config/keybase",   // Keybase keys and tokens
	".pki",              // NSS certificate/key databases
	".local/share/pki",  // XDG location for the same
	".minisign",         // minisign secret keys
	".config/mutt",      // XDG mutt config (imap_pass, exec knobs)
	".config/msmtp",     // XDG msmtp config
	".mutt",             // ~/.mutt/muttrc and sourced files
	".subversion/auth",  // SVN stores plaintext passwords under auth/svn.simple/
	".config/openstack", // clouds.yaml / secure.yaml hold passwords and app-cred secrets

	// pass(1) is genuinely key-bearing and anchors, but it is also a git repo by design.
	// The alias scan skips VCS object stores inside an anchor separately, so a
	// `git clone --local` of the store does not read as an alias. Both narrowings are
	// load-bearing: this one decides the store counts, that one decides its blobs do not.
	".password-store",

	// OS secret stores: the master keyring behind saved passwords and tokens.
	".local/share/keyrings",    // GNOME Keyring
	".local/share/kwalletd",    // KDE Wallet
	".gnome2/keyrings",         // GNOME Keyring (legacy path)
	".kde/share/apps/kwallet",  // KDE Wallet (legacy path)
	".kde4/share/apps/kwallet", // KDE Wallet (legacy KDE4 path)
	".git-credential-cache",    // git credential-cache helper socket dir
	".cache/git/credential",    // modern git credential-cache socket location

	".cert", // NetworkManager / 802.1X / VPN client certificates and private keys

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
var bulkStoreDirs = []string{
	// Mail clients: saved IMAP/SMTP passwords in the profile store, and message bodies
	// that carry reset links and 2FA codes.
	".thunderbird",
	".config/evolution",
	".mail", // mutt/notmuch maildir; message bodies and cached credentials
	".Mail", // same, capitalized variant used by some setups
	"Mail",  // mutt default mail folder at ~/Mail (no leading dot)
	"mail",  // mutt default mail folder at ~/mail
	".icedove",
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
	".cache/mutt", // cached message bodies
	".local/share/evolution",
	".cache/evolution",
	".config/geary",
	".local/share/geary",
	".cache/geary",

	// Browser profiles: cookies, session tokens, and saved-password databases.
	".mozilla",               // Firefox
	".config/mozilla",        // XDG Firefox profile location (cookies, key4.db, logins.json)
	".zen",                   // Zen (Firefox fork): same profile store contents
	".config/google-chrome",  // Chrome
	".config/chromium",       // Chromium
	".config/BraveSoftware",  // Brave
	".config/microsoft-edge", // Edge

	// Encrypted-home trees: the whole home in either form, so bulk by construction.
	".Private", // ecryptfs private directory (encrypted underlay)
	"Private",  // ecryptfs DECRYPTED mount point at ~/Private: holds cleartext when mounted

	// Full-node wallet clients: the spending keys anchor via walletKeyDirs, but the data
	// directory as a whole is chain data.
	".bitcoin",
	".config/Bitcoin",
	".ethereum",
	".dashcore",

	// History and clipboard stores: can hold pasted or typed secrets. Under bento's
	// default-deny a program that legitimately needs its own history opts in per-path.
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

// persistenceDirs run code on the host at the next login or session. Hiding them (not
// merely denying writes) both blocks planting and keeps a sandboxed run from reading a
// session layout that aids a later attack; firejail blacklists them and there is no
// in-sandbox need to read them. They hold no key material, so they anchor nothing.
var persistenceDirs = []string{
	".config/autostart",    // XDG autostart .desktop entries
	".config/systemd",      // systemd --user units/timers (whole tree: user/ and drop-ins)
	".local/share/systemd", // systemd --user timer/service state
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
