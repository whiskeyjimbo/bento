package denylist

import (
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The deny-list is a security invariant: dropping an entry silently re-exposes a
// credential store. This guards the high-value stores that are easy to forget -
// OS keyrings and browser profiles hold saved passwords and session tokens.
func TestHomeShieldsSecretStores(t *testing.T) {
	rules := Home("/home/u")
	byPath := make(map[string]Rule, len(rules))
	for _, r := range rules {
		byPath[r.Path] = r
	}

	wantDenyAllDir := []string{
		"/home/u/.ssh",
		"/home/u/.aws",
		"/home/u/.local/share/keyrings",
		"/home/u/.mozilla",
		"/home/u/.config/mozilla", // XDG Firefox profile store
		"/home/u/.zen",            // Zen browser profile store
		"/home/u/.config/google-chrome",
		// Electron messengers: a live account token recoverable from the local store,
		// the browser session-cookie class rather than message content. All nine, since
		// each is a separate install location and missing one re-exposes that account.
		"/home/u/.config/discord",
		"/home/u/.config/discordcanary",
		"/home/u/.config/discordptb",
		"/home/u/.config/Slack",
		"/home/u/.config/skypeforlinux",
		"/home/u/.cache/ms-skype-online",
		"/home/u/.TelegramDesktop",
		"/home/u/.local/share/TelegramDesktop",
		"/home/u/.local/share/telegram-desktop",
		"/home/u/.config/rclone",
		"/home/u/.config/keybase",       // Keybase keys/tokens
		"/home/u/.pki",                  // NSS cert/key DBs
		"/home/u/.gnome2/keyrings",      // legacy keyring path
		"/home/u/.git-credential-cache", // git credential cache
		"/home/u/.mutt",                 // mutt config (imap_pass) hidden
		// podman/skopeo/buildah's fallback registry auth store (auth.json), the same
		// content ~/.docker holds - hidden, not merely write-shielded.
		"/home/u/.config/containers",
		"/home/u/.config/mutt",         // XDG mutt config
		"/home/u/.subversion/auth",     // SVN plaintext passwords
		"/home/u/.config/openstack",    // OpenStack clouds.yaml/secure.yaml
		"/home/u/.thunderbird",         // Thunderbird saved mail passwords
		"/home/u/.config/evolution",    // Evolution saved mail passwords
		"/home/u/.cert",                // 802.1X/VPN client keys (real kind varies by host)
		"/home/u/.mail",                // maildir bodies and cached creds
		"/home/u/.Mail",                // capitalized maildir variant
		"/home/u/.local/state/nvim",    // shada/undo/swap/backup: registers, search history, and full buffer contents
		"/home/u/.local/share/nvim",    // pre-0.8 legacy location of the same stores, abandoned but not deleted on upgrade
		"/home/u/.config/autostart",    // XDG autostart .desktop entries (hidden, matching firejail)
		"/home/u/.config/systemd",      // systemd --user unit/timer tree
		"/home/u/.local/share/systemd", // systemd --user state
		"/home/u/Mail",                 // mutt default mail folder (no leading dot)
		"/home/u/mail",                 // mutt default mail folder
		"/home/u/Private",              // ecryptfs decrypted mount point
		"/home/u/.keepassxc",           // password-manager vault
		"/home/u/.config/keepassxc",    // and its config/cache siblings
		"/home/u/.cache/keepassxc",
		"/home/u/.config/Bitwarden",
		"/home/u/.config/1Password",
		"/home/u/.local/share/Enpass",
		"/home/u/.config/Authenticator", // TOTP seeds
		"/home/u/.smartgit",             // per-version subdir holds remote passwords
		"/home/u/.bitcoin",              // wallet private keys
		"/home/u/.electrum",             // named instance behind the .electrum* glob
		"/home/u/Monero/wallets",        // non-hidden wallet dir at the home root
		"/home/u/.ethereum",             // geth keystore
		"/home/u/.electron-cash",        // Electrum fork that dropped the stem
		"/home/u/.config/Ledger Live",
		"/home/u/.config/cointop",
		"/home/u/.icedove",    // Debian-rebranded Thunderbird, same profile format
		"/home/u/.claws-mail", // saved IMAP/SMTP passwords
		"/home/u/.remmina",    // recoverable RDP/VNC passwords
		"/home/u/.anydesk",
		"/home/u/.gdfuse",    // Google Drive OAuth tokens
		"/home/u/.filezilla", // base64-encoded site passwords
		"/home/u/.purple",    // pidgin plaintext passwords and OTR keys
		"/home/u/.weechat",   // IRC server passwords
		"/home/u/.config/coyim",
		"/home/u/.config/hexchat",        // servlist.conf plaintext server passwords
		"/home/u/.config/neomutt",        // same imap_pass class as .mutt
		"/home/u/.local/share/evolution", // message store (only .config/evolution was shielded before)
		"/home/u/.config/geary",
		"/home/u/.alpine-smime",    // alpine S/MIME private keys
		"/home/u/.config/sinew.in", // Enpass under its vendor name
		"/home/u/.config/Sinew Software Systems",
		"/home/u/.config/i3",               // WM config `exec` (hidden, matching firejail)
		"/home/u/.config/plasma-workspace", // KDE session env/autostart
		"/home/u/.kde4/Autostart",          // legacy KDE autostart
	}
	for _, p := range wantDenyAllDir {
		r, ok := byPath[p]
		if !ok {
			t.Errorf("%s is not shielded", p)
			continue
		}
		if r.Deny != DenyAll || !r.Dir {
			t.Errorf("%s: got Deny=%v Dir=%v, want DenyAll directory", p, r.Deny, r.Dir)
		}
	}

	wantDenyAllFile := []string{
		"/home/u/.netrc",
		"/home/u/.pgpass",
		"/home/u/.smbcredentials",          // SMB mount credentials
		"/home/u/.config/hub",              // hub OAuth token
		"/home/u/.msmtprc",                 // SMTP passwords (hidden, not just write-denied)
		"/home/u/.yarnrc.yml",              // yarn npmAuthToken
		"/home/u/.Renviron",                // plaintext API keys/DB passwords loaded into the R session; hiding also neutralizes its R_PROFILE_USER exec knob
		"/home/u/.my.cnf",                  // MySQL plaintext password
		"/home/u/.mylogin.cnf",             // MySQL login-path store (obfuscated, not encrypted)
		"/home/u/.xinitrc",                 // X startup script (hidden, matching firejail)
		"/home/u/.xsession",                // X session script
		"/home/u/.xprofile",                // X login profile
		"/home/u/.xsessionrc",              // Debian/Ubuntu Xsession startup
		"/home/u/.Xauthority",              // X display-access cookie (credential)
		"/home/u/.signature",               // mail signature (PII/PGP fingerprint)
		"/home/u/postponed",                // mutt postponed mbox
		"/home/u/sent",                     // mutt sent mbox
		"/home/u/.zuluCrypt-socket",        // zuluCrypt IPC socket
		"/home/u/.s3cmd",                   // s3cmd state
		"/home/u/.Xresources",              // xrdb resources (hidden, matching firejail)
		"/home/u/.xserverrc",               // startx X server launch script
		"/home/u/.config/startupconfig",    // KDE generated startup config
		"/home/u/.history",                 // tcsh default history (bento shields .tcshrc, so the shell is in-model)
		"/home/u/.sh_history",              // ksh default HISTFILE (bento shields .kshrc)
		"/home/u/.php_history",             // php -a interactive REPL history
		"/home/u/.python-history",          // dash-spelled Python REPL history variant
		"/home/u/.cache/greenclip.history", // greenclip clipboard history (pasted secrets)
		"/home/u/.config/KeePassXCrc",      // vault location and recently-opened entries
		"/home/u/.config/kwalletrc",        // KDE Wallet config
		"/home/u/wallet.dat",               // Bitcoin Core wallet at the home root
		"/home/u/.mcabberrc",               // XMPP account password
		"/home/u/.pinerc",                  // pine/alpine config
		"/home/u/.config/mailtransports",   // Akonadi SMTP transports, incl. passwords
		"/home/u/.pine-interrupted-mail",   // draft message body on disk
		"/home/u/.config/plasmavaultrc",    // names the vaults whose store is shielded
		"/home/u/.gist",                    // GitHub OAuth token, a file not a dir
		"/home/u/.authinfo",                // Emacs auth-source, the .netrc sibling default
		"/home/u/.hgrc",                    // Mercurial [auth] passwords and [hooks] host exec
		"/home/u/.config/hg/hgrc",          // the XDG spelling hg reads the same way
		"/home/u/.curlrc",                  // --user user:pass, read by default
		"/home/u/.dbt/profiles.yml",        // warehouse passwords, the .pgpass class
		"/home/u/.ansible/galaxy_token",    // the token, not the collections cache beside it
	}
	for _, p := range wantDenyAllFile {
		r, ok := byPath[p]
		if !ok {
			t.Errorf("%s is not shielded", p)
			continue
		}
		if r.Deny != DenyAll || r.Dir {
			t.Errorf("%s: got Deny=%v Dir=%v, want DenyAll file", p, r.Deny, r.Dir)
		}
	}

	// Config files that grant host code execution when modified must be readable
	// (git legitimately reads them) but not writable. Both the classic ~/.gitconfig
	// and its XDG twin ~/.config/git/config are read the same way by git, so a home
	// write grant must not be able to plant core.hooksPath/core.pager in either.
	wantDenyWriteFile := []string{
		"/home/u/.gitconfig",
		"/home/u/.config/git/config",   // XDG git config
		"/home/u/.zshenv",              // read for every zsh invocation, incl. non-interactive
		"/home/u/.zlogin",              // zsh login
		"/home/u/.zlogout",             // zsh logout
		"/home/u/.bash_login",          // bash login fallback
		"/home/u/.bash_aliases",        // sourced by the default .bashrc; usually absent so plantable
		"/home/u/.bash_logout",         // bash logout
		"/home/u/.cargo/config.toml",   // cargo honors rustc-wrapper / target runners
		"/home/u/.cargo/config",        // legacy cargo config filename
		"/home/u/.vimrc",               // sourced when vim opens a file
		"/home/u/.emacs",               // elisp at emacs startup
		"/home/u/.gdbinit",             // executed by gdb on startup
		"/home/u/.direnvrc",            // legacy direnv global rc
		"/home/u/.cargo/env",           // rustup makes .profile source it
		"/home/u/.exrc",                // vim also sources this
		"/home/u/.gvimrc",              // gvim rc
		"/home/u/.screenrc",            // GNU screen runs commands
		"/home/u/.mailcap",             // MIME handler commands
		"/home/u/.yarnrc",              // yarn-path exec (classic, no token)
		"/home/u/.pam_environment",     // PAM login env (LD_PRELOAD/PATH)
		"/home/u/.config/pip/pip.conf", // pip index-url registry redirect
		"/home/u/.pip/pip.conf",        // legacy per-user pip config, also default-read
		"/home/u/.inputrc",             // readline macro binding runs on a keypress
		"/home/u/.nanorc",              // nano rc (include/syntax)
		"/home/u/.plan",                // finger info: readable, tamper-protected
		"/home/u/.Xdefaults",           // xrdb resources read at login
		"/home/u/.bash_completion",     // sourced by the distro bash.bashrc for every interactive shell
		"/home/u/.selected_editor",     // sensible-editor sources it and runs $SELECTED_EDITOR
		"/home/u/.fzf.zsh",             // sourced by the line fzf's installer appends to the rc
		"/home/u/.p10k.zsh",            // sourced verbatim by the powerlevel10k line in .zshrc
	}
	for _, p := range wantDenyWriteFile {
		r, ok := byPath[p]
		if !ok {
			t.Errorf("%s is not shielded", p)
			continue
		}
		if r.Deny != DenyWrite || r.Dir {
			t.Errorf("%s: got Deny=%v Dir=%v, want DenyWrite file", p, r.Deny, r.Dir)
		}
	}

	// Login-persistence directories: readable, but no new entry may be created,
	// so a broad home write grant cannot plant an autostart entry or user service.
	wantDenyWriteDir := []string{
		"/home/u/.bashrc.d",                                // Fedora/RHEL .bashrc sources ~/.bashrc.d/*.sh
		"/home/u/.config/fish",                             // config.fish, conf.d/*.fish, and autoloaded functions/*.fish
		"/home/u/.config/nushell",                          // nushell config and autoloads
		"/home/u/.vim",                                     // auto-sourced plugin/autoload dirs
		"/home/u/.config/nvim",                             // neovim config tree
		"/home/u/.emacs.d",                                 // emacs init and site-lisp
		"/home/u/.config/environment.d",                    // systemd user-session env
		"/home/u/.local/share/direnv/allow",                // direnv authorization records
		"/home/u/.config/Code",                             // VS Code User settings (git.path etc.)
		"/home/u/.vscode",                                  // VS Code extensions dir
		"/home/u/.config/mpv",                              // mpv autoloaded scripts
		"/home/u/.xmonad",                                  // xmonad.hs compiled+run
		"/home/u/.local/lib",                               // user libraries imported at runtime
		"/home/u/.local/share/bash-completion/completions", // sourced on the first tab-complete of that command
		"/home/u/.config/zsh",                              // the conventional ZDOTDIR, shielded without the (non-exported) variable
		"/home/u/.zprezto",                                 // zsh framework, the .oh-my-zsh class
		"/home/u/.zinit",                                   // zsh plugin manager
		"/home/u/.tmux/plugins",                            // what the write-denied .tmux.conf actually runs
		// $PATH-resident directories: a planted file runs under a bare command name.
		"/home/u/go/bin",
		"/home/u/.pyenv/shims",
		"/home/u/.asdf/shims",
		"/home/u/.local/share/mise/shims",
		"/home/u/.local/share/pnpm",
	}
	for _, p := range wantDenyWriteDir {
		r, ok := byPath[p]
		if !ok {
			t.Errorf("%s is not shielded", p)
			continue
		}
		if r.Deny != DenyWrite || !r.Dir {
			t.Errorf("%s: got Deny=%v Dir=%v, want DenyWrite directory", p, r.Deny, r.Dir)
		}
	}
}

// A write grant to a repository must not let a script plant an editor config that
// runs a host binary the next time the project is opened. The editor dirs are shielded
// whole (DenyWrite directories) so no individual file - .vscode/settings.json,
// .idea/runConfigurations/*.xml - is left plantable by enumeration.
func TestWorkspaceShieldsEditorConfigDirs(t *testing.T) {
	byPath := make(map[string]Rule)
	for _, r := range Workspace("/w") {
		byPath[r.Path] = r
	}
	for _, p := range []string{"/w/.vscode", "/w/.idea"} {
		r, ok := byPath[p]
		if !ok {
			t.Errorf("%s is not shielded", p)
			continue
		}
		if r.Deny != DenyWrite || !r.Dir {
			t.Errorf("%s: got Deny=%v Dir=%v, want DenyWrite directory", p, r.Deny, r.Dir)
		}
	}
	// The old per-file entries must be gone: a bare settings.json shield would mean the
	// directory itself is writable and its siblings plantable.
	for _, p := range []string{"/w/.vscode/tasks.json", "/w/.vscode/settings.json", "/w/.idea/workspace.xml"} {
		if _, ok := byPath[p]; ok {
			t.Errorf("%s is shielded as an individual file; the whole dir must be shielded instead", p)
		}
	}
}

// The host's runtime directory holds its services' control sockets (the docker
// daemon, the session bus, gpg-agent). Connecting to one is a read-write channel
// to that service no matter how the path is mounted - a read-only bind does not
// stop connect() - so /run must be shielded whole, not left to a read grant.
func TestRuntimeShieldsHostSockets(t *testing.T) {
	for _, r := range Runtime("/run/user/1000") {
		if r.Deny != DenyAll || !r.Dir {
			t.Errorf("%s: got Deny=%v Dir=%v, want DenyAll directory", r.Path, r.Deny, r.Dir)
		}
	}
	byPath := make(map[string]bool, len(Runtime("/run/user/1000")))
	for _, r := range Runtime("/run/user/1000") {
		byPath[r.Path] = true
	}
	// /var/run is the pre-usrmerge spelling: a symlink to /run on most hosts, a
	// real directory on those that predate the merge, where the /run rule alone
	// would leave every socket reachable under the other name.
	for _, p := range []string{"/run", "/var/run"} {
		if !byPath[p] {
			t.Errorf("%s is not shielded", p)
		}
	}
}

// A relocated XDG base moves credential/config stores out from under ~/.config,
// so the shields must cover the XDG location too (bv2-3qg).
func TestHomeShieldsXDGRelocatedStores(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/home/u/cfg")
	t.Setenv("XDG_DATA_HOME", "/home/u/data")
	t.Setenv("XDG_STATE_HOME", "/home/u/state")
	byPath := map[string]bool{}
	for _, r := range Home("/home/u") {
		byPath[r.Path] = true
	}
	// Shielded at BOTH the default and the relocated XDG location.
	for _, p := range []string{
		"/home/u/.config/gh", "/home/u/cfg/gh", // gh tokens (config)
		"/home/u/.local/share/keyrings", "/home/u/data/keyrings", // GNOME keyring (data)
		"/home/u/.local/state/nvim", "/home/u/state/nvim", // nvim state tree (state)
	} {
		if !byPath[p] {
			t.Errorf("expected a shield at %q (XDG relocation), missing", p)
		}
	}
}

// A relative XDG base is invalid per the spec and ignored by conforming tools. Emitting
// a relative Rule.Path would shield nothing at the intended location while looking like
// coverage, so the base is dropped and only the (absolute) default location is shielded.
func TestHomeIgnoresRelativeXDGBase(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "relcfg")
	for _, r := range Home("/home/u") {
		if !filepath.IsAbs(r.Path) {
			t.Errorf("relative XDG base leaked a non-absolute shield path %q", r.Path)
		}
	}
}

// A tool-specific env var (GNUPGHOME etc.) moves a whole credential store off its default
// path; the shield must follow to the absolute target while the default stays shielded.
// A relative value is ignored, like a relative XDG base (bv2-ovj).
func TestHomeShieldsRelocatedCredentialDirs(t *testing.T) {
	t.Setenv("GNUPGHOME", "/secrets/gnupg")
	t.Setenv("DOCKER_CONFIG", "/secrets/docker")
	t.Setenv("CLOUDSDK_CONFIG", "/secrets/gcloud")
	t.Setenv("GH_CONFIG_DIR", "/secrets/gh")
	t.Setenv("AZURE_CONFIG_DIR", "/secrets/azure")
	t.Setenv("PASSWORD_STORE_DIR", "relpass") // relative: must not shield

	byPath := map[string]bool{}
	for _, r := range Home("/home/u") {
		if !filepath.IsAbs(r.Path) {
			t.Errorf("relative relocation env leaked a non-absolute shield path %q", r.Path)
		}
		byPath[r.Path] = true
	}
	// Absolute relocations shielded at the target, defaults still shielded.
	for _, p := range []string{
		"/secrets/gnupg", "/home/u/.gnupg",
		"/secrets/docker", "/home/u/.docker",
		"/secrets/gcloud", "/home/u/.config/gcloud",
		"/secrets/gh", "/home/u/.config/gh",
		"/secrets/azure", "/home/u/.azure",
	} {
		if !byPath[p] {
			t.Errorf("expected a shield at %q (credential relocation), missing", p)
		}
	}
	// The relative PASSWORD_STORE_DIR is dropped; only the default remains.
	if byPath["relpass"] {
		t.Error("a relative PASSWORD_STORE_DIR must not produce a shield")
	}
	if !byPath["/home/u/.password-store"] {
		t.Error("the default password store must stay shielded")
	}
}

// A relocation variable accepts any absolute path, so a shield can land on something the
// run then needs and fail with an error naming only the target. Nothing can reconstruct
// the cause from the path afterwards, so every family that follows a variable must record
// which one it followed - and a rule at its default location must claim no variable, or
// the report would blame the environment for a shield bento would have applied anyway.
func TestHomeRecordsWhichVariableRelocatedAShield(t *testing.T) {
	t.Setenv("GNUPGHOME", "/secrets/gnupg")          // dirEnvs
	t.Setenv("KUBECONFIG", "/secrets/kubeconfig")    // fileEnvs, colon-split
	t.Setenv("HISTFILE", "/secrets/history")         // fileDenyAllEnvs
	t.Setenv("ZDOTDIR", "/secrets/zsh")              // startup group
	t.Setenv("PIP_CONFIG_FILE", "/secrets/pip.conf") // single-default write shield
	t.Setenv("MAILCAPS", "/secrets/mailcap")         // colon-split write shield
	t.Setenv("CARGO_HOME", "/secrets/cargo")         // mixed severities
	t.Setenv("XDG_CONFIG_HOME", "/secrets/xdg")      // whole-base expansion

	bySource := map[string]string{}
	for _, r := range Home("/home/u") {
		bySource[r.Path] = r.Source
	}
	for path, want := range map[string]string{
		"/secrets/gnupg":             "GNUPGHOME",
		"/secrets/kubeconfig":        "KUBECONFIG",
		"/secrets/history":           "HISTFILE",
		"/secrets/zsh/.zshrc":        "ZDOTDIR",
		"/secrets/pip.conf":          "PIP_CONFIG_FILE",
		"/secrets/mailcap":           "MAILCAPS",
		"/secrets/cargo/credentials": "CARGO_HOME",
		"/secrets/xdg/gh":            "XDG_CONFIG_HOME",
		"/home/u/.gnupg":             "",
		"/home/u/.bash_history":      "",
		"/home/u/.config/gh":         "",
	} {
		got, ok := bySource[path]
		if !ok {
			t.Errorf("expected a shield at %q, missing", path)
			continue
		}
		if got != want {
			t.Errorf("shield at %q credits %q, want %q", path, got, want)
		}
	}
}

// XDG_RUNTIME_DIR is the one relocation outside Home, and it breaks a run the same way:
// the socket directory follows the variable, so a value pointing somewhere the script
// needs blanks it with nothing naming the cause.
func TestRuntimeRecordsTheRelocatingVariable(t *testing.T) {
	rules := Runtime("/custom/run", "/home/u")
	for _, r := range rules {
		want := ""
		if r.Path == "/custom/run" {
			want = "XDG_RUNTIME_DIR"
		}
		if r.Source != want {
			t.Errorf("shield at %q credits %q, want %q", r.Path, r.Source, want)
		}
	}
}

// A relocation target that swallows the whole home cannot be shielded: one DenyAll on
// the home hides every granted path, so the run confines nothing it could still do -
// and it subsumes every other rule, which silently empties the set the completeness
// audit compares against firejail's. The store's own default stays shielded, and the
// rest of the deny-list must survive intact.
func TestHomeIgnoresRelocationsThatSwallowTheHome(t *testing.T) {
	baseline := len(Home("/home/u"))

	for _, tc := range []struct{ env, value string }{
		{"GNUPGHOME", "/home/u"},  // the home itself
		{"GNUPGHOME", "/home"},    // an ancestor of it
		{"GNUPGHOME", "/"},        // the root
		{"KUBECONFIG", "/home/u"}, // the same via a file relocation
		{"AWS_CONFIG_FILE", "/home"},
		{"PASSWORD_STORE_DIR", "/home/u/"}, // a trailing slash must not evade the check
	} {
		t.Run(tc.env+"="+tc.value, func(t *testing.T) {
			t.Setenv(tc.env, tc.value)
			rules := Home("/home/u")
			for _, r := range rules {
				if r.Path == "/" || r.Path == "/home" || r.Path == "/home/u" {
					t.Fatalf("%s=%s produced a shield at %q, which hides the whole home", tc.env, tc.value, r.Path)
				}
			}
			// Not merely absent: the rest of the list is untouched, so dropping the
			// unshieldable target did not take the real shields with it.
			if len(rules) != baseline {
				t.Errorf("rule count = %d, want the unchanged baseline %d", len(rules), baseline)
			}
			if !slices.ContainsFunc(rules, func(r Rule) bool { return r.Path == "/home/u/.gnupg" }) {
				t.Error("the default ~/.gnupg shield must stay in place")
			}
		})
	}
}

// A run with more than one home anchor calls Home once per anchor, so the guard has to
// see the whole set: an env pointing at a SIBLING anchor swallows that anchor's tree
// just as thoroughly, and the call that would notice is the one that never sees it.
func TestHomeIgnoresRelocationsThatSwallowAnotherHome(t *testing.T) {
	t.Setenv("GNUPGHOME", "/home/other")

	for _, r := range Home("/home/u", "/home/u", "/home/other") {
		if r.Path == "/home/other" {
			t.Fatalf("GNUPGHOME produced a shield at %q, which hides the whole of the other home anchor", r.Path)
		}
	}
}

// KUBECONFIG (a colon-separated list of files) and the AWS_*_FILE envs relocate individual
// credential files off ~/.kube / ~/.aws. Each absolute target must be shielded at its own
// path; relative and empty entries are ignored, like a relative directory relocation.
func TestHomeShieldsRelocatedCredentialFiles(t *testing.T) {
	// The first KUBECONFIG entry restates the default under the already-shielded ~/.kube,
	// so it must be dropped; only the relocated entries get their own file shield.
	t.Setenv("KUBECONFIG", "/home/u/.kube/config:/secrets/kube.yaml:relkube:/secrets/kube2.yaml")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/secrets/aws-creds")
	t.Setenv("AWS_CONFIG_FILE", "relaws") // relative: must not shield

	byPath := map[string]bool{}
	byRule := map[string]Rule{}
	for _, r := range Home("/home/u") {
		if !filepath.IsAbs(r.Path) {
			t.Errorf("relative file relocation leaked a non-absolute shield path %q", r.Path)
		}
		byPath[r.Path] = true
		byRule[r.Path] = r
	}
	for _, p := range []string{"/secrets/kube.yaml", "/secrets/kube2.yaml", "/secrets/aws-creds"} {
		r, ok := byRule[p]
		if !ok {
			t.Errorf("expected a shield at %q (file relocation), missing", p)
			continue
		}
		if r.Deny != DenyAll || r.Dir {
			t.Errorf("shield at %q must be a DenyAll file rule, got %+v", p, r)
		}
	}
	if byPath["relkube"] || byPath["relaws"] {
		t.Error("a relative file relocation must not produce a shield")
	}
	// A restatement of the default under the shielded store must not get an interior
	// file rule: it would blank the file out from under a read:~/.kube opt-in.
	if byPath["/home/u/.kube/config"] {
		t.Error("a KUBECONFIG entry under the shielded ~/.kube must not add an interior file rule")
	}
	// The default directories stay shielded regardless.
	if !byPath["/home/u/.kube"] || !byPath["/home/u/.aws"] {
		t.Error("default ~/.kube and ~/.aws must stay shielded")
	}
}

// The GCP/podman/AWS file pointers name ONE file, so a colon in the path is part of the
// name: splitting on it would shield two halves and leave the real file exposed. Only
// KUBECONFIG is a search list.
func TestHomeShieldsSingleFileRelocationsWhole(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/secrets/a:b/sa.json")
	t.Setenv("REGISTRY_AUTH_FILE", "/secrets/auth.json")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "/secrets/token")
	t.Setenv("TF_CLI_CONFIG_FILE", "/secrets/terraformrc")
	t.Setenv("ANSIBLE_CONFIG", "/secrets/ansible.cfg")

	byRule := map[string]Rule{}
	for _, r := range Home("/home/u") {
		byRule[r.Path] = r
	}
	for _, p := range []string{
		"/secrets/a:b/sa.json",
		"/secrets/auth.json",
		"/secrets/token",
		"/secrets/terraformrc",
		"/secrets/ansible.cfg",
	} {
		r, ok := byRule[p]
		if !ok {
			t.Errorf("expected a shield at %q, missing", p)
			continue
		}
		if r.Deny != DenyAll || r.Dir || r.Holds != HoldsCredentials {
			t.Errorf("shield at %q must be a DenyAll credential file rule, got %+v", p, r)
		}
	}
	if _, ok := byRule["/secrets/a"]; ok {
		t.Error("a single-file pointer must not be split on the colon in its path")
	}
}

// The store a file pointer is measured against is itself relocatable. With the directory
// followed to /secrets/gcloud, a credential file INSIDE it must not get its own interior
// rule: that rule survives a `read: /secrets/gcloud` opt-in and hands back a zero-byte
// file, the same failure the default-store check prevents at the unrelocated path.
func TestHomeSkipsFileRelocationInsideARelocatedStore(t *testing.T) {
	t.Setenv("CLOUDSDK_CONFIG", "/secrets/gcloud")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/secrets/gcloud/sa.json")

	byPath := map[string]bool{}
	for _, r := range Home("/home/u") {
		byPath[r.Path] = true
	}
	if !byPath["/secrets/gcloud"] {
		t.Fatal("the relocated gcloud store must still be shielded")
	}
	if byPath["/secrets/gcloud/sa.json"] {
		t.Error("a file pointer inside the relocated store must not add an interior rule")
	}
}

// ZDOTDIR relocates zsh's startup files off $HOME, and GIT_CONFIG_GLOBAL points git
// at a different global config file. The persistence shields (DenyWrite: readable,
// not plantable) must follow, or a write grant over the relocated path could plant a
// startup file the host runs on the next shell or git invocation.
func TestHomeShieldsRelocatedStartupFiles(t *testing.T) {
	t.Setenv("ZDOTDIR", "/cfg/zsh")
	t.Setenv("GIT_CONFIG_GLOBAL", "/cfg/gitconfig")

	byRule := map[string]Rule{}
	for _, r := range Home("/home/u") {
		byRule[r.Path] = r
	}
	// Every zsh startup file relocates as a group under ZDOTDIR.
	for _, f := range []string{".zshenv", ".zshrc", ".zshrc.local", ".zprofile", ".zlogin", ".zlogout"} {
		p := "/cfg/zsh/" + f
		r, ok := byRule[p]
		if !ok {
			t.Errorf("expected a shield at %q (ZDOTDIR relocation), missing", p)
			continue
		}
		if r.Deny != DenyWrite || r.Dir {
			t.Errorf("shield at %q must be a DenyWrite file rule, got %+v", p, r)
		}
	}
	if r, ok := byRule["/cfg/gitconfig"]; !ok {
		t.Error("expected a DenyWrite shield at the GIT_CONFIG_GLOBAL target, missing")
	} else if r.Deny != DenyWrite || r.Dir {
		t.Errorf("GIT_CONFIG_GLOBAL shield must be a DenyWrite file rule, got %+v", r)
	}
	// The defaults stay shielded regardless of the relocation.
	if _, ok := byRule["/home/u/.zshrc"]; !ok {
		t.Error("default ~/.zshrc must stay shielded")
	}
	if _, ok := byRule["/home/u/.gitconfig"]; !ok {
		t.Error("default ~/.gitconfig must stay shielded")
	}
}

// GIT_CONFIG_GLOBAL=/dev/null is git's idiom for "no global config" and names no
// plantable file; a relative value, the default location, or ZDOTDIR=$HOME must not
// add a shield either.
func TestHomeStartupRelocationIgnoresNonPlantable(t *testing.T) {
	t.Setenv("ZDOTDIR", "/home/u")             // the default: block skipped, no relocated rules
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null") // disables global config; nothing to plant
	for _, r := range Home("/home/u") {
		if r.Path == "/dev/null" {
			t.Errorf("unexpected shield at %q for a non-plantable relocation", r.Path)
		}
		if !filepath.IsAbs(r.Path) {
			t.Errorf("startup relocation leaked a non-absolute shield path %q", r.Path)
		}
	}
	// A relative ZDOTDIR cannot be bound and must be dropped.
	t.Setenv("ZDOTDIR", "relzsh")
	for _, r := range Home("/home/u") {
		if !filepath.IsAbs(r.Path) {
			t.Errorf("relative ZDOTDIR leaked a non-absolute shield path %q", r.Path)
		}
	}
}

// A relocation that lands at or under a DenyAll credential path must NOT get a
// DenyWrite shield: stacked after the DenyAll hide, its readable ro-bind would
// expose the credential under bwrap's last-wins ordering.
func TestHomeStartupRelocationSkipsDenyAllCollision(t *testing.T) {
	t.Setenv("GIT_CONFIG_GLOBAL", "/home/u/.netrc")       // a DenyAll file
	t.Setenv("ZDOTDIR", "/home/u/.ssh")                   // under a DenyAll dir
	t.Setenv("PIP_CONFIG_FILE", "/home/u/.netrc")         // a colon-free single-file follow
	t.Setenv("MAILCAPS", "/home/u/.ssh/x:/home/u/.netrc") // each colon entry must also route through the collision guard
	for _, r := range Home("/home/u") {
		if r.Deny == DenyWrite && (r.Path == "/home/u/.netrc" || strings.HasPrefix(r.Path, "/home/u/.ssh/")) {
			t.Errorf("DenyWrite shield at %q collides with a DenyAll rule and would expose it", r.Path)
		}
	}
	// The DenyAll shields themselves must still be present.
	byRule := map[string]Rule{}
	for _, r := range Home("/home/u") {
		byRule[r.Path] = r
	}
	if r := byRule["/home/u/.netrc"]; r.Deny != DenyAll {
		t.Errorf("~/.netrc must stay DenyAll, got %+v", r)
	}
	if r := byRule["/home/u/.ssh"]; r.Deny != DenyAll || !r.Dir {
		t.Errorf("~/.ssh must stay a DenyAll dir, got %+v", r)
	}
}

// BASH_ENV/ENV designate a startup file the host sources (non-interactive bash; POSIX
// sh/ksh/mksh/dash), and INPUTRC relocates readline's inputrc (macro bindings run on a
// keypress). Each must get a DenyWrite file shield at the target, or a write grant there
// could plant a line the host runs. INPUTRC=default and relative values are dropped.
func TestHomeShieldsRelocatedStartupEnvFiles(t *testing.T) {
	t.Setenv("BASH_ENV", "/cfg/bashenv")
	t.Setenv("ENV", "/cfg/shinit")
	t.Setenv("INPUTRC", "/cfg/inputrc")
	t.Setenv("PYTHONSTARTUP", "/cfg/pystartup")
	t.Setenv("SCREENRC", "/cfg/screenrc")
	t.Setenv("PSQLRC", "/cfg/psqlrc")
	t.Setenv("R_PROFILE_USER", "/cfg/rprofile")

	byRule := map[string]Rule{}
	for _, r := range Home("/home/u") {
		if !filepath.IsAbs(r.Path) {
			t.Errorf("relocation env leaked a non-absolute shield path %q", r.Path)
		}
		byRule[r.Path] = r
	}
	for _, p := range []string{
		"/cfg/bashenv", "/cfg/shinit", "/cfg/inputrc", "/cfg/pystartup",
		"/cfg/screenrc", "/cfg/psqlrc", "/cfg/rprofile",
	} {
		r, ok := byRule[p]
		if !ok {
			t.Errorf("expected a DenyWrite shield at %q (startup env relocation), missing", p)
			continue
		}
		if r.Deny != DenyWrite || r.Dir {
			t.Errorf("shield at %q must be a DenyWrite file rule, got %+v", p, r)
		}
	}
	// The default ~/.inputrc stays shielded regardless of the relocation.
	if r := byRule["/home/u/.inputrc"]; r.Deny != DenyWrite || r.Dir {
		t.Errorf("default ~/.inputrc must stay a DenyWrite file, got %+v", r)
	}

	// INPUTRC pointed at its own default adds no second rule; a relative value is dropped.
	t.Setenv("INPUTRC", "/home/u/.inputrc")
	t.Setenv("BASH_ENV", "relenv")
	count := 0
	for _, r := range Home("/home/u") {
		if !filepath.IsAbs(r.Path) {
			t.Errorf("relative BASH_ENV leaked a non-absolute shield path %q", r.Path)
		}
		if r.Path == "/home/u/.inputrc" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("INPUTRC=default must not add a second ~/.inputrc rule, got %d", count)
	}
}

// PIP_CONFIG_FILE relocates pip.conf (index-url can redirect installs to a malicious
// registry) and MAILCAPS relocates .mailcap (MIME handlers run on attachment open); both
// name a file the host acts on, so each target gets a DenyWrite shield. MAILCAPS is a
// colon-separated list (it replaces the default search path when set), so every entry is
// shielded. Values equal to a shielded default and relative entries are dropped.
func TestHomeShieldsRelocatedPipAndMailcapConfigs(t *testing.T) {
	t.Setenv("PIP_CONFIG_FILE", "/cfg/pip.conf")
	t.Setenv("MAILCAPS", "/cfg/a.mailcap:/cfg/b.mailcap")

	byRule := map[string]Rule{}
	for _, r := range Home("/home/u") {
		if !filepath.IsAbs(r.Path) {
			t.Errorf("relocation env leaked a non-absolute shield path %q", r.Path)
		}
		byRule[r.Path] = r
	}
	for _, p := range []string{"/cfg/pip.conf", "/cfg/a.mailcap", "/cfg/b.mailcap"} {
		r, ok := byRule[p]
		if !ok {
			t.Errorf("expected a DenyWrite shield at %q (config relocation), missing", p)
			continue
		}
		if r.Deny != DenyWrite || r.Dir {
			t.Errorf("shield at %q must be a DenyWrite file rule, got %+v", p, r)
		}
	}

	// A PIP_CONFIG_FILE equal to either shielded default and a MAILCAPS entry equal to the
	// default add no second rule; relative entries are dropped entirely.
	t.Setenv("PIP_CONFIG_FILE", "/home/u/.pip/pip.conf")
	t.Setenv("MAILCAPS", "/home/u/.mailcap:rel.mailcap:/cfg/c.mailcap")
	pipCount, mailcapCount, cCount := 0, 0, 0
	for _, r := range Home("/home/u") {
		if !filepath.IsAbs(r.Path) {
			t.Errorf("relative MAILCAPS entry leaked a non-absolute shield path %q", r.Path)
		}
		switch r.Path {
		case "/home/u/.pip/pip.conf":
			pipCount++
		case "/home/u/.mailcap":
			mailcapCount++
		case "/cfg/c.mailcap":
			cCount++
		}
	}
	if pipCount != 1 {
		t.Errorf("PIP_CONFIG_FILE=default must not add a second ~/.pip/pip.conf rule, got %d", pipCount)
	}
	if mailcapCount != 1 {
		t.Errorf("MAILCAPS default entry must not add a second ~/.mailcap rule, got %d", mailcapCount)
	}
	if cCount != 1 {
		t.Errorf("a valid MAILCAPS entry alongside a relative one must still be shielded, got %d", cCount)
	}
}

// HISTFILE relocates the shell history (typed passwords, pasted tokens) and
// NPM_CONFIG_USERCONFIG relocates ~/.npmrc (auth tokens); both must get a DenyAll file
// shield at the target so a broad read grant cannot read the secret. HISTFILE=/dev/null
// (disable-history idiom), NPM_CONFIG_USERCONFIG=default, and relative values are dropped.
func TestHomeShieldsRelocatedHistoryAndNpmConfig(t *testing.T) {
	t.Setenv("HISTFILE", "/secrets/histfile")
	t.Setenv("NPM_CONFIG_USERCONFIG", "/secrets/npmrc")
	t.Setenv("LESSHISTFILE", "/secrets/lesshst")
	t.Setenv("MYSQL_HISTFILE", "/secrets/mysqlhist")
	t.Setenv("PSQL_HISTORY", "/secrets/psqlhist")
	t.Setenv("SQLITE_HISTORY", "/secrets/sqlitehist")
	t.Setenv("REDISCLI_HISTFILE", "/secrets/redishist")
	t.Setenv("NODE_REPL_HISTORY", "/secrets/nodehist")
	t.Setenv("R_ENVIRON_USER", "/secrets/renviron") // .Renviron holds plaintext secrets, so its relocation is a DenyAll target, not DenyWrite

	byRule := map[string]Rule{}
	for _, r := range Home("/home/u") {
		if !filepath.IsAbs(r.Path) {
			t.Errorf("relocation env leaked a non-absolute shield path %q", r.Path)
		}
		byRule[r.Path] = r
	}
	for _, p := range []string{
		"/secrets/histfile", "/secrets/npmrc",
		"/secrets/lesshst", "/secrets/mysqlhist", "/secrets/psqlhist",
		"/secrets/sqlitehist", "/secrets/redishist", "/secrets/nodehist",
		"/secrets/renviron",
	} {
		r, ok := byRule[p]
		if !ok {
			t.Errorf("expected a DenyAll shield at %q (credential relocation), missing", p)
			continue
		}
		if r.Deny != DenyAll || r.Dir {
			t.Errorf("shield at %q must be a DenyAll file rule, got %+v", p, r)
		}
	}
	// The default ~/.npmrc and ~/.bash_history stay shielded.
	if r := byRule["/home/u/.npmrc"]; r.Deny != DenyAll {
		t.Errorf("default ~/.npmrc must stay DenyAll, got %+v", r)
	}

	// Non-plantable / redundant / relative values add no shield.
	t.Setenv("HISTFILE", "/dev/null")
	t.Setenv("NPM_CONFIG_USERCONFIG", "/home/u/.npmrc")
	npmCount := 0
	for _, r := range Home("/home/u") {
		if r.Path == "/dev/null" {
			t.Error("HISTFILE=/dev/null must not add a shield")
		}
		if r.Path == "/home/u/.npmrc" {
			npmCount++
		}
	}
	if npmCount != 1 {
		t.Errorf("NPM_CONFIG_USERCONFIG=default must not add a second ~/.npmrc rule, got %d", npmCount)
	}
	t.Setenv("HISTFILE", "relhist")
	for _, r := range Home("/home/u") {
		if !filepath.IsAbs(r.Path) {
			t.Errorf("relative HISTFILE leaked a non-absolute shield path %q", r.Path)
		}
	}
}

// CARGO_HOME relocates both severity classes at once: the registry tokens
// (credentials{,.toml}) hidden, and the build configs (config{,.toml}, env - each names
// a tool the host executes) readable but not writable. Both must follow the relocation,
// mirroring the default ~/.cargo. A relative value and the default location are dropped.
func TestHomeShieldsRelocatedCargoHome(t *testing.T) {
	t.Setenv("CARGO_HOME", "/cfg/cargo")

	byRule := map[string]Rule{}
	for _, r := range Home("/home/u") {
		if !filepath.IsAbs(r.Path) {
			t.Errorf("CARGO_HOME relocation leaked a non-absolute shield path %q", r.Path)
		}
		byRule[r.Path] = r
	}
	for _, f := range []string{"credentials.toml", "credentials"} {
		p := "/cfg/cargo/" + f
		if r, ok := byRule[p]; !ok || r.Deny != DenyAll || r.Dir {
			t.Errorf("shield at %q must be a DenyAll file rule, got %+v (present=%v)", p, byRule[p], ok)
		}
	}
	for _, f := range []string{"config.toml", "config", "env"} {
		p := "/cfg/cargo/" + f
		if r, ok := byRule[p]; !ok || r.Deny != DenyWrite || r.Dir {
			t.Errorf("shield at %q must be a DenyWrite file rule, got %+v (present=%v)", p, byRule[p], ok)
		}
	}
	// The default ~/.cargo files stay shielded regardless.
	if r := byRule["/home/u/.cargo/credentials.toml"]; r.Deny != DenyAll {
		t.Errorf("default ~/.cargo/credentials.toml must stay DenyAll, got %+v", r)
	}

	// A relative value adds nothing; the default location is already covered and dropped.
	t.Setenv("CARGO_HOME", "relcargo")
	for _, r := range Home("/home/u") {
		if !filepath.IsAbs(r.Path) {
			t.Errorf("relative CARGO_HOME leaked a non-absolute shield path %q", r.Path)
		}
	}
	// Pointing CARGO_HOME at the default must add nothing. Compared against the rules
	// with it unset rather than against an enumerated list of the static ~/.cargo
	// shields, which would need editing every time one is added - and would then be
	// asserting the shield list rather than the relocation logic this test is about.
	os.Unsetenv("CARGO_HOME")
	baseline := map[string]bool{}
	for _, r := range Home("/home/u") {
		baseline[r.Path] = true
	}
	t.Setenv("CARGO_HOME", "/home/u/.cargo")
	for _, r := range Home("/home/u") {
		if !baseline[r.Path] {
			t.Errorf("CARGO_HOME=default must not add extra rules, saw %q", r.Path)
		}
	}
}

// Every alias anchor must be covered by a hidden directory rule, so no anchor can point
// at a tree the sandbox still exposes.
//
// For the top-level anchors this now holds by construction - the shielded set is built by
// concatenating the same three buckets the anchors are drawn from, which is the point of
// splitting them - so this asserts a structural invariant rather than catching drift.
// Where it still has teeth is the nested anchors (a wallet client's key subdirectory),
// which name a path no rule mentions and could be moved under a parent that is not
// shielded at all.
func TestAliasAnchorsAreAllHiddenDirRules(t *testing.T) {
	const home = "/home/u"
	var hidden []string
	for _, r := range Home(home) {
		if r.Deny == DenyAll && r.Dir {
			hidden = append(hidden, r.Path)
		}
	}
	// An anchor is normally a hidden directory itself, but a full-node wallet client
	// anchors only its key subdirectory while the shield covers the whole data dir, so
	// the invariant is coverage, not equality.
	covered := func(a string) bool {
		for _, h := range hidden {
			if a == h || strings.HasPrefix(a, h+"/") {
				return true
			}
		}
		return false
	}
	for _, a := range AliasAnchors(home) {
		if !covered(a) {
			t.Errorf("alias anchor %q is not covered by any DenyAll directory rule in Home() - renamed or misspelled?", a)
		}
	}
}

// A store moved out of the home by its tool's own variable is shielded, but until it also
// anchors the scan a second readable name for those keys is undetectable. A target at or
// above a home anchor is skipped: the scan would walk the whole home for aliases of it.
func TestAliasAnchorsFollowRelocatedStores(t *testing.T) {
	t.Setenv("GNUPGHOME", "/srv/keys")
	t.Setenv("PASSWORD_STORE_DIR", "/srv/pass")
	t.Setenv("DOCKER_CONFIG", "relative/docker")
	t.Setenv("AZURE_CONFIG_DIR", "/home/u")

	anchors := AliasAnchors("/home/u", "/home/other")
	for _, want := range []string{"/srv/keys", "/srv/pass", "/home/u/.ssh", "/home/other/.ssh"} {
		if !slices.Contains(anchors, want) {
			t.Errorf("%q must anchor the alias scan; got %v", want, anchors)
		}
	}
	for _, unwanted := range []string{"relative/docker", "/home/u"} {
		if slices.Contains(anchors, unwanted) {
			t.Errorf("%q must not anchor the alias scan", unwanted)
		}
	}
}

// The completeness ratchet is firejail-shaped, so anything firejail does not list is
// invisible to it and can only be caught by hand. These entries were found that way:
// each is a store or plant target whose SIBLING bento already shields, which is what
// makes the omission an internal inconsistency rather than a scope choice. Guarding
// them here is what stops the next edit from quietly dropping one again.
func TestHomeShieldsPathsFirejailDoesNotList(t *testing.T) {
	rules := Home("/home/u")
	byPath := make(map[string]Rule, len(rules))
	for _, r := range rules {
		byPath[r.Path] = r
	}

	// Credentials: hidden, since a sandboxed run has no reason to read the secret.
	for _, p := range []string{
		"/home/u/.ICEauthority",             // session-manager cookie; .Xauthority is DenyAll
		"/home/u/.terraformrc",              // Terraform Cloud tokens; .terraform.d is an anchor
		"/home/u/.m2/settings.xml",          // Maven server passwords
		"/home/u/.gradle/gradle.properties", // signing keys and repo credentials
		"/home/u/.composer/auth.json",       // Composer registry tokens
		"/home/u/.bundle/config",            // bundler gem-source credentials
		"/home/u/.nuget/NuGet/NuGet.Config", // NuGet apikeys
		"/home/u/.claude/.credentials.json", // coding-agent OAuth token
		"/home/u/.codex/auth.json",
		// The same account/OAuth block as .claude.json, under the one backup name that
		// is concrete. Its epoch-suffixed siblings are not expressible and stay a
		// recorded residual; this one is, so dropping it would be the silent regression.
		"/home/u/.claude.json",
		"/home/u/.claude.json.backup",
	} {
		r, ok := byPath[p]
		if !ok {
			t.Errorf("%s is not shielded", p)
			continue
		}
		if r.Deny != DenyAll || r.Dir {
			t.Errorf("%s must be a DenyAll file shield, got %+v", p, r)
		}
	}

	for _, p := range []string{
		"/home/u/.config/glab-cli", // GitLab CLI tokens, the .config/gh analog
		"/home/u/.config/helm",     // repository and OCI registry auth
	} {
		r, ok := byPath[p]
		if !ok {
			t.Errorf("%s is not shielded", p)
			continue
		}
		if r.Deny != DenyAll || !r.Dir {
			t.Errorf("%s must be a DenyAll dir shield, got %+v", p, r)
		}
	}

	// Plant targets: write-denied, not hidden, because a build or an agent may
	// legitimately read them from inside the sandbox.
	for _, p := range []string{
		"/home/u/.claude", // hooks and MCP server command lines run on the host later
		"/home/u/.codex",
		"/home/u/.cursor",
		"/home/u/.local/bin",     // on $PATH via the distro default profile
		"/home/u/bin",            // same
		"/home/u/.gradle/init.d", // every .gradle here runs before each build
		// bento's own approval journal. A forged entry makes the re-approval diff lie about
		// which grant is new, and the entry is trusted precisely because only this host's
		// approve writes it - so a sandboxed run must not be able to author one.
		"/home/u/.local/state/bento",
	} {
		r, ok := byPath[p]
		if !ok {
			t.Errorf("%s is not shielded", p)
			continue
		}
		if r.Deny != DenyWrite || !r.Dir {
			t.Errorf("%s must be a DenyWrite dir shield, got %+v", p, r)
		}
	}

	// The package-cache trees stay reachable on purpose: shielding ~/.m2 or ~/.gradle
	// wholesale to hide one credential file would break ordinary in-sandbox builds, so
	// the file is shielded and the cache is not. A future edit that promotes the tree
	// should be a deliberate one, not a silent side effect.
	for _, p := range []string{"/home/u/.m2", "/home/u/.gradle", "/home/u/.nuget", "/home/u/.composer", "/home/u/.bundle"} {
		if r, ok := byPath[p]; ok {
			t.Errorf("%s is shielded as %+v; the credential file inside is shielded instead so builds keep working", p, r)
		}
	}
}

// A DenyWrite directory ro-binds its real subtree, which would re-expose a DenyAll file
// nested inside it if the shields landed in the wrong order. denyArgs emits DenyWrite
// before DenyAll for exactly that reason, so the agent trees below are a live instance
// of the pattern: the tree is readable, the token inside it is not.
func TestHomeHidesCredentialsInsideWriteShieldedAgentTrees(t *testing.T) {
	rules := Home("/home/u")
	for _, tc := range []struct{ tree, secret string }{
		{"/home/u/.claude", "/home/u/.claude/.credentials.json"},
		{"/home/u/.codex", "/home/u/.codex/auth.json"},
	} {
		var tree, secret *Rule
		for i := range rules {
			switch rules[i].Path {
			case tc.tree:
				tree = &rules[i]
			case tc.secret:
				secret = &rules[i]
			}
		}
		if tree == nil || secret == nil {
			t.Errorf("%s: expected both the tree and its credential to be shielded", tc.tree)
			continue
		}
		if tree.Deny != DenyWrite || secret.Deny != DenyAll {
			t.Errorf("%s: want a DenyWrite tree around a DenyAll credential, got %+v and %+v", tc.tree, *tree, *secret)
		}
	}
}

// Tier-2 credential classes: the same "plaintext credentials on disk" rule bento already
// applies to pidgin/weechat, extended to the protocols and tools that were only out of
// scope because no classifier token matched them. Each store below holds an account
// password, a private key, or cracked plaintext - not message content, which stays out.
func TestHomeShieldsTierTwoCredentialStores(t *testing.T) {
	rules := Home("/home/u")
	byPath := make(map[string]Rule, len(rules))
	for _, r := range rules {
		byPath[r.Path] = r
	}
	for _, p := range []string{
		"/home/u/.local/share/dino",      // OMEMO identity keys and account passwords
		"/home/u/.config/gajim",          // saved XMPP account passwords
		"/home/u/.config/psi",            // XMPP account passwords and OTR keys
		"/home/u/.local/share/Psi",       // firejail carries both spellings
		"/home/u/.config/profanity",      //
		"/home/u/.local/share/telepathy", // accounts.cfg connection-manager passwords
		"/home/u/.nicotine",              //
		"/home/u/.linphonerc",            // SIP account auth password
		"/home/u/.config/Mumble",         // client certificate including its private key
		"/home/u/.config/kdeconnect",     // device-pairing RSA key
		"/home/u/.parsec",                // remote-desktop saved credentials
		"/home/u/.hashcat",               // potfile: recovered plaintext passwords
		"/home/u/.ivy2/.credentials",     // build-tool registry credentials
		"/home/u/.sbt/.credentials",      //
	} {
		if r, ok := byPath[p]; !ok || r.Deny != DenyAll {
			t.Errorf("%s must be shielded DenyAll, got %+v (present=%v)", p, byPath[p], ok)
		}
	}
	// The build-tool trees stay readable, as in TestHomeShieldsPathsFirejailDoesNotList:
	// only the credential file inside is hidden, so in-sandbox builds keep their caches.
	for _, p := range []string{"/home/u/.ivy2", "/home/u/.sbt"} {
		if r, ok := byPath[p]; ok {
			t.Errorf("%s is shielded as %+v; only its credentials file should be", p, r)
		}
	}
}

// Cloud-sync clients: the config tree holds the account token and is shielded; the synced
// DOCUMENT folder is user data and is deliberately left alone. The two cannot be told
// apart by the audit's component-token classifier - any token matching .config/Nextcloud
// also matches ~/Nextcloud - which is why these are shielded by name and given no token.
func TestHomeShieldsCloudSyncConfigButNotDocuments(t *testing.T) {
	rules := Home("/home/u")
	byPath := make(map[string]Rule, len(rules))
	for _, r := range rules {
		byPath[r.Path] = r
	}
	for _, p := range []string{
		"/home/u/.config/Nextcloud",
		"/home/u/.local/share/Nextcloud",
		"/home/u/.config/Seafile",
		"/home/u/.dropbox",
	} {
		if r, ok := byPath[p]; !ok || r.Deny != DenyAll || !r.Dir {
			t.Errorf("%s must be a DenyAll dir shield, got %+v (present=%v)", p, byPath[p], ok)
		}
	}
	for _, p := range []string{"/home/u/Nextcloud", "/home/u/Nextcloud/Notes", "/home/u/Seafile"} {
		if r, ok := byPath[p]; ok {
			t.Errorf("%s is the synced document folder, not a credential store, but is shielded as %+v", p, r)
		}
	}
}

// $PATH-resident binary directories: a planted file here runs on the host under the next
// bare command name that resolves to it. Write-denied rather than hidden, since a build
// legitimately reads and executes from its own toolchain.
func TestHomeWriteShieldsPathBinaryDirs(t *testing.T) {
	rules := Home("/home/u")
	byPath := make(map[string]Rule, len(rules))
	for _, r := range rules {
		byPath[r.Path] = r
	}
	for _, p := range []string{
		"/home/u/.bin", "/home/u/.cargo/bin", "/home/u/.gem",
		"/home/u/.local/share/coursier/bin", "/home/u/.luarocks", "/home/u/.npm-packages",
		"/home/u/.nvm", "/home/u/.rustup", "/home/u/Applications",
	} {
		if r, ok := byPath[p]; !ok || r.Deny != DenyWrite || !r.Dir {
			t.Errorf("%s must be a DenyWrite dir shield, got %+v (present=%v)", p, byPath[p], ok)
		}
	}
	// ~/.gem is write-shielded for its binaries while the credentials file inside stays
	// hidden - the same DenyWrite-tree-around-a-DenyAll-file pairing the agent trees use.
	if r, ok := byPath["/home/u/.gem/credentials"]; !ok || r.Deny != DenyAll {
		t.Errorf("~/.gem/credentials must stay DenyAll inside the write-shielded tree, got %+v (present=%v)", r, ok)
	}
}

// The passwd anchor is what a caller-chosen $HOME cannot move, so it must survive any
// value of $HOME - including one that is itself a valid home directory.
func TestHomeAnchorsKeepsPasswdHome(t *testing.T) {
	u, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		t.Skip("no passwd entry for this uid")
	}
	t.Setenv("HOME", "/")

	homes, err := HomeAnchors()
	if err != nil {
		t.Fatalf("homeAnchors: %v", err)
	}
	if !slices.Contains(homes, filepath.Clean(u.HomeDir)) {
		t.Errorf("HomeAnchors() = %v, want it to contain the passwd home %q whatever $HOME says", homes, u.HomeDir)
	}
	if !slices.Contains(homes, "/") {
		t.Errorf("HomeAnchors() = %v, want it to contain $HOME", homes)
	}
}

// The passwd anchor only resists a caller-chosen environment while the lookup stays in
// pure Go: built against libc NSS, an LD_PRELOAD that fails getpwuid_r drops the anchor
// and restores the bug homeAnchors exists to fix (verified by hand against a cgo build).
// The osusergo tag is what makes the pure-Go resolver unconditional, so it is a security
// flag rather than a build preference and both build paths must carry it.
func TestBuildsPinThePureGoPasswdResolver(t *testing.T) {
	for _, f := range []string{"../../Makefile", "../../.goreleaser.yaml"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "osusergo") {
			t.Errorf("%s does not build with the osusergo tag, so the passwd anchor the credential shields rely on can be dropped by LD_PRELOAD", f)
		}
	}
}

// The passwd anchor is the one the caller cannot move, so an environment with no usable
// $HOME at all - a bare cron job, a systemd unit, env -i - must still shield it rather
// than refusing the run. Refusing there would fail closed on hosts where the anchor that
// matters is intact.
func TestHomeAnchorsSurvivesAnUnusableHome(t *testing.T) {
	pw := PasswdHome()
	if pw == "" {
		t.Skip("no passwd entry for this uid")
	}

	for _, tc := range []struct{ name, home string }{
		{"unset", ""},
		{"relative", "rel/ative"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HOME", tc.home)
			if tc.home == "" {
				os.Unsetenv("HOME") // t.Setenv still restores it after the test
			}
			homes, err := HomeAnchors()
			if err != nil {
				t.Fatalf("HomeAnchors: %v, want the passwd anchor to carry the run", err)
			}
			if want := []string{pw}; !slices.Equal(homes, want) {
				t.Errorf("HomeAnchors() = %v, want %v", homes, want)
			}
		})
	}
}

// $HOME agreeing with passwd is the common case and must not shield everything twice -
// including when the two differ only in a trailing slash.
func TestHomeAnchorsDeduplicates(t *testing.T) {
	u, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		t.Skip("no passwd entry for this uid")
	}
	t.Setenv("HOME", u.HomeDir+"/")

	homes, err := HomeAnchors()
	if err != nil {
		t.Fatalf("homeAnchors: %v", err)
	}
	if want := []string{filepath.Clean(u.HomeDir)}; !slices.Equal(homes, want) {
		t.Errorf("HomeAnchors() = %v, want %v", homes, want)
	}
}

// A file relocation env var naming a path inside ONE anchor's credential store must not
// produce an interior file rule on another anchor's pass. Home runs once per anchor, and
// keyed on the current anchor alone the sibling pass emits a DenyAll on the file itself -
// a rule no `read: ~/.kube` opt-in matches, so the user who opts in gets a zero-byte
// kubeconfig instead of a refusal. The store is the store under every anchor.
func TestFileRelocationInsideAnySiblingAnchorStoreIsNotShieldedByFile(t *testing.T) {
	t.Setenv("KUBECONFIG", "/home/a/.kube/config")
	for _, r := range Home("/home/b", "/home/a", "/home/b") {
		if r.Path == "/home/a/.kube/config" {
			t.Errorf("the sibling anchor's pass emitted an interior file rule on %s; the anchor's own directory shield covers it, and this rule survives a read grant on the directory", r.Path)
		}
	}
	// The directory shield the drop relies on has to actually be there.
	var covered bool
	for _, r := range Home("/home/a", "/home/a", "/home/b") {
		if r.Path == "/home/a/.kube" && r.Deny == DenyAll && r.Dir {
			covered = true
		}
	}
	if !covered {
		t.Error("no DenyAll directory shield on /home/a/.kube; dropping the sibling's file rule would lose coverage")
	}
	// A target outside every anchor's store still gets its own rule - the drop is
	// containment, not a blanket exemption for relocated files.
	t.Setenv("KUBECONFIG", "/srv/kubeconfig")
	if !slices.ContainsFunc(Home("/home/b", "/home/a", "/home/b"), func(r Rule) bool {
		return r.Path == "/srv/kubeconfig" && r.Deny == DenyAll
	}) {
		t.Error("a relocation outside every anchor's store must still be shielded")
	}
}

// XDG_RUNTIME_DIR holds what /run holds - the podman auth.json, the gpg-agent socket, the
// dbus and wayland sockets - and a host that points it outside /run keeps them there,
// where the /run shield names nothing. Two call sites skip work believing Runtime covers
// this; the shield has to follow the variable for that belief to hold.
func TestRuntimeFollowsRelocatedRuntimeDir(t *testing.T) {
	rules := Runtime("/tmp/runtime-u", "/home/u")
	if !slices.ContainsFunc(rules, func(r Rule) bool {
		return r.Path == "/tmp/runtime-u" && r.Deny == DenyAll && r.Dir
	}) {
		t.Errorf("Runtime(/tmp/runtime-u) = %v, want a DenyAll directory shield on the relocated runtime dir", rules)
	}

	// The ordinary host: /run/user/<uid> is already inside the /run shield, so following
	// it would only add a redundant rule for every backend to bind and reconcile.
	if got := len(Runtime("/run/user/1000", "/home/u")); got != 2 {
		t.Errorf("Runtime(/run/user/1000) emitted %d rules, want the 2 base rules and no redundant interior shield", got)
	}

	// A runtime dir that is the home, an ancestor of it, or the root cannot be shielded:
	// the rule would hide the whole grant surface and subsume every other rule.
	for _, dir := range []string{"/", "/home", "/home/u", ""} {
		if got := len(Runtime(dir, "/home/u")); got != 2 {
			t.Errorf("Runtime(%q) emitted %d rules, want only the 2 base rules - it cannot shield the grant surface itself", dir, got)
		}
	}
}

// The journal must stay shielded under a relocated state home too: XDG_STATE_HOME is in
// profile's discovery set, so a sandboxed script can see where the journal was pointed, and
// the default location is guessable without any passthrough. homeLocations expands the
// home-relative entry to both, which is the whole reason the entry is spelled that way.
func TestApprovalJournalIsShieldedUnderARelocatedStateHome(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "/home/u/state")
	byPath := make(map[string]Rule)
	for _, r := range Home("/home/u") {
		byPath[r.Path] = r
	}
	for _, p := range []string{"/home/u/.local/state/bento", "/home/u/state/bento"} {
		r, ok := byPath[p]
		if !ok {
			t.Errorf("%s is not shielded, so a sandboxed run could forge an approval record there", p)
			continue
		}
		if r.Deny != DenyWrite || !r.Dir {
			t.Errorf("%s must be a DenyWrite dir shield, got %+v", p, r)
		}
	}
}

// Every DenyAll rule has to say what it hides: the callouts that ask a reviewer to
// approve lifting a shield print Holds, and an unclassified rule would fall back to the
// vague wording for a store that has a name. A new entry added to a list nobody wired
// into dirGroups fails here rather than in a user-facing sentence.
func TestDenyAllRulesAreClassified(t *testing.T) {
	// The relocations are exercised too: each emits its own rule, and those are the sites
	// where a Holds is easiest to leave off.
	t.Setenv("GNUPGHOME", "/srv/keys")
	t.Setenv("KUBECONFIG", "/srv/kube.yaml")
	t.Setenv("HISTFILE", "/srv/history")
	t.Setenv("CARGO_HOME", "/srv/cargo")
	rules := slices.Concat(Home("/home/u"), Runtime("/tmp/rt", "/home/u"))
	for _, r := range rules {
		if r.Deny == DenyAll && r.Holds == HoldsUnknown {
			t.Errorf("%q is hidden but unclassified; add it to a list dirGroups names", r.Path)
		}
	}
}

// The buckets exist so a callout can name what it exposes. A history store described as
// a credential store is the drain this classification exists to stop, so the examples
// that motivated it are pinned.
func TestHomeShieldClassification(t *testing.T) {
	byPath := map[string]Rule{}
	for _, r := range Home("/home/u") {
		byPath[r.Path] = r
	}
	for path, want := range map[string]Holds{
		"/home/u/.ssh":              HoldsCredentials,
		"/home/u/.netrc":            HoldsCredentials,
		"/home/u/.mozilla":          HoldsPrivateData,
		"/home/u/.local/state/nvim": HoldsHistory,
		"/home/u/.config/autostart": HoldsPersistence,
		"/home/u/.bash_history":     HoldsHistory,
		"/home/u/.viminfo":          HoldsHistory,
		"/home/u/.xinitrc":          HoldsPersistence,
		"/home/u/postponed":         HoldsPrivateData,
		"/home/u/.zuluCrypt-socket": HoldsServices,
		"/home/u/.rhosts":           HoldsPersistence,
		"/home/u/.config/kwalletrc": HoldsPrivateData,
	} {
		if got := byPath[path]; got.Holds != want {
			t.Errorf("%s: Holds = %v (%q), want %v", path, got.Holds, got.Holds.Noun(), want)
		}
	}
	if got := Runtime("/tmp/rt", "/home/u")[0]; got.Holds != HoldsServices {
		t.Errorf("%s: Holds = %v, want HoldsServices", got.Path, got.Holds)
	}
}

// A store's classification is a property of the store, not of how it was reached: a
// relocation env var moves where the rule points and must not change what bento says is
// behind it. Exporting LESSHISTFILE used to turn the same history file from a credential
// store into a history store.
func TestRelocationKeepsTheSameClassification(t *testing.T) {
	for _, tc := range []struct{ env, def, relocated string }{
		{"LESSHISTFILE", "/home/u/.lesshst", "/srv/lesshst"},
		{"MYSQL_HISTFILE", "/home/u/.mysql_history", "/srv/mysql_history"},
		{"NPM_CONFIG_USERCONFIG", "/home/u/.npmrc", "/srv/npmrc"},
	} {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv(tc.env, tc.relocated)
			var def, moved Rule
			for _, r := range Home("/home/u") {
				switch r.Path {
				case tc.def:
					def = r
				case tc.relocated:
					moved = r
				}
			}
			if def.Holds != moved.Holds {
				t.Errorf("%s: default %q holds %v, relocated %q holds %v", tc.env, tc.def, def.Holds, tc.relocated, moved.Holds)
			}
		})
	}
}
