package denylist

import (
	"path/filepath"
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
		"/home/u/.config/google-chrome",
		"/home/u/.config/rclone",
		"/home/u/.config/keybase",       // Keybase keys/tokens
		"/home/u/.pki",                  // NSS cert/key DBs
		"/home/u/.gnome2/keyrings",      // legacy keyring path
		"/home/u/.git-credential-cache", // git credential cache
		"/home/u/.mutt",                 // mutt config (imap_pass) hidden
		"/home/u/.config/mutt",          // XDG mutt config
		"/home/u/.subversion/auth",      // SVN plaintext passwords
		"/home/u/.config/openstack",     // OpenStack clouds.yaml/secure.yaml
		"/home/u/.thunderbird",          // Thunderbird saved mail passwords
		"/home/u/.config/evolution",     // Evolution saved mail passwords
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
		"/home/u/.smbcredentials", // SMB mount credentials
		"/home/u/.config/hub",     // hub OAuth token
		"/home/u/.msmtprc",        // SMTP passwords (hidden, not just write-denied)
		"/home/u/.yarnrc.yml",     // yarn npmAuthToken
		"/home/u/.my.cnf",         // MySQL plaintext password
		"/home/u/.mylogin.cnf",    // MySQL login-path store (obfuscated, not encrypted)
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
		"/home/u/.Renviron",            // can set R_PROFILE_USER
		"/home/u/.cargo/env",           // rustup makes .profile source it
		"/home/u/.exrc",                // vim also sources this
		"/home/u/.gvimrc",              // gvim rc
		"/home/u/.screenrc",            // GNU screen runs commands
		"/home/u/.mailcap",             // MIME handler commands
		"/home/u/.yarnrc",              // yarn-path exec (classic, no token)
		"/home/u/.xsessionrc",          // Debian/Ubuntu Xsession startup
		"/home/u/.pam_environment",     // PAM login env (LD_PRELOAD/PATH)
		"/home/u/.config/pip/pip.conf", // pip index-url registry redirect
		"/home/u/.pip/pip.conf",        // legacy per-user pip config, also default-read
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
		"/home/u/.bashrc.d",          // Fedora/RHEL .bashrc sources ~/.bashrc.d/*.sh
		"/home/u/.config/containers", // podman/skopeo exec-redirect knobs
		"/home/u/.config/autostart",
		"/home/u/.config/systemd/user",
		"/home/u/.config/fish",              // config.fish, conf.d/*.fish, and autoloaded functions/*.fish
		"/home/u/.config/nushell",           // nushell config and autoloads
		"/home/u/.vim",                      // auto-sourced plugin/autoload dirs
		"/home/u/.config/nvim",              // neovim config tree
		"/home/u/.local/share/nvim/site",    // nvim packpath auto-source
		"/home/u/.emacs.d",                  // emacs init and site-lisp
		"/home/u/.config/environment.d",     // systemd user-session env
		"/home/u/.local/share/direnv/allow", // direnv authorization records
		"/home/u/.config/Code",              // VS Code User settings (git.path etc.)
		"/home/u/.vscode",                   // VS Code extensions dir
		"/home/u/.config/mpv",               // mpv autoloaded scripts
		"/home/u/.xmonad",                   // xmonad.hs compiled+run
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
	for _, r := range Runtime() {
		if r.Deny != DenyAll || !r.Dir {
			t.Errorf("%s: got Deny=%v Dir=%v, want DenyAll directory", r.Path, r.Deny, r.Dir)
		}
	}
	byPath := make(map[string]bool, len(Runtime()))
	for _, r := range Runtime() {
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
	byPath := map[string]bool{}
	for _, r := range Home("/home/u") {
		byPath[r.Path] = true
	}
	// Shielded at BOTH the default and the relocated XDG location.
	for _, p := range []string{
		"/home/u/.config/gh", "/home/u/cfg/gh", // gh tokens (config)
		"/home/u/.local/share/keyrings", "/home/u/data/keyrings", // GNOME keyring (data)
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
