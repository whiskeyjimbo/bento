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

	dirs := []string{
		".ssh",             // private keys, authorized_keys
		".aws",             // credentials, config
		".config/gcloud",   // application-default credentials, tokens
		".azure",           // access tokens
		".kube",            // cluster credentials
		".docker",          // registry auth
		".gnupg",           // secret keyrings
		".password-store",  // pass(1)
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

		// OS secret stores: the master keyring behind saved passwords and tokens.
		".local/share/keyrings",    // GNOME Keyring
		".local/share/kwalletd",    // KDE Wallet
		".gnome2/keyrings",         // GNOME Keyring (legacy path)
		".kde/share/apps/kwallet",  // KDE Wallet (legacy path)
		".kde4/share/apps/kwallet", // KDE Wallet (legacy KDE4 path)
		".git-credential-cache",    // git credential-cache helper socket dir
		".cache/git/credential",    // modern git credential-cache socket location

		// Browser profiles: cookies, session tokens, and saved-password databases.
		".mozilla",               // Firefox
		".config/google-chrome",  // Chrome
		".config/chromium",       // Chromium
		".config/BraveSoftware",  // Brave
		".config/microsoft-edge", // Edge
	}
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
		// Graphical-login scripts (X11; Wayland persistence routes through the
		// systemd/autostart dirs below).
		".xprofile",
		".xinitrc",
		".xsession",
		".xsessionrc", // sourced by the Debian/Ubuntu Xsession startup, like .xsession
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
		".Rprofile",            // R sources it at startup
		".Renviron",            // can set R_PROFILE_USER to a writable file; creating it is the attack
		".mcp.json",
	}

	// Directories whose contents run on the host at the next login, shell start, or
	// editor/tool invocation. Reads stay allowed (a script may legitimately inspect
	// them); creating or modifying an entry is what grants persistence, so writes are
	// denied. These are shielded as whole directories because their autoloaded/plugin
	// files cannot be pre-enumerated - a not-yet-created entry is still plantable, the
	// same reason git hooks are shielded as a directory.
	writeOnlyDirs := []string{
		".bashrc.d",                    // Fedora/RHEL default .bashrc sources ~/.bashrc.d/*.sh; a planted entry runs on next shell (.bashrc itself is write-shielded, but the loop only checks the dir exists)
		".config/autostart",            // XDG autostart .desktop entries
		".config/systemd/user",         // systemd user services and timers
		".config/environment.d",        // systemd user-session env (LD_PRELOAD, PATH, ...)
		".config/plasma-workspace/env", // KDE login shell scripts
		".config/fish",                 // config.fish, conf.d/*.fish, autoloaded functions/*.fish (planting ls.fish hijacks `ls`)
		".config/nushell",              // config.nu/env.nu and autoloads
		".vim",                         // plugin/, autoload/, after/plugin/ are auto-sourced
		".config/nvim",                 // init.{vim,lua}, lua/, plugin/, after/
		".local/share/nvim/site",       // packpath: site/pack/*/start/*/plugin/ auto-sourced
		".emacs.d",                     // init.el and site-lisp
		".config/emacs",                // XDG location for the same
		".config/gdb",                  // gdb 11+ reads gdbinit/gdbearlyinit here
		".config/tmux",                 // XDG location for tmux.conf
		".config/direnv",               // direnvrc, sourced on cd for direnv users
		".local/share/direnv/allow",    // authorization records: an entry pre-approves a workspace .envrc
		".config/Code",                 // VS Code User/settings.json (git.path, interpreter paths) run commands
		".vscode",                      // extensions/ load on startup
		".config/mpv",                  // scripts/*.lua autoloaded on launch
		".xmonad",                      // xmonad.hs is compiled and executed
		".config/xmonad",               // XDG location for xmonad.hs (0.17+)
	}

	// A relocated XDG base moves the real credential/config stores out from under the
	// default ~/.config etc., so a config/data/cache-relative entry is shielded at
	// BOTH its default location and the XDG one - a tool that honors XDG_CONFIG_HOME
	// reads from there, a tool that ignores it from the default, and both are covered.
	xdgBases := []struct{ prefix, env, def string }{
		{".config/", "XDG_CONFIG_HOME", ".config"},
		{".local/share/", "XDG_DATA_HOME", ".local/share"},
		{".cache/", "XDG_CACHE_HOME", ".cache"},
	}
	locations := func(entry string) []string {
		for _, b := range xdgBases {
			if rel, ok := strings.CutPrefix(entry, b.prefix); ok {
				out := []string{join(entry)}
				if base := os.Getenv(b.env); base != "" && filepath.Clean(base) != join(b.def) {
					out = append(out, filepath.Join(base, rel))
				}
				return out
			}
		}
		return []string{join(entry)}
	}

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
func Workspace(dir string) []Rule {
	join := func(p string) string { return filepath.Join(dir, p) }
	return []Rule{
		{Path: join(".git/hooks"), Deny: DenyWrite, Dir: true},
		{Path: join(".git/config"), Deny: DenyWrite},
		{Path: join(".git/config.worktree"), Deny: DenyWrite}, // honored under extensions.worktreeConfig
		{Path: join(".vscode/tasks.json"), Deny: DenyWrite},
		{Path: join(".vscode/launch.json"), Deny: DenyWrite},
		{Path: join(".idea/workspace.xml"), Deny: DenyWrite},
	}
}
