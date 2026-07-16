// Package denylist declares the paths Bento shields no matter what a policy
// grants.
//
// The list is data, not code: it is platform-independent and testable on its
// own, while each backend decides how to enforce a rule (bind mounts on Linux,
// SBPL rules on macOS). A policy that grants a broad path - say all of $HOME -
// must never expose these.
package denylist

import "path/filepath"

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
		// Tool configs that define a command run on a common host action.
		".gitconfig",
		".config/git/config", // XDG location git reads the same as ~/.gitconfig
		".cargo/config.toml", // cargo build/run honors build.rustc-wrapper, target runners, [target] linker
		".cargo/config",      // legacy (pre-1.39) cargo config filename, still read
		".cargo/env",         // shell script rustup makes .profile source; runs on next shell
		".vimrc",             // sourced when vim opens a file
		".exrc",              // vim also sources this (ex/vi rc) on startup
		".gvimrc",            // gvim rc, sourced on gvim startup
		".emacs",             // elisp run at emacs startup
		".emacs.el",          // alternate emacs init filename
		".screenrc",          // GNU screen runs commands from it
		".gdbinit",           // executed by gdb on startup
		".tmux.conf",         // run-shell hooks execute on tmux start
		".direnvrc",          // legacy direnv global rc (XDG dir shielded below)
		".mailcap",           // maps MIME types to commands run on attachment open
		".yarnrc",            // yarn-path names a binary yarn execs (classic; rarely holds a token)
		".xscreensaver",      // names programs run as screensavers
		".psqlrc",            // \! runs a shell command when psql starts
		".Rprofile",          // R sources it at startup
		".Renviron",          // can set R_PROFILE_USER to a writable file; creating it is the attack
		".mcp.json",
	}

	// Directories whose contents run on the host at the next login, shell start, or
	// editor/tool invocation. Reads stay allowed (a script may legitimately inspect
	// them); creating or modifying an entry is what grants persistence, so writes are
	// denied. These are shielded as whole directories because their autoloaded/plugin
	// files cannot be pre-enumerated - a not-yet-created entry is still plantable, the
	// same reason git hooks are shielded as a directory.
	writeOnlyDirs := []string{
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

	rules := make([]Rule, 0, len(dirs)+len(files)+len(writeOnly)+len(writeOnlyDirs))
	for _, d := range dirs {
		rules = append(rules, Rule{Path: join(d), Deny: DenyAll, Dir: true})
	}
	for _, f := range files {
		rules = append(rules, Rule{Path: join(f), Deny: DenyAll})
	}
	for _, f := range writeOnly {
		rules = append(rules, Rule{Path: join(f), Deny: DenyWrite})
	}
	for _, d := range writeOnlyDirs {
		rules = append(rules, Rule{Path: join(d), Deny: DenyWrite, Dir: true})
	}
	return rules
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
