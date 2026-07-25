package denylist

import (
	"path/filepath"
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
		"/home/u/.cert",                 // 802.1X/VPN client keys (real kind varies by host)
		"/home/u/.mail",                 // maildir bodies and cached creds
		"/home/u/.Mail",                 // capitalized maildir variant
		"/home/u/.local/state/nvim",     // shada/undo/swap/backup: registers, search history, and full buffer contents
		"/home/u/.local/share/nvim",     // pre-0.8 legacy location of the same stores, abandoned but not deleted on upgrade
		"/home/u/.config/autostart",     // XDG autostart .desktop entries (hidden, matching firejail)
		"/home/u/.config/systemd",       // systemd --user unit/timer tree
		"/home/u/.local/share/systemd",  // systemd --user state
		"/home/u/Mail",                  // mutt default mail folder (no leading dot)
		"/home/u/mail",                  // mutt default mail folder
		"/home/u/Private",               // ecryptfs decrypted mount point
		"/home/u/.keepassxc",            // password-manager vault
		"/home/u/.config/keepassxc",     // and its config/cache siblings
		"/home/u/.cache/keepassxc",
		"/home/u/.config/Bitwarden",
		"/home/u/.config/1Password",
		"/home/u/.local/share/Enpass",
		"/home/u/.config/Authenticator",    // TOTP seeds
		"/home/u/.smartgit",                // per-version subdir holds remote passwords
		"/home/u/.bitcoin",                 // wallet private keys
		"/home/u/.electrum",                // named instance behind the .electrum* glob
		"/home/u/Monero/wallets",           // non-hidden wallet dir at the home root
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
		"/home/u/.bashrc.d",                 // Fedora/RHEL .bashrc sources ~/.bashrc.d/*.sh
		"/home/u/.config/containers",        // podman/skopeo exec-redirect knobs
		"/home/u/.config/fish",              // config.fish, conf.d/*.fish, and autoloaded functions/*.fish
		"/home/u/.config/nushell",           // nushell config and autoloads
		"/home/u/.vim",                      // auto-sourced plugin/autoload dirs
		"/home/u/.config/nvim",              // neovim config tree
		"/home/u/.emacs.d",                  // emacs init and site-lisp
		"/home/u/.config/environment.d",     // systemd user-session env
		"/home/u/.local/share/direnv/allow", // direnv authorization records
		"/home/u/.config/Code",              // VS Code User settings (git.path etc.)
		"/home/u/.vscode",                   // VS Code extensions dir
		"/home/u/.config/mpv",               // mpv autoloaded scripts
		"/home/u/.xmonad",                   // xmonad.hs compiled+run
		"/home/u/.local/lib",                // user libraries imported at runtime
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
	t.Setenv("CARGO_HOME", "/home/u/.cargo")
	for _, r := range Home("/home/u") {
		if strings.HasPrefix(r.Path, "/home/u/.cargo/") && r.Path != "/home/u/.cargo/credentials.toml" &&
			r.Path != "/home/u/.cargo/credentials" && r.Path != "/home/u/.cargo/config.toml" &&
			r.Path != "/home/u/.cargo/config" && r.Path != "/home/u/.cargo/env" {
			t.Errorf("CARGO_HOME=default must not add extra rules, saw %q", r.Path)
		}
	}
}
