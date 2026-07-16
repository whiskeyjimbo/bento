package denylist

import "testing"

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
		"/home/u/.config/git/config", // XDG git config
		"/home/u/.zshenv",            // read for every zsh invocation, incl. non-interactive
		"/home/u/.zlogin",            // zsh login
		"/home/u/.zlogout",           // zsh logout
		"/home/u/.bash_login",        // bash login fallback
		"/home/u/.bash_aliases",      // sourced by the default .bashrc; usually absent so plantable
		"/home/u/.bash_logout",       // bash logout
		"/home/u/.cargo/config.toml", // cargo honors rustc-wrapper / target runners
		"/home/u/.cargo/config",      // legacy cargo config filename
		"/home/u/.vimrc",             // sourced when vim opens a file
		"/home/u/.emacs",             // elisp at emacs startup
		"/home/u/.gdbinit",           // executed by gdb on startup
		"/home/u/.direnvrc",          // legacy direnv global rc
		"/home/u/.Renviron",          // can set R_PROFILE_USER
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
