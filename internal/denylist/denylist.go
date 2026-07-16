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
		".ssh",            // private keys, authorized_keys
		".aws",            // credentials, config
		".config/gcloud",  // application-default credentials, tokens
		".azure",          // access tokens
		".kube",           // cluster credentials
		".docker",         // registry auth
		".gnupg",          // secret keyrings
		".password-store", // pass(1)
		".terraform.d",    // credentials.tfrc.json
		".config/gh",      // GitHub CLI tokens
		".local/share/gh", // GitHub CLI tokens
		".config/rclone",  // remote storage tokens
		".oci",            // Oracle Cloud keys
		".config/doctl",   // DigitalOcean tokens
		".config/op",      // 1Password CLI

		// OS secret stores: the master keyring behind saved passwords and tokens.
		".local/share/keyrings", // GNOME Keyring
		".local/share/kwalletd", // KDE Wallet

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
		".pgpass",        // PostgreSQL passwords
		".s3cfg",         // s3cmd keys
		".boto",          // legacy AWS/GCP credentials
		".databrickscfg", // Databricks tokens
	}
	// Modifying any of these grants persistence or code execution on the host the
	// next time the user opens a shell or runs git. Reads stay allowed: git
	// legitimately reads ~/.gitconfig, and blinding it breaks real work.
	writeOnly := []string{
		".bashrc",
		".bash_profile",
		".zshrc",
		".zprofile",
		".profile",
		".gitconfig",
		".config/git/config", // XDG location git reads the same as ~/.gitconfig
		".mcp.json",
	}

	// Directories whose contents run on the host at the next login or shell start.
	// Reads stay allowed (a script may legitimately inspect them); creating or
	// modifying an entry is what grants persistence, so writes are denied.
	writeOnlyDirs := []string{
		".config/autostart",            // XDG autostart .desktop entries
		".config/systemd/user",         // systemd user services and timers
		".config/plasma-workspace/env", // KDE login shell scripts
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
