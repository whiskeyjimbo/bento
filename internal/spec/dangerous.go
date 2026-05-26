package spec

import (
	"path/filepath"
	"strings"
)

// DangerousFiles is the read-protection list — sensitive files that
// bento refuses to expose to sandboxed scripts even when the user's
// read rules would allow them. Defaults exist because users forget to
// explicitly deny these.
//
// Paths use ~ for the user's home directory; ExpandDangerousPaths
// resolves them. Use literal file paths (not directories) so the
// /dev/null bind-mount trick works on Linux without needing an empty
// scratch directory.
//
// /dev/null binds also incidentally shield writes (writes get
// discarded), so files in this list are also effectively
// write-protected. Items that are ONLY persistence/RCE concerns (no
// credential value) belong in DangerousWriteFiles instead so the
// list's intent stays clear.
//
// Additions should be: globally sensitive (not project-specific),
// commonly present on dev machines, and high-impact if exposed
// (credentials, signing keys, session tokens).
var DangerousFiles = []string{
	// SSH private keys (all common algorithms)
	"~/.ssh/id_rsa",
	"~/.ssh/id_ed25519",
	"~/.ssh/id_ecdsa",
	"~/.ssh/id_dsa",
	"~/.ssh/identity",

	// Cloud credentials
	"~/.aws/credentials",
	"~/.aws/config",
	"~/.config/gcloud/credentials.db",
	"~/.config/gcloud/application_default_credentials.json",
	"~/.config/gcloud/legacy_credentials",
	"~/.azure/accessTokens.json",
	"~/.azure/azureProfile.json",
	"~/.kube/config",
	"~/.docker/config.json",

	// Generic secrets
	"~/.git-credentials",
	"~/.netrc",
	"~/.pypirc",
	"~/.npmrc",
	"~/.gem/credentials",

	// Password manager data
	"~/.password-store",
}

// DangerousWriteFiles is the write-protection list — files where a
// successful write means persistence or delayed RCE on the host, even
// though reading them is harmless. Examples:
//
//   - Shell rc files (.bashrc, .zshrc, .profile): appending a line
//     means malicious code runs on every new shell.
//   - User git config (.gitconfig): the [alias] section runs arbitrary
//     shell on aliased git commands.
//   - .mcp.json: registers MCP servers that auto-execute.
//
// Treated the same as DangerousFiles on the wire — bind /dev/null over
// each existing path. Maintained as a separate list so additions are
// reviewed in the persistence-threat context, not the credential
// context.
//
// Workspace-relative dangers (.git/hooks, .vscode/, .idea/) are
// handled separately by ExpandWorkspaceWriteProtection because they
// depend on the user's declared write paths.
var DangerousWriteFiles = []string{
	"~/.bashrc",
	"~/.bash_profile",
	"~/.zshrc",
	"~/.zprofile",
	"~/.profile",
	"~/.gitconfig",
	"~/.gitmodules",
	"~/.mcp.json",
	"~/.ripgreprc",
}

// ExpandDangerousPaths returns DangerousFiles with ~ expanded to the
// given home directory and paths cleaned. Empty home returns nil
// (caller's choice whether that's a fatal error).
func ExpandDangerousPaths(home string) []string {
	return expand(home, DangerousFiles)
}

// ExpandDangerousWritePaths returns DangerousWriteFiles with ~
// expanded. Same contract as ExpandDangerousPaths.
func ExpandDangerousWritePaths(home string) []string {
	return expand(home, DangerousWriteFiles)
}

func expand(home string, paths []string) []string {
	if home == "" {
		return nil
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, filepath.Clean(strings.Replace(p, "~", home, 1)))
	}
	return out
}

// WorkspaceWriteProtection separates the two shapes of in-workspace
// protection: directories that should be read-only-rebound (to shield
// all current AND future contents) and files that should be shadowed
// with /dev/null. The split exists because bwrap can't create a
// /dev/null mount point under a read-only parent, so we can't shield
// a single file that doesn't exist yet — but re-binding the whole
// directory as read-only DOES catch unborn files inside.
type WorkspaceWriteProtection struct {
	ReadOnlyDirs []string // ro-rebind these (shields all contents incl. unborn files)
	ShadowFiles  []string // /dev/null over these (only if they exist on host)
}

// WorkspaceWriteProtectionFor returns the protection list for the given
// user-declared write path. .git/hooks (directory) is re-bound
// read-only — that blocks creation of any new hook including
// post-checkout (RCE on next git op). .git/config and IDE configs are
// shadowed as files.
func WorkspaceWriteProtectionFor(workspace string) WorkspaceWriteProtection {
	clean := filepath.Clean(workspace)
	gitDir := filepath.Join(clean, ".git")
	return WorkspaceWriteProtection{
		ReadOnlyDirs: []string{
			filepath.Join(gitDir, "hooks"),
		},
		ShadowFiles: []string{
			filepath.Join(gitDir, "config"),
			filepath.Join(clean, ".vscode", "tasks.json"),
			filepath.Join(clean, ".vscode", "launch.json"),
			filepath.Join(clean, ".idea", "workspace.xml"),
		},
	}
}
