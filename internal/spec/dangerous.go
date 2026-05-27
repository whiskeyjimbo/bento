package spec

import (
	"path/filepath"
	"strings"
)

// DangerousFiles is the read-protection list — sensitive files always denied
// regardless of the manifest's read rules. ~ resolves via ExpandDangerousPaths.
// Use literal file paths (not directories) so the /dev/null bind-mount works on Linux.
// Items only relevant to persistence/RCE (not credentials) belong in DangerousWriteFiles.
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

// DangerousWriteFiles is the write-protection list — writes mean persistence
// or delayed RCE even though reading them is harmless (shell rc files,
// .gitconfig aliases, .mcp.json, etc.).
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

// ExpandDangerousPaths returns DangerousFiles with ~ expanded. Empty home → nil.
func ExpandDangerousPaths(home string) []string {
	return expand(home, DangerousFiles)
}

// ExpandDangerousWritePaths returns DangerousWriteFiles with ~ expanded.
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

// WorkspaceWriteProtection splits in-workspace protection: dirs to ro-rebind
// (catches unborn files too) and files to /dev/null-shadow (existing only).
type WorkspaceWriteProtection struct {
	ReadOnlyDirs []string
	ShadowFiles  []string
}

// WorkspaceWriteProtectionFor returns the protection list for a user-declared
// write path. .git/hooks is ro-rebound to block new hook creation (RCE on next git op).
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
