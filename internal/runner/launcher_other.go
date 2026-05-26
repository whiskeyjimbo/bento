//go:build !linux

package runner

// ExtractLauncher is a no-op on non-Linux platforms; the launcher
// shim is Linux-amd64-only. Returns ("", nil) so the Sandbox warm-
// pool API works uniformly across platforms (no warm asset to
// extract, but no error either).
func ExtractLauncher() (string, error) {
	return "", nil
}
