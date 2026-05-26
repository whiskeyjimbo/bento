//go:build !linux

package runner

// ExtractOption configures launcher extraction.
type ExtractOption func(*extractOpts)

type extractOpts struct {
	dir string
}

// WithExtractDir sets the target directory where the launcher binary is extracted.
func WithExtractDir(dir string) ExtractOption {
	return func(o *extractOpts) { o.dir = dir }
}

// ExtractLauncher is a no-op on non-Linux platforms; the launcher
// shim is Linux-amd64-only. Returns ("", nil) so the Sandbox warm-
// pool API works uniformly across platforms (no warm asset to
// extract, but no error either).
func ExtractLauncher(opts ...ExtractOption) (string, error) {
	return "", nil
}
