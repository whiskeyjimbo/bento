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

// ExtractLauncher is a no-op on non-Linux platforms.
func ExtractLauncher(opts ...ExtractOption) (string, error) {
	return "", nil
}
