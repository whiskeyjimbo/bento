//go:build linux

package runner

import (
	"fmt"
	"os"
	"runtime"

	"github.com/whiskeyjimbo/bento/internal/launcherbin"
)

// ExtractOption configures launcher extraction.
type ExtractOption func(*extractOpts)

type extractOpts struct {
	dir string
}

// WithExtractDir sets the target dir for the launcher binary. Empty → system temp.
func WithExtractDir(dir string) ExtractOption {
	return func(o *extractOpts) { o.dir = dir }
}

// ExtractLauncher writes the embedded launcher to a temp file (0755) and returns its path.
// Exported so the warm-pool Sandbox can extract once and reuse.
func ExtractLauncher(opts ...ExtractOption) (string, error) {
	return extractLauncher(opts...)
}

func extractLauncher(opts ...ExtractOption) (string, error) {
	cfg := &extractOpts{}
	for _, opt := range opts {
		opt(cfg)
	}

	blob := embeddedLauncherForArch()
	if len(blob) == 0 {
		return "", fmt.Errorf("no embedded launcher for %s/%s — run 'make launcher'", runtime.GOOS, runtime.GOARCH)
	}
	f, err := os.CreateTemp(cfg.dir, "bento-launcher-*")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(blob); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	if err := f.Chmod(0o755); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	f.Close()
	return f.Name(), nil
}

func embeddedLauncherForArch() []byte {
	switch runtime.GOARCH {
	case "amd64":
		return launcherbin.LinuxAMD64
	default:
		return nil
	}
}
