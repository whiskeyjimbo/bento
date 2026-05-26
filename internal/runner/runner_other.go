//go:build !linux && !darwin

package runner

import (
	"context"
	"fmt"
	"runtime"

	"github.com/whiskeyjimbo/bento/internal/spec"
)

func runPlatform(_ context.Context, _ *spec.Manifest, _ *Config) (int, error) {
	return -1, fmt.Errorf("bento: unsupported platform %q", runtime.GOOS)
}
