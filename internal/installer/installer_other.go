//go:build !linux

package installer

import (
	"context"
	"errors"
	"io"
)

// Init is a no-op on non-Linux platforms. macOS ships with everything
// bento needs by default; Windows isn't supported.
func Init(_ context.Context, _ io.Writer, _ ...InitOption) (int, error) {
	return 0, errors.New("bento init has no work on this platform — try `bento doctor` instead")
}
