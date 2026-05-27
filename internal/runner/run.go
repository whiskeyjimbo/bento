package runner

import (
	"context"
	"time"

	"github.com/whiskeyjimbo/bento/internal/spec"
)

// Run executes the script under platform-appropriate sandboxing.
// Timeout: 0 → DefaultTimeout (10m); sentinel(-1) → no timeout; >0 → passthrough.
func Run(ctx context.Context, m *spec.Manifest, opts ...Option) (int, error) {
	if err := m.Validate(); err != nil {
		return -1, err
	}
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}
	cfg.Timeout = resolveTimeout(cfg.Timeout)
	if cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
	}
	return runPlatform(ctx, m, cfg)
}

// resolveTimeout: 0 → default, sentinel → no timeout, positive → passthrough.
func resolveTimeout(t time.Duration) time.Duration {
	if t == 0 {
		return DefaultTimeout
	}
	if t == timeoutUnlimited {
		return 0
	}
	return t
}
