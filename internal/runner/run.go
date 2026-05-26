package runner

import (
	"context"
	"time"

	"github.com/whiskeyjimbo/bento/internal/spec"
)

// Run executes the script described by m under platform-appropriate
// sandboxing. Returns the script's exit code and an error for setup
// failures.
//
// Timeout resolution:
//   - cfg.Timeout == 0       → DefaultTimeout (10m) applies
//   - cfg.Timeout == sentinel (-1) → no timeout (explicit opt-out via WithTimeout(0))
//   - cfg.Timeout > 0        → that duration applies
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

// resolveTimeout translates the option's three states into an
// effective duration: 0 → default, sentinel → no timeout, positive →
// passthrough. Exposed (lowercase) for the platform runners to call
// when wiring systemd-run RuntimeMaxSec.
func resolveTimeout(t time.Duration) time.Duration {
	if t == 0 {
		return DefaultTimeout
	}
	if t == timeoutUnlimited {
		return 0
	}
	return t
}
