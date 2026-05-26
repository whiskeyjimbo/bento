package bento

import (
	"context"
	"errors"
	"os"
	"sync"

	"github.com/whiskeyjimbo/bento/internal/runner"
)

// Sandbox is a long-lived holder of reusable setup costs (today: the
// extracted launcher binary). High-throughput consumers — CI runners,
// notebook executors, MCP gateways — that run many scripts back to
// back amortize the ~1.7 MB launcher extract over all of them.
//
// Per-Run resources (filter proxies, proxychains config, bwrap
// process) are still set up and torn down per Run because they
// depend on the manifest. The Sandbox doesn't make Runs concurrent;
// concurrent Run calls are supported (each gets its own proxies).
//
// Use as:
//
//	sb, err := bento.NewSandbox()
//	defer sb.Close()
//	for _, m := range manifests {
//	    code, err := sb.Run(ctx, m, opts...)
//	}
//
// On Linux, the warm asset is the bento-launcher binary. On macOS
// (no launcher needed today), NewSandbox is a cheap no-op and the
// throughput win is zero — but the API stays uniform.
type Sandbox struct {
	mu           sync.Mutex
	launcherPath string // "" on macOS / when extraction failed
	closed       bool
}

// NewSandbox extracts shared resources once. Call Close when done.
func NewSandbox() (*Sandbox, error) {
	s := &Sandbox{}
	path, err := runner.ExtractLauncher()
	if err == nil {
		s.launcherPath = path
	}
	// Extraction failure isn't fatal — falls back to per-Run extract,
	// which surfaces its own warning via cfg.warn.
	return s, nil
}

// Run executes the script under this Sandbox, reusing the warm
// launcher. Same semantics as bento.Run otherwise.
func (s *Sandbox) Run(ctx context.Context, m *Manifest, opts ...Option) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return -1, errors.New("Sandbox is closed")
	}
	path := s.launcherPath
	s.mu.Unlock()

	if path != "" {
		opts = append([]Option{runner.WithPreExtractedLauncher(path)}, opts...)
	}
	return Run(ctx, m, opts...)
}

// Close releases the warm resources. Subsequent Run calls error.
// Safe to call multiple times.
func (s *Sandbox) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.launcherPath != "" {
		os.Remove(s.launcherPath)
		s.launcherPath = ""
	}
	return nil
}
