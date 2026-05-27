// Package runner holds the platform-specific sandbox runners (bubblewrap on Linux,
// sandbox-exec on macOS) plus the launcher extraction logic. Internal and unstable.
package runner

import (
	"io"
	"os"
	"time"

	"github.com/whiskeyjimbo/bento/internal/grants"
	"github.com/whiskeyjimbo/bento/internal/spec"
)

// Logger is the minimum logging interface bento needs.
type Logger = spec.Logger

// Option configures a Run invocation.
type Option func(*Config)

// Config is the per-invocation configuration assembled by Options.
type Config struct {
	Logger        Logger
	Stdin         io.Reader
	Stdout        io.Writer
	Stderr        io.Writer
	Telemetry     io.Writer         // optional: script's fd 3 writes go here
	Timeout       time.Duration     // 0 = no per-call timeout
	ExtraEnv      map[string]string // env vars set in addition to Manifest.Env passthrough
	NetworkMode   spec.NetworkMode  // Auto / Landlock / Bridge; Linux only
	GrantCallback grants.Callback   // optional: prompt on allowlist miss

	// PreExtractedLauncher reuses an already-extracted launcher (warm-pool Sandbox).
	// Empty → extract per-Run.
	PreExtractedLauncher string

	// Verbose enables extra diagnostic logging (sandbox argv, etc.) via Logger.
	Verbose bool

	// FSObserver, if non-nil, is invoked once after the script exits with all
	// unique host paths the script attempted to open. Each entry carries
	// OK=true (open succeeded) or OK=false (open failed). Used by Profile to
	// suggest read rules and surface mandatory-deny hits. Implementation
	// wraps the sandbox in strace on Linux, falling back to the LD_PRELOAD
	// fsshim if strace isn't available.
	FSObserver func(opens []FSOpen)
}

// FSOpen is one open() attempt recorded by the filesystem observer.
type FSOpen struct {
	Path  string
	OK    bool // open returned a non-negative fd
	Write bool // open requested write access (O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND)
}

// DefaultTimeout caps unbounded script runs when the caller doesn't pass WithTimeout.
const DefaultTimeout = 10 * time.Minute

// timeoutUnlimited distinguishes "zero value (apply default)" from "explicit zero (no timeout)".
const timeoutUnlimited time.Duration = -1

// DefaultConfig is the starting point for an Option chain.
func DefaultConfig() *Config {
	return &Config{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
}

// WithLogger enables internal logging. Pass nil to suppress.
func WithLogger(l Logger) Option {
	return func(c *Config) { c.Logger = l }
}

// WithStdin connects the script's stdin to r.
func WithStdin(r io.Reader) Option {
	return func(c *Config) { c.Stdin = r }
}

// WithStdout connects the script's stdout to w.
func WithStdout(w io.Writer) Option {
	return func(c *Config) { c.Stdout = w }
}

// WithStderr connects the script's stderr to w.
func WithStderr(w io.Writer) Option {
	return func(c *Config) { c.Stderr = w }
}

// WithTimeout caps the script's run time. Not called: 10m default.
// WithTimeout(0): no timeout. WithTimeout(d>0): hard cap at d.
func WithTimeout(d time.Duration) Option {
	return func(c *Config) {
		if d == 0 {
			c.Timeout = timeoutUnlimited
		} else {
			c.Timeout = d
		}
	}
}

// WithExtraEnv sets env vars in addition to the manifest's Env passthrough.
func WithExtraEnv(env map[string]string) Option {
	return func(c *Config) { c.ExtraEnv = env }
}

// WithTelemetry connects the script's fd 3 to w. Nothing is captured by default.
func WithTelemetry(w io.Writer) Option {
	return func(c *Config) { c.Telemetry = w }
}

// WithPreExtractedLauncher reuses an already-extracted launcher (warm-pool Sandbox only).
func WithPreExtractedLauncher(path string) Option {
	return func(c *Config) { c.PreExtractedLauncher = path }
}

// WithGrantCallback installs an interactive grant callback for allowlist-miss
// network requests. nil → hard-deny. Decisions cached per-Run only.
func WithGrantCallback(cb grants.Callback) Option {
	return func(c *Config) { c.GrantCallback = cb }
}

// WithVerbose toggles extra diagnostic logging (e.g. the sandbox argv dump).
// Has no effect without WithLogger.
func WithVerbose(v bool) Option {
	return func(c *Config) { c.Verbose = v }
}

// WithFilesystemObserver installs a callback invoked once after the script
// exits with every open() attempt the script made (path + success bit).
// Linux-only; uses strace if available, else the LD_PRELOAD fsshim.
// nil → no observation.
func WithFilesystemObserver(cb func(opens []FSOpen)) Option {
	return func(c *Config) { c.FSObserver = cb }
}

// WithNetworkMode selects the Linux network-enforcement strategy.
// Auto (default), Landlock (kernel ≥6.7), or Bridge (needs socat).
func WithNetworkMode(m spec.NetworkMode) Option {
	return func(c *Config) { c.NetworkMode = m }
}
