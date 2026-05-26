// Package runner contains the platform-specific sandbox runners
// (bubblewrap on Linux, sandbox-exec on macOS) plus the launcher
// extraction logic. Consumers should use the root bento package; this
// is internal and unstable.
package runner

import (
	"io"
	"os"
	"time"

	"github.com/whiskeyjimbo/bento/internal/grants"
	"github.com/whiskeyjimbo/bento/internal/spec"
)

// Logger is the minimum logging interface bento needs. Re-exported from
// the spec package so callers don't have to import internal/spec
// directly.
type Logger = spec.Logger

// Option configures a Run invocation.
type Option func(*Config)

// Config is the per-invocation configuration assembled by Options.
// Exported so the platform-specific runner files (in the same package)
// can read it; not intended for external use.
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

	// PreExtractedLauncher is the path to an already-extracted bento-launcher
	// binary. When set, startAuxiliary uses it instead of writing a fresh
	// temp file. Used by the warm-pool Sandbox to amortize the ~1.7 MB
	// launcher extraction across many Runs. Empty (default) → extract per-Run.
	PreExtractedLauncher string
}

// DefaultTimeout caps unbounded script runs at a sensible ceiling
// when the caller doesn't pass WithTimeout. 10 minutes is long enough
// for most legitimate automation and short enough to catch hangs
// before they accumulate. Callers needing more should pass
// WithTimeout(longer); callers explicitly disabling should pass
// WithTimeout(0) (treated as "no timeout").
const DefaultTimeout = 10 * time.Minute

// timeoutUnlimited is the sentinel for "disable the default timeout".
// We distinguish "zero value (apply default)" from "explicit zero
// (no timeout)" by storing time.Duration(-1) for the explicit case.
// WithTimeout(0) sets the sentinel; Run() resolves zero values to the
// default and the sentinel to "no deadline".
const timeoutUnlimited time.Duration = -1

// DefaultConfig is the starting point for an Option chain. Timeout is
// left at zero so Run can distinguish "caller didn't say" from
// "caller explicitly opted out" (sentinel value).
func DefaultConfig() *Config {
	return &Config{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
}

// WithLogger enables internal logging to the given logger. Pass nil to
// suppress all internal logs.
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

// WithTimeout caps the script's run time. On expiry, the sandboxed
// process tree receives SIGTERM (via context cancellation), then
// SIGKILL after a brief grace period.
//
// Special values:
//   - Not called: DefaultTimeout (10 minutes) applies.
//   - WithTimeout(0): explicit "no timeout" — script may run forever.
//   - WithTimeout(d) where d > 0: hard cap at d.
//
// When systemd-run is available, RuntimeMaxSec= is also set as a
// belt-and-suspenders deadline that survives parent crashes.
func WithTimeout(d time.Duration) Option {
	return func(c *Config) {
		if d == 0 {
			c.Timeout = timeoutUnlimited
		} else {
			c.Timeout = d
		}
	}
}

// WithExtraEnv sets env vars on the script in addition to whatever the
// manifest's Env passthrough provides. Useful for caller-supplied
// values (e.g. AWS_SESSION_TOKEN) that shouldn't be hard-coded into
// the manifest.
func WithExtraEnv(env map[string]string) Option {
	return func(c *Config) { c.ExtraEnv = env }
}

// WithTelemetry connects the script's fd 3 to w. Scripts opt in by
// writing to fd 3 explicitly (e.g. `os.write(3, b'{...}')` in Python,
// `echo ... >&3` in bash). Nothing is captured by default.
// Recommended convention: line-delimited JSON.
func WithTelemetry(w io.Writer) Option {
	return func(c *Config) { c.Telemetry = w }
}

// WithPreExtractedLauncher tells the runner to reuse an already-
// extracted launcher binary instead of writing one to a fresh temp
// file. Used by the warm-pool Sandbox. Library consumers calling Run
// directly should NOT set this — they don't own the launcher's
// lifecycle.
func WithPreExtractedLauncher(path string) Option {
	return func(c *Config) { c.PreExtractedLauncher = path }
}

// WithGrantCallback installs an interactive grant callback for
// network host:port requests not in the manifest's allowlist. When
// nil (default), unrecognized hosts are hard-denied as before.
//
// CLI's -i / --prompt is a wrapper that installs a TTY-backed
// callback. Library consumers without a TTY supply their own (auto-
// allow, deny-with-log, GUI prompt, etc.). Decisions are cached
// per-Run so a script making 100 requests to the same host prompts
// once. Decisions do NOT persist across Runs.
func WithGrantCallback(cb grants.Callback) Option {
	return func(c *Config) { c.GrantCallback = cb }
}

// WithNetworkMode selects the Linux network-enforcement strategy:
// spec.NetworkModeAuto (default; picks based on kernel capability),
// spec.NetworkModeLandlock (kernel ≥ 6.7 only), or
// spec.NetworkModeBridge (any kernel; needs socat).
func WithNetworkMode(m spec.NetworkMode) Option {
	return func(c *Config) { c.NetworkMode = m }
}
