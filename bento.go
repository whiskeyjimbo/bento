package bento

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/whiskeyjimbo/bento/internal/doctor"
	"github.com/whiskeyjimbo/bento/internal/grants"
	"github.com/whiskeyjimbo/bento/internal/installer"
	"github.com/whiskeyjimbo/bento/internal/runner"
	"github.com/whiskeyjimbo/bento/internal/spec"
)

// =============================================================================
// Shared types
// =============================================================================

// Logger is the minimum logging interface bento needs. The standard
// library's *log.Logger satisfies it; slog or zap users can pass a
// one-method adapter.
type Logger = spec.Logger

// =============================================================================
// Running scripts
// =============================================================================

// Manifest is the per-script permission declaration. Empty / nil fields
// mean "deny." A nil Network blocks all network; an empty Exec slice
// blocks all subprocesses.
type Manifest = spec.Manifest

// NetworkPerm describes allowed outbound traffic.
type NetworkPerm = spec.NetworkPerm

// NetworkRule is one host:port allowance.
type NetworkRule = spec.NetworkRule

// Limits is the per-script resource ceiling.
type Limits = spec.Limits

// NetworkMode selects the Linux network-enforcement strategy. Ignored
// on macOS (Seatbelt handles per-host filtering natively).
type NetworkMode = spec.NetworkMode

// Network mode constants.
const (
	NetworkModeAuto     = spec.NetworkModeAuto
	NetworkModeLandlock = spec.NetworkModeLandlock
	NetworkModeBridge   = spec.NetworkModeBridge
)

// ParseNetworkMode resolves a CLI-style string (auto, landlock,
// bridge, or empty) to a NetworkMode. Returns (Auto, false) for
// unknown values.
func ParseNetworkMode(s string) (NetworkMode, bool) { return spec.ParseNetworkMode(s) }

// Option configures a Run invocation.
type Option = runner.Option

// ResolveOption configures an interpreter resolution.
type ResolveOption = spec.ResolveOption

// RegisterExtensionInterpreter maps a file extension (e.g. ".ts") to a default
// interpreter name (e.g. "bun") globally. Thread-safe.
func RegisterExtensionInterpreter(ext, interpreter string) {
	spec.RegisterExtensionInterpreter(ext, interpreter)
}

// WithCustomExtensions provides temporary/one-off extension-to-interpreter
// mappings for a single ResolveInterpreter call.
func WithCustomExtensions(mappings map[string]string) ResolveOption {
	return spec.WithCustomExtensions(mappings)
}

// WithDisableShebang skips checking shebang (#!) lines during resolution.
func WithDisableShebang() ResolveOption {
	return spec.WithDisableShebang()
}

// ResolveInterpreter returns the default interpreter for the given
// script path: the extension table (.py → python3, .js → node, etc.)
// or the script's shebang line if the extension isn't mapped.
// Returns an error with remediation hints when neither path
// succeeds.
//
// Library consumers building manifests programmatically use this to
// match the CLI's zero-config behavior.
func ResolveInterpreter(scriptPath string, opts ...ResolveOption) (string, error) {
	return spec.ResolveInterpreter(scriptPath, opts...)
}

// PracticalStrictManifest builds the zero-config default manifest for
// a script: read access only to the script's own directory; no write;
// no network; no subprocess spawning. The same defaults the CLI
// applies for `bento run script.py` (no YAML manifest).
//
// Pair with [ResolveInterpreter] for full zero-config behavior:
//
//	interp, err := bento.ResolveInterpreter("script.py")
//	m, err := bento.PracticalStrictManifest("script.py", interp)
//	code, err := bento.Run(ctx, m)
func PracticalStrictManifest(scriptPath, interpreter string) (*Manifest, error) {
	return spec.PracticalStrictManifest(scriptPath, interpreter)
}

// LoadOption configures manifest parsing.
type LoadOption func(*loadConfig)

type loadConfig struct {
	baseDir        string
	envExpansion   bool
	skipValidation bool
}

// WithBaseDir joins relative script, read, and write paths inside the manifest
// with the specified directory path.
func WithBaseDir(path string) LoadOption {
	return func(c *loadConfig) { c.baseDir = path }
}

// WithEnvExpansion resolves environment variables (e.g. ${VAR}) inside the
// manifest string before parsing.
func WithEnvExpansion() LoadOption {
	return func(c *loadConfig) { c.envExpansion = true }
}

// WithSkipValidation skips standard manifest validation on load (useful for
// testing non-standard settings).
func WithSkipValidation() LoadOption {
	return func(c *loadConfig) { c.skipValidation = true }
}

// LoadManifest reads a YAML manifest from r, unmarshals it, and runs
// [Manifest.Validate] in one call. Library consumers loading
// manifests from disk, databases, HTTP responses, or in-memory
// strings should prefer this over rolling their own yaml.Unmarshal +
// Validate pair so they can't forget the validate step.
//
// Accepts optional LoadOptions to post-process paths or expand environment
// variables.
func LoadManifest(r io.Reader, opts ...LoadOption) (*Manifest, error) {
	if r == nil {
		return nil, fmt.Errorf("LoadManifest: nil reader")
	}
	cfg := &loadConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("LoadManifest: read: %w", err)
	}

	if cfg.envExpansion {
		data = []byte(os.ExpandEnv(string(data)))
	}

	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("LoadManifest: yaml: %w", err)
	}

	if cfg.baseDir != "" {
		if m.Script != "" && !filepath.IsAbs(m.Script) {
			m.Script = filepath.Join(cfg.baseDir, m.Script)
		}
		for i, p := range m.Read {
			if !filepath.IsAbs(p) {
				m.Read[i] = filepath.Join(cfg.baseDir, p)
			}
		}
		for i, p := range m.Write {
			if !filepath.IsAbs(p) {
				m.Write[i] = filepath.Join(cfg.baseDir, p)
			}
		}
	}

	if !cfg.skipValidation {
		if err := m.Validate(); err != nil {
			return nil, err // already prefixed with "manifest..."
		}
	}
	return &m, nil
}

// Run executes the script described by m under platform-appropriate
// sandboxing (bubblewrap on Linux, sandbox-exec on macOS). Returns the
// script's exit code (0 on success) and an error for setup failures.
// A non-zero script exit code does NOT produce an error.
//
// Cancelling ctx sends SIGTERM to the sandboxed process tree.
func Run(ctx context.Context, m *Manifest, opts ...Option) (int, error) {
	return runner.Run(ctx, m, opts...)
}

// WithLogger enables internal logging (proxy events, bwrap argv, etc.)
// to the given logger. Pass nil to suppress all internal logs.
func WithLogger(l Logger) Option { return runner.WithLogger(l) }

// WithStdin connects the script's stdin to r. Defaults to os.Stdin.
func WithStdin(r io.Reader) Option { return runner.WithStdin(r) }

// WithStdout connects the script's stdout to w. Defaults to os.Stdout.
func WithStdout(w io.Writer) Option { return runner.WithStdout(w) }

// WithStderr connects the script's stderr to w. Defaults to os.Stderr.
func WithStderr(w io.Writer) Option { return runner.WithStderr(w) }

// WithTimeout caps the script's wall-clock run time. On expiry, the
// sandboxed process tree is terminated. Special values:
//
//   - Omitted: the default (10 minutes) applies. This catches hangs
//     without bespoke per-call configuration.
//   - WithTimeout(0): explicit opt-out, no timeout.
//   - WithTimeout(d) where d > 0: hard cap at d.
//
// When systemd-run is available, RuntimeMaxSec= is also set so a
// crashed bento parent still terminates the sandbox.
func WithTimeout(d time.Duration) Option { return runner.WithTimeout(d) }

// WithExtraEnv sets env vars on the script in addition to the
// manifest's Env passthrough list. Useful for caller-supplied secrets
// or session values that shouldn't be hard-coded into the manifest.
func WithExtraEnv(env map[string]string) Option { return runner.WithExtraEnv(env) }

// GrantRequest is what bento hands a [GrantCallback] when a script
// requests a network host:port that isn't in the manifest's allowlist.
type GrantRequest = grants.Request

// GrantDecision is what a [GrantCallback] returns.
type GrantDecision = grants.Decision

// Grant decision constants.
const (
	GrantDeny  = grants.DecisionDeny
	GrantAllow = grants.DecisionAllow
)

// GrantCallback is the interactive permission decider. When set via
// [WithGrantCallback], it's consulted on allowlist misses. Must be
// goroutine-safe. Decisions are cached per Run so a script making
// 100 requests to the same host prompts once. Decisions do NOT
// persist across Runs.
type GrantCallback = grants.Callback

// WithGrantCallback installs a permission callback consulted on
// network allowlist misses. Without this option, unrecognized hosts
// are hard-denied.
//
// Library consumers without a TTY (servers, GUIs, CI) supply their
// own — auto-allow with logging, auto-deny, GUI dialog, Slack
// approval, etc. The CLI's `-i` / `--prompt` flag is a thin wrapper
// that installs a TTY-backed callback.
func WithGrantCallback(cb GrantCallback) Option { return runner.WithGrantCallback(cb) }

// WithTelemetry connects the script's fd 3 to w. Scripts that want to
// return structured data write to fd 3 explicitly (e.g.
// `os.write(3, b'{...}')` in Python; `echo ... >&3` in bash). Nothing
// is captured by default — fd 3 is closed in the child unless
// WithTelemetry sets up the pipe. Recommended convention:
// line-delimited JSON.
func WithTelemetry(w io.Writer) Option { return runner.WithTelemetry(w) }

// WithNetworkMode selects how the Linux runner enforces network rules.
// Defaults to NetworkModeAuto (picks Landlock on kernel ≥ 6.7,
// Bridge otherwise). NetworkModeBridge requires socat installed.
// Ignored on macOS.
func WithNetworkMode(m NetworkMode) Option { return runner.WithNetworkMode(m) }

// =============================================================================
// Doctor / health checks
// =============================================================================

// CheckResult is a single line in the doctor report.
type CheckResult = doctor.CheckResult

// Status is the outcome of a doctor check.
type Status = doctor.Status

// Doctor check statuses.
const (
	StatusPass = doctor.StatusPass
	StatusWarn = doctor.StatusWarn
	StatusFail = doctor.StatusFail
)

// CheckOption configures a Doctor / Checks invocation.
type CheckOption = doctor.Option

// CustomCheck is a caller-supplied health check.
type CustomCheck = doctor.Check

// Doctor probes the environment for sandbox prerequisites and writes a
// human-readable report to w. Returns true iff all checks passed.
func Doctor(w io.Writer, opts ...CheckOption) bool {
	return doctor.Format(w, doctor.Run(opts...))
}

// Checks returns the doctor results without formatting them — useful
// for programmatic inspection (CI, monitoring) instead of CLI output.
func Checks(opts ...CheckOption) []CheckResult {
	return doctor.Run(opts...)
}

// InitOption configures the package installer loop.
type InitOption = installer.InitOption

// WithDryRun specifies that bento init should only plan and print
// commands without modifying the system.
func WithDryRun() InitOption { return installer.WithDryRun() }

// WithDistroOverride overrides the auto-detected Linux distribution.
func WithDistroOverride(distro string) InitOption { return installer.WithDistroOverride(distro) }

// WithSkipAppArmor skips generating and loading the AppArmor profile.
func WithSkipAppArmor() InitOption { return installer.WithSkipAppArmor() }

// WithCustomPackageManager registers or overrides a package manager configuration
// for a given Linux distribution (distro name).
func WithCustomPackageManager(distro string, cmd []string, proxychainsPkg string) InitOption {
	return installer.WithCustomPackageManager(distro, cmd, proxychainsPkg)
}

// Init turns a failing host setup into a passing one: installs
// missing packages (bubblewrap, socat, proxychains4) and applies the
// AppArmor profile for bwrap when needed. Detects the distro from
// /etc/os-release and uses the appropriate package manager.
//
// Requires sudo for the install + apparmor_parser steps; sudo will
// prompt as needed.
//
// On macOS this is a no-op (everything is already present).
func Init(ctx context.Context, w io.Writer, opts ...InitOption) (int, error) {
	return installer.Init(ctx, w, opts...)
}

// WithSkipNetwork omits network-dependent doctor checks (libproxychains,
// Landlock TCP support). Useful in CI environments where these aren't
// relevant.
func WithSkipNetwork() CheckOption { return doctor.WithSkipNetwork() }

// WithFailFast stops doctor at the first FAIL.
func WithFailFast() CheckOption { return doctor.WithFailFast() }

// WithCheck appends a caller-supplied check to the built-in doctor set.
func WithCheck(c CustomCheck) CheckOption { return doctor.WithCheck(c) }

// WithInterpreters dynamically configures which target runtimes the doctor
// checks for. If empty, the default set (python3, bash, node) is verified.
func WithInterpreters(runtimes ...string) CheckOption {
	return doctor.WithInterpreters(runtimes...)
}
