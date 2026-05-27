package bento

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/whiskeyjimbo/bento/internal/doctor"
	"github.com/whiskeyjimbo/bento/internal/grants"
	"github.com/whiskeyjimbo/bento/internal/installer"
	"github.com/whiskeyjimbo/bento/internal/runner"
	"github.com/whiskeyjimbo/bento/internal/spec"
)

// Logger is the minimum logging interface bento needs; *log.Logger satisfies it.
type Logger = spec.Logger

// Manifest is the per-script permission declaration. Empty/nil fields mean "deny".
type Manifest = spec.Manifest

// NetworkPerm describes allowed outbound traffic.
type NetworkPerm = spec.NetworkPerm

// NetworkRule is one host:port allowance.
type NetworkRule = spec.NetworkRule

// Limits is the per-script resource ceiling.
type Limits = spec.Limits

// NetworkMode selects the Linux network-enforcement strategy. Ignored on macOS.
type NetworkMode = spec.NetworkMode

// Network mode constants.
const (
	NetworkModeAuto     = spec.NetworkModeAuto
	NetworkModeLandlock = spec.NetworkModeLandlock
	NetworkModeBridge   = spec.NetworkModeBridge
)

// ParseNetworkMode resolves a CLI-style string to a NetworkMode. Returns (Auto, false) for unknown values.
func ParseNetworkMode(s string) (NetworkMode, bool) { return spec.ParseNetworkMode(s) }

// Option configures a Run invocation.
type Option = runner.Option

// ResolveOption configures an interpreter resolution.
type ResolveOption = spec.ResolveOption

// RegisterExtensionInterpreter maps a file extension to a default interpreter name globally. Thread-safe.
func RegisterExtensionInterpreter(ext, interpreter string) {
	spec.RegisterExtensionInterpreter(ext, interpreter)
}

// WithCustomExtensions provides one-off extension-to-interpreter mappings for a single ResolveInterpreter call.
func WithCustomExtensions(mappings map[string]string) ResolveOption {
	return spec.WithCustomExtensions(mappings)
}

// WithDisableShebang skips checking shebang lines during resolution.
func WithDisableShebang() ResolveOption {
	return spec.WithDisableShebang()
}

// ResolveInterpreter returns the default interpreter for the given script path,
// using the extension table or the script's shebang line.
func ResolveInterpreter(scriptPath string, opts ...ResolveOption) (string, error) {
	return spec.ResolveInterpreter(scriptPath, opts...)
}

// PracticalStrictManifest builds the zero-config default manifest: read-only
// access to the script's directory, no write, no network, no subprocess spawning.
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

// WithBaseDir joins relative script, read, and write paths with the specified directory.
func WithBaseDir(path string) LoadOption {
	return func(c *loadConfig) { c.baseDir = path }
}

// WithEnvExpansion resolves environment variables (${VAR}) inside the manifest before parsing.
func WithEnvExpansion() LoadOption {
	return func(c *loadConfig) { c.envExpansion = true }
}

// WithSkipValidation skips manifest validation on load.
func WithSkipValidation() LoadOption {
	return func(c *loadConfig) { c.skipValidation = true }
}

// friendlyYAMLError rewrites the cryptic messages yaml.v3 emits for common
// manifest mistakes ("!!seq into spec.NetworkPerm") into something a user can
// act on. Falls back to the raw error if no pattern matches. Idempotent —
// translates only known patterns and leaves everything else alone.
func friendlyYAMLError(err error) string {
	raw := err.Error()
	// Strip the redundant "yaml: unmarshal errors:" header and trailing
	// `into spec.TypeName` suffix that exposes internal types.
	clean := raw
	clean = strings.TrimPrefix(clean, "yaml: ")
	clean = strings.TrimPrefix(clean, "unmarshal errors:\n  ")

	// Mistake: `network: [- host: ...]` instead of `network: { rules: [...] }`.
	if strings.Contains(raw, "!!seq into spec.NetworkPerm") {
		return clean + "\n\nhint: `network:` must be a mapping with a `rules:` key, not a list. Example:\n" +
			"    network:\n" +
			"      rules:\n" +
			"        - host: api.example.com\n" +
			"          port: \"443\""
	}
	// Generic !!seq into <struct>: user wrote a list where a mapping is expected.
	if strings.Contains(raw, "!!seq into spec.") {
		field := extractFieldFromTypeError(raw, "!!seq into spec.")
		return clean + fmt.Sprintf("\n\nhint: the `%s:` field expects a mapping (with named keys), not a list.", field)
	}
	// !!map into []: user wrote a mapping where a list is expected (e.g.
	// `read: { foo: bar }` instead of `read: [foo]`).
	if strings.Contains(raw, "!!map into []") {
		return clean + "\n\nhint: this field expects a list (use `- item` lines), not a mapping."
	}
	// !!str into [] or struct: scalar where collection expected.
	if strings.Contains(raw, "!!str into []") {
		return clean + "\n\nhint: this field expects a list (use `- item` lines), not a single value."
	}
	// Unknown field with KnownFields(true).
	if strings.Contains(raw, "field ") && strings.Contains(raw, "not found in") {
		return clean + "\n\nhint: check spelling of the field name. Valid top-level fields:\n" +
			"    interpreter, script, args, env, read, write, network, allow_exec, limits"
	}
	return raw
}

func extractFieldFromTypeError(raw, marker string) string {
	// Errors look like: "line 4: cannot unmarshal !!seq into spec.NetworkPerm"
	// We have no field name in there, so map the struct type to its YAML key.
	_, after, ok := strings.Cut(raw, marker)
	if !ok {
		return "this"
	}
	rest := after
	end := strings.IndexAny(rest, " \n\t")
	if end < 0 {
		end = len(rest)
	}
	switch rest[:end] {
	case "NetworkPerm":
		return "network"
	case "Limits":
		return "limits"
	case "Manifest":
		return "(root)"
	default:
		return rest[:end]
	}
}

// LoadManifest reads a YAML manifest from r, unmarshals it, and validates it in one call.
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
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil && err != io.EOF {
		return nil, fmt.Errorf("LoadManifest: %s", friendlyYAMLError(err))
	}

	// Legacy `exec: [...]` is treated as allow_exec: true. Per-binary
	// allowlisting was never implemented; any non-empty list historically
	// disabled the launcher entirely. Normalize and warn.
	if len(m.Exec) > 0 {
		m.LegacyExecField = true
		if !m.AllowExec {
			m.AllowExec = true
		}
	}
	m.Exec = nil

	// `binary: ./tool` is a more natural alias for `script: ./tool` when
	// the target is a compiled ELF binary. Resolve into Script so the rest
	// of the codebase only deals with one field.
	if m.Script == "" && m.Binary != "" {
		m.Script = m.Binary
	}
	if m.Binary != "" && m.Script != m.Binary {
		return nil, fmt.Errorf("LoadManifest: cannot set both `script:` and `binary:` to different values")
	}
	m.Binary = ""

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

	// ELF default: an absent `interpreter:` means the script is its own
	// interpreter (a compiled binary). Fill it in so downstream consumers
	// (validate, runner) don't need a special case.
	if m.Interpreter == "" && m.Script != "" {
		m.Interpreter = m.Script
	}

	if !cfg.skipValidation {
		if err := m.Validate(); err != nil {
			return nil, err
		}
	}
	return &m, nil
}

// Run executes the script described by m under platform-appropriate sandboxing.
// Returns the script's exit code; a non-zero exit code does NOT produce an error.
// Cancelling ctx sends SIGTERM to the sandboxed process tree.
func Run(ctx context.Context, m *Manifest, opts ...Option) (int, error) {
	return runner.Run(ctx, m, opts...)
}

// WithLogger enables internal logging to the given logger. Pass nil to suppress.
func WithLogger(l Logger) Option { return runner.WithLogger(l) }

// WithVerbose toggles extra diagnostic logging (e.g. the sandbox argv dump).
// Has no effect without WithLogger.
func WithVerbose(v bool) Option { return runner.WithVerbose(v) }

// FSOpen is one open() attempt recorded by Profile.
type FSOpen = runner.FSOpen

// WithFilesystemObserver installs a callback invoked once after the script
// exits with every open() attempt the script made. Linux-only; uses strace
// if available, else the LD_PRELOAD fsshim. nil → no observation.
func WithFilesystemObserver(cb func(opens []FSOpen)) Option {
	return runner.WithFilesystemObserver(cb)
}

// WithStdin connects the script's stdin to r. Defaults to os.Stdin.
func WithStdin(r io.Reader) Option { return runner.WithStdin(r) }

// WithStdout connects the script's stdout to w. Defaults to os.Stdout.
func WithStdout(w io.Writer) Option { return runner.WithStdout(w) }

// WithStderr connects the script's stderr to w. Defaults to os.Stderr.
func WithStderr(w io.Writer) Option { return runner.WithStderr(w) }

// WithTimeout caps the script's wall-clock run time. Omitted: 10 minute default.
// WithTimeout(0): explicit opt-out. WithTimeout(d>0): hard cap at d.
func WithTimeout(d time.Duration) Option { return runner.WithTimeout(d) }

// WithExtraEnv sets env vars on the script in addition to the manifest's Env list.
func WithExtraEnv(env map[string]string) Option { return runner.WithExtraEnv(env) }

// WithEnv is an alias for [WithExtraEnv] that matches the CLI's `--env` flag
// name. Library callers can use either; both add to the manifest's Env list.
func WithEnv(env map[string]string) Option { return runner.WithExtraEnv(env) }

// GrantRequest is what bento hands a [GrantCallback] when a script requests
// a network host:port that isn't in the manifest's allowlist.
type GrantRequest = grants.Request

// GrantDecision is what a [GrantCallback] returns.
type GrantDecision = grants.Decision

// GrantKind discriminates GrantRequest types. Callbacks should default-deny unrecognized kinds.
type GrantKind = grants.Kind

// Grant kind constants.
const (
	KindNetwork = grants.KindNetwork
)

// Grant decision constants.
const (
	GrantDeny  = grants.DecisionDeny
	GrantAllow = grants.DecisionAllow
)

// GrantCallback is the interactive permission decider, consulted on allowlist misses.
// Must be goroutine-safe. Decisions are cached per Run; they do NOT persist across Runs.
type GrantCallback = grants.Callback

// WithGrantCallback installs a permission callback consulted on network
// allowlist misses. Without this option, unrecognized hosts are hard-denied.
func WithGrantCallback(cb GrantCallback) Option { return runner.WithGrantCallback(cb) }

// WithTelemetry connects the script's fd 3 to w. Scripts write structured data
// to fd 3 explicitly; nothing is captured unless WithTelemetry sets up the pipe.
func WithTelemetry(w io.Writer) Option { return runner.WithTelemetry(w) }

// WithNetworkMode selects how the Linux runner enforces network rules.
// Defaults to Auto (Landlock on kernel ≥ 6.7, Bridge otherwise).
func WithNetworkMode(m NetworkMode) Option { return runner.WithNetworkMode(m) }

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

// Doctor probes the environment for sandbox prerequisites and writes a report to w.
// Returns true iff all checks passed.
func Doctor(w io.Writer, opts ...CheckOption) bool {
	return doctor.Format(w, doctor.Run(opts...))
}

// Checks returns the doctor results without formatting them.
func Checks(opts ...CheckOption) []CheckResult {
	return doctor.Run(opts...)
}

// InitOption configures the package installer loop.
type InitOption = installer.InitOption

// WithDryRun makes bento init only plan and print commands without modifying the system.
func WithDryRun() InitOption { return installer.WithDryRun() }

// WithDistroOverride overrides the auto-detected Linux distribution.
func WithDistroOverride(distro string) InitOption { return installer.WithDistroOverride(distro) }

// WithSkipAppArmor skips generating and loading the AppArmor profile.
func WithSkipAppArmor() InitOption { return installer.WithSkipAppArmor() }

// WithCustomPackageManager registers or overrides a package manager configuration for a distro.
func WithCustomPackageManager(distro string, cmd []string, proxychainsPkg string) InitOption {
	return installer.WithCustomPackageManager(distro, cmd, proxychainsPkg)
}

// Init installs missing packages and applies the AppArmor profile for bwrap.
// Requires sudo. On macOS this is a no-op.
func Init(ctx context.Context, w io.Writer, opts ...InitOption) (int, error) {
	return installer.Init(ctx, w, opts...)
}

// WithSkipNetwork omits network-dependent doctor checks.
func WithSkipNetwork() CheckOption { return doctor.WithSkipNetwork() }

// WithFailFast stops doctor at the first FAIL.
func WithFailFast() CheckOption { return doctor.WithFailFast() }

// WithCheck appends a caller-supplied check to the built-in doctor set.
func WithCheck(c CustomCheck) CheckOption { return doctor.WithCheck(c) }

// WithInterpreters configures which target runtimes the doctor checks for.
// If empty, the default set (python3, bash, node) is verified.
func WithInterpreters(runtimes ...string) CheckOption {
	return doctor.WithInterpreters(runtimes...)
}
