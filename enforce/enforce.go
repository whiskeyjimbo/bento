// Package enforce defines the seam between Bento's platform-independent core and
// the platform backends that apply isolation (Linux, macOS).
//
// The Enforcer interface is that seam. The core and frontends depend on it;
// backends implement it. Dependency points inward: this package imports the
// domain (policy) but nothing platform-specific, and no backend type appears in
// its signatures.
package enforce

import (
	"context"
	"io"

	"github.com/whiskeyjimbo/bento-v2/policy"
)

// Enforcer applies a policy around a process under platform isolation.
type Enforcer interface {
	// Probe reports what this host can enforce, per layer, without running a
	// target. It backs both `doctor` and strict-mode's pre-run refusal.
	Probe(ctx context.Context) Report

	// Run enforces p around proc, runs it to completion, and reports what was
	// actually enforced. A non-zero process exit is returned in Result, not as
	// err; err is reserved for a failure to set up or run the sandbox itself.
	Run(ctx context.Context, p *policy.Policy, proc Process) (Result, error)
}

// Process is the runtime binding a policy does not carry: where the target's
// standard streams connect, and the environment values it runs with.
type Process struct {
	// Stdin, Stdout, Stderr connect the target's standard streams. A nil stream
	// means "no stream" (e.g. /dev/null), not "inherit"; frontends pass
	// os.Stdin/os.Stdout explicitly when they want inheritance.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	// Env are the resolved environment values handed to the target. The policy
	// declares which NAMES may pass through; resolving those names against the
	// host, and merging any values supplied at invocation, is the core's job -
	// a backend applies this map and makes no decisions about it.
	Env map[string]string
}

// Result is the outcome of a Run: the target's exit code and the report of what
// the sandbox actually enforced around it.
type Result struct {
	ExitCode int
	Report   Report
	// EgressConnections is how many outbound connections reached the egress proxy
	// during the run. It is meaningful only when the policy allows egress; a
	// count of zero there means the target either used no network or bypassed the
	// proxy (which, in the default cooperative mode, fails closed) - letting a
	// frontend explain a network failure precisely.
	EgressConnections int
}
