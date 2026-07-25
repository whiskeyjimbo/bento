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

	"github.com/whiskeyjimbo/bento/policy"
)

// Enforcer applies a policy around a process under platform isolation.
type Enforcer interface {
	// Probe reports what this host can enforce, per layer, without running a
	// target. It backs both `doctor` and strict-mode's pre-run refusal.
	Probe(ctx context.Context) Report

	// Run enforces p around proc, runs it to completion, and reports what was
	// actually enforced. A non-zero process exit is returned in Result, not as
	// err; err is reserved for a failure to set up or run the sandbox itself.
	//
	// gate, when non-nil, admits an egress host the manifest does not declare; nil
	// keeps the declarative default of denying anything undeclared.
	//
	// degraded tells the backend the core filesystem layer can only be partially
	// enforced (the probe reported it Degraded, e.g. bubblewrap cannot run because
	// user namespaces are blocked) and the run was admitted anyway under
	// --allow-degraded. The backend must then confine with its reduced-confinement
	// tier rather than assume its full mechanism is available. Run never decides this
	// itself: the refuse-versus-degrade choice lives in enforce.Run, so a backend can
	// never silently downgrade.
	Run(ctx context.Context, p *policy.Policy, proc Process, gate NetworkGate, degraded bool) (Result, error)
}

// NetworkGate decides an egress host the manifest's allowlist does not permit.
// Returning true admits that connection for this run only; it is the seam a
// supervising caller uses to prompt a human. It is consulted synchronously in
// the connection's own goroutine, so it MAY block to prompt - but it must return
// promptly once ctx is done (the run is ending), or it stalls run teardown. host
// and port are attacker-controlled (a sandboxed target chose them); sanitize
// before displaying. A nil gate denies everything undeclared.
type NetworkGate func(ctx context.Context, host, port string) bool

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
	// a backend applies this map and makes no decisions about it. Callers MUST build
	// this via ResolveEnv, which is what enforces the policy's allowlist: Run does not
	// re-check the keys, so a map assembled by any other path (e.g. from os.Environ)
	// would leak host variables the manifest never declared straight into the sandbox.
	Env map[string]string
}

// Result is the outcome of a Run: the target's exit code and the report of what
// the sandbox actually enforced around it.
type Result struct {
	ExitCode int
	Report   Report
	// EgressConnections is how many outbound connections reached the egress proxy
	// during the run. A count of zero on a run that could egress (the policy allows
	// it, or a NetworkGate is present) means the target either used no network or
	// bypassed the proxy (which, in the default cooperative mode, fails closed) -
	// letting a frontend explain a network failure precisely.
	EgressConnections int
	// GateAdmitted lists the destinations a NetworkGate admitted beyond the
	// manifest, deduped and sorted. A host appears once the gate approved it, even
	// if the subsequent dial then failed - EXCEPT a dial the upstream guard blocked
	// (a gate-approved host resolving to a non-public address): that reports Denied
	// and is not listed, since it was never admitted past the guard. Empty when no
	// gate is set, so the count and this list keep the run honest about egress it
	// permitted beyond the declared policy.
	GateAdmitted []HostPort
	// ShieldedGrants lists the always-shielded credential paths (~/.ssh, ~/.gnupg, the
	// runtime dir, ...) the policy explicitly granted, so the backend honored the grant
	// over its built-in shield. These are a deliberate caveat-emptor opt-in: exposing a
	// credential store to the sandboxed program. Sorted, empty for the common run that
	// opts into none. A frontend surfaces each as a loud warning so the exposure is
	// never silent - the backend does not refuse it, the operator chose it.
	ShieldedGrants []string
	// Shields lists the always-on shields the run actually engaged: the credential
	// and host-service paths the sandbox hid or made read-only for this policy. It is
	// the operator-visible evidence that the boundary engaged, and shows which
	// credential classes a reachable grant would otherwise have exposed. Sorted by
	// path. Empty means the run shielded nothing - either no grant reached a shield,
	// or the tier does not shield at all (the degraded tier exposes reachable
	// credentials by design and reports its shortfall through the Report, not here),
	// so an empty list is not proof that nothing sensitive was in scope. It records
	// what the sandbox shielded from its own rule set, NOT what the target tried to
	// reach: there is no observer at enforce time, so a tool that fails closed because
	// a path it needs was denied is diagnosed by profiling, not from this list.
	Shields []ShieldApplied
	// Exposed lists the always-on shields a full bwrap run WOULD have engaged for this
	// policy but that this run left exposed, so the audit stays honest on a tier that
	// cannot shield. It is populated only by the degraded tier, which has no mount
	// namespace and therefore applies no shields at all: a home read grant that reached
	// a credential store makes it readable to the target here, where the full tier would
	// have hidden it. Each record names the path and the Kind the full tier would have
	// applied ("hidden"/"read-only") - it is the protection this tier did NOT deliver,
	// the mirror image of Shields, not evidence anything was hidden. Opt-ins are excluded
	// (they are a deliberate exposure the full tier makes too, reported via
	// ShieldedGrants). Sorted by path, empty for the full tier and for a degraded run
	// whose grants reached no shield.
	Exposed []ShieldApplied
}

// ShieldApplied is one always-on shield the run engaged. Kind is "hidden" (the path
// is absent - a credential store the sandbox tmpfs'd or overmounted with an empty
// file) or "read-only" (the path stays readable but cannot be written - a
// code-execution surface like a git hooks dir). Path can carry bytes influenced by a
// prior run (a git submodule directory name), so a consumer that renders it to a
// terminal must quote it; the built-in surfaces do (JSON-encoded, or counts only).
type ShieldApplied struct {
	Path string
	Kind string
}

// HostPort is one egress destination admitted at runtime by a NetworkGate rather
// than declared in the manifest. It duplicates profile.HostPort deliberately:
// enforce importing profile for a two-field value would point the dependency the
// wrong way.
type HostPort struct{ Host, Port string }
