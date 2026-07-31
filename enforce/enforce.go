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
//
// An Enforcer is reusable and safe for concurrent use: it holds no per-run state, so
// one value serves a whole process and several Runs may be in flight at once, each
// reporting its own target's outcome. Two concurrent runs that WRITE the same host tree
// are the caller's problem, not this seam's - they are two processes writing one
// directory, and the sandbox does not serialize them.
//
// Reusing the value is not what makes a second run cheaper, though, and an embedder
// structuring itself around this should know which one it is: the expensive host probes
// are memoized per PROCESS, not per Enforcer. A long-lived process amortizes them
// however many Enforcers it builds; a fresh exec per invocation pays them every time.
type Enforcer interface {
	// Probe reports what this host can enforce, per layer, without running a
	// target. It backs both `doctor` and strict-mode's pre-run refusal.
	Probe(ctx context.Context) Report

	// Run enforces p around proc, runs it to completion, and reports what was
	// actually enforced. A non-zero process exit is returned in Result, not as
	// err; err is reserved for a failure to set up or run the sandbox itself.
	//
	// Everything the core decided about this particular invocation travels in
	// RunOptions rather than as positional arguments, so a new decision does not
	// change this signature and a backend cannot mistake one flag for another.
	Run(ctx context.Context, p *policy.Policy, proc Process, opts RunOptions) (Result, error)
}

// RunOptions carries what the core decided for one invocation. It is distinct from
// Options: Options is what a frontend asks for, RunOptions is what the core resolved
// after probing the host, so a backend never re-decides an admission question.
type RunOptions struct {
	// Gate, when non-nil, admits an egress host the manifest does not declare; nil
	// keeps the declarative default of denying anything undeclared.
	Gate NetworkGate

	// Degraded tells the backend the core filesystem layer can only be partially
	// enforced (the probe reported it Degraded, e.g. bubblewrap cannot run because
	// user namespaces are blocked) and the run was admitted anyway under
	// --allow-degraded. The backend must then confine with its reduced-confinement
	// tier rather than assume its full mechanism is available. A backend never decides
	// this itself: the refuse-versus-degrade choice lives in enforce.Run, so a backend
	// can never silently downgrade.
	//
	// It selects a filesystem mechanism and nothing else, so it is derived from the
	// filesystem layer alone: another core layer the probe judged Degraded is admitted
	// or refused on its own terms and reported in the Report, and never reaches a
	// backend through this flag.
	Degraded bool

	// DenyPaths are absolute host paths the run must not reach, shielded on top of the
	// built-in deny-list. See Options.DenyPaths for what the guarantee covers.
	DenyPaths []string

	// AcceptAliasesUnder are host trees whose credential aliases the caller has
	// acknowledged. A shield hides a credential's path, not the content behind it, so a
	// second name for one inside a tree the run can read is normally a refusal. Naming a
	// tree here says "I know the aliases in here and accept them" - which a snapshot tool
	// that hardlinks against the live file (cp -al, a whole-tree deduplicator) makes
	// necessary, since it puts a second name for every credential under a backup root.
	//
	// It is a tree, not a path, because those tools rotate: today's snapshot directory is
	// dated and tomorrow's is a different name, so acknowledging exact paths would go
	// stale daily. It is deliberately NOT a policy field: an alias is a fact about this
	// host's filesystem, and folding it into a portable, fingerprinted manifest would
	// carry one machine's backup layout to every other. Whatever it admits is reported in
	// Result.AcceptedAliases, the same way a gate admission is.
	//
	// It has no effect on a Degraded run, and not because there is nothing to
	// acknowledge: that tier applies no shields and never scans for an alias, so an
	// alias inside a granted tree is readable there and the run proceeds where the full
	// tier refuses. The guarantee is absent rather than waived, and what the tier does
	// expose is reported through the Report.
	AcceptAliasesUnder []string
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

	// AllowNetworkStdio permits a stdio stream that is already an open network
	// socket. Bento otherwise refuses such a run: no layer it installs revokes an
	// already-open description - a netns binds at socket creation, the seccomp
	// egress block filters socket(2), and Landlock governs paths - so the target
	// gets an unfiltered channel past the manifest's allowlist. The socket-activation
	// pattern (a server handing a per-connection handler its accepted conn as stdio)
	// is doing that deliberately, and this is how it says so. It is deliberately not
	// a manifest field and not a CLI flag: a downloaded manifest or a copied command
	// line must never be able to re-open the channel, so only a Go caller that passed
	// the socket in the first place can permit it. The degraded (no-bwrap) tier
	// refuses regardless: every confinement there is the only one of its kind, so it
	// takes no bypass at all.
	AllowNetworkStdio bool

	// Env are the resolved environment values handed to the target. The policy
	// declares which NAMES may pass through; resolving those names against the
	// host, and merging any values supplied at invocation, is the core's job -
	// a backend applies this map and makes no decisions about it. Callers MUST build
	// this via ResolveEnv, which is what enforces the policy's allowlist: Run does not
	// re-check the keys, so a map assembled by any other path (e.g. from os.Environ)
	// would leak host variables the manifest never declared straight into the sandbox.
	Env map[string]string
}

// CredentialAlias is a second readable path to a shielded credential: Path reaches the
// content, Credential is the shielded file it reaches.
type CredentialAlias struct {
	Path       string
	Credential string
}

// SetupState is how far the in-sandbox stage got before the target ran: whether the
// exit code in a Result is the TARGET's answer or bento's.
//
// It is a heuristic, deliberately, and the names say which way it errs. The stage
// attests its own setup by writing a marker after every layer decision, so a stage
// killed outright mid-setup is indistinguishable from one that never started - both
// read as SetupSilent. What it will not do is claim SetupAttested for a stage that did
// not say so, which is what makes it safe to branch on.
type SetupState int

const (
	// SetupSilent means the stage reported nothing: it died during setup (the usual
	// case, exiting 125), never ran, or its report could not be read back. The exit
	// code is bento's, not the target's. It is the zero value so a Result that never
	// reached a stage at all never reads as attested.
	SetupSilent SetupState = iota
	// SetupTargetUnreached means the stage installed its layers and then could not
	// execute the target. Setup succeeded; the target never ran.
	SetupTargetUnreached
	// SetupAttested means the stage completed setup and reached the target, so the
	// exit code is the target's own.
	SetupAttested
)

func (s SetupState) String() string {
	switch s {
	case SetupTargetUnreached:
		return "target-unreached"
	case SetupAttested:
		return "attested"
	default:
		return "silent"
	}
}

// Result is the outcome of a Run: the target's exit code and the report of what
// the sandbox actually enforced around it.
type Result struct {
	ExitCode int
	Report   Report
	// Setup separates a bento setup failure from a target that exited with the same
	// code. Bento's "could not run the target" code is 125, which a target may also
	// exit itself, so the code alone cannot tell them apart - an embedder mapping the
	// two onto different exit codes of its own reads this instead of the Report's prose
	// reasons, which are written for humans and will change wording.
	//
	// It matters most under Strict, where it is the ONLY thing that separates two
	// outcomes that arrive identically as a populated Result plus a *Shortfall: a
	// genuine mid-run lapse (SetupAttested - the target ran, and a guarantee slipped)
	// and a stage that never got the layers up (SetupSilent). An embedder treating
	// those as disjoint on the error alone reports the wrong one.
	//
	// It is meaningful only when Run returned nil or a *Shortfall - the cases where a
	// target was actually launched. Every other error means the run was refused or
	// failed before any stage existed (a nil enforcer, an invalid policy, a host that
	// admission turned away), and the zero value reads as SetupSilent there without a
	// stage having died: read the error first, this second.
	//
	// It lives on Result rather than in Report because Report is overlaid after the
	// backend returns; see SetupState for what the states do and do not attest.
	Setup SetupState
	// EgressConnections is how many outbound connections reached the egress proxy
	// during the run, including any the proxy turned away at its concurrency limit
	// before reading their request. A count of zero on a run that could egress (the
	// policy allows it, or a NetworkGate is present) means the target either used no
	// network or bypassed the proxy (which, in the default cooperative mode, fails
	// closed) - letting a frontend explain a network failure precisely.
	EgressConnections int
	// GateAdmitted lists the destinations a NetworkGate admitted beyond the
	// manifest, deduped and sorted. A host appears once the gate approved it, even
	// if the subsequent dial then failed - EXCEPT a dial the upstream guard blocked
	// (a gate-approved host resolving to a non-public address): that connection is
	// reported in GuardBlocked, since it was never admitted past the guard - so a
	// destination that resolved public on one connection and private on another appears
	// in both lists, which is the honest account of it. Empty means no
	// destination was admitted beyond the manifest, which is also what a run with no
	// gate at all reports - it is not evidence a gate was present, only that nothing
	// went through one. Together with the count it keeps the run honest about egress it
	// permitted beyond the declared policy.
	GateAdmitted []HostPort
	// GuardBlocked lists the destinations the allowlist permitted by name but the
	// egress guard then refused to dial, because the name resolved to an address the
	// sandbox must not reach (loopback, cloud metadata, private space it holds no
	// explicit IP rule for) - or to one the guard could not classify at all. Deduped
	// and sorted.
	//
	// Each entry names the destination as the target ASKED for it, not the address it
	// resolved to: the sandbox is told nothing that separates this from an ordinary
	// dial failure (telling the two apart classifies names against the host's internal
	// DNS), so the resolved address stays out of the report as well. A frontend
	// surfaces these, because an allowlisted name resolving into private space is an
	// ordinary corporate-network misconfiguration that otherwise presents to the
	// operator as an unexplained connection failure, and no amount of widening the
	// allowlist fixes it - only an explicit IP rule for the address does.
	//
	// The Host is ATTACKER-CONTROLLED (the sandboxed target chose the CONNECT target),
	// so a consumer rendering it to a terminal must quote it. Empty is not evidence
	// that no name resolved into private space: a run that made no connections, or one
	// with no egress at all, reports empty too.
	GuardBlocked []HostPort
	// AcceptedAliases lists the credential aliases this run was allowed to read past a
	// shield because the caller acknowledged the tree they sit in. Each names the path
	// that reaches the content and the credential it reaches. Non-empty means the run
	// proceeded over a known gap in the boundary, so it is reported rather than assumed
	// harmless - an audit that showed only the shields would claim a guarantee this run
	// did not have. Sorted and deduped; empty for the ordinary run.
	AcceptedAliases []CredentialAlias
	// ShieldedGrants lists the always-shielded credential paths (~/.ssh, ~/.gnupg, the
	// runtime dir, ...) the policy explicitly granted, so the backend honored the grant
	// over its built-in shield. These are a deliberate caveat-emptor opt-in: exposing a
	// credential store to the sandboxed program. Sorted, empty for the common run that
	// opts into none. A frontend surfaces each as a loud warning so the exposure is
	// never silent - the backend does not refuse it, the operator chose it.
	ShieldedGrants []string
	// ShieldedGrantTargets pairs an opted-in grant with the store it actually bound, for
	// the entries where the two differ - Path is the spelling from ShieldedGrants,
	// Credential the path it reached. The deny-list builds the names that count as an
	// opt-in from the run's home anchors, and $HOME is caller-chosen, so a grant can name
	// a symlink while the exposure lands elsewhere; a frontend that reported only the
	// spelling would name a scratch path where a private key was handed over.
	//
	// The backend resolves these as it binds them, not afterwards. Re-resolving at report
	// time would name whatever the path points at once the target has exited, which for a
	// run that moved a symlink underneath itself is not what was exposed. Sorted by Path,
	// empty for the ordinary run that opted into nothing and for opt-ins that name their
	// own target.
	ShieldedGrantTargets []CredentialAlias
	// Shields lists the always-on shields the run actually engaged: the credential
	// and host-service paths the sandbox hid or made read-only for this policy, plus
	// any path the caller shielded through Options.DenyPaths. It is
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
