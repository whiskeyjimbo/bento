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
// structuring itself around this should know which one it is: the host probes that ARE
// memoized are memoized per PROCESS, not per Enforcer, so a long-lived process amortizes
// them however many Enforcers it builds and a fresh exec per invocation pays them every
// time. Not all of them are. On Linux the cgroup scope and delegation probes are cached;
// the namespace probe is not, and it is the expensive one - it execs the sandbox binary
// on every call.
//
// Two Probe calls in one process can therefore disagree, and an embedder must not read
// one as a promise about the other: a host that loses the namespace between them answers
// truthfully both times. A backend correcting a layer mid-run has to compare against what
// the report already holds for the same reason.
type Enforcer interface {
	// Probe reports what this host can enforce, per layer, without running a
	// target. It backs both `doctor` and strict-mode's pre-run refusal.
	//
	// It must report every core layer, LayerNetwork included, whatever the manifest
	// asks for. A layer left out is read as Unavailable, which is the only reading that
	// fails safe: Run cannot tell "this host has no netns" from "the probe was not
	// written to say so", and the second must not be the shape that runs unfenced.
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

	// ReadOnlyPaths are existing host files the run may read but not write, even under a
	// write grant. See Options.ReadOnlyPaths.
	ReadOnlyPaths []string

	// RecordExec asks the backend to record the tree of execs the run performs, returned
	// in Result.ExecRecord. It is off by default, and not out of caution about the
	// mechanism: recording takes the ability to ptrace away from everything inside the
	// sandbox, so strace, gdb, rr and a test harness attaching to its own child stop
	// working under it. That lands on exactly the toolchain runs the record is for, which
	// is why a run that did not ask for one is byte-for-byte the run it would otherwise
	// be. Asking on a run that cannot have one is not an error: Result.ExecRecord comes
	// back saying nothing was watching and why.
	RecordExec bool

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
	// It applies on the degraded tier too: that tier runs the same scan and makes the
	// same refusal, so one manifest means one thing on both. What differs is the outcome
	// it acknowledges - the tier applies no shields, so the credential the alias names is
	// readable under a granted tree either way, and that exposure is reported through
	// Result.Exposed rather than through this.
	AcceptAliasesUnder []string

	// RunID names this run so a supervisor outside it can reap the sandboxed tree. A
	// backend that confines through a transient systemd scope MUST name that scope
	// "bento-run-<RunID>.scope" in the user manager; empty means the backend names it
	// however it likes and the caller gets no handle.
	//
	// The caller supplies the id rather than reading one back deliberately. Under exec:
	// all the target has children, so a supervisor that recorded bento's own pid can
	// report a job dead while a test runner it spawned still holds the checkout - the
	// tree, not the pid, is the thing to kill. Every design that hands the handle BACK
	// has a window between the target starting and the supervisor learning the name,
	// which is precisely when a run that hangs immediately needs killing. An id chosen
	// before the run is exec'd has no such window: the derivation above is one-way and
	// documented, so the supervisor knows the unit name in advance and can
	// `systemctl --user kill` it (or read its cgroup path back with
	// `systemctl --user show -p ControlGroup`) at any point, including before the scope
	// exists.
	//
	// It is not a policy field and never enters the fingerprint: it identifies one
	// invocation, not what that invocation is permitted to do, and a manifest carrying it
	// would name every run started from that manifest the same thing.
	//
	// enforce.Run refuses a run whose id could not get a scope, so a backend reaching
	// here with a non-empty id has already been told a scope will be created. Whether
	// the id is well-formed is settled there too.
	RunID string

	// Probed is the host probe the core took to admit this run, handed on so the backend
	// reports from that reading rather than taking a second one moments later. A probe
	// builds namespaces and asks the systemd user manager, so taking it twice doubled the
	// cost of every launch, and on a manager too busy to answer it repeated the slowest
	// part. Nil means the caller took none and the backend probes for itself.
	//
	// It may cover only the layers this run requires (see Run), so a backend must not read
	// a layer from it that the policy did not ask for. And it must be this host's reading,
	// taken by this process for this run: the backend reports from it as measured, and
	// only lowers a layer the launcher attests it could not apply - a report carried over
	// from another host or boot can attest a filter no launch was asked to install.
	Probed *Report
}

// NetworkGate decides an egress host the manifest's allowlist does not permit.
// Returning true admits that connection for this run only; it is the seam a
// supervising caller uses to prompt a human. It is consulted synchronously in
// the connection's own goroutine, so it MAY block to prompt - but it must return
// promptly once ctx is done (the run is ending), or it stalls run teardown. host
// and port are attacker-controlled (a sandboxed target chose them); sanitize
// before displaying. A nil gate denies everything undeclared.
//
// It carries no run identity, deliberately: a gate belongs to exactly one Run, so a
// fleet running many jobs at once attributes a refusal by closing over the job when it
// builds the gate. Threading identity through the signature would let one gate serve
// several runs, which is the shape that cannot attribute anything.
//
// Consulting it is not the only way to learn what was refused, and a gate that returns
// false only to log the attempt is not needed for that: on a run that brings the egress
// stack up at all, Result.Denied reports every destination that was REFUSED, gate or no
// gate - which is not the same set the gate sees: a host outside the allowlist that the
// gate then admits was refused by nothing, and lands in GateAdmitted instead. The gate is
// what a caller reaches for to see a refusal WHILE the run is alive, which Result,
// arriving at exit, cannot give it.
//
// "At all" is the load-bearing part: a policy that declares no network rules and gets no
// gate runs with no proxy, so the target's connect is stopped by the egress block itself
// and Denied stays empty. An empty Denied is never evidence the target tried nothing.
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
	// is doing that deliberately, and this is how it says so - which is also why it
	// permits only AF_INET and AF_INET6. An embedder passing a TCP connection is not
	// thereby permitting an inherited netlink or packet socket, and it permits nothing
	// that is not a socket at all. It is deliberately not
	// a manifest field and not a CLI flag: a downloaded manifest or a copied command
	// line must never be able to re-open the channel, so only a Go caller that passed
	// the socket in the first place can permit it. The degraded (no-bwrap) tier
	// refuses regardless: every confinement there is the only one of its kind, so it
	// takes no bypass at all.
	AllowNetworkStdio bool

	// Env are the resolved environment values handed to the target. The policy
	// declares which NAMES may pass through; resolving those names against the
	// host, and merging any values supplied at invocation, is the core's job -
	// a backend applies this map and makes no decisions about it. Build it with
	// ResolveEnv, which is what resolves the policy's allowlist against the host.
	//
	// Run refuses a map with a name the policy does not declare (see admitEnv). Profile
	// shares this type and does not: it runs a discovery pass whose whole purpose is to
	// find out what the manifest should declare, so it is given an environment the
	// not-yet-written manifest cannot list.
	Env map[string]string

	// ExtraArgs are appended to the target's argv after the policy's Args, for a policy
	// that sets ExtraArgs. They are an invocation, not a permission - never fingerprinted,
	// and not screened like the policy's own fields, whose screen keeps a newline from
	// forging a fingerprint line. A multi-line shell script is the ordinary value here.
	ExtraArgs []string
}

// CredentialAlias is a second readable path to a shielded credential: Path reaches the
// content, Credential is the shielded file it reaches.
type CredentialAlias struct {
	Path       string
	Credential string
}

// UnresolvedGrant is one write grant the auto-exec report could not read whole, and why.
// See Result.UnresolvedHooks.
type UnresolvedGrant struct {
	Path   string
	Reason UnresolvedReason
}

// UnresolvedReason is why a grant went unread: one of the constants below, each a phrase a
// frontend can print as is.
type UnresolvedReason string

const (
	UnresolvedGitMissing UnresolvedReason = "git is not installed"
	// UnresolvedGitRefused is git exiting with an error: an unreadable .git, a
	// safe.directory refusal, a config it could not parse.
	UnresolvedGitRefused UnresolvedReason = "git refused to answer"
	// UnresolvedTimedOut is git or the grant's filesystem not answering within the bound,
	// which is what a dead mount looks like.
	UnresolvedTimedOut UnresolvedReason = "timed out"
	// UnresolvedUnreadable is any other failure to read the grant, such as a permission
	// error walking it.
	UnresolvedUnreadable UnresolvedReason = "could not be read"
)

// ShieldedGrant is one always-shielded path a policy explicitly granted, so the backend
// honored the grant over its own shield. See Result.ShieldedGrants.
type ShieldedGrant struct {
	// Path is the grant as the policy spelled it, which is the name the deny-list gave
	// the shield it matched.
	Path string
	// OnHost is the store the grant actually bound, set only where that differs from
	// Path. The deny-list builds the names that count as an opt-in from the run's home
	// anchors, and $HOME is caller-chosen, so a grant can name a symlink while the
	// exposure lands elsewhere; a frontend that reported only the spelling would name a
	// scratch path where a private key was handed over.
	//
	// The backend resolves this as it binds, not afterwards. Re-resolving at report time
	// would name whatever the path points at once the target has exited, which for a run
	// that moved a symlink underneath itself is not what was exposed.
	OnHost string
	// Holds is what the shield was hiding: "credentials", "private-data", "history",
	// "persistence", "services", or "unknown" for a path the backend cannot classify.
	// A string rather than an enum for the reason ShieldApplied.Kind is one - the seam
	// is what an out-of-tree embedder sees, and the classification lives in a package
	// they cannot import.
	//
	// It is here because "credential store" is the sentence a reviewer reads while
	// deciding whether an exposure was acceptable, and the shields also cover history
	// stores, session layout, and the host's service sockets.
	Holds string
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
	case SetupSilent:
	}
	// Silent, and the state the enum does not name yet: a stage that reached no stage at
	// all must never read as attested, so the unnamed one reads as the weakest.
	return "silent"
}

// Result is the outcome of a Run: the target's exit code and the report of what
// the sandbox actually enforced around it.
// ExecRun is one exec an enforced run performed: the image the kernel actually ran and
// the argv it ran with. Exe is resolved - a PATH search and a symlinked interpreter are
// already followed - because it is read back from the kernel rather than from what the
// target asked for. Pid is zero for the target itself, the one entry no observation
// reported: its exec retires before the recorder can be installed, so it is known by
// construction rather than seen.
type ExecRun struct {
	Pid  int
	Exe  string
	Argv []string
	// ArgvTruncated is whether Argv is a prefix of what actually ran. A very long command
	// line - a link or compile step - is cut so one entry cannot cost the rest of the
	// record, and the cut is reported rather than silent: an argv missing its tail that
	// did not say so would be a record that lies about what ran.
	ArgvTruncated bool
}

// ExecRecord is what a run that asked to record its execs got back.
//
// Only what RAN is here, never what was attempted: a denied exec produces no entry, so
// this does not answer "what did the sandbox stop", only "what did the sandbox run".
type ExecRecord struct {
	// Watched is whether anything was recording. When false, Reason says why - a mode
	// that structurally cannot have a recorder (the degraded tier's own ptrace block,
	// or an exec: none run, which replaces the launcher with the target and leaves no
	// supervisor), or a host that refused the attach (Yama ptrace_scope 2 and 3 both do).
	// Distinguishing this from an empty record is the point: "no execs happened" and
	// "nothing was watching" are different answers.
	Watched bool
	Reason  string
	// Complete is whether the record can be trusted as every exec the run made, not whether it reached
	// its end marker: a recorder that lost or never attached to its target still writes
	// the marker, and a watched record with no runs lost at least the target itself. The
	// recorder is deliberately not allowed to kill the run it observes, so a partial
	// record that read as whole would be worse than none. A mode that could never watch
	// is complete, because nothing was there to lose; Watched is what says so.
	Complete bool
	// Runs is every exec observed, in the order observed, led by the target itself.
	Runs []ExecRun
}

type Result struct {
	ExitCode int
	// Signaled reports that the run ended on a signal rather than an exit code, and
	// Signal is that signal number; ExitCode is 128+Signal there, the code a shell
	// reports. A frontend needs it because 128+N alone is indistinguishable from a
	// target that exited 137 on purpose.
	//
	// It says the run was killed, not who killed it, and the two tiers put different
	// deaths through it. Behind bwrap or a limits scope the wrapper is what this
	// observes: it renders a signaled target as 128+signal of its own, so an ordinary
	// crash arrives as a plain exit code and reads as Signaled false, and what does
	// reach this field is the sandbox being torn down around the target - the cgroup
	// kill under declared limits. On the degraded tier with exec blocking there is no
	// wrapper: the launcher execs into the target, so the target's own crash arrives
	// here signaled. A frontend that words this as an external kill is wrong on the
	// second tier, and one that words it as the script's own doing is wrong on the first
	// - what holds for both is that the run did not choose the code it ended with.
	Signaled bool
	Signal   int
	Report   Report
	// Setup separates a bento setup failure from a target that exited with the same
	// code. Bento's "could not run the target" code is 125, which a target may also
	// exit itself, so the code alone cannot tell them apart - an embedder mapping the
	// two onto different exit codes of its own reads this instead of the Report's prose
	// reasons, which are written for humans and will change wording.
	//
	// A backend must set it on every Result it returns without an error. Run refuses a
	// run that comes back SetupSilent - nothing about it is attested, so its exit code
	// is not an answer to hand back - and SetupSilent is the zero value, so a backend
	// that leaves the field alone has every run refused. That is the fail-closed
	// direction, and it is why the field is not optional.
	//
	// A *Shortfall therefore always means the target ran and a guarantee slipped, never
	// a stage that never got its layers up.
	//
	// It is meaningful only when Run returned nil or a *Shortfall - the cases where a
	// target was actually launched. Every other error means the run was refused or
	// failed before any stage existed (a nil enforcer, an invalid policy, a host that
	// admission turned away, a backend that could not start), and the zero value reads
	// as SetupSilent there without a stage having died: read the error first, this
	// second. A backend that failed before producing any report of its own gets an empty
	// Report back, not the probe's verdicts, so no layer reads as enforced for it.
	//
	// It lives on Result rather than in Report because Report is overlaid after the
	// backend returns; see SetupState for what the states do and do not attest.
	Setup SetupState
	// ExecRecord is the tree of execs the run performed, when RunOptions.RecordExec
	// asked for one; nil when it did not. It is a diagnostic and nothing else: its
	// presence, absence and failure all leave the Report and Setup exactly as they would
	// have been, so a frontend must never read a shortfall out of it.
	ExecRecord *ExecRecord
	// Degraded is whether the run took the backend's reduced-confinement tier, the one
	// RunOptions.Degraded selects. Run sets it from the same decision, so a backend never
	// has to. A frontend reads it rather than a Degraded filesystem layer, which a full-tier
	// run also reports when only a second kernel layer behind its mount namespace failed:
	// the errors a denial arrives as differ between the two, and the layer cannot say which.
	Degraded bool
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
	// GuardBlockedMetadata is the subset of GuardBlocked refused for being the cloud
	// instance metadata address - 169.254.169.254, or a 6to4/NAT64/IPv4-mapped form of
	// it. Every entry here is also in GuardBlocked, so a consumer asking only whether
	// the guard refused anything reads that one and is unaffected.
	//
	// It is carried apart because it is the only guard refusal that reads as a
	// credential probe. The other causes say a name resolved somewhere the sandbox may
	// not go - or that bento could not classify it at all - which on a corporate network
	// is routine; this one says the target went
	// looking for the instance's credentials, which is worth an operator's attention
	// even on a run that otherwise succeeded.
	//
	// The Host is ATTACKER-CONTROLLED for the same reason GuardBlocked's is, and must
	// be quoted the same way. Empty carries no assurance either: a run that made no
	// connections reports empty too.
	GuardBlockedMetadata []HostPort
	// Denied lists the destinations the allowlist refused outright - no rule named them,
	// and no gate was there to be asked - deduped and sorted. A destination a gate was
	// consulted about and refused is in GateDenied instead, so this list is exactly the
	// set a manifest rule would have admitted. It is the answer to what the target
	// tried to reach and what was refused, which nothing else in the result carries: the
	// sandbox meets the refusal as a 403 from the proxy inside its own error, with nothing
	// naming the rule it fell outside of.
	//
	// Distinct from GuardBlocked because the operator action differs: a denial is fixed by
	// naming the destination in the manifest, a guard block is not fixable that way at all.
	// Distinct from GateDenied on a different axis: a gate denial is also fixable by a
	// manifest rule, but it is a decision someone already made, so telling them to add
	// the rule describes the choice they declined rather than an oversight.
	//
	// The Host is ATTACKER-CONTROLLED (the sandboxed target chose the CONNECT target), so
	// a consumer rendering it to a terminal must quote it. Empty is not evidence the target
	// stayed inside the allowlist: a run that made no connections reports empty too.
	Denied []HostPort
	// GateDenied lists the destinations no manifest rule covered and a NetworkGate,
	// consulted about them, did not admit - deduped and sorted. It is the negative half of
	// GateAdmitted, and the whole of what a supervised run with an empty network: block
	// refuses: every destination goes to the gate, so nothing in such a run is ever
	// refused by the allowlist alone.
	//
	// A gate that PANICKED on a destination puts it here too: the operator still has to
	// see the host, and the gate was consulted either way. What separates the two is the
	// report, whose network layer is degraded with the count when a gate panicked - and
	// the remedy below is the wrong one for that case, so a consumer rendering this list
	// should say which it is reading.
	//
	// Distinct from Denied because the remedy differs and the operator is usually the
	// one who chose it. Reporting one as the other tells someone who just answered a
	// prompt that their manifest is missing a rule, in the workflow where adding that
	// rule is precisely the decision they declined to make.
	//
	// The Host is ATTACKER-CONTROLLED (the sandboxed target chose the CONNECT target), so
	// a consumer rendering it to a terminal must quote it. Empty is also what every
	// ungated run reports, so it is not evidence a gate admitted everything.
	GateDenied []HostPort
	// Untunneled lists the destinations a request addressed without asking the proxy to
	// tunnel to them - the shape a client sends for plain http:// - deduped and sorted.
	// bento's egress rides an HTTP CONNECT proxy, so such a request is refused with a
	// 400 whatever the manifest grants, and a network rule naming the host and port
	// reads as granted everywhere else while carrying no traffic at all.
	//
	// Distinct from Denied because no manifest edit fixes it: the remedy is the client's
	// scheme or its proxy mode. Empty is not evidence every request was tunneled - a run
	// that made no connections reports empty too.
	//
	// The Host is ATTACKER-CONTROLLED (the sandboxed target chose the request target), so
	// a consumer rendering it to a terminal must quote it.
	Untunneled []HostPort
	// AcceptedAliases lists the credential aliases this run was allowed to read past a
	// shield because the caller acknowledged the tree they sit in. Each names the path
	// that reaches the content and the credential it reaches. Non-empty means the run
	// proceeded over a known gap in the boundary, so it is reported rather than assumed
	// harmless - an audit that showed only the shields would claim a guarantee this run
	// did not have. Sorted and deduped; empty for the ordinary run.
	AcceptedAliases []CredentialAlias
	// ShieldedGrants lists the always-shielded paths (~/.ssh, ~/.gnupg, the runtime dir,
	// ...) the policy explicitly granted, so the backend honored the grant over its
	// built-in shield. These are a deliberate caveat-emptor opt-in: exposing a store the
	// sandbox would otherwise hide to the program. Sorted by Path, empty for the common
	// run that opts into none. A frontend surfaces each as a loud warning so the exposure
	// is never silent - the backend does not refuse it, the operator chose it.
	ShieldedGrants []ShieldedGrant
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
	// Exposed lists the shielded paths this run left reachable by the target anyway, so
	// the audit stays honest where the boundary did not hold. Sorted by path. It is
	// populated for two different reasons, told apart by the Kind on each record.
	//
	// Most of it is the degraded tier's, which has no mount namespace and therefore
	// applies no shields at all: a home read grant that reached a credential store makes
	// it readable to the target here, where the full tier would have hidden it. Those
	// records name the Kind the full tier WOULD have applied
	// ("hidden"/"read-only"/"discarded") - the protection this tier did not deliver, the
	// mirror image of Shields, not evidence anything was hidden.
	//
	// The full tier populates it too, and only with "folded" records. There the shield IS
	// applied - the same path appears in Shields - but it is one byte-exact bind, and the
	// mount hands its directory out under a second spelling that sits inside a write
	// grant's read-write bind. The bind is not walked back; it is walked around. A run
	// carrying these is not a degraded run, and a consumer that reads a non-empty Exposed
	// as "this host cannot shield" is wrong about it.
	//
	// Opt-ins are excluded (they are a deliberate exposure the full tier makes too,
	// reported via ShieldedGrants). Empty means no grant reached a shield the run failed
	// to hold - which on the full tier is the ordinary case.
	Exposed []ShieldApplied
	// ChangedAutoExec names the files under a write grant that auto-execute on the host
	// later and that this run created, modified or removed - a package.json's install
	// scripts, a conftest.py, a .github/workflows entry, a hook in whatever directory
	// this checkout's core.hooksPath resolves to. These are the surfaces the
	// shields deliberately do not deny, because an agent doing ordinary work must be able
	// to edit them, so the guarantee here is weaker than a shield's by design: nothing
	// the sandbox wrote executes without someone having had the chance to look at it, and
	// this is what tells a reviewer where to look. Sorted. A cancelled run carries it too,
	// because a target killed partway is the one most likely to have left something
	// behind; empty is not evidence the target changed none, since a run that failed
	// before the target started reports empty as well.
	//
	// Every entry is a file the run really changed; a hook directory the run REDIRECTED is
	// a different fact and travels in RedirectedHooks.
	//
	// Two blind spots, both deliberate, and both the reason a gap here is a missed hint
	// rather than a hole. The names are a fixed list checked at the root of each write
	// grant, so a nested package.json in a monorepo is not covered. And the comparison is
	// size and mtime, not content: a rewrite that keeps both - the same length with the
	// timestamp restored - is invisible to it.
	//
	// Path can carry bytes a prior run chose (a workflow filename), so a consumer
	// rendering it to a terminal must quote it.
	ChangedAutoExec []string
	// RedirectedHooks names the hook DIRECTORIES this run put in play, by pointing
	// core.hooksPath somewhere it did not point when the run started. That happens where
	// no shield holds .git/config down - a write grant with no enclosing checkout, or the
	// degraded tier, which shields nothing.
	//
	// It is separate from ChangedAutoExec because it is a different claim, in both
	// directions. The directory is named instead of its contents, since the run's baseline
	// never stamped it and every file inside would otherwise read as one this run created -
	// so as a "changed file" each entry is a false positive the reviewer finds nothing in.
	// And the fact itself is worth more than the ones beside it: the run chose where the
	// host's next commit executes from, whether or not anything was planted there yet, and
	// flattened into a list of edited files it reads as routine.
	//
	// Sorted, and carried on the same arms as ChangedAutoExec, the cancel path included.
	// The same quoting caveat applies: a directory name can carry bytes a prior run chose.
	RedirectedHooks []string
	// UnresolvedHooks names the write GRANTS the run could not read whole: git did not
	// answer where they run their hooks, or the grant itself stopped answering and the
	// after-run snapshot of its auto-executing files gave up on it. Either way the two
	// lists above are short for that grant. It is what keeps them readable: both are
	// empty on a clean run and equally empty on a host where the question was never
	// answered, and only this says which happened. An operator told to read the hook
	// report has to know when the report is short, and each entry's Reason says what to
	// fix: a missing git, a git that refused the checkout, or a mount that timed out.
	//
	// Sorted by path, one entry per grant, and carried on the same arms as the two lists
	// it qualifies. The same quoting caveat applies: a grant path can carry bytes a prior
	// run chose.
	UnresolvedHooks []UnresolvedGrant
	// Residue names the host paths this run left standing that it created itself: a
	// write-grant directory made for a run whose target never started, and a shield
	// mount point the post-run reclaim could not remove. It is the same account a
	// backend writes to Process.Stderr, for a caller that has no terminal - an embedder
	// may pass a nil Stderr, and without this the account is simply lost.
	//
	// Deliberately one list rather than one per category. A consumer's question is
	// "what is on my host that was not there before", which both answers; splitting it
	// would be three fields for one question. What a consumer must NOT read into it is
	// a negative: the two halves populate on different arms. The shield half is answered
	// on every arm, including the error ones; the write-grant half is only asked when the
	// target never started, since a run that started asked for that directory and keeping
	// it is the point. An empty Residue on a successful run therefore means no mount point
	// survived, not that no directory was created.
	//
	// It is not an error and never becomes one: a run that left a mount point standing
	// still confined what it ran, and a caller taught to read the error for hygiene would
	// learn to ignore the error. It is not a layer state either - see warnResidue.
	//
	// Paths can carry bytes a prior run chose (a shield under a git submodule directory),
	// so a consumer rendering one to a terminal must quote it.
	Residue []string
}

// ShieldApplied is one always-on shield the run engaged. Kind is "hidden" (the path was
// on the host and its contents are not reachable - a credential store the sandbox tmpfs'd
// or overmounted with an empty file), "read-only" (the path was on the host and stays
// readable but cannot be written - a code-execution surface like a git hooks dir), or
// "discarded" (the path was NOT on the host: bento materialized it for the run, and
// removes it at teardown).
//
// Materialized is not the same as invisible while the run is alive. A directory one is a
// tmpfs and the host index cannot see it, but a FILE one is a real zero-byte host file at
// that path for the length of the run - so a target that stages its whole tree can commit
// it, and the commit outlives the file. That is the reason this kind exists.
//
// "discarded" is about provenance, not about what a write does there, and the two do not
// line up: an absent directory becomes a writable scratch mount that takes writes and
// drops them, while an absent file becomes an empty read-only stand-in that refuses them.
// So a consumer asking whether a write can fail must not read these as two values and
// must not read "discarded" as "writable" either; only the distinction from the other two
// kinds is carried here, and the shield's own Path is what says which shape it is.
//
// The provenance is the half a consumer cannot recover later. A run killed before its
// teardown leaves a materialized path standing, and from then on every run sees it exist
// and reports it "hidden" or "read-only" - correctly, and indistinguishably from a file
// the user wrote. This field is the only window in which anything says bento made it.
// Path can carry bytes influenced by a
// prior run (a git submodule directory name), so a consumer that renders it to a
// terminal must quote it; the built-in surfaces do (JSON-encoded, or counts only).
type ShieldApplied struct {
	Path string
	// Kind is one of "hidden", "read-only", "discarded" or "folded". The first three
	// name what the sandbox did at the path and appear in Shields and Exposed alike.
	//
	// "folded" is the odd one and never appears in Shields: it names a shield the run
	// DID apply, byte-exact, whose directory hands the same content out under a second
	// spelling that a grant reaches anyway. It is a property of the host's mount rather
	// than of the bind, so the same path can be "read-only" in Shields and "folded" in
	// Exposed in one run - not a contradiction, but the two halves of one fact. Readers
	// counting or filtering Kind over Shields (a run's applied summary) will never see
	// it; readers over Exposed must word it as reachable-despite-the-shield rather than
	// as unshielded.
	Kind string
	// Source names the environment variable that put the shield at this path, empty
	// for a shield at its default location. A relocation variable accepts any absolute
	// path, so a run can fail on a path the shield blanked with nothing else naming the
	// variable that moved it there.
	Source string
}

// HostPort is one egress destination admitted at runtime by a NetworkGate rather
// than declared in the manifest. It duplicates profile.HostPort deliberately:
// enforce importing profile for a two-field value would point the dependency the
// wrong way.
type HostPort struct{ Host, Port string }
