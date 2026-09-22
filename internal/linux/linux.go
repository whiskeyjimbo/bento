//go:build linux

// Package linux enforces a policy with bubblewrap.
//
// It is an adapter behind the enforce.Enforcer seam: the core hands it a
// validated policy and it answers with what it actually enforced. Nothing here
// decides policy - that is the core's job - and no type from here appears in the
// core's signatures.
package linux

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/grantrefusal"
	"github.com/whiskeyjimbo/bento/internal/proxy"
	"github.com/whiskeyjimbo/bento/internal/shield"
	"github.com/whiskeyjimbo/bento/policy"
)

// Enforcer applies policies with bubblewrap.
type Enforcer struct {
	// selfPath overrides the path to the bento binary used as the in-sandbox
	// egress forwarder. Empty means "the running executable", which is correct in
	// production; tests set it because the test process is not bento.
	selfPath string
}

// New returns a bubblewrap-backed Enforcer.
func New() *Enforcer { return &Enforcer{} }

var _ enforce.Enforcer = (*Enforcer)(nil)

// Run compiles the policy into a bubblewrap invocation and executes the target
// inside it. A non-zero exit from the target is returned in the Result; err is
// reserved for a failure to build or start the sandbox, so a script that merely
// fails is never confused with a sandbox that did not hold.
func (e *Enforcer) Run(ctx context.Context, p *policy.Policy, proc enforce.Process, opts enforce.RunOptions) (res enforce.Result, err error) {
	// launched separates a setup failure from a run whose target actually started; the
	// deferred residue report below is only about the former.
	var launched bool
	// enforce.Run validates before it gets here, but this is an exported entry point an
	// embedder can call directly - as Profile already does for the same reason.
	if err := p.Validate(); err != nil {
		return enforce.Result{}, err
	}
	if err := p.RequireExpanded(); err != nil {
		return enforce.Result{}, err
	}
	if err := e.screenRunID(ctx, p, opts.RunID); err != nil {
		return enforce.Result{}, err
	}
	// A degraded run cannot use bubblewrap (user namespaces are blocked); take the
	// Landlock-only no-bwrap tier instead. The caller (enforce.Run) only sets this
	// after admitting the run under --allow-degraded, so this never silently downgrades.
	if opts.Degraded {
		// This tier has no network namespace and no proxy, so there is nothing to
		// consult a gate. enforce.Run cannot pair the two (a gate requires LayerNetwork,
		// which is Unavailable on the userns-blocked host this tier is for), but Run is
		// reachable without it, and silently running with the gate dropped would tell a
		// supervising caller its prompt was never needed when it was never possible.
		if opts.Gate != nil {
			return enforce.Result{}, fmt.Errorf("linux: a network gate cannot be honored by the degraded tier: it has no network namespace to run the egress proxy in")
		}
		// Network rules are the same class as the gate - enforce.requiredLayers brings
		// LayerNetwork up for either - and were the half this guard was missing. newSandbox
		// does set sb.proxySocket for a network manifest and runDegraded never listens on
		// it, so the run would get the launcher's blanket egress block while its report
		// claimed the declared destinations were allowed.
		if len(p.Network) > 0 {
			return enforce.Result{}, fmt.Errorf("linux: network rules cannot be honored by the degraded tier: it has no network namespace to run the egress proxy in, and blocks egress outright")
		}
		// Same shape as the gate above: this tier has no mount namespace and applies no
		// shields, so a caller deny would silently not be enforced. Reporting it through
		// Exposed instead would hand back a run that read the caller's control state and
		// an audit record saying so after the fact, which is the false confidence a
		// fail-closed posture exists to refuse.
		if len(opts.DenyPaths) > 0 {
			return enforce.Result{}, fmt.Errorf("linux: caller deny paths cannot be honored by the degraded tier: it has no mount namespace and applies no shields")
		}
		for _, ro := range opts.ReadOnlyPaths {
			for _, w := range p.Write {
				// ro arrives symlink-resolved, so the grant has to be compared the way the
				// sandbox would bind it.
				if r, err := filepath.EvalSymlinks(w); err == nil {
					w = r
				}
				if policy.CoversResolved(w, ro) {
					return enforce.Result{}, fmt.Errorf("linux: %s cannot be kept read-only by the degraded tier under the write grant %q: it has no mount namespace", ro, w)
				}
			}
		}
		// The record itself is stamped inside runDegraded, on every arm where the launcher
		// was dispatched: which arms those are is only knowable there.
		return e.runDegraded(ctx, p, proc, opts)
	}

	// Before any shield is computed: a stranded empty .git/ from a killed run otherwise
	// anchors this run's workspace shields on a repository that never existed.
	reclaimStrandedShields(proc.Stderr)

	report := e.Probe(ctx)

	bwrap, _, err := resolveBwrap()
	if err != nil {
		return enforce.Result{}, fmt.Errorf("linux: %w", err)
	}
	// A gate forces the egress stack up even with zero rules: a supervised run with
	// no manifest network means "prompt on every host", so the proxy must exist for
	// the gate to be consulted at all.
	sb, cleanup, err := newSandbox(p, e.selfPath, opts.Gate != nil, opts.DenyPaths, opts.ReadOnlyPaths)
	if err != nil {
		return enforce.Result{}, err
	}
	defer cleanup()

	// Registered before the call, not after it: prepareWriteDirs creates one grant's
	// directory at a time, so a refusal on a later grant returns with an earlier one
	// already on the host - and preflightGrants hands those back on its error path too.
	var preflight preflighted
	defer func() {
		if err != nil && !launched {
			recordResidue(proc.Stderr, &res.Residue, "write-grant directories it created for a run that did not start", preflight.createdWrites)
		}
	}()
	preflight, err = preflightGrants(sb, p, opts.AcceptAliasesUnder)
	if err != nil {
		return enforce.Result{}, err
	}
	optIns, accepted := preflight.optIns, preflight.aliases

	// Taken after preflightGrants, so the write grants are resolved and any directory it
	// created for one is already in the baseline and does not read as a change.
	// Bounded like the seams that resolved those writes: an empty baseline is safe here
	// only because compile below refuses a run whose host seams expired, so it is never
	// the baseline anything is compared against.
	autoExecBefore := boundedSeam(sb, "the auto-exec baseline of the write grants", autoExecBaseline{}, func() (autoExecBaseline, error) {
		return baselineAutoExec(preflight.writes), nil
	})

	// bwrap creates a shield mount point on the host when the shielded path does not
	// exist yet and a write grant makes its parent writable (e.g. a project's unborn
	// .git/hooks). Remove those after the run so the sandbox leaves no artifact; see
	// removeCreatedShields for why this is safe and best-effort.
	shieldDirs, shieldFiles := preflight.createdShields(sb)
	// The durable half of the same account: the defer below cannot run on a SIGKILL, so
	// the paths go on disk first and a later run reclaims them from there.
	shieldRecord, err := recordCreatedShields(sb.runDir, shieldDirs, shieldFiles)
	if err != nil {
		return enforce.Result{}, err
	}
	defer func() {
		recordResidue(proc.Stderr, &res.Residue, "shield mount points it could not reclaim", removeCreatedShields(shieldDirs, shieldFiles))
		if shieldRecord != nil {
			shieldRecord.Close()
		}
	}()
	if err := preflight.createShieldAncestors(sb); err != nil {
		return enforce.Result{}, err
	}

	// When the policy allows egress (or a gate supervises it), run the allowlist
	// proxy on the sandbox's unix socket for the lifetime of the run. The sandbox
	// reaches it only through that socket; nothing else can leave the network
	// namespace. stopProxy waits for every in-flight handler (Serve's wg.Wait), so
	// it is called explicitly before each success return - not just deferred - so
	// a gate admitted during target teardown is recorded before the result is read.
	// It is idempotent (sync.OnceFunc inside startProxy), so the defer stays as a
	// safety net for the error paths without double-closing.
	stopProxy := func() proxyOutcome { return proxyOutcome{} }
	// A run with no proxy socket reads its egress numbers off this zero collector,
	// which reports what such a run in fact saw: no connections, nothing admitted,
	// nothing blocked.
	collected := &egressCollector{}
	if sb.proxySocket != "" {
		stopProxy, collected, err = startProxy(ctx, p, sb.proxySocket, opts.Gate)
		if err != nil {
			return enforce.Result{}, err
		}
		defer func() { _ = stopProxy() }()
	}

	// The in-sandbox launcher reports what it actually applied through this file, and
	// the report below is reconciled against it: without that, every layer the child
	// installs would be claimed on the strength of a host-side probe alone. Set before
	// compile, which encodes the descriptor into the launch invocation.
	sb.applied = true
	sb.recordExec = opts.RecordExec
	appliedReport, dropApplied, err := newAppliedReport(sb.runDir)
	if err != nil {
		return enforce.Result{}, err
	}
	defer dropApplied()

	args, shields, err := compile(p, proc, sb)
	if err != nil {
		return enforce.Result{}, err
	}
	// Read here, immediately after compile, so the disclosure describes the host the run
	// was compiled against rather than whatever it is by teardown. It rides out on every
	// arm below beside Shields, for the reason those carry it - what the boundary engaged,
	// and what got around it, is no less true for the run having failed.
	//
	// It is NOT the same set of syscalls compile made, which is why it is a read of its
	// own: the fold question over a workspace shield is a stat pair (hooks against HOOKS)
	// that compile never issues - Contains asks foldsCase of the assembled shields alone,
	// and its workspace loop uses covers by itself. So a mount that dies between compile
	// and here answers ok=false from boundedStatID, which is not a deadMount note, and the
	// run proceeds with nothing disclosed. That is a silence on a host already coming
	// apart, not a wrong claim, and it is the direction to fail in here - but it is a
	// silence, so it is written down rather than assumed away.
	//
	// No test drives this assignment. A fold is a property of the host's mount, and
	// internal/shieldcorpus's Case.Folding documents why no layout staged on disk produces
	// one - two spellings under a temp directory on ext4 are two genuinely different files
	// - so every site that judges a fold injects it through its own filesystem seam, and a
	// full-tier Run has no such seam to inject through. The disclosure is pinned one level
	// down instead, where a fold IS expressible: at shield.Set.FoldedWorkspaceShields and
	// at foldedWorkspaceExposure, both driven off shieldcorpus.FoldedPath. What is
	// unreachable is this wiring alone, so deleting these four Exposed fields would go
	// green - the gap is named here rather than covered, and building CI mount
	// infrastructure to close it was weighed and declined.
	exposed := foldedWorkspaceExposure(sb, preflight.writes)
	// The same call compile makes, so reconcile judges the report against the filter
	// the launcher was actually asked for. Recomputing it from the policy alone would
	// read a seccomp-less host's honest "none" as a shortfall.
	blockWanted, strictWanted := execBlockFlags(p.Exec, seccompSupported())

	// When the policy sets limits and this host can enforce them, run bwrap inside
	// a transient systemd scope carrying the limits. When it cannot, the run has
	// already been admitted (refused by default, or permitted under
	// --allow-degraded) - here it simply proceeds unwrapped, and the report says so
	// without a second check. canCreateScope caches every definitive verdict, so where
	// the probe above answered, this reads that same answer. Where it could not answer
	// it recorded the limits layers Unavailable and this re-probes, which can only go
	// the harmless way: limits applied under a report that did not claim them. There is
	// no window in which the report claims a limit nothing applied.
	//
	// The gate is scope creation alone, which is all the wrapping needs. A layer can
	// also be Unavailable because its controllers are undelegated, on a host where a
	// scope creates fine; wrapping there is the same harmless direction, since systemd
	// ignores the property and the report already claims nothing.
	exe, cargs := bwrap, args
	if !p.Limits.IsZero() {
		if ok, _ := canCreateScope(ctx); ok {
			// Preflight the exact limits so a scope-creation failure surfaces as a
			// clear error, never as the target's exit code for a target that never
			// ran.
			runner, err := preflightLimits(ctx, p.Limits, nil)
			if err != nil {
				return enforce.Result{}, fmt.Errorf("linux: %w", err)
			}
			exe, cargs = wrapWithLimits(runner, bwrap, args, p.Limits, opts.RunID)
			// An undelegated cpu controller is reported by the probe as LayerLimitsCPU
			// Unavailable and refused at admission; a run that reaches here with a cpu
			// limit was either delegated or explicitly permitted under --allow-degraded.
			// The probe's state is where the final report starts, not where it ends:
			// noteScopeLimits reads the scope this run was actually given and worsens any
			// layer the kernel shows uncapped.
		}
	}

	if err := checkLauncher(sb.bentoPath); err != nil {
		return enforce.Result{}, err
	}
	cmd := exec.CommandContext(ctx, exe, cargs...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = proc.Stdin, proc.Stdout, proc.Stderr
	// bwrap passes this through to the launcher as FD appliedReportFD; it survives the
	// systemd-run scope wrapper above too. The launcher marks it close-on-exec, so the
	// target never inherits the channel.
	cmd.ExtraFiles = []*os.File{appliedReport}

	// A run with egress also carries the bridge's liveness pipe as fd bridgeLivenessFD.
	// The in-sandbox bridge is the sole writer once the host drops its own end below;
	// see noteDeadBridge for why a written byte, not the pipe closing, is the signal.
	var bridgeLiveness, bridgeLivenessW *os.File
	if sb.proxySocket != "" {
		r, w, err := os.Pipe()
		if err != nil {
			return enforce.Result{}, fmt.Errorf("linux: bridge liveness pipe: %w", err)
		}
		defer r.Close()
		bridgeLiveness, bridgeLivenessW = r, w
		cmd.ExtraFiles = append(cmd.ExtraFiles, w)
	}

	// Only when the run was actually wrapped in a scope: unwrapped, there is no scope to
	// read and the report already claims nothing about the limits.
	var scoped scopeLimits
	runErr := runCmd(cmd, func(pid int) {
		// Only reached once Start succeeded, which is what separates a setup failure from
		// a run: a cancel that arrives first, or a wrapper that will not exec, leaves the
		// write-grant directory behind with no target ever having used it.
		launched = true
		if exe != bwrap {
			scoped = attestScopeLimits(pid)
		}
	})
	// Dropping the host's write end before reading: while the host holds one the read
	// below would block past the sandbox's exit waiting for an EOF only it can send.
	if bridgeLivenessW != nil {
		bridgeLivenessW.Close()
	}
	bridgeDied := bridgeReportedDeath(bridgeLiveness)

	// A cancelled ctx SIGKILLs the wrapper, and the signalled status that produces is
	// byte-identical to the policy's own memory cap bringing the scope down around the
	// run under a full Enforced report - the opposite meaning. Only consulted where the
	// command failed, and only for that signalled status: bwrap reports a signalled
	// target as 128+signal of its own, so an ordinary exit code here is one the target
	// ran to completion for, and a late cancel does not unmake that.
	// Stamped once for every arm below: the target has finished on all of them, so the
	// answer is the same whichever one returns.
	changedAuto, redirected, unresolvedHooks := autoExecBefore.changed(preflight.writes)

	if runErr != nil && ctx.Err() != nil && killedByCancel(cmd.ProcessState) {
		// Everything the run computed before the cancel is still true of it, and is
		// assembled the same way the two completing arms assemble it: a supervised run
		// timed out after a human admitted a host reached the proxy, and a Result that
		// dropped GateAdmitted would report the empty value whose documented meaning is
		// that nothing was admitted beyond the manifest. The auto-exec report rides out
		// here for a reason of its own: a target killed partway is the run most likely to
		// have rewritten a package.json and least likely to be looked at.
		//
		// stopProxy before the collector is read, not the deferred one, for the reason the
		// success arm gives: Serve's wg.Wait is what drains a decision landing during
		// teardown, and returning first would read a partially-drained collector - a
		// wrong-and-quiet result rather than an empty-and-quiet one. It reports nil on a
		// cancelled run (Serve returns nil when the run had already ended when accepting
		// stopped), so noteDeadListener does not manufacture a dead listener out of the
		// cancel itself.
		px := stopProxy()
		a := parseApplied(appliedReport)
		// The wrapper's real status, not a literal 0: reconcile stamps it into the reason
		// for a stage that reported nothing, and a SIGKILLed child did not end with exit
		// code 0. A cancel landing before the wrapper started leaves no status at all -
		// killedByCancel reads a nil ProcessState as the cancel, which is how a context
		// already cancelled when Run was called arrives here - and -1 is what os reports
		// for a process with no exit code of its own.
		cancelCode := -1
		if cmd.ProcessState != nil {
			cancelCode, _, _ = exitStatusOf(cmd.ProcessState)
		}
		setup := a.reconcile(&report, blockWanted, strictWanted, true, cancelCode)
		noteScopeLimits(&report, p.Limits, scoped)
		noteDeadListener(&report, px.serveErr)
		noteDeadBridge(&report, bridgeDied)
		noteProxyFault(&report, collected.faultCount())
		noteLostRecords(&report, px.observerFaults, px.handlerFaults)
		noteNAT64Blackout(&report, px.nat64Blackouts)
		noteAcceptRetries(&report, px.acceptRetries, px.acceptBackoff)
		noteGateFault(&report, collected.gateFaultCount())
		noteRefusedAtCapacity(&report, collected.atCapacityCount())
		// No ExitCode or Signaled: the kill was the cancel's, and a SIGKILLed target has
		// no outcome of its own to report. That separation is what tells an operator who
		// aborted a run apart from a policy that killed it.
		return enforce.Result{Report: report, Setup: setup, ExecRecord: a.execRecord(opts.RecordExec), EgressConnections: collected.counted(), GateAdmitted: collected.gateAdmitted(), GuardBlocked: collected.guardBlocked(), GuardBlockedMetadata: collected.guardBlockedMetadata(), Denied: collected.allowlistDenied(), GateDenied: collected.gateRefused(), Untunneled: collected.untunneledDestinations(), ShieldedGrants: reportedOptIns(optIns), Shields: shields, Exposed: exposed, AcceptedAliases: reportedAliases(accepted), ChangedAutoExec: changedAuto, RedirectedHooks: redirected, UnresolvedHooks: unresolvedHooks}, fmt.Errorf("linux: the run was cancelled before the target finished: %w", ctx.Err())
	}

	switch err := runErr; {
	case err == nil:
		px := stopProxy()
		a := parseApplied(appliedReport)
		setup := a.reconcile(&report, blockWanted, strictWanted, true, 0)
		noteScopeLimits(&report, p.Limits, scoped)
		noteDeadListener(&report, px.serveErr)
		noteDeadBridge(&report, bridgeDied)
		noteProxyFault(&report, collected.faultCount())
		noteLostRecords(&report, px.observerFaults, px.handlerFaults)
		noteNAT64Blackout(&report, px.nat64Blackouts)
		noteAcceptRetries(&report, px.acceptRetries, px.acceptBackoff)
		noteGateFault(&report, collected.gateFaultCount())
		noteRefusedAtCapacity(&report, collected.atCapacityCount())
		return enforce.Result{ExitCode: 0, Report: report, Setup: setup, ExecRecord: a.execRecord(opts.RecordExec), EgressConnections: collected.counted(), GateAdmitted: collected.gateAdmitted(), GuardBlocked: collected.guardBlocked(), GuardBlockedMetadata: collected.guardBlockedMetadata(), Denied: collected.allowlistDenied(), GateDenied: collected.gateRefused(), Untunneled: collected.untunneledDestinations(), ShieldedGrants: reportedOptIns(optIns), Shields: shields, Exposed: exposed, AcceptedAliases: reportedAliases(accepted), ChangedAutoExec: changedAuto, RedirectedHooks: redirected, UnresolvedHooks: unresolvedHooks}, nil
	case isExitError(err):
		var ee *exec.ExitError
		errors.As(err, &ee)
		px := stopProxy()
		// A signal here killed the wrapper, not the target: bwrap reports a signaled
		// target as 128+signal itself. What reaches this branch signaled is the scope
		// coming down around the run, which is how a cgroup limit ends it.
		code, signaled, sig := exitStatusOf(ee.ProcessState)
		a := parseApplied(appliedReport)
		setup := a.reconcile(&report, blockWanted, strictWanted, true, code)
		noteScopeLimits(&report, p.Limits, scoped)
		noteDeadListener(&report, px.serveErr)
		noteDeadBridge(&report, bridgeDied)
		noteProxyFault(&report, collected.faultCount())
		noteLostRecords(&report, px.observerFaults, px.handlerFaults)
		noteNAT64Blackout(&report, px.nat64Blackouts)
		noteAcceptRetries(&report, px.acceptRetries, px.acceptBackoff)
		noteGateFault(&report, collected.gateFaultCount())
		noteRefusedAtCapacity(&report, collected.atCapacityCount())
		return enforce.Result{ExitCode: code, Signaled: signaled, Signal: sig, Report: report, Setup: setup, ExecRecord: a.execRecord(opts.RecordExec), EgressConnections: collected.counted(), GateAdmitted: collected.gateAdmitted(), GuardBlocked: collected.guardBlocked(), GuardBlockedMetadata: collected.guardBlockedMetadata(), Denied: collected.allowlistDenied(), GateDenied: collected.gateRefused(), Untunneled: collected.untunneledDestinations(), ShieldedGrants: reportedOptIns(optIns), Shields: shields, Exposed: exposed, AcceptedAliases: reportedAliases(accepted), ChangedAutoExec: changedAuto, RedirectedHooks: redirected, UnresolvedHooks: unresolvedHooks}, nil
	default:
		// The auto-exec list for the same reason the cancel arm carries it: the target may
		// already have run, and this is the arm where nothing else says what the host holds.
		// The shield and egress audit rides out beside it on the same reasoning - what the
		// boundary engaged and what went through it is no less true for the run having
		// failed on its way out.
		px := stopProxy()
		// The applied report is on disk for the same reason - the launcher wrote it before
		// the wait failed - and it is reconciled here like every other arm. The failure says
		// nothing about which layers the run reached, and that is the argument FOR the
		// reconcile rather than against it: reconcile only ever lowers a layer, so what it
		// rewrites is the probe's claim that the host CAN enforce something into the fact
		// that no stage reported doing so. Returning the probe raw attests the tier's fences
		// to a run whose in-sandbox stage may never have installed one.
		//
		// -1 where the wrapper left no status, as the degraded tier's arms do: the exit code
		// only appears in reconcile's sentence about a stage that stayed silent, and there
		// is no status to name.
		code := -1
		if cmd.ProcessState != nil {
			code, _, _ = exitStatusOf(cmd.ProcessState)
		}
		a := parseApplied(appliedReport)
		setup := a.reconcile(&report, blockWanted, strictWanted, true, code)
		noteScopeLimits(&report, p.Limits, scoped)
		noteDeadListener(&report, px.serveErr)
		noteDeadBridge(&report, bridgeDied)
		noteProxyFault(&report, collected.faultCount())
		noteLostRecords(&report, px.observerFaults, px.handlerFaults)
		noteNAT64Blackout(&report, px.nat64Blackouts)
		noteAcceptRetries(&report, px.acceptRetries, px.acceptBackoff)
		noteGateFault(&report, collected.gateFaultCount())
		noteRefusedAtCapacity(&report, collected.atCapacityCount())
		return enforce.Result{Report: report, Setup: setup, ExecRecord: a.execRecord(opts.RecordExec), EgressConnections: collected.counted(), GateAdmitted: collected.gateAdmitted(), GuardBlocked: collected.guardBlocked(), GuardBlockedMetadata: collected.guardBlockedMetadata(), Denied: collected.allowlistDenied(), GateDenied: collected.gateRefused(), Untunneled: collected.untunneledDestinations(), ShieldedGrants: reportedOptIns(optIns), Shields: shields, Exposed: exposed, AcceptedAliases: reportedAliases(accepted), ChangedAutoExec: changedAuto, RedirectedHooks: redirected, UnresolvedHooks: unresolvedHooks}, fmt.Errorf("linux: running sandbox: %w", err)
	}
}

// noteDeadListener records a proxy listener that stopped accepting on its own. The
// run fails closed - the socket is gone, so the sandbox cannot reach the network at
// all past that point - but the egress the manifest declared was only served for
// part of the run, and a report that claimed LayerNetwork Enforced would hide that.
// It runs after reconcile so the in-sandbox report cannot overwrite it.
func noteDeadListener(r *enforce.Report, err error) {
	if err == nil {
		return
	}
	worsenNetwork(r, enforce.Degraded,
		fmt.Sprintf("the egress proxy stopped accepting mid-run (%v); declared egress was refused for the remainder", err))
}

// noteProxyFault records connections a panicking proxy handler dropped. The run does
// not fail on one - the connection is dropped, which is the safe direction - but the
// layer cannot be reported as having enforced the manifest on a connection whose
// handler did not run to an outcome. The destination is not said, because it never
// surfaced: a fault is reported only for a connection that reached no decision at all,
// so one counted here is one whose CONNECT was never read or never allowed.
func noteProxyFault(r *enforce.Report, faults int) {
	if faults == 0 {
		return
	}
	worsenNetwork(r, enforce.Degraded,
		fmt.Sprintf("the egress proxy dropped %d connection(s) on an internal fault, so their handlers did not run to an outcome", faults))
}

// noteGateFault records the connections a supervising gate panicked on. The refusal
// itself is the safe direction - a gate that cannot answer has not admitted anything, and
// the connection got the same 403 a declined one gets - but the run's record then says a
// supervisor refused these destinations when none decided them, and an operator reading
// it would go on adding hosts to the manifest instead of fixing the gate. Under the
// prompt-on-every-host mode (an empty network: block plus a gate) a gate that panics on
// every call refuses the whole run's egress while the layer reports Enforced, which is
// the state this exists to name.
//
// Degraded rather than a bare disclosure, for the reason noteLostRecords is: a report
// that misdescribes what happened is worth the run's exit code.
func noteGateFault(r *enforce.Report, faults int) {
	if faults == 0 {
		return
	}
	worsenNetwork(r, enforce.Degraded,
		fmt.Sprintf("the supervising network gate panicked on %d connection(s), so they were refused without any supervisor deciding them", faults))
}

// noteLostRecords records the proxy's own faults, which reach the report as two counts
// because they call for two different remedies. Neither weakened the fence - the
// allowlist was applied either way - and both are the claim noteProxyFault makes about a
// connection with no decision at all, seen from the other side: there the outcome is
// missing, here the record of it is.
//
// A swallowed decision leaves the report's egress record short by that many events, so an
// Enforced layer would present an incomplete record as a complete one, and the operator's
// move is to fix the observer the embedder installed. A post-decision handler panic
// leaves the record intact and the connection broken, and the operator can do nothing
// about it but report the bug - which is why the two are said separately rather than
// summed: in one bucket the rare cause is the one worth acting on and the common one
// drowns it.
func noteLostRecords(r *enforce.Report, observerFaults, handlerFaults int) {
	if observerFaults > 0 {
		worsenNetwork(r, enforce.Degraded,
			fmt.Sprintf("the run's egress observer panicked on %d decision(s), so this report's egress is short by that many events", observerFaults))
	}
	if handlerFaults > 0 {
		worsenNetwork(r, enforce.Degraded,
			fmt.Sprintf("the egress proxy panicked on %d connection(s) after deciding them, so the report names those destinations but the connections did not run to completion", handlerFaults))
	}
}

// noteNAT64Blackout records destinations the egress guard refused because NAT64 discovery
// could not rule out a site prefix, so an IPv6 address no transition prefix decodes had to
// fail closed. Failing closed is correct - a synthesized RFC1918 target reached through a
// permitted hostname is the SSRF this decode exists to catch - but the run was then denied
// egress its manifest declared, by a DNS lookup that failed at proxy start rather than by
// policy, and the client side is deliberately told nothing (the refusal is worded exactly
// like a dial failure so a target cannot classify names against the host's DNS). This is
// the only side that can say it.
//
// Keyed on the refusals rather than on discovery having been inconclusive: that condition
// holds on any host whose resolver cannot answer at all, and a run that never dialed an
// IPv6-only destination lost nothing to it. Degraded for the reason noteRefusedAtCapacity
// is - a declared destination denied by something that is not the allowlist.
func noteNAT64Blackout(r *enforce.Report, refusals int) {
	if refusals == 0 {
		return
	}
	worsenNetwork(r, enforce.Degraded,
		fmt.Sprintf("NAT64 discovery could not reach a resolver, so %d IPv6 destination(s) that no transition prefix decodes were refused for the run rather than risk a synthesized private address", refusals))
}

// noteAcceptRetries records the transient Accept failures the proxy rode out. Retrying is
// right - the alternative leaves the socket bind-mounted into the sandbox with nothing
// serving it for the rest of the run - but every CONNECT made during the backoff met a
// socket nothing was accepting on, and a report that claimed LayerNetwork Enforced would
// present that window as fully served. noteDeadListener covers only the terminal case; a
// recovered one left no trace at all before this.
//
// Degraded, on the same reasoning noteRefusedAtCapacity gives: the run's own egress record
// cannot account for the window, since the proxy was not refusing by policy during it. The
// duration is what tells an operator whether they are looking at milliseconds of fd
// pressure or seconds of it.
func noteAcceptRetries(r *enforce.Report, retries int, backoff time.Duration) {
	if retries == 0 {
		return
	}
	worsenNetwork(r, enforce.Degraded,
		fmt.Sprintf("the egress proxy recovered %d transient listener failure(s), spending %s with nothing accepting on the sandbox's socket", retries, backoff.Round(time.Millisecond)))
}

// noteRefusedAtCapacity records connections the proxy turned away with a 503 because
// every handler slot was taken. The refusal itself is the safe direction, but the layer
// cannot be reported as having enforced the manifest over a window where a declared
// destination was denied by load rather than by policy, and nothing else in the report
// tells the two apart.
//
// Degraded on a core layer is a posture shortfall under every posture but
// --allow-degraded, so this costs the run its exit code rather than only a line in the
// report. That is the intended weight: a run whose declared egress was blacked out and
// which then reports the script's own clean exit is what the shortfall code exists to
// prevent. It is reachable without anything malicious, by legitimate CONNECTs that hold
// their slots, so the count in the disclosure is what tells an operator which of the two
// they are looking at.
func noteRefusedAtCapacity(r *enforce.Report, refusals int) {
	if refusals == 0 {
		return
	}
	worsenNetwork(r, enforce.Degraded,
		fmt.Sprintf("the egress proxy was at its connection limit for %d connection(s), which were refused without the allowlist being consulted", refusals))
}

// bridgeReportedDeath reads the bridge's liveness pipe, which the host has already
// stopped writing to. One byte means the bridge wrote that it stopped serving; EOF
// with nothing read is an ordinary run, since the pid namespace collapses at every
// exit and would otherwise make EOF look like a failure on every run. A read error is
// treated as no report: the pipe is the host's own, and the alternative is claiming a
// degraded network layer on the strength of a broken channel.
//
// Deadlined, because the sandbox is not always dead when the command this run waited
// on is. `systemd-run --user --scope` execs in place (measured), so even under the
// limits wrapper the process reaped is bwrap itself - but a cancel that kills it does
// not synchronously reap everything holding the write end, and an undeadlined read
// would then block on a straggler rather than on the bridge, turning a cancelled run
// into a hang. On every ordinary path the pid namespace has already collapsed and
// EOF is immediate, so the bound is never approached.
func bridgeReportedDeath(r *os.File) bool {
	if r == nil {
		return false
	}
	if err := r.SetReadDeadline(time.Now().Add(bridgeLivenessReadTimeout)); err != nil {
		return false
	}
	var b [1]byte
	n, _ := r.Read(b[:])
	return n > 0
}

// bridgeLivenessReadTimeout bounds the wait for the bridge's liveness pipe to close.
// It is a backstop against a sandbox that outlived the process this run waited on, not
// a pacing knob: the pipe is already closed by the time it is read on every path where
// the sandbox actually exited.
var bridgeLivenessReadTimeout = 2 * time.Second

// noteDeadBridge records an in-sandbox egress bridge that stopped serving mid-run.
// Nothing else can report this: on the exec-block path the launcher has been replaced
// by the target, so the bridge outlives every process that could write the applied
// report, and the host-side proxy listener stays healthy (noteDeadListener covers that
// one, not this one). Declared egress simply stopped, and a report claiming
// LayerNetwork Enforced would hide it. It runs after reconcile so the in-sandbox
// report cannot overwrite it.
//
// A bridge killed outright leaves no byte and is not covered; only a bridge that
// noticed its own listener had stopped serving reports itself. The reachable case is
// a memory-limited run: wrapWithLimits puts MemoryMax on the whole scope, so the
// bridge shares the target's cap and an OOM kill can pick it. Nothing the bridge can
// do about a SIGKILL, and reading death from the pipe closing instead would misreport
// every ordinary run, so this stays a known hole rather than a trade. It may also have
// recovered afterwards, which is why this says egress stopped rather than that it
// stayed down. Where a dead host-side listener degraded the layer too, both reasons are
// carried: worsenNetwork joins them in call order, so the operator gets each half of a
// two-part failure rather than whichever one fired first.
func noteDeadBridge(r *enforce.Report, died bool) {
	if !died {
		return
	}
	worsenNetwork(r, enforce.Degraded,
		"the in-sandbox egress bridge stopped serving mid-run; declared egress was unreachable for part of the run")
}

// worsenNetwork records a mid-run egress failure without letting it UPGRADE the layer.
// Report.Set replaces unconditionally, and the three notes run after reconcile, so a
// network layer already judged Unavailable would be softened to Degraded by an error path
// - a report reading better because something else went wrong. Every other Set in the
// backend writes either Unavailable or a state no better than what the probe reported, so
// these are the only ones that could land on an already-worse layer.
//
// A note landing on a layer already at ITS OWN state joins its reason to what is there
// instead of being dropped. The three are independent - an OOM kill under the scope's
// shared MemoryMax can take the bridge while the host listener dies on its own - and all
// three write Degraded, so discarding the later ones handed the operator one half of a
// two-part failure. The fault count in particular has no other channel: noteProxyFault is
// its only consumer, so a listener that degraded the layer first erased the number of
// connections whose handlers never ran to an outcome from the run record entirely.
func worsenNetwork(r *enforce.Report, state enforce.State, reason string) {
	current, prior, probed := networkState(r)
	// An ABSENT layer is not a worse one. StateOf folds "the probe said nothing" into
	// Unavailable, which is the right fail-safe for a layer the run requires and the
	// wrong answer here: read that way, a note onto a report with no network layer is
	// discarded as an upgrade of a layer nobody ever asserted, and the run's only account
	// of the fault disappears. Nothing reaches here that way today - every note-firing
	// path seeds from a probe, and the probe adds the layer unconditionally - so this is
	// the coupling held straight rather than a live fix. enforce.Report.probedState draws
	// the same distinction for callers inside that package.
	if probed && state < current {
		return
	}
	if probed && state == current && prior != "" {
		reason = joinReason(prior, reason)
	}
	r.Set(enforce.LayerNetwork, state, reason)
}

// networkState returns what the report currently says about the network layer - its
// state, its reason so a second note can extend rather than replace it, and whether the
// report says anything about it at all. Duplicate entries are read the way StateOf and
// probedState read them, the most severe winning, since that is the one admission
// governs on.
func networkState(r *enforce.Report) (enforce.State, string, bool) {
	worst, reason, found := enforce.Enforced, "", false
	for _, l := range r.Layers {
		if l.Layer == enforce.LayerNetwork && (!found || l.State > worst) {
			worst, reason, found = l.State, l.Reason, true
		}
	}
	return worst, reason, found
}

func isExitError(err error) bool {
	var ee *exec.ExitError
	return errors.As(err, &ee)
}

// preflighted is what the pre-launch checks produced for a run that passed them: the
// resolved grants the sandbox will bind, the always-shielded stores the policy opted
// back in, and the aliases the caller acknowledged.
type preflighted struct {
	reads, writes []string
	// optIns are the shields the policy opted back into the sandbox: the literal
	// deny-list names for the frontend's warning, and the resolved ones the shield
	// bookkeeping compares against.
	optIns  []shield.OptIn
	aliases []credentialAlias
	// createdWrites are the write grants prepareWriteDirs created on the host for this
	// run, so a setup failure before the target starts can name what it left there.
	createdWrites []string
}

// createdShields names the shield mount points bwrap will create on the host for this
// run, so the caller can remove them afterwards.
func (pf preflighted) createdShields(sb sandbox) (dirs, files []string) {
	return createdShields(sb, exposedPaths(sb, pf.reads, pf.writes), pf.writes, shield.Targets(pf.optIns))
}

// createShieldAncestors makes the directories pinShieldAncestors binds that do not exist
// yet. Each is an absent directory inside a write grant above an absent shield target,
// which createdShields already lists, so the removal after the run covers it - call this
// only once that list is recorded.
func (pf preflighted) createShieldAncestors(sb sandbox) error {
	_, applied := denyArgs(sb, exposedPaths(sb, pf.reads, pf.writes), pf.writes, shield.Targets(pf.optIns))
	for _, d := range shieldAncestors(sb, applied, pf.writes) {
		if sb.exists(d) {
			continue
		}
		if err := os.Mkdir(d, 0o700); err != nil {
			return fmt.Errorf("linux: creating %s so it can be pinned above its shield: %w", d, err)
		}
	}
	return nil
}

// preflightGrants decides everything that can refuse a run and then prepares the host
// for it, in that order: the full grant-safety set and the alias scan run before
// prepareWriteDirs, so a to-be-refused grant never leaves behind a directory that was
// created for it. compile re-runs checkGrants as its own guard.
//
// The ordering covers the refusals named here and nothing beyond them. Several steps
// after this function returns can still fail before the target runs, and the directory
// is already on the host by then; Run names it on stderr rather than reclaiming it,
// since the manifest asked for it and an enforced run creates it again.
//
// Both bwrap tiers - the enforced run and the profiling run - go through here. Profiling
// needs it for exactly the same reason Run does: the profiled target is untrusted by
// construction, so a hardlink to a credential inside an accepted read grant would be
// readable there too, and a write grant naming a not-yet-existing directory would be a
// silent no-op that the convergence loop then never converges on.
//
// The degraded tier does not go through here - it has no bwrap binds to derive its
// exposure from - but it runs the same alias scan over its own Landlock read/write set
// through checkAliasedCredentials, so one manifest means one thing on both tiers.
func preflightGrants(sb sandbox, p *policy.Policy, acceptAliasesUnder []string) (preflighted, error) {
	reads, writes, err := resolveGrants(sb, p)
	if err != nil {
		return preflighted{}, err
	}
	if err := checkGrants(sb, p, reads, writes); err != nil {
		return preflighted{}, err
	}

	// Surface any always-shielded store the policy explicitly opted back into the sandbox
	// for the frontend to warn about, named by its literal deny-list path and by
	// what it holds. The shields still protect every path not opted into.
	optIns := explicitShieldOptIns(sb, p.Read)

	// A shield hides a credential's path, not the content behind it. Refuse before the
	// target starts if anything this run can read holds a second name for a shielded
	// credential's inode: the user granted that tree, not the credential, so proceeding
	// would hand over a store they never opted into. The scan covers everything bwrap
	// binds, not only the policy's own grants, because an out-of-FHS interpreter's prefix
	// is bound too and may sit under the home. An explicit opt-in is honored - those
	// credentials are dropped from the scan - and a caller who acknowledges a tree keeps
	// the aliases in it, so this refuses only what nobody asked for.
	accepted, err := checkAliasedCredentials(sb, exposedPaths(sb, reads, writes), optInPaths(optIns), acceptAliasesUnder)
	if err != nil {
		return preflighted{}, err
	}

	// Before prepareWriteDirs, so a grant this refuses leaves no host directory behind,
	// and before the launch, which reports a bwrap that could not carve a shield as a
	// silent stage that names no grant at all.
	if err := checkShieldsCarvable(sb, exposedPaths(sb, reads, writes), writes, shield.Targets(optIns)); err != nil {
		return preflighted{}, err
	}

	created, err := prepareWriteDirs(p, sb)
	if err != nil {
		// The list rides out with the error: it creates one grant at a time, so a
		// refusal on a later grant leaves an earlier grant's directory on the host.
		return preflighted{createdWrites: created}, err
	}
	return preflighted{reads: reads, writes: writes, optIns: optIns, aliases: accepted, createdWrites: created}, nil
}

// warnResidue names host paths a run left behind, on the caller's own stderr.
//
// The teardown invariant is one-sided: leaving a path bento cannot prove it created is
// the safe direction, leaving one it did create unreclaimed AND unmentioned is not.
// Worsening a confinement layer for it would report a shortfall on a run whose
// confinement in fact held, so this is not a layer state - it is the operator's stderr,
// which is the right channel for a CLI and the wrong one for an embedder that passed no
// terminal at all. recordResidue writes it to enforce.Result.Residue as well, for that
// caller; the two are one account on two channels, not two facts.
//
// Quoted, for the reason enforce.Result.Residue's doc gives its own consumers: a residue
// path can carry bytes a prior run chose - a shield mount point sits under a git submodule
// directory whose name came from the checkout - and this writes to a terminal.
func warnResidue(w io.Writer, what string, paths []string) {
	if w == nil || len(paths) == 0 {
		return
	}
	fmt.Fprintf(w, "bento: %s:\n", what)
	for _, p := range paths {
		fmt.Fprintf(w, "  %s\n", strconv.Quote(p))
	}
}

// recordResidue hands one account of what a run left on the host to both channels at
// once: the operator's stderr, where a CLI reader sees it, and the run's own result,
// which is the only channel an embedder passing a nil Stderr has. Appended rather than
// assigned, because the two categories are reported from two separate defers and the
// result carries one list; and the destination is a pointer because a defer that
// populates a result has nothing else to write through.
func recordResidue(w io.Writer, into *[]string, what string, paths []string) {
	warnResidue(w, what, paths)
	*into = append(*into, paths...)
}

// prepareWriteDirs makes each granted write directory exist on the host before it
// is bound, so writes persist. bwrap can only bind an existing path, and only a
// directory can be made writable in a way that supports creating and renaming
// files inside it - binding a file makes it a mount point, which breaks atomic
// save-and-rename. A write grant is therefore a directory: a missing one is
// created, an existing file is refused. Both tiers call this, so a file grant means
// the same thing under Landlock-only confinement as under bwrap - and the degraded
// tier never creates a host directory where the policy named a file.
//
// Both callers run the full checkGrants before this, so every refusal is already
// decided by the time anything is created. The two shield checks repeated here are
// belt-and-suspenders against that ordering drifting: they are what stops a mkdir
// inside ~/.ssh for a grant that is about to be rejected.
//
// created names the grants this brought into existence, so a caller whose run then
// fails before the target starts can say what it left on the host. It is recorded here
// rather than by a second pass over the grants because the stat that decides it is the
// one this already makes: asking again doubles the bounded wait on a dead mount, and
// would name a grant a refusal earlier in the loop meant was never attempted. It rides
// out with the error for the same reason - one grant is created at a time. A stat that
// could not answer is not counted: the teardown invariant names only what bento can
// prove it created. Missing parents MkdirAll creates alongside the grant are not named
// separately - the grant is the path the manifest asked for and the one an operator
// looks for.
func prepareWriteDirs(p *policy.Policy, sb sandbox) (created []string, err error) {
	writes, err := resolveAll(sb, p.Write)
	if err != nil {
		return nil, err
	}
	// Writes never carry the read opt-in, so no host directory is created under a
	// shield the policy merely reads.
	if err := checkWriteNotShielded(sb, writes); err != nil {
		return nil, err
	}
	// Refuse a grant above a credential shield before creating any directory, so a
	// to-be-refused grant does not leave a host artifact from the MkdirAll below.
	if err := checkWriteNotAboveShield(sb, writes); err != nil {
		return nil, err
	}
	for _, w := range writes {
		// Bounded, like the sandbox's own seams: the grant is a host path, and this runs
		// after checkShieldsCarvable, so bounding those alone would only move the hang on
		// an unresponsive mount here. The expiry has an error to travel in, so it needs no
		// fallback - it lands in WriteUnstattable below, naming the grant.
		switch fi, err := bounded("the stat of "+w, func() (os.FileInfo, error) { return os.Stat(w) }); {
		case err == nil && fi.IsDir():
			// Already a directory: nothing to prepare.
		case err == nil:
			return created, grantrefusal.WriteIsFile(w)
		case os.IsNotExist(err):
			// Recorded before the MkdirAll, not after it answers: a MkdirAll that fails
			// partway still leaves the parents it managed to make, and those are exactly
			// what an operator is otherwise never told about. It over-names when the
			// MkdirAll makes no progress at all, which is the safe side of the one-sided
			// invariant warnResidue states.
			created = append(created, w)
			// 0700: only the invoking user's own target writes here (bwrap unshares
			// the user namespace without remapping the uid), so nothing needs group
			// or other access to a directory that exists because a sandbox asked
			// for it. Applies to any missing parent MkdirAll creates too; an
			// already-existing directory keeps whatever mode the user gave it.
			if _, err := bounded("the creation of "+w, func() (struct{}, error) {
				return struct{}{}, os.MkdirAll(w, 0o700)
			}); err != nil {
				return created, fmt.Errorf("linux: creating write directory %q: %w", w, err)
			}
		case errors.Is(err, syscall.ELOOP):
			// Reached before compile's own check, so refuse it in the same words a
			// looping read grant gets rather than leaking a bare stat error.
			return created, grantrefusal.Looped(w)
		default:
			return created, grantrefusal.WriteUnstattable(w, err)
		}
	}
	return created, nil
}

// runDirBase is where bento's own per-run directory goes on both bwrap tiers and the
// degraded one. Fixed rather than $TMPDIR-derived; see the run directory below.
// A var only so a test can point the stranded-artifact sweep at a directory of its own
// instead of the host's real /tmp.
var runDirBase = "/tmp"

// newSandbox resolves the host facts the argv compiler needs, and returns a
// cleanup for the temporary files it creates.
func newSandbox(p *policy.Policy, selfPath string, gated bool, denyPaths, readOnlyPaths []string) (sandbox, func(), error) {
	noop := func() {}

	// Bounded, like the sandbox's own seams, except these run before the sandbox exists:
	// the entrypoint is the first host path a run touches, so one on an unresponsive
	// mount would otherwise hang the preflight with no output and no exit. Both return an
	// error already, so the expiry needs no fallback - it travels in the error below,
	// which names the entrypoint.
	entrypoint, err := bounded("the symlink resolution of "+p.Entrypoint, func() (string, error) {
		return resolve(p.Entrypoint)
	})
	if err != nil {
		return sandbox{}, noop, err
	}
	if _, err := bounded("the stat of "+entrypoint, func() (os.FileInfo, error) {
		return os.Stat(entrypoint)
	}); err != nil {
		return sandbox{}, noop, fmt.Errorf("entrypoint %q: %w", p.Entrypoint, err)
	}

	// An empty interpreter means the entrypoint runs itself: a compiled binary.
	var interp, interpName string
	if p.Interpreter != "" {
		found, err := bounded("the PATH lookup of "+p.Interpreter, func() (string, error) {
			return exec.LookPath(p.Interpreter)
		})
		if errors.Is(err, errDidNotAnswer) {
			return sandbox{}, noop, err
		}
		if err != nil {
			return sandbox{}, noop, fmt.Errorf("interpreter %q not found: %w", p.Interpreter, err)
		}
		if interp, err = bounded("the symlink resolution of "+found, func() (string, error) {
			return resolve(found)
		}); err != nil {
			return sandbox{}, noop, err
		}
		if found != interp {
			interpName = found
		}
	}

	// Relative here would be taken by bwrap against its own working directory, which is
	// the caller's - a run that starts somewhere nobody named. manifest.Resolve anchors
	// the manifest's value; a Go embedder who built the policy by hand gets this.
	if p.Workdir != "" && !filepath.IsAbs(p.Workdir) {
		return sandbox{}, noop, fmt.Errorf("workdir %q is not absolute; resolve the policy first (manifest.Resolve) or write the path out in full", p.Workdir)
	}

	homes, err := denylist.HomeAnchors()
	if err != nil {
		return sandbox{}, noop, err
	}

	// "/tmp" rather than "", which is $TMPDIR: this is bento's own run directory, not the
	// target's, and the target never sees it - it holds the empty file the shields bind
	// and, when profiling, the observation report. Honoring $TMPDIR put it wherever the
	// invoking environment pointed, including inside the user's own checkout under a
	// write grant, where it sat live for the length of the run named in no report. The
	// sandbox's own scratch is /tmp regardless, so this is where the rest of a run already
	// lives. The cost is a host whose /tmp is small, noexec or read-only and that set
	// $TMPDIR for exactly that reason: such a run now fails here, or on the degraded tier
	// hands the target a scratch it cannot build in. That is the trade - a loud failure
	// naming the run directory, against a silent one inside the user's checkout.
	dir, err := os.MkdirTemp(runDirBase, "bento-run-")
	if err != nil {
		return sandbox{}, noop, fmt.Errorf("linux: creating run directory: %w", err)
	}
	cleanup := func() { os.RemoveAll(dir) }

	empty := filepath.Join(dir, "shield")
	if err := writeEmptyFile(empty); err != nil {
		cleanup()
		return sandbox{}, noop, err
	}

	sb := sandbox{
		homes:           homes,
		runDir:          dir,
		runtimeDir:      denylist.RuntimeDir(),
		emptyFile:       empty,
		entrypoint:      entrypoint,
		workdir:         p.Workdir,
		interpreter:     interp,
		interpreterName: interpName,
		exists:          hostExists,
		writable:        hostWritable,
		isDir:           hostIsDir,
		rootDirs:        hostRootDirs,
		resolve:         hostResolve,
		listDir:         hostListDir,
		fileIDs:         hostFileIDs,
		aliasesUnder:    hostAliasesUnder,
		mountpoints:     hostMountpoints,
		statID:          hostStatIDOK,
		// Allocated here, not lazily: the sandbox is passed by value, so a map created
		// on first use would live in one copy and every other call site would miss it.
		workspaceShieldCache: map[string][]denylist.Rule{},
		deadMount:            &deadMount{},
	}
	sb = boundHostSeams(sb)

	// The in-sandbox launcher (the bento binary) runs on every sandbox: it is the
	// one process bento controls between bwrap and the target, so it is where every
	// inherited file descriptor is dropped before the target sees it (a descriptor
	// bento's parent leaked without O_CLOEXEC would otherwise bypass the mount
	// namespace and the deny-list entirely). So bentoPath is always bound. The proxy
	// socket is separate: it is set up only for egress or a supervising gate.
	if sb.bentoPath, err = bentoSelfPath(selfPath); err != nil {
		cleanup()
		return sandbox{}, noop, err
	}
	if len(p.Network) > 0 || gated {
		sb.proxySocket = filepath.Join(dir, "proxy.sock")
	}

	// Caller-supplied deny paths join the built-in deny-list. Built here, after the
	// resolve/stat seams are set, so the shield-cleanup defer in Profile sees them.
	if sb.extraDeny, err = buildExtraDeny(denyPaths, sb); err != nil {
		cleanup()
		return sandbox{}, noop, err
	}
	for _, ro := range readOnlyPaths {
		// A file only: a DenyWrite directory shield over an absent path would be a tmpfs,
		// and over a present one it is DenyPaths' job with its own refusals.
		if !filepath.IsAbs(ro) || !sb.exists(ro) || sb.isDir(ro) {
			cleanup()
			return sandbox{}, noop, fmt.Errorf("linux: read-only path %q must be an absolute path to an existing file", ro)
		}
		sb.extraDeny = append(sb.extraDeny, denylist.Rule{Path: ro, Deny: denylist.DenyWrite})
	}
	// Allocated only now, after the caller's denies are final. The memo holds the whole
	// assembled set, denies included, so warming it any earlier would hand every later
	// question a set the caller's shields never reached - and it would do it silently.
	sb.shieldCache = &shieldMemo{}

	// compile re-binds the entrypoint and the interpreter read-only AFTER the
	// deny-list, so either one can carry a fully-shielded file into the sandbox
	// whatever the shields say - and the run reports nothing lifted, because no
	// shield was. Both directions of that leak: where a grant covers the store the
	// shield is emitted and the re-bind lands read-only INSIDE the tmpfs meant to
	// hide it; where none does there is no shield at all and the bind creates the
	// path. Harmless in the CLI frame, where the operator typed the entrypoint, but
	// an approved manifest is untrusted input under --allow-unapproved and in the
	// embedder frame (a supervisor profiling untrusted code with its own control
	// store shielded). Refuse here, where both are already resolved.
	//
	// Asked of the whole assembled DenyAll set rather than only the caller's denies:
	// ~/.ssh is no more executable than an embedder's control store, and the opt-ins
	// are honored so a read grant naming the store still binds it as the full tier
	// already promises.
	set := shields(sb)
	optIns := shield.Targets(explicitShieldOptIns(sb, p.Read))
	for _, e := range []struct{ kind, path string }{
		{"entrypoint", sb.entrypoint},
		{"interpreter", sb.interpreter},
	} {
		if e.path == "" {
			continue
		}
		// Every verdict but Honored, rather than the two Inside ones: under shield.Read
		// Contains answers Honored, InsideShield, InsideCallerShield or FoldedShield, and
		// naming a subset left the fourth admitted by omission. This site is a consumer of
		// shield.Verdict that no corpus case and no exhaustive-lint-checked switch reaches,
		// so a new read verdict would be admitted here the same silent way; asking for
		// Honored is the only form that cannot be.
		if r, v := set.Contains(e.path, shield.Read, optIns, nil); v != shield.Honored {
			cleanup()
			return sandbox{}, noop, fmt.Errorf("linux: %s %q would expose the shielded path %q, which the sandbox may not lift", e.kind, e.path, r.Path)
		}
	}
	return sb, cleanup, nil
}

// buildExtraDeny turns caller-supplied deny paths into DenyAll shield rules. Each
// must be absolute and must not resolve to the root; a path that does not exist
// yet (the common first-run case for a wrapper's own store directory) is shielded
// as a directory, so it never leaves a host file artifact, while an existing
// regular file is shielded as a file. The rule keeps the unresolved path; the
// shield machinery resolves it the same way it resolves grants.
func buildExtraDeny(denyPaths []string, sb sandbox) ([]denylist.Rule, error) {
	var rules []denylist.Rule
	for _, p := range denyPaths {
		if !filepath.IsAbs(p) {
			return nil, fmt.Errorf("deny path %q must be absolute", p)
		}
		// Classify by the RESOLVED path, since the shield binds there (denyArgs
		// resolves r.Path). Only an existing regular file gets a file shield; a
		// directory, an absent path, or a dangling symlink (resolves to an absent
		// target) all get a directory shield - so a nonexistent target never leaves an
		// uncleanable empty host file.
		rp := sb.resolve(p)
		homes := make([]string, len(sb.homes))
		for i, h := range sb.homes {
			homes[i] = sb.resolve(h)
		}
		if rp == "/" {
			return nil, fmt.Errorf("deny path %q resolves to the root and cannot be shielded", p)
		}
		// The same test denyArgs applies to every resolved rule, raised here so a caller
		// learns its deny cannot be shielded instead of having it accepted and then
		// silently dropped - a shield over a home or one of its ancestors would take the
		// whole grant surface with it, so there is nothing to enforce either way.
		// It is a check at this instant, not a guarantee: denyArgs resolves again at
		// compile time and drops silently what fails there, so a symlink component
		// rewritten in between passes here and vanishes later. Closing that would mean
		// resolving once and carrying the result, which costs the shield machinery its
		// own late resolution of grants; the residue is an unenforced CALLER deny, never
		// an exposure of anything bento shields itself.
		if rp == "/dev/null" {
			return nil, fmt.Errorf("deny path %q resolves to %q, which every program in the sandbox needs writable as its stream sink", p, rp)
		}
		if !denylist.Shieldable(rp, homes) {
			return nil, fmt.Errorf("deny path %q resolves to %q, which is a home directory or contains one, so shielding it would hide everything the policy grants", p, rp)
		}
		dir := true
		if sb.exists(rp) && !sb.isDir(rp) {
			dir = false
		}
		rules = append(rules, denylist.Rule{Path: p, Deny: denylist.DenyAll, Dir: dir})
	}
	return rules, nil
}

// bentoSelfPath returns the path to the bento binary to bind as the in-sandbox
// launcher. selfPath overrides it (tests set it because the test process is not
// bento); empty means the running executable.
func bentoSelfPath(selfPath string) (string, error) {
	if selfPath != "" {
		return selfPath, nil
	}
	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("linux: locating the bento binary for the in-sandbox launcher: %w", err)
	}
	return self, nil
}

// launchGuard is nil in production. The test suite installs one so a launch that
// would bind the test binary as the in-sandbox launcher fails loudly instead of
// re-execing the suite inside the sandbox - a failure mode that otherwise passes
// green after minutes of wall clock and a leaked sandbox.
var launchGuard func(bentoPath string) error

// runCmd runs the wrapper and waits for it, as cmd.Run does, calling started with the
// wrapper's pid in between. It is a seam over that one call so a test can produce the
// failure the post-run default arm exists for: an error that is neither nil nor an
// *exec.ExitError - a vanished wrapper binary, a fork failure, an I/O error on the pipes.
// Nothing else in the suite can manufacture one, and that arm carries the whole audit out
// for a target that may already have run.
//
// started is where the run's own scope is read back, which can only be done while the
// target is alive; it runs between Start and Wait, so the target is under way throughout
// and the reading costs the bookkeeping rather than the run.
var runCmd = func(c *exec.Cmd, started func(pid int)) error {
	if err := c.Start(); err != nil {
		return err
	}
	started(c.Process.Pid)
	return c.Wait()
}

// checkLauncher rules on the binary about to be launched as the in-sandbox
// launcher. It is a no-op unless launchGuard is installed.
func checkLauncher(bentoPath string) error {
	if launchGuard == nil {
		return nil
	}
	return launchGuard(bentoPath)
}

// writeEmptyFile creates the empty file the deny-list binds over paths that must
// be shielded even though they do not exist on the host yet. It lives in the
// per-run temp directory, so it is created fresh and removed with it. Its parent
// is already 0700, and the target reads it as the invoking user, so owner-only
// read is all the mode has to carry.
func writeEmptyFile(path string) error {
	if err := os.WriteFile(path, nil, 0o400); err != nil {
		return fmt.Errorf("linux: creating deny-list shield: %w", err)
	}
	return nil
}

// startProxy serves the egress allowlist on socket for the run's lifetime,
// optionally consulting gate for hosts the manifest does not declare. It returns
// an idempotent stop function (which reports the listener's terminal error) and the
// collector holding what the run's egress actually did: how many connections reached
// the proxy (a zero count on an egress-capable run tells the frontend the target never
// went through the proxy - used no network, or bypassed it), the hosts the gate
// admitted beyond the manifest, and the ones the upstream guard refused to dial.
func startProxy(ctx context.Context, p *policy.Policy, socket string, gate enforce.NetworkGate) (stop func() proxyOutcome, collected *egressCollector, err error) {
	c := &egressCollector{}
	// Discover the host's NAT64 prefix so a synthesized RFC1918 target cannot reach
	// the LAN through a permitted public hostname (RFC 7050). The profiling path
	// applies the same discovery in its forwarding (allowNetwork) mode, where it too
	// dials upstream.
	opts := []proxy.Option{proxy.WithNAT64Discovery(proxy.DefaultNAT64Lookup)}
	if gate != nil {
		opts = append(opts, proxy.WithGatekeeper(gate))
	}
	stop, err = startProxyWith(ctx, p, socket, c.observe, opts...)
	if err != nil {
		return nil, nil, err
	}
	return sync.OnceValue(stop), c, nil
}

// egressCollector records the proxy's per-connection decisions for the run
// result: a total count, the deduped set of hosts the gate admitted beyond
// the manifest, the deduped set the upstream guard refused to dial, the
// deduped set the allowlist itself refused, the deduped set a consulted gate
// refused, the deduped set refused for not being a CONNECT at all, a count of
// the connections a panicking handler dropped, and a count of the ones a panicking
// gate refused. The
// observer runs in each handler's own goroutine, so a mutex guards the shared
// state; the gate itself is never called under this lock (it runs in the handler,
// the observer only records the outcome).
type egressCollector struct {
	mu         sync.Mutex
	count      int
	faulted    int
	gateFaults int
	atCapacity int
	admitted   map[string]enforce.HostPort
	blocked    map[string]enforce.HostPort
	metadata   map[string]enforce.HostPort
	denied     map[string]enforce.HostPort
	gateDenied map[string]enforce.HostPort
	untunneled map[string]enforce.HostPort
}

func (c *egressCollector) observe(d proxy.Decision, host, port string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// A fault is an outcome on a connection, not another connection, so it is counted
	// apart from the tally rather than added to it. A fault is reported only for a
	// connection that reached no other decision, so it is missing from that tally
	// entirely; the degraded network layer this count produces is what covers it.
	if d == proxy.Faulted {
		c.faulted++
		return
	}
	c.count++
	// Key each set on JoinHostPort so an IPv6 host:port dedupes correctly. Each
	// CONNECT lands in at most one of them - the guard's refusal replaces the gate's
	// admission rather than following it, which keeps the admitted list from claiming a
	// host that never got past the guard - but a destination can appear in more than one
	// across connections, when the name resolved public on one and private on another.
	// That is the rebinding case the guard exists for, so every list is reported as it is
	// rather than one being suppressed.
	switch d {
	case proxy.AdmittedByGate:
		if c.admitted == nil {
			c.admitted = make(map[string]enforce.HostPort)
		}
		c.admitted[net.JoinHostPort(host, port)] = enforce.HostPort{Host: host, Port: port}
	case proxy.Denied:
		if c.denied == nil {
			c.denied = make(map[string]enforce.HostPort)
		}
		c.denied[net.JoinHostPort(host, port)] = enforce.HostPort{Host: host, Port: port}
	case proxy.GateDenied:
		if c.gateDenied == nil {
			c.gateDenied = make(map[string]enforce.HostPort)
		}
		c.gateDenied[net.JoinHostPort(host, port)] = enforce.HostPort{Host: host, Port: port}
	case proxy.GateFaulted:
		// Named in the same set as a gate denial, because that is what the destination
		// list is for: the gate was consulted and the connection did not go through, and
		// an operator reading the result still has to see the host. What the two do not
		// share is the remedy, and that is what the count carries - noteGateFault turns it
		// into the one line that says the gate is broken rather than answering no.
		if c.gateDenied == nil {
			c.gateDenied = make(map[string]enforce.HostPort)
		}
		c.gateDenied[net.JoinHostPort(host, port)] = enforce.HostPort{Host: host, Port: port}
		c.gateFaults++
	case proxy.GuardBlockedMetadata:
		// A metadata probe is a guard block like the four below - the operator needs the
		// destination either way - and is also recorded apart, because it is the one cause
		// that reads as a credential probe: 169.254.169.254 and the 6to4/NAT64/mapped forms
		// of it are reached only by a target that went looking for them.
		// The subset stays a subset rather than replacing the entry, so a consumer that
		// only asks "did the guard refuse anything" keeps the whole set.
		if c.blocked == nil {
			c.blocked = make(map[string]enforce.HostPort)
		}
		if c.metadata == nil {
			c.metadata = make(map[string]enforce.HostPort)
		}
		c.blocked[net.JoinHostPort(host, port)] = enforce.HostPort{Host: host, Port: port}
		c.metadata[net.JoinHostPort(host, port)] = enforce.HostPort{Host: host, Port: port}
	case proxy.GuardBlockedReserved, proxy.GuardBlockedUnparsed, proxy.GuardBlockedPrivate, proxy.GuardBlockedNAT64:
		// These four share one set: an operator reading the result needs the destination
		// whatever the cause was, and they differ in the remedy rather than in whether the
		// host belongs here. Telling THEM apart is the embedder's observer's job, which
		// sees the decision itself; the metadata cause above is the one worth carrying
		// this far, because it is the only one that reads as an attack rather than a
		// corporate DNS. The constants are listed rather than folded into
		// Decision.GuardRefused deliberately: the exhaustive switch is what fails when a
		// sixth cause is added and nobody decides which half it belongs in.
		if c.blocked == nil {
			c.blocked = make(map[string]enforce.HostPort)
		}
		c.blocked[net.JoinHostPort(host, port)] = enforce.HostPort{Host: host, Port: port}
	case proxy.Untunneled:
		if c.untunneled == nil {
			c.untunneled = make(map[string]enforce.HostPort)
		}
		c.untunneled[net.JoinHostPort(host, port)] = enforce.HostPort{Host: host, Port: port}
	case proxy.Allowed, proxy.Refused, proxy.Unreachable:
		// Counted but not named. An egress the rules allow outright is what the manifest
		// already says, and the report exists for the destinations a run would not predict
		// from reading it. One the rules allowed and the network then failed to carry is
		// the same manifest with a dead host behind it, which the script's own error says
		// better than this report could.
	case proxy.RefusedAtCapacity:
		// Counted like the arm above - it is a connection that reached the proxy - and
		// tallied apart as well, because unlike them it says the allowlist was never
		// consulted. noteRefusedAtCapacity is what turns the tally into a verdict; without
		// it a declared destination refused by load reads as one the rules allowed.
		c.atCapacity++
	case proxy.Faulted:
		// Returned above, before the tally: a fault is an outcome on a connection rather
		// than a destination reached.
	}
}

func (c *egressCollector) counted() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

func (c *egressCollector) atCapacityCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.atCapacity
}

func (c *egressCollector) faultCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.faulted
}

func (c *egressCollector) gateFaultCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gateFaults
}

// gateAdmitted returns a copy of the admitted set, sorted so the result is
// deterministic (map iteration order would flap tests and JSON output).
func (c *egressCollector) gateAdmitted() []enforce.HostPort {
	c.mu.Lock()
	defer c.mu.Unlock()
	return sortedHostPorts(c.admitted)
}

// guardBlocked returns a copy of the guard-blocked set, sorted for the same reason
// gateAdmitted is.
func (c *egressCollector) guardBlocked() []enforce.HostPort {
	c.mu.Lock()
	defer c.mu.Unlock()
	return sortedHostPorts(c.blocked)
}

// guardBlockedMetadata returns a copy of the subset of the guard-blocked set refused for
// being the cloud metadata address, sorted for the same reason gateAdmitted is.
func (c *egressCollector) guardBlockedMetadata() []enforce.HostPort {
	c.mu.Lock()
	defer c.mu.Unlock()
	return sortedHostPorts(c.metadata)
}

// allowlistDenied returns a copy of the set the allowlist refused, sorted for the same reason
// gateAdmitted is.
func (c *egressCollector) allowlistDenied() []enforce.HostPort {
	c.mu.Lock()
	defer c.mu.Unlock()
	return sortedHostPorts(c.denied)
}

// gateRefused returns a copy of the set a consulted gate refused, sorted for the same
// reason gateAdmitted is.
func (c *egressCollector) gateRefused() []enforce.HostPort {
	c.mu.Lock()
	defer c.mu.Unlock()
	return sortedHostPorts(c.gateDenied)
}

// untunneledDestinations returns a copy of the set refused for not being a CONNECT,
// sorted for the same reason gateAdmitted is.
func (c *egressCollector) untunneledDestinations() []enforce.HostPort {
	c.mu.Lock()
	defer c.mu.Unlock()
	return sortedHostPorts(c.untunneled)
}

func sortedHostPorts(m map[string]enforce.HostPort) []enforce.HostPort {
	out := make([]enforce.HostPort, 0, len(m))
	for _, hp := range m {
		out = append(out, hp)
	}
	slices.SortFunc(out, func(a, b enforce.HostPort) int {
		return cmp.Or(cmp.Compare(a.Host, b.Host), cmp.Compare(a.Port, b.Port))
	})
	return out
}

// startProxyWith serves the egress allowlist on socket with a caller-supplied
// observer, returning a stop function.
// The returned stop reports the listener's terminal error: non-nil when Accept
// failed while the run was still live, so the egress fence stopped serving for the
// rest of it. A nil is weaker than "the run ended cleanly" - Serve cannot tell an
// Accept that failed in the same instant as teardown from one caused by it, and
// answers nil - so noteDeadListener under-reports that overlap rather than
// inventing a Degraded run out of a race.
func startProxyWith(ctx context.Context, p *policy.Policy, socket string, observe func(proxy.Decision, string, string), opts ...proxy.Option) (stop func() proxyOutcome, err error) {
	l, err := net.Listen("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("linux: starting egress proxy: %w", err)
	}
	proxyCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	// serveErr is written before done is closed and read only after it, so the close
	// carries the handoff.
	var serveErr error
	pr := proxy.New(p.Network, append([]proxy.Option{proxy.WithObserver(observe)}, opts...)...)
	go func() {
		serveErr = pr.Serve(proxyCtx, l)
		close(done)
	}()
	// Every count is read after done, which is after Serve's wg.Wait, so every handler
	// and the accept goroutine itself have finished adding to them.
	return func() proxyOutcome {
		cancel()
		<-done
		retries, backoff := pr.AcceptRetries()
		return proxyOutcome{
			observerFaults: pr.ObserverFaults(),
			handlerFaults:  pr.HandlerFaults(),
			nat64Blackouts: pr.NAT64Blackouts(),
			acceptRetries:  retries,
			acceptBackoff:  backoff,
			serveErr:       serveErr,
		}
	}, nil
}

// proxyOutcome is what the run's proxy has to say about itself once it has stopped: its
// own two faults, told apart because their remedies are, the egress it refused for reasons that were not the
// manifest's, and the listener's terminal error. Each one is a note in the run's report;
// they travel together because they are all read from the same stopped Proxy.
type proxyOutcome struct {
	observerFaults int
	handlerFaults  int
	nat64Blackouts int
	acceptRetries  int
	acceptBackoff  time.Duration
	serveErr       error
}
