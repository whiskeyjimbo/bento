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
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/proxy"
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
func (e *Enforcer) Run(ctx context.Context, p *policy.Policy, proc enforce.Process, opts enforce.RunOptions) (enforce.Result, error) {
	// enforce.Run validates before it gets here, but this is an exported entry point an
	// embedder can call directly - as Profile already does for the same reason.
	if err := p.Validate(); err != nil {
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
		// Same shape as the gate above: this tier has no mount namespace and applies no
		// shields, so a caller deny would silently not be enforced. Reporting it through
		// Exposed instead would hand back a run that read the caller's control state and
		// an audit record saying so after the fact, which is the false confidence a
		// fail-closed posture exists to refuse.
		if len(opts.DenyPaths) > 0 {
			return enforce.Result{}, fmt.Errorf("linux: caller deny paths cannot be honored by the degraded tier: it has no mount namespace and applies no shields")
		}
		return e.runDegraded(ctx, p, proc)
	}

	report := e.Probe(ctx)

	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return enforce.Result{}, fmt.Errorf("linux: bubblewrap (bwrap) not found: %w", err)
	}
	// A gate forces the egress stack up even with zero rules: a supervised run with
	// no manifest network means "prompt on every host", so the proxy must exist for
	// the gate to be consulted at all.
	sb, cleanup, err := newSandbox(p, e.selfPath, opts.Gate != nil, opts.DenyPaths)
	if err != nil {
		return enforce.Result{}, err
	}
	defer cleanup()

	preflight, err := preflightGrants(sb, p, opts.AcceptAliasesUnder)
	if err != nil {
		return enforce.Result{}, err
	}
	optedIn, optIns, accepted := preflight.optedIn, preflight.optIns, preflight.aliases

	// bwrap creates a shield mount point on the host when the shielded path does not
	// exist yet and a write grant makes its parent writable (e.g. a project's unborn
	// .git/hooks). Remove those after the run so the sandbox leaves no artifact; see
	// removeCreatedShields for why this is safe and best-effort.
	shieldDirs, shieldFiles := preflight.createdShields(sb)
	defer removeCreatedShields(shieldDirs, shieldFiles)

	// When the policy allows egress (or a gate supervises it), run the allowlist
	// proxy on the sandbox's unix socket for the lifetime of the run. The sandbox
	// reaches it only through that socket; nothing else can leave the network
	// namespace. stopProxy waits for every in-flight handler (Serve's wg.Wait), so
	// it is called explicitly before each success return - not just deferred - so
	// a gate admitted during target teardown is recorded before the result is read.
	// It is idempotent (sync.OnceFunc inside startProxy), so the defer stays as a
	// safety net for the error paths without double-closing.
	stopProxy := func() error { return nil }
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
	appliedReport, dropApplied, err := newAppliedReport()
	if err != nil {
		return enforce.Result{}, err
	}
	defer dropApplied()

	args, shields, err := compile(p, proc, sb)
	if err != nil {
		return enforce.Result{}, err
	}

	// When the policy sets limits and this host can enforce them, run bwrap inside
	// a transient systemd scope carrying the limits. When it cannot, the run has
	// already been admitted (refused by default, or permitted under
	// --allow-degraded) - here it simply proceeds unwrapped, and the report says so
	// without a second check: canCreateScope is memoized for the life of the process,
	// so the probe above recorded LayerLimits Unavailable from the same answer this
	// reads. There is no window in which the report can claim a limit nothing applied.
	exe, cargs := bwrap, args
	if !p.Limits.IsZero() {
		if ok, _ := canCreateScope(); ok {
			// Preflight the exact limits so a scope-creation failure surfaces as a
			// clear error, never as the target's exit code for a target that never
			// ran.
			if err := preflightLimits(p.Limits, nil); err != nil {
				return enforce.Result{}, fmt.Errorf("linux: %w", err)
			}
			exe, cargs = wrapWithLimits(bwrap, args, p.Limits)
			// An undelegated cpu controller is reported by the probe as LayerLimitsCPU
			// Unavailable and refused at admission; a run that reaches here with a cpu
			// limit was either delegated or explicitly permitted under --allow-degraded,
			// and the probe's LayerLimitsCPU state carries through to the final report.
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

	runErr := cmd.Run()
	// Dropping the host's write end before reading: while the host holds one the read
	// below would block past the sandbox's exit waiting for an EOF only it can send.
	if bridgeLivenessW != nil {
		bridgeLivenessW.Close()
	}
	bridgeDied := bridgeReportedDeath(bridgeLiveness)

	switch err := runErr; {
	case err == nil:
		serveErr := stopProxy()
		setup := parseApplied(appliedReport.Name()).reconcile(&report, p.Exec != policy.ExecAll, p.Exec == policy.ExecNoneStrict, 0)
		noteDeadListener(&report, serveErr)
		noteDeadBridge(&report, bridgeDied)
		return enforce.Result{ExitCode: 0, Report: report, Setup: setup, EgressConnections: collected.counted(), GateAdmitted: collected.gateAdmitted(), GuardBlocked: collected.guardBlocked(), Denied: collected.allowlistDenied(), ShieldedGrants: optedIn, ShieldedGrantTargets: shieldGrantTargets(optedIn, optIns), Shields: shields, AcceptedAliases: reportedAliases(accepted)}, nil
	case isExitError(err):
		var ee *exec.ExitError
		errors.As(err, &ee)
		serveErr := stopProxy()
		// A signal here killed the wrapper, not the target: bwrap reports a signaled
		// target as 128+signal itself. What reaches this branch signaled is the scope
		// coming down around the run, which is how a cgroup limit ends it.
		code, signaled, sig := exitStatusOf(ee.ProcessState)
		setup := parseApplied(appliedReport.Name()).reconcile(&report, p.Exec != policy.ExecAll, p.Exec == policy.ExecNoneStrict, code)
		noteDeadListener(&report, serveErr)
		noteDeadBridge(&report, bridgeDied)
		return enforce.Result{ExitCode: code, Signaled: signaled, Signal: sig, Report: report, Setup: setup, EgressConnections: collected.counted(), GateAdmitted: collected.gateAdmitted(), GuardBlocked: collected.guardBlocked(), Denied: collected.allowlistDenied(), ShieldedGrants: optedIn, ShieldedGrantTargets: shieldGrantTargets(optedIn, optIns), Shields: shields, AcceptedAliases: reportedAliases(accepted)}, nil
	default:
		return enforce.Result{Report: report}, fmt.Errorf("linux: running sandbox: %w", err)
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
	r.Set(enforce.LayerNetwork, enforce.Degraded,
		fmt.Sprintf("the egress proxy stopped accepting mid-run (%v); declared egress was refused for the remainder", err))
}

// bridgeReportedDeath reads the bridge's liveness pipe, which the host has already
// stopped writing to. One byte means the bridge wrote that it stopped serving; EOF
// with nothing read is an ordinary run, since the pid namespace collapses at every
// exit and would otherwise make EOF look like a failure on every run. A read error is
// treated as no report: the pipe is the host's own, and the alternative is claiming a
// degraded network layer on the strength of a broken channel.
//
// Deadlined, because the sandbox is not always dead when the command this run waited
// on is. Under the limits wrapper the process reaped is systemd-run, and a cancelled
// run can leave bwrap orphaned with the bridge still holding the write end - an
// undeadlined read would then block until a runaway target exited, turning a cancelled
// run into a hang. On every ordinary path the pid namespace has already collapsed and
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
// stayed down. Set last, so where a dead host-side listener also degraded the layer
// this is the reason the operator sees - it names the half that stopped first.
func noteDeadBridge(r *enforce.Report, died bool) {
	if !died {
		return
	}
	r.Set(enforce.LayerNetwork, enforce.Degraded,
		"the in-sandbox egress bridge stopped serving mid-run; declared egress was unreachable for part of the run")
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
	// optedIn are the LITERAL deny-list paths the policy opted back into the sandbox,
	// for the frontend to warn about by the name the deny-list uses; optIns are the
	// same paths resolved, which is what the shield bookkeeping compares against.
	optedIn, optIns []string
	aliases         []credentialAlias
}

// createdShields names the shield mount points bwrap will create on the host for this
// run, so the caller can remove them afterwards.
func (pf preflighted) createdShields(sb sandbox) (dirs, files []string) {
	return createdShields(sb, exposedPaths(sb, pf.reads, pf.writes), pf.writes, pf.optIns)
}

// preflightGrants decides everything that can refuse a run and then prepares the host
// for it, in that order: the full grant-safety set and the alias scan run before
// prepareWriteDirs, so a to-be-refused grant never leaves behind a directory that was
// created for it. compile re-runs checkGrants as its own guard.
//
// Both bwrap tiers - the enforced run and the profiling run - go through here. Profiling
// needs it for exactly the same reason Run does: the profiled target is untrusted by
// construction, so a hardlink to a credential inside an accepted read grant would be
// readable there too, and a write grant naming a not-yet-existing directory would be a
// silent no-op that the convergence loop then never converges on.
//
// The degraded tier does not, and that is a real gap rather than a clean exemption: it
// confines with Landlock, which is path-hierarchy based, so an alias inside a granted
// tree is readable there for exactly the reason it would be past a shield - Landlock
// never consults an inode's other names. Nor is it reported: the exposure list can only
// name built-in shield paths that fall in the visible set, and an arbitrary alias path
// is not one. So --allow-degraded proceeds where the full tier refuses. It is opt-in and
// already the weaker tier, which is why this is documented rather than fixed here.
func preflightGrants(sb sandbox, p *policy.Policy, acceptAliasesUnder []string) (preflighted, error) {
	reads, writes, err := resolveGrants(sb, p)
	if err != nil {
		return preflighted{}, err
	}
	if err := checkGrants(sb, p, reads, writes); err != nil {
		return preflighted{}, err
	}

	// Surface any always-shielded credential store the policy explicitly opted back into
	// the sandbox (yz3.2) for the frontend to warn about, named by its literal deny-list
	// path. The shields still protect every path not opted into.
	optedIn, optIns := explicitShieldOptIns(sb, p.Read)

	// A shield hides a credential's path, not the content behind it. Refuse before the
	// target starts if anything this run can read holds a second name for a shielded
	// credential's inode: the user granted that tree, not the credential, so proceeding
	// would hand over a store they never opted into. The scan covers everything bwrap
	// binds, not only the policy's own grants, because an out-of-FHS interpreter's prefix
	// is bound too and may sit under the home. An explicit opt-in is honored - those
	// credentials are dropped from the scan - and a caller who acknowledges a tree keeps
	// the aliases in it, so this refuses only what nobody asked for.
	scan, err := aliasedCredentials(sb, exposedPaths(sb, reads, writes), optedIn)
	if err != nil {
		return preflighted{}, err
	}
	refuse, accepted, err := splitAcknowledgedAliases(sb, scan, acceptAliasesUnder)
	if err != nil {
		return preflighted{}, err
	}
	if len(refuse) > 0 {
		return preflighted{}, aliasRefusal(refuse, scan.credentials)
	}

	if err := prepareWriteDirs(p, sb); err != nil {
		return preflighted{}, err
	}
	return preflighted{reads: reads, writes: writes, optedIn: optedIn, optIns: optIns, aliases: accepted}, nil
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
func prepareWriteDirs(p *policy.Policy, sb sandbox) error {
	writes, err := resolveAll(sb, p.Write)
	if err != nil {
		return err
	}
	// Writes never carry the read opt-in, so no host directory is created under a
	// shield the policy merely reads.
	if err := checkNotShielded(sb, writes, nil); err != nil {
		return err
	}
	// Refuse a grant above a credential shield before creating any directory, so a
	// to-be-refused grant does not leave a host artifact from the MkdirAll below.
	if err := checkWriteNotAboveShield(sb, writes); err != nil {
		return err
	}
	for _, w := range writes {
		switch fi, err := os.Stat(w); {
		case err == nil && fi.IsDir():
			// Already a directory: nothing to prepare.
		case err == nil:
			return fmt.Errorf("write grant %q is a file; grant its parent directory instead", w)
		case os.IsNotExist(err):
			// 0700: only the invoking user's own target writes here (bwrap unshares
			// the user namespace without remapping the uid), so nothing needs group
			// or other access to a directory that exists because a sandbox asked
			// for it. Applies to any missing parent MkdirAll creates too; an
			// already-existing directory keeps whatever mode the user gave it.
			if err := os.MkdirAll(w, 0o700); err != nil {
				return fmt.Errorf("linux: creating write directory %q: %w", w, err)
			}
		case errors.Is(err, syscall.ELOOP):
			// Reached before compile's own check, so refuse it in the same words a
			// looping read grant gets rather than leaking a bare stat error.
			return loopedGrantError(w)
		default:
			return fmt.Errorf("checking write grant %q: %w", w, err)
		}
	}
	return nil
}

// newSandbox resolves the host facts the argv compiler needs, and returns a
// cleanup for the temporary files it creates.
func newSandbox(p *policy.Policy, selfPath string, gated bool, denyPaths []string) (sandbox, func(), error) {
	noop := func() {}

	entrypoint, err := resolve(p.Entrypoint)
	if err != nil {
		return sandbox{}, noop, err
	}
	if _, err := os.Stat(entrypoint); err != nil {
		return sandbox{}, noop, fmt.Errorf("entrypoint %q: %w", p.Entrypoint, err)
	}

	// An empty interpreter means the entrypoint runs itself: a compiled binary.
	var interp, interpName string
	if p.Interpreter != "" {
		found, err := exec.LookPath(p.Interpreter)
		if err != nil {
			return sandbox{}, noop, fmt.Errorf("interpreter %q not found: %w", p.Interpreter, err)
		}
		if interp, err = resolve(found); err != nil {
			return sandbox{}, noop, err
		}
		if found != interp {
			interpName = found
		}
	}

	homes, err := denylist.HomeAnchors()
	if err != nil {
		return sandbox{}, noop, err
	}

	dir, err := os.MkdirTemp("", "bento-run-")
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
		runtimeDir:      denylist.RuntimeDir(),
		emptyFile:       empty,
		entrypoint:      entrypoint,
		interpreter:     interp,
		interpreterName: interpName,
		exists:          hostExists,
		isDir:           hostIsDir,
		rootDirs:        hostRootDirs,
		resolve:         hostResolve,
		listDir:         hostListDir,
		fileIDs:         hostFileIDs,
		aliasesUnder:    hostAliasesUnder,
		mountpoints:     hostMountpoints,
		statID:          hostStatID,
	}

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
		if rp == "/" {
			return nil, fmt.Errorf("deny path %q resolves to the root and cannot be shielded", p)
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
func startProxy(ctx context.Context, p *policy.Policy, socket string, gate enforce.NetworkGate) (stop func() error, collected *egressCollector, err error) {
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
// the manifest, the deduped set the upstream guard refused to dial, and the
// deduped set the allowlist itself refused. The
// observer runs in each handler's own goroutine, so a mutex guards the shared
// state; the gate itself is never called under this lock (it runs in the handler,
// the observer only records the outcome).
type egressCollector struct {
	mu       sync.Mutex
	count    int
	admitted map[string]enforce.HostPort
	blocked  map[string]enforce.HostPort
	denied   map[string]enforce.HostPort
}

func (c *egressCollector) observe(d proxy.Decision, host, port string) {
	c.mu.Lock()
	defer c.mu.Unlock()
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
	case proxy.GuardBlocked:
		if c.blocked == nil {
			c.blocked = make(map[string]enforce.HostPort)
		}
		c.blocked[net.JoinHostPort(host, port)] = enforce.HostPort{Host: host, Port: port}
	case proxy.Denied:
		if c.denied == nil {
			c.denied = make(map[string]enforce.HostPort)
		}
		c.denied[net.JoinHostPort(host, port)] = enforce.HostPort{Host: host, Port: port}
	}
}

func (c *egressCollector) counted() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
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

// allowlistDenied returns a copy of the set the allowlist refused, sorted for the same reason
// gateAdmitted is.
func (c *egressCollector) allowlistDenied() []enforce.HostPort {
	c.mu.Lock()
	defer c.mu.Unlock()
	return sortedHostPorts(c.denied)
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
func startProxyWith(ctx context.Context, p *policy.Policy, socket string, observe func(proxy.Decision, string, string), opts ...proxy.Option) (stop func() error, err error) {
	l, err := net.Listen("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("linux: starting egress proxy: %w", err)
	}
	proxyCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	// serveErr is written before done is closed and read only after it, so the close
	// carries the handoff.
	var serveErr error
	go func() {
		serveErr = proxy.New(p.Network, append([]proxy.Option{proxy.WithObserver(observe)}, opts...)...).Serve(proxyCtx, l)
		close(done)
	}()
	return func() error { cancel(); <-done; return serveErr }, nil
}

// ResolveInterpreter guesses the interpreter for a script from its extension or
// shebang, so a policy need not spell out what a `.py` file runs with. An empty
// result means the file is its own interpreter (a compiled binary).
func ResolveInterpreter(path string) string {
	switch filepath.Ext(path) {
	case ".py":
		return "python3"
	case ".sh", ".bash":
		return "bash"
	case ".js":
		return "node"
	case ".rb":
		return "ruby"
	}
	return shebang(path)
}

func shebang(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	var buf [256]byte
	n, _ := f.Read(buf[:])
	line, _, _ := strings.Cut(string(buf[:n]), "\n")
	if !strings.HasPrefix(line, "#!") {
		return ""
	}
	fields := strings.Fields(strings.TrimPrefix(line, "#!"))
	if len(fields) == 0 {
		return ""
	}
	// "#!/usr/bin/env python3" runs the interpreter named after env. env may be
	// given options first - notably `-S`/`--split-string`, the standard way a
	// shebang passes multiple args to the interpreter (`env -S python3 -u`) - and
	// NAME=VALUE assignments; the interpreter is the first field that is neither, not
	// simply fields[1] (which would be `-S`).
	if filepath.Base(fields[0]) == "env" {
		for _, f := range fields[1:] {
			// Skip env's leading options and NAME=VALUE assignments; an interpreter
			// (a path or a bare name) contains neither, so any '='-bearing word is an
			// assignment, matching env's own handling.
			if strings.HasPrefix(f, "-") || strings.Contains(f, "=") {
				continue
			}
			return f
		}
		return ""
	}
	return fields[0]
}
