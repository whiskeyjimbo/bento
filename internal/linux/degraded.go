//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/launcher"
	"github.com/whiskeyjimbo/bento/internal/shield"
	"github.com/whiskeyjimbo/bento/policy"
)

// runDegraded runs the target under the no-bwrap Landlock-only tier: bento re-exec'd
// as a DIRECT child (no bubblewrap) that applies Landlock filesystem confinement plus
// the seccomp exec- and egress-blocks. It is selected only for a run admitted under
// --allow-degraded on a userns-blocked host; the caller (enforce.admit) has already
// refused anything that needs egress - a network manifest or a supervising gate, both
// of which require LayerNetwork, which is Unavailable without a netns - so this path
// only ever runs a policy with no egress at all.
//
// Without a mount namespace the whole host filesystem is visible, so the Landlock
// read set must name everything the target may touch: the interpreter's runtime and
// CA bundle (systemReadPaths), the granted reads, and the entrypoint/interpreter as
// executables. It is the same source the bwrap binds draw on, so the two tiers grant
// the same paths - the difference is the mechanism, not the policy.
func (e *Enforcer) runDegraded(ctx context.Context, p *policy.Policy, proc enforce.Process, runID string, acceptAliasesUnder []string) (enforce.Result, error) {
	report := e.degradedProbe(ctx)

	// Resolve the sandbox facts the grant checks need (home shields, the resolve/isDir
	// seams) along with the entrypoint and interpreter. gated is false: the degraded
	// tier is only reached for a no-network manifest, so there is no proxy socket.
	sb, cleanup, err := newSandbox(p, e.selfPath, false, nil)
	if err != nil {
		return enforce.Result{}, err
	}
	defer cleanup()

	reads, writes, err := resolveGrants(sb, p)
	if err != nil {
		return enforce.Result{}, err
	}
	// The degraded tier shares the full tier's grant-safety checks. Without them
	// --allow-degraded would accept a manifest the full tier hard-refuses - write: ~
	// above the ~/.ssh shield, read: /proc onto the host process table - and here
	// there is no mount namespace or deny-list to catch it afterward. They and the
	// alias scan below run before prepareWriteDirs, so a to-be-refused grant leaves no
	// host directory artifact.
	if err := checkGrants(sb, p, reads, writes); err != nil {
		return enforce.Result{}, err
	}
	// The one grant check this tier does not share, because it is the one the full tier's
	// bind ordering genuinely enforces and this tier has no way to.
	if err := checkWriteNotAboveWriteShield(sb, writes); err != nil {
		return enforce.Result{}, err
	}
	// Report the same explicit shield opt-ins the full tier does, named by their literal
	// deny-list path. The degraded tier cannot carve a shield out of a read grant at all,
	// so it exposes them regardless; surfacing the opted-in ones keeps its warning
	// consistent with the full tier's.
	optIns := explicitShieldOptIns(sb, p.Read)
	// The paths THIS tier actually exposes - its Landlock read/write set, sysReads +
	// reads + writes - which both the alias scan and the shield report below run over.
	// Scoping to the real exposure, not the full tier's exposedPaths, keeps them tied to
	// what this tier actually makes readable.
	sysReads, sysWrites := degradedSystemPaths(sb)
	// An interpreter outside the system paths (pyenv, mise, conda) needs its install
	// prefix readable or it cannot load its stdlib. The launcher grants the interpreter
	// FILE (it is an exec path), so the binary starts - and then fails on the first
	// stdlib read. The bwrap tier ro-binds the whole prefix; without the same grant here
	// a manifest profiled for such a runtime cannot run, and Synthesize strips the
	// runtime tree from proposals, so the manifest never carries a read grant for it.
	// Added before the exposure scan below, so a credential under the prefix is reported
	// rather than silently readable. On a Nix host this repeats the /nix grant
	// degradedSystemPaths already makes; a duplicate Landlock rule is harmless.
	if extra := interpreterReadPath(sb); extra != "" {
		sysReads = append(sysReads, extra)
	}

	visible := concat(sysReads, reads, writes)

	// The same refusal the bwrap tier makes before launch, over this tier's own visible
	// set. Landlock consults an inode's names no more than a bind does, so without it a
	// hardlink to ~/.ssh/id_ed25519 inside a granted tree is readable here while the
	// full tier refuses the run - one manifest meaning two things, in the direction
	// that hands over a credential nobody opted into. It runs over the write grants
	// before they exist, as the bwrap tier's does: a directory that has just been
	// created holds no alias, so the verdict is the same either way, and refusing first
	// is what keeps a refused run from leaving one behind.
	accepted, err := checkAliasedCredentials(sb, visible, optInPaths(optIns), acceptAliasesUnder)
	if err != nil {
		return enforce.Result{}, err
	}

	// Write grants are prepared exactly as the bwrap tier prepares them, through the
	// same function: a missing directory is created so Landlock has a path to grant
	// (its rules skip a path that does not exist), and a grant naming an existing FILE
	// is refused rather than accepted. Sharing it is what keeps one manifest from
	// meaning two things - this tier used to accept a file grant the full tier
	// refuses, and to MkdirAll a directory on the host at a path the policy meant as a
	// file. Landlock still cannot carve a shielded subpath out of an allowed tree, so a
	// read grant containing a credential dir exposes it: the documented cost of this
	// tier, and why a broad read here is weaker than under bwrap.
	// The tier with no mount namespace and no shields at all is the one where knowing
	// which auto-executing file a run changed matters most, so the snapshot is taken here
	// too rather than only on the bwrap path - and after prepareWriteDirs, matching the
	// full tier, so a directory created for a grant is in the baseline rather than reading
	// as a change the target made. The ordering matters twice over now that the baseline
	// also resolves core.hooksPath: run against a grant whose directory does not exist
	// yet, git answers nothing and the empty answer would be the one frozen for the run.
	if err := prepareWriteDirs(p, sb); err != nil {
		return enforce.Result{}, err
	}
	autoExecBefore := baselineAutoExec(writes)

	// With the write dirs now present (so the same Workspace/gitDir shields the full tier
	// would carve are discovered), record which always-on shields a bwrap run would have
	// engaged among the exposed paths. The degraded tier applies none of them (no mount
	// namespace), so they are exposed, not hidden, and the audit says so rather than
	// reporting an empty shield set for a run that shielded nothing. The set includes the
	// interpreter prefix, so a credential store inside one IS reported here. That is the
	// honest answer: the full tier binds a shield over it, and Landlock cannot carve one
	// out of a granted tree.
	exposed := exposedShields(sb, visible, writes, shield.Targets(optIns))

	// A fresh scratch dir stands in for the bwrap tier's tmpfs /tmp: granted writable
	// and exported as TMPDIR, so a target's temp files have a home without exposing the
	// host /tmp (and other tenants' scratch), which the read/write set excludes.
	dir, err := os.MkdirTemp("", "bento-degraded-")
	if err != nil {
		return enforce.Result{}, fmt.Errorf("linux: creating run directory: %w", err)
	}
	defer os.RemoveAll(dir)
	scratch := filepath.Join(dir, "tmp")
	if err := os.MkdirAll(scratch, 0o700); err != nil {
		return enforce.Result{}, fmt.Errorf("linux: creating scratch directory: %w", err)
	}

	execPaths := []string{sb.entrypoint}
	if sb.interpreter != "" {
		execPaths = append(execPaths, sb.interpreter)
	}
	// The launcher runs with the sanitized policy environment, which has none of the
	// session-bus variables systemd-run needs to reach the user manager - so add them
	// here and have the launcher drop them again before exec. Without limits nothing is
	// added and the run is unchanged.
	env := envSlice(sandboxEnv(proc.Env, scratch))
	var stripEnv []string
	scoped := false
	if !p.Limits.IsZero() {
		if ok, _ := canCreateScope(ctx); ok {
			env, stripEnv = withScopeBusVars(env, proc.Env)
			// Preflight with the environment the real command will get: a probe run with
			// the enforcer's own environment would find the bus even when the sanitized
			// one cannot, and the failure would then surface as systemd-run's exit code
			// for a target that never ran.
			if err := preflightLimits(ctx, p.Limits, env); err != nil {
				return enforce.Result{}, fmt.Errorf("linux: %w", err)
			}
			scoped = true
		}
	}

	// The degraded stage reports what it applied through this file, as the bwrap tier
	// does. It matters more here: every fence in this tier is the only one of its kind,
	// so a stage that died before applying them ran nothing confined, and the report
	// must not describe a shielded run.
	appliedReport, dropApplied, err := newAppliedReport(dir)
	if err != nil {
		return enforce.Result{}, err
	}
	defer dropApplied()

	block, strictBlock := execBlockFlags(p.Exec, seccompSupported())
	cfg := launcher.DegradedConfig{
		Readable:    concat(sysReads, reads),
		Writable:    concat(sysWrites, writes, []string{scratch}),
		ExecPaths:   execPaths,
		Block:       block,
		StrictBlock: strictBlock,
		Scratch:     scratch,
		StripEnv:    stripEnv,
		AppliedFD:   appliedReportFD,
		Target:      command(p, sb),
	}

	// A scope execs its command in place, so the launcher stays the leader of the group
	// set below and the process-group sweep still reaches anything it leaks.
	exe, cargs := sb.bentoPath, launcher.EncodeLaunchDegraded(cfg)
	if scoped {
		exe, cargs = wrapWithLimits(exe, cargs, p.Limits, runID)
	}
	if err := checkLauncher(sb.bentoPath); err != nil {
		return enforce.Result{}, err
	}
	cmd := exec.CommandContext(ctx, exe, cargs...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = proc.Stdin, proc.Stdout, proc.Stderr
	// Run the launcher in its own process group so a descendant it leaves behind can be
	// swept on teardown. Without a PID namespace this is the only sweep available, and
	// it is best-effort - a descendant that calls setsid() escapes the group and
	// survives, which the degraded report discloses. The default ctx-cancel kill hits
	// only the launcher pid, so Cancel is overridden to kill the whole group too.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return killProcessGroup(cmd.Process) }
	// A descendant the target backgrounds inherits the stdout/stderr pipes and, with no
	// PID namespace, is not torn down when the target exits - so cmd.Wait would block
	// on the open pipes until that descendant dies. WaitDelay bounds that: once the
	// target exits, Wait waits this long for the pipes, then closes them and returns so
	// the group sweep below can reap the straggler.
	cmd.WaitDelay = 2 * time.Second
	// Placed at FD appliedReportFD in the launcher, surviving the systemd-run scope
	// wrapper above; the launcher marks it close-on-exec so the target never sees it.
	cmd.ExtraFiles = []*os.File{appliedReport}

	err = cmd.Run()
	_ = killProcessGroup(cmd.Process)
	// See the same guard in Run: a cancel kills the launcher group and the signalled
	// status it leaves is indistinguishable from the policy's limits ending the target.
	// An ordinary exit status is not that kill: on the supervise path the launcher
	// outlives the target and reports even a signalled one as 128+signal of its own, so
	// a cancel landing after that status does not unmake it. On the exec-block path the
	// launcher execveats the target over itself and there is nothing left to convert, so
	// a target that dies of its own signal inside the cancel window is read as the
	// cancel - the same conservative direction the guard takes everywhere else.
	if err != nil && ctx.Err() != nil && killedByCancel(cmd.ProcessState) {
		// Carried out through the cancel for the reason the full tier's is: a target killed
		// partway is the run least likely to be looked at and most likely to have left an
		// auto-executing file behind.
		changedAuto, redirected := autoExecBefore.changed(writes)
		// The exposure audit is carried out with them: this tier's whole honesty rests on
		// Exposed naming what it could not shield, and the target reached those credentials
		// whether or not it lived to finish. Dropping the list here reports a cancelled run
		// as having exposed nothing.
		return enforce.Result{Report: report, ShieldedGrants: reportedOptIns(optIns), Exposed: exposed, AcceptedAliases: reportedAliases(accepted), ChangedAutoExec: changedAuto, RedirectedHooks: redirected}, fmt.Errorf("linux: the run was cancelled before the target finished: %w", ctx.Err())
	}
	switch {
	case cmd.ProcessState == nil:
		// The launcher never started or exec failed - a genuine setup failure.
		return enforce.Result{Report: report}, fmt.Errorf("linux: running degraded sandbox: %w", err)
	case err == nil, isExitError(err), errors.Is(err, exec.ErrWaitDelay):
		// The target ran to completion; its exit code is authoritative even when a
		// leaked descendant held the pipes past WaitDelay.
		code, signaled, sig := exitStatusOf(cmd.ProcessState)
		setup := parseApplied(appliedReport).reconcile(&report, block, strictBlock, false, code)
		changedAuto, redirected := autoExecBefore.changed(writes)
		return enforce.Result{ExitCode: code, Signaled: signaled, Signal: sig, Report: report, Setup: setup, ShieldedGrants: reportedOptIns(optIns), Exposed: exposed, AcceptedAliases: reportedAliases(accepted), ChangedAutoExec: changedAuto, RedirectedHooks: redirected}, nil
	default:
		// As on the cancel arm above: the target may already have run, so these are the only
		// things on this path that say what the host now holds and what it was left reachable.
		changedAuto, redirected := autoExecBefore.changed(writes)
		return enforce.Result{Report: report, ShieldedGrants: reportedOptIns(optIns), Exposed: exposed, AcceptedAliases: reportedAliases(accepted), ChangedAutoExec: changedAuto, RedirectedHooks: redirected}, fmt.Errorf("linux: running degraded sandbox: %w", err)
	}
}

// killedByCancel reports whether a cancel is the better reading of how a run ended,
// for a run whose context was cancelled and whose command failed. A signalled status is
// ambiguous - the cancel's own kill and the policy's limits both produce it - and is
// read as the cancel, which is the conservative half: it withholds a result rather than
// attributing one. Anything else is read as the target's, because both tiers turn a
// signalled target into an ordinary 128+signal exit code, so an exit status reaching
// here is one the wrapper chose to report after the target finished. That leaves a
// narrow race where the launcher had already computed the status when the group kill
// landed; the status it reports is still the target's.
//
// No status at all means the command never started, where the cancel is all there is
// to say.
func killedByCancel(st *os.ProcessState) bool {
	if st == nil {
		return true
	}
	_, signaled, _ := exitStatusOf(st)
	return signaled
}

// exitStatusOf maps a finished process's status to a conventional exit code, plus
// whether a signal ended it: a signal-killed process reports 128+signal, matching what
// bwrap does for a signaled target and what a shell returns. os.ProcessState.ExitCode
// returns -1 for a signal, which would otherwise surface to the caller as 255.
//
// The signal travels alongside the code because 128+N is not recoverable from it - a
// process can exit 137 of its own accord - and a frontend explaining the death needs
// the two apart.
func exitStatusOf(st *os.ProcessState) (code int, signaled bool, sig int) {
	if ws, ok := st.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal()), true, int(ws.Signal())
	}
	return st.ExitCode(), false, 0
}

// degradedProbe is the host probe corrected to what THIS TIER can enforce. The probe
// answers what the host supports, and on a host where bwrap works it answers a full
// sandbox - which this tier is not, whichever way it was selected. Reporting the probe
// raw attested LayerFilesystem Enforced and LayerNetwork Enforced for a run with no mount
// namespace, no netns and no shields, and reconcile only worsens, so nothing downstream
// caught it. The CLI reaches this tier only on a userns-blocked host, where the probe
// already says both; Run is exported and an embedder can set Degraded on any host, which
// is the same reason screenRunID re-screens what admission already checked.
//
// Only these two layers. The exec and limits layers are measurements of the host that
// hold on this tier too - the launcher installs the same seccomp filters and wraps the
// same systemd scope - and are left as the probe found them.
func (e *Enforcer) degradedProbe(ctx context.Context) enforce.Report {
	r := e.Probe(ctx)
	// Rebuilt through filesystemLayer rather than patched, so this tier's verdict and its
	// disclosure of what it does not confine are the same text the userns-blocked host
	// gets - one account of the tier, not two that can drift.
	if r.StateOf(enforce.LayerFilesystem) < enforce.Degraded {
		r.SetStatus(filesystemLayer(namespacesBlocked, degradedTierReason, landlockAvailable(),
			landlockTruncateRestricted(), landlockIoctlDevRestricted(), landlockResolveUnixRestricted(),
			landlockScopedIPCRestricted(), seccompSupported() && seccompEgressSupported()))
	}
	if r.StateOf(enforce.LayerNetwork) < enforce.Unavailable {
		r.Set(enforce.LayerNetwork, enforce.Unavailable, degradedTierReason+
			", so there is no network namespace to fence egress into; the launcher blocks IP egress with seccomp instead, which does not confine what a netns confines")
	}
	return r
}

// degradedTierReason opens both corrected layers. It states the selection rather than a
// host defect, because on the path this correction exists for the host has no defect: the
// caller asked for this tier.
const degradedTierReason = "this run was launched on the reduced-confinement tier, which uses no namespaces at all"

// killProcessGroup SIGKILLs every process still in the launcher's group. The
// negative pid targets the group (the launcher is its leader via Setpgid). ESRCH -
// the group is already empty, the common case where the target left nothing behind -
// is expected and ignored. A missing or zero pid means there is no group to sweep,
// and must not reach Kill: -0 is the *caller's* group, so the launcher would SIGKILL
// itself and everything sharing its group.
func killProcessGroup(p *os.Process) error {
	if p == nil || p.Pid <= 0 {
		return nil
	}
	if err := syscall.Kill(-p.Pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
		return err
	}
	return nil
}

// degradedSystemPaths are the host paths every degraded run needs regardless of the
// policy: the FHS interpreter/library/CA locations (systemReadPaths), the Nix store
// when present (on NixOS the interpreter and its whole library closure live there,
// so the bwrap tier binds it and this tier must grant it), and the device nodes a
// runtime opens to initialize - /dev/urandom and /dev/random for entropy, /dev/null and
// /dev/zero for the usual stream sinks. These are read-only except /dev/null, which is
// read-write. They are host paths, not a fresh /dev: another cost of having no mount
// namespace, and part of why the tier is materially weaker.
//
// Every path is resolved through the sandbox's resolver, as grants are. These are raw
// literals and several are commonly symlinks - /dev/urandom and the FHS lib paths on a
// usrmerge host, /nix on some Nix setups. go-landlock opens a path without O_NOFOLLOW,
// so the rule it installs already lands on the resolved target; resolving here is what
// makes bento's own record of the read set name the same paths, so the exposure scan
// that runs over it sees what was actually granted rather than the name it was granted
// under.
func degradedSystemPaths(sb sandbox) (reads, writes []string) {
	resolved := func(paths ...string) []string {
		out := make([]string, 0, len(paths))
		for _, p := range paths {
			out = append(out, sb.resolve(p))
		}
		return out
	}
	reads = resolved(systemReadPaths...)
	if sb.exists("/nix") {
		reads = append(reads, sb.resolve("/nix"))
	}
	reads = append(reads, resolved("/dev/urandom", "/dev/random", "/dev/zero")...)
	return reads, resolved("/dev/null")
}

// concat joins path lists into a fresh slice, so a caller's append never aliases a
// shared backing array.
func concat(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

// envSlice renders the resolved environment map as KEY=VALUE pairs. The target sees
// only what the policy declared, not the host environment the enforcer runs in.
func envSlice(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	return out
}
