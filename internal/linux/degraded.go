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
func (e *Enforcer) runDegraded(ctx context.Context, p *policy.Policy, proc enforce.Process) (enforce.Result, error) {
	report := e.Probe(ctx)

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
	// there is no mount namespace or deny-list to catch it afterward. Run them before
	// the MkdirAll below so a to-be-refused grant leaves no host directory artifact.
	if err := checkGrants(sb, p, reads, writes); err != nil {
		return enforce.Result{}, err
	}
	// Report the same explicit shield opt-ins the full tier does, named by their literal
	// deny-list path. The degraded tier cannot carve a shield out of a read grant at all,
	// so it exposes them regardless; surfacing the opted-in ones keeps its warning
	// consistent with the full tier's.
	optedIn, optIns := explicitShieldOptIns(sb, p.Read)
	// Write grants are prepared exactly as the bwrap tier prepares them, through the
	// same function: a missing directory is created so Landlock has a path to grant
	// (its rules skip a path that does not exist), and a grant naming an existing FILE
	// is refused rather than accepted. Sharing it is what keeps one manifest from
	// meaning two things - this tier used to accept a file grant the full tier
	// refuses, and to MkdirAll a directory on the host at a path the policy meant as a
	// file. Landlock still cannot carve a shielded subpath out of an allowed tree, so a
	// read grant containing a credential dir exposes it: the documented cost of this
	// tier, and why a broad read here is weaker than under bwrap.
	if err := prepareWriteDirs(p, sb); err != nil {
		return enforce.Result{}, err
	}

	// With the write dirs now present (so the same Workspace/gitDir shields the full tier
	// would carve are discovered), record which always-on shields a bwrap run would have
	// engaged among the paths THIS tier actually exposes - its Landlock read/write set,
	// sysReads + reads + writes. The degraded tier applies none of them (no mount
	// namespace), so they are exposed, not hidden, and the audit says so rather than
	// reporting an empty shield set for a run that shielded nothing. Scoping to the real
	// exposure, not the full tier's exposedPaths, keeps the warning tied to what this tier
	// actually makes readable - which now includes the interpreter prefix added below, so
	// a credential store inside one IS reported here. That is the honest answer: the full
	// tier binds a shield over it, and Landlock cannot carve one out of a granted tree.
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

	exposed := exposedShields(sb, concat(sysReads, reads, writes), writes, optIns)

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
	env := envSlice(proc.Env)
	var stripEnv []string
	scoped := false
	if !p.Limits.IsZero() {
		if ok, _ := canCreateScope(); ok {
			env, stripEnv = withScopeBusVars(env, proc.Env)
			// Preflight with the environment the real command will get: a probe run with
			// the enforcer's own environment would find the bus even when the sanitized
			// one cannot, and the failure would then surface as systemd-run's exit code
			// for a target that never ran.
			if err := preflightLimits(p.Limits, env); err != nil {
				return enforce.Result{}, fmt.Errorf("linux: %w", err)
			}
			scoped = true
		}
	}

	// The degraded stage reports what it applied through this file, as the bwrap tier
	// does. It matters more here: every fence in this tier is the only one of its kind,
	// so a stage that died before applying them ran nothing confined, and the report
	// must not describe a shielded run.
	appliedReport, dropApplied, err := newAppliedReport()
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
		Target:      degradedTarget(sb.interpreter, sb.entrypoint, p.Args),
	}

	// A scope execs its command in place, so the launcher stays the leader of the group
	// set below and the process-group sweep still reaches anything it leaks.
	exe, cargs := sb.bentoPath, launcher.EncodeLaunchDegraded(cfg)
	if scoped {
		exe, cargs = wrapWithLimits(exe, cargs, p.Limits)
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
	switch {
	case cmd.ProcessState == nil:
		// The launcher never started or exec failed - a genuine setup failure.
		return enforce.Result{Report: report}, fmt.Errorf("linux: running degraded sandbox: %w", err)
	case err == nil, isExitError(err), errors.Is(err, exec.ErrWaitDelay):
		// The target ran to completion; its exit code is authoritative even when a
		// leaked descendant held the pipes past WaitDelay.
		code := exitCodeOf(cmd.ProcessState)
		parseApplied(appliedReport.Name()).reconcile(&report, p.Exec != policy.ExecAll, p.Exec == policy.ExecNoneStrict, code)
		return enforce.Result{ExitCode: code, Report: report, ShieldedGrants: optedIn, ShieldedGrantTargets: shieldGrantTargets(optedIn, optIns), Exposed: exposed}, nil
	default:
		return enforce.Result{Report: report}, fmt.Errorf("linux: running degraded sandbox: %w", err)
	}
}

// exitCodeOf maps a finished process's status to a conventional exit code: a
// signal-killed target reports 128+signal, matching the bwrap and supervise paths
// (and what a shell returns). os.ProcessState.ExitCode returns -1 for a signal, which
// would otherwise surface to the caller as 255.
func exitCodeOf(st *os.ProcessState) int {
	if ws, ok := st.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return st.ExitCode()
}

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
// runtime opens to initialize - /dev/urandom for entropy, /dev/null and /dev/zero
// for the usual stream sinks. These are read-only except /dev/null, which is
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
	if _, err := os.Stat("/nix"); err == nil {
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

// degradedTarget builds the command to run: the interpreter (when set) followed by
// the entrypoint and its args, matching how the bwrap tier launches a script.
func degradedTarget(interp, entrypoint string, args []string) []string {
	var t []string
	if interp != "" {
		t = append(t, interp)
	}
	t = append(t, entrypoint)
	return append(t, args...)
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
