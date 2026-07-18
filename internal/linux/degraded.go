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

	"github.com/whiskeyjimbo/bento-v2/enforce"
	"github.com/whiskeyjimbo/bento-v2/internal/launcher"
	"github.com/whiskeyjimbo/bento-v2/internal/seccomp"
	"github.com/whiskeyjimbo/bento-v2/policy"
)

// runDegraded runs the target under the no-bwrap Landlock-only tier: bento re-exec'd
// as a DIRECT child (no bubblewrap) that applies Landlock filesystem confinement plus
// the seccomp exec- and egress-blocks. It is selected only for a run admitted under
// --allow-degraded on a userns-blocked host; the caller (enforce.admit) has already
// refused a network manifest (LayerNetwork is Unavailable without a netns), so this
// path only ever runs a no-network policy.
//
// Without a mount namespace the whole host filesystem is visible, so the Landlock
// read set must name everything the target may touch: the interpreter's runtime and
// CA bundle (systemReadPaths), the granted reads, and the entrypoint/interpreter as
// executables. It is the same source the bwrap binds draw on, so the two tiers grant
// the same paths - the difference is the mechanism, not the policy.
func (e *Enforcer) runDegraded(ctx context.Context, p *policy.Policy, proc enforce.Process) (enforce.Result, error) {
	report := e.Probe(ctx)

	entrypoint, err := resolve(p.Entrypoint)
	if err != nil {
		return enforce.Result{}, err
	}
	if _, err := os.Stat(entrypoint); err != nil {
		return enforce.Result{}, fmt.Errorf("linux: entrypoint %q: %w", p.Entrypoint, err)
	}
	var interp string
	if p.Interpreter != "" {
		found, err := exec.LookPath(p.Interpreter)
		if err != nil {
			return enforce.Result{}, fmt.Errorf("linux: interpreter %q not found: %w", p.Interpreter, err)
		}
		if interp, err = resolve(found); err != nil {
			return enforce.Result{}, err
		}
	}

	reads, writes, err := resolveGrants(p)
	if err != nil {
		return enforce.Result{}, err
	}
	// A write grant is a directory the target writes into; create a missing one so
	// Landlock has a path to grant (RWDirs skips a path that does not exist). There is
	// no deny-list here: Landlock cannot carve a shielded subpath out of an allowed
	// tree, so the credential shielding the bwrap tier provides does not apply - the
	// documented cost of the degraded tier, not an oversight.
	for _, w := range writes {
		if _, err := os.Stat(w); errors.Is(err, os.ErrNotExist) {
			if err := os.MkdirAll(w, 0o755); err != nil {
				return enforce.Result{}, fmt.Errorf("linux: creating write directory %q: %w", w, err)
			}
		}
	}

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

	execPaths := []string{entrypoint}
	if interp != "" {
		execPaths = append(execPaths, interp)
	}
	sysReads, sysWrites := degradedSystemPaths()
	block, strictBlock := execBlockFlags(p.Exec, seccomp.Supported())
	cfg := launcher.DegradedConfig{
		Readable:    concat(sysReads, reads),
		Writable:    concat(sysWrites, writes, []string{scratch}),
		ExecPaths:   execPaths,
		Block:       block,
		StrictBlock: strictBlock,
		Scratch:     scratch,
		Target:      degradedTarget(interp, entrypoint, p.Args),
	}

	self, err := bentoSelfPath(e.selfPath)
	if err != nil {
		return enforce.Result{}, err
	}
	cmd := exec.CommandContext(ctx, self, launcher.EncodeLaunchDegraded(cfg)...)
	cmd.Env = envSlice(proc.Env)
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

	err = cmd.Run()
	killProcessGroup(cmd.Process)
	switch {
	case cmd.ProcessState == nil:
		// The launcher never started or exec failed - a genuine setup failure.
		return enforce.Result{Report: report}, fmt.Errorf("linux: running degraded sandbox: %w", err)
	case err == nil, isExitError(err), errors.Is(err, exec.ErrWaitDelay):
		// The target ran to completion; its exit code is authoritative even when a
		// leaked descendant held the pipes past WaitDelay.
		return enforce.Result{ExitCode: cmd.ProcessState.ExitCode(), Report: report}, nil
	default:
		return enforce.Result{Report: report}, fmt.Errorf("linux: running degraded sandbox: %w", err)
	}
}

// killProcessGroup SIGKILLs every process still in the launcher's group. The
// negative pid targets the group (the launcher is its leader via Setpgid). ESRCH -
// the group is already empty, the common case where the target left nothing behind -
// is expected and ignored.
func killProcessGroup(p *os.Process) error {
	if p == nil {
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
func degradedSystemPaths() (reads, writes []string) {
	reads = append([]string{}, systemReadPaths...)
	if _, err := os.Stat("/nix"); err == nil {
		reads = append(reads, "/nix")
	}
	reads = append(reads, "/dev/urandom", "/dev/random", "/dev/zero")
	writes = []string{"/dev/null"}
	return reads, writes
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
