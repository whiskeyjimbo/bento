//go:build linux

package linux

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/landlock"
	"github.com/whiskeyjimbo/bento/internal/seccomp"
	"github.com/whiskeyjimbo/bento/policy"
)

// exposedShields is the pure computation behind Result.Exposed: the always-on shields a
// full bwrap run would have engaged, which the degraded tier records as exposed because
// it has no mount namespace to apply them. A credential store a read grant reaches must
// appear (with the kind the full tier would have used), an opted-in store must not (the
// operator chose to expose it, reported via ShieldedGrants), and a grant reaching no
// shield yields nothing. Kept off the requireDegraded gate so the audit logic is verified
// on any host, not only where the degraded tier is forced.
func TestExposedShieldsNamesReachableUnappliedShields(t *testing.T) {
	// The fake FS models a childless entry as a file, so place each credential file
	// under its store to make the store a directory the DenyAll shield keys off.
	sb := testSandbox("/home/u/.ssh", "/home/u/.ssh/id_rsa", "/home/u/.aws", "/home/u/.aws/credentials")
	for _, d := range []string{"/home/u/.ssh", "/home/u/.aws"} {
		if !sb.isDir(d) {
			t.Fatalf("fixture: %q is not a directory; the shield kind would differ", d)
		}
	}

	has := func(got []enforce.ShieldApplied, path, kind string) bool {
		return slices.ContainsFunc(got, func(s enforce.ShieldApplied) bool {
			return s.Path == path && s.Kind == kind
		})
	}

	// A broad home read reaches both stores; neither is opted in, so both are exposed
	// and named with the "hidden" kind the full tier would have applied.
	reads := []string{"/home/u"}
	_, optIns := explicitShieldOptIns(sb, reads)
	got := exposedShields(sb, reads, nil, optIns)
	if !has(got, "/home/u/.ssh", "hidden") || !has(got, "/home/u/.aws", "hidden") {
		t.Fatalf("broad home read: exposed = %v, want ~/.ssh and ~/.aws hidden", got)
	}

	// Opting into ~/.ssh drops it from the exposed audit: the operator chose that
	// exposure and it is reported through ShieldedGrants, not here. The grant reaches no
	// other shield, so the audit is empty.
	reads = []string{"/home/u/.ssh"}
	_, optIns = explicitShieldOptIns(sb, reads)
	if got := exposedShields(sb, reads, nil, optIns); len(got) != 0 {
		t.Fatalf("opt-in ~/.ssh: exposed = %v, want empty (opt-in surfaced via ShieldedGrants)", got)
	}

	// A read that reaches no shield exposes nothing, so the audit stays empty rather than
	// warning about credentials the run never made reachable.
	reads = []string{"/home/u/proj"}
	_, optIns = explicitShieldOptIns(sb, reads)
	if got := exposedShields(sb, reads, nil, optIns); len(got) != 0 {
		t.Fatalf("unrelated read: exposed = %v, want empty", got)
	}

	// A write grant on a checkout exposes its persistence surfaces - git hooks and editor
	// task dirs - which the full tier would make read-only. This exercises the DenyWrite ->
	// "read-only" kind, distinct from the hidden credential stores above, so a regression
	// that flattened every exposed record to "hidden" is caught.
	proj := testSandbox("/home/u/proj/.git/config", "/home/u/proj/.git/hooks/pre-commit")
	writes := []string{"/home/u/proj"}
	_, wOptIns := explicitShieldOptIns(proj, nil)
	if got := exposedShields(proj, writes, writes, wOptIns); !has(got, "/home/u/proj/.git/hooks", "read-only") {
		t.Fatalf("write grant on a checkout: exposed = %v, want .git/hooks read-only", got)
	}
}

// A signal-killed process must surface as 128+signal, matching the bwrap and supervise
// paths: the raw cmd.ProcessState.ExitCode() is -1 for a signal and would otherwise
// reach the caller as 255. The signal comes back beside the code because a target can
// exit 143 on its own, and only the flag separates the two. Verify against real
// processes.
func TestExitStatusOfMapsSignalToConvention(t *testing.T) {
	cmd := exec.Command("sh", "-c", "kill -TERM $$")
	_ = cmd.Run() // exits via SIGTERM; ProcessState is set regardless of the error
	code, signaled, sig := exitStatusOf(cmd.ProcessState)
	if code != 128+int(syscall.SIGTERM) || !signaled || sig != int(syscall.SIGTERM) {
		t.Errorf("signaled target: exitStatusOf = (%d, %v, %d), want (%d, true, %d)",
			code, signaled, sig, 128+int(syscall.SIGTERM), int(syscall.SIGTERM))
	}

	ok := exec.Command("sh", "-c", "exit 42")
	_ = ok.Run()
	if code, signaled, sig := exitStatusOf(ok.ProcessState); code != 42 || signaled || sig != 0 {
		t.Errorf("normal exit: exitStatusOf = (%d, %v, %d), want (42, false, 0)", code, signaled, sig)
	}
}

// The degraded (no-bwrap) tier must actually confine: a granted read works, an
// ungranted read is denied by Landlock, and an IP socket is refused by the seccomp
// egress block. The probe is a static (CGO-free) Go binary run as its own entrypoint
// under exec: none, so no interpreter or subprocess is involved.
func TestDegradedConfinesFilesystemAndEgress(t *testing.T) {
	requireDegraded(t)
	bin := buildDegradedProbe(t)

	grantedDir := t.TempDir()
	grantedFile := filepath.Join(grantedDir, "ok.txt")
	if err := os.WriteFile(grantedFile, []byte("granted-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	ungrantedFile := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(ungrantedFile, []byte("do-not-read"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{Entrypoint: bin, Read: []string{grantedDir}, Exec: policy.ExecNone}
	var out strings.Builder
	proc := enforce.Process{
		Stdout: &out, Stderr: &out,
		Env: map[string]string{"GRANTED": grantedFile, "UNGRANTED": ungrantedFile},
	}
	res, err := enforcerUsing(testBento(t)).runDegraded(context.Background(), p, proc, "")
	if err != nil {
		t.Fatalf("runDegraded: %v\noutput:\n%s", err, out.String())
	}
	got := out.String()
	for _, want := range []string{"GRANTED_READ_OK", "UNGRANTED_READ_DENIED", "SOCKET_BLOCKED", "EXEC_BLOCKED"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q; exit=%d output:\n%s", want, res.ExitCode, got)
		}
	}
}

// An interpreter run works under the degraded tier when its runtime is in a system
// location the read set covers (bash is in systemReadPaths on an FHS host, and under
// /nix on NixOS - both granted). The script reads a granted file with a shell
// redirect (no subprocess), so exec: none does not interfere.
func TestDegradedRunsInterpreterOnGrantedRead(t *testing.T) {
	requireDegraded(t)
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	data := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(data, []byte("degraded-file-content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "s.sh")
	if err := os.WriteFile(script, []byte(`read x < "$DATA"; echo "got=$x"`), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "bash", Read: []string{dir}, Exec: policy.ExecNone}
	var out strings.Builder
	proc := enforce.Process{Stdout: &out, Stderr: &out, Env: map[string]string{"DATA": data}}
	res, err := enforcerUsing(testBento(t)).runDegraded(context.Background(), p, proc, "")
	if err != nil {
		t.Fatalf("runDegraded: %v\noutput:\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "got=degraded-file-content") {
		t.Errorf("interpreter did not read the granted file; exit=%d output:\n%s", res.ExitCode, out.String())
	}
}

// An exec:all degraded run exercises the launcher's superviseTarget path (fork the
// target, reap it) with the cross-process seccomp block installed. It is the guard
// that the block refuses only pidfd_getfd, not the whole pidfd family - Go's child
// management uses pidfd_open/pidfd_send_signal, so over-blocking would break the
// launcher here and the exec:none tests (which execveat) would not catch it.
func TestDegradedExecAllSupervisesChild(t *testing.T) {
	requireDegraded(t)
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "s.sh")
	if err := os.WriteFile(script, []byte("echo parent-ran; exit 0"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "bash", Read: []string{dir}, Exec: policy.ExecAll}
	var out strings.Builder
	res, err := enforcerUsing(testBento(t)).runDegraded(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out}, "")
	if err != nil {
		t.Fatalf("exec:all degraded run failed (cross-process block may over-restrict pidfd): %v\noutput:\n%s", err, out.String())
	}
	if res.ExitCode != 0 || !strings.Contains(out.String(), "parent-ran") {
		t.Errorf("supervised child did not run cleanly: exit=%d output:\n%s", res.ExitCode, out.String())
	}
}

// runDegraded decides whether to install the exec-block from the REAL seccomp check
// (execBlockFlags(p.Exec, seccompSupported), degraded.go), the twin of the bwrap
// compile() call site that TestCompileReadsTheRealSeccompCheck covers. A host with
// seccomp cannot otherwise reach the fallback, so a runDegraded that hardcoded seccomp
// support would drop the block on a no-seccomp kernel while looking correct here. This
// drives the real degraded run and reads the effect on a subprocess: with seccomp the
// exec:none block stops it, and with the seam forced off the block is absent and it
// runs.
func TestRunDegradedExecBlockGatesOnRealSeccomp(t *testing.T) {
	requireDegraded(t)
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "s.sh")
	// An ABSOLUTE path to a reachable shell: the degraded tier sets no PATH (only the
	// policy's declared env), so a bare `sh` would fail the lookup and read as blocked
	// whether or not the exec filter is installed. /bin is in systemReadPaths, so the
	// only thing that can stop this execve is the block under test.
	spawn := "echo START; /bin/sh -c 'echo SUBPROCESS-RAN' 2>/dev/null || echo SUBPROCESS-BLOCKED; echo END"
	if err := os.WriteFile(script, []byte(spawn), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func() string {
		var out strings.Builder
		p := &policy.Policy{Entrypoint: script, Interpreter: "bash", Read: []string{dir}, Exec: policy.ExecNone}
		if _, err := enforcerUsing(testBento(t)).runDegraded(context.Background(),
			p, enforce.Process{Stdout: &out, Stderr: &out}, ""); err != nil {
			t.Fatalf("runDegraded: %v\noutput:\n%s", err, out.String())
		}
		return out.String()
	}

	// Positive control: with the real seccomp check the exec:none block engages and the
	// subprocess is refused, so the fallback below is caused by losing the capability.
	if base := run(); !strings.Contains(base, "SUBPROCESS-BLOCKED") {
		t.Fatalf("with seccomp present exec:none did not block the subprocess: %q", base)
	}

	swap(t, &seccompSupported, false)
	if got := run(); !strings.Contains(got, "SUBPROCESS-RAN") {
		t.Errorf("with seccomp forced unsupported runDegraded still installed the exec block: %q - it is not reading the check", got)
	}
}

// A process the target backgrounds and leaves running must be swept when the run
// ends: with no PID namespace to tear down, the enforcer runs the launcher in its
// own process group and SIGKILLs the group on teardown. The target records the
// background pid; after the run it must be dead.
func TestDegradedSweepsLeakedProcessGroup(t *testing.T) {
	requireDegraded(t)
	sleepBin, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep not available")
	}
	if resolved, err := filepath.EvalSymlinks(sleepBin); err == nil {
		sleepBin = resolved // the real binary, which the read set (systemReadPaths / /nix) covers
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")
	script := filepath.Join(dir, "s.sh")
	// Background a long sleep, record its pid, and exit - the sleep outlives the script.
	if err := os.WriteFile(script, []byte(`"$SLEEP" 300 & echo $! > "$PIDFILE"; echo backgrounded`), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "bash", Read: []string{dir}, Write: []string{dir}, Exec: policy.ExecAll}
	var out strings.Builder
	proc := enforce.Process{Stdout: &out, Stderr: &out, Env: map[string]string{"SLEEP": sleepBin, "PIDFILE": pidFile}}
	if _, err := enforcerUsing(testBento(t)).runDegraded(context.Background(), p, proc, ""); err != nil {
		t.Fatalf("runDegraded: %v\noutput:\n%s", err, out.String())
	}

	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("no background pid recorded (did the run reach the script?): %v\noutput:\n%s", err, out.String())
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("bad pid %q: %v", data, err)
	}
	// The sweep SIGKILLs the group; the leaked sleep should die and be reaped shortly.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
			return // gone
		}
		if time.Now().After(deadline) {
			t.Fatalf("backgrounded pid %d survived the run; the process-group sweep did not reach it", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The degraded tier must apply the same grant-safety checks as the full tier: a write
// grant that contains the ~/.ssh credential shield is refused, not silently accepted.
// Without a mount namespace or deny-list here, accepting it would hand the whole home -
// including ~/.ssh - to Landlock read-write, an escape the full tier hard-refuses via
// checkWriteNotAboveShield. The check fires before any exec, so no real kernel is
// needed and no host directory is created for the refused grant.
func TestDegradedRefusesWriteAboveShield(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(t.TempDir(), "entry.sh")
	if err := os.WriteFile(entry, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: entry, Write: []string{home}, Exec: policy.ExecNone}
	_, err := enforcerUsing("/bin/true").runDegraded(context.Background(), p, enforce.Process{}, "")
	if err == nil || !strings.Contains(err.Error(), "always-shielded") {
		t.Fatalf("degraded tier must refuse a write grant above the ~/.ssh shield; got err=%v", err)
	}
}

// A grant onto a whole managed pseudo-filesystem is refused in the degraded tier too.
// With no pid namespace and no fresh /proc, a read: /proc grant would serve the host's
// process table (environ of same-uid processes: tokens, DB passwords), so the full
// tier's checkGrantNotManagedMount refusal must hold here as well.
func TestDegradedRefusesManagedMountGrant(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	entry := filepath.Join(t.TempDir(), "entry.sh")
	if err := os.WriteFile(entry, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: entry, Read: []string{"/proc"}, Exec: policy.ExecNone}
	_, err := enforcerUsing("/bin/true").runDegraded(context.Background(), p, enforce.Process{}, "")
	if err == nil || !strings.Contains(err.Error(), "pseudo-filesystem") {
		t.Fatalf("degraded tier must refuse a whole-/proc grant; got err=%v", err)
	}
}

func requireDegraded(t *testing.T) {
	t.Helper()
	if !landlock.Available() {
		t.Skip("Landlock not available on this kernel")
	}
	if !seccomp.EgressSupported() {
		t.Skip("seccomp egress block not implemented for this architecture")
	}
}

// buildDegradedProbe compiles a static Go binary that reports whether a granted read
// succeeds, an ungranted read is denied, and an IP socket is refused. Static (CGO
// off) so it needs no libc in the read set.
func buildDegradedProbe(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		skipMissingDep(t, "go toolchain not available to build the probe")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "probe.go")
	const prog = `package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func main() {
	if _, err := os.ReadFile(os.Getenv("GRANTED")); err == nil {
		fmt.Println("GRANTED_READ_OK")
	} else {
		fmt.Println("GRANTED_READ_FAIL", err)
	}
	if _, err := os.ReadFile(os.Getenv("UNGRANTED")); err != nil {
		fmt.Println("UNGRANTED_READ_DENIED")
	} else {
		fmt.Println("UNGRANTED_READ_LEAK")
	}
	if fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0); err == syscall.EPERM {
		fmt.Println("SOCKET_BLOCKED")
	} else if err == nil {
		syscall.Close(fd)
		fmt.Println("SOCKET_NOT_BLOCKED")
	} else {
		fmt.Println("SOCKET_ERR", err)
	}
	if err := exec.Command("/bin/true").Run(); err != nil {
		fmt.Println("EXEC_BLOCKED")
	} else {
		fmt.Println("EXEC_NOT_BLOCKED")
	}
}
`
	if err := os.WriteFile(src, []byte(prog), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "probe")
	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0", "HOME="+toolchainHome)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building degraded probe: %v\n%s", err, out)
	}
	return bin
}

// exec: none-strict is the one guarantee whose availability is decided at COMPILE
// time rather than probed: the none-strict filter is written for amd64 and every
// other architecture gets a stub reporting it unsupported. So on arm64 this layer
// vanishes for a reason no probe can discover at runtime, and what a manifest
// asking for it gets must be a decision rather than an accident of build tags.
//
// The decision this pins: --strict refuses, naming the layer, and the target does
// not run; the default posture runs it, because exec-strict is hardening tier and
// the execve block underneath it still holds. Every other --strict assertion over
// a real Enforcer covers the limits layer, so without this the exec-strict half of
// the refusal path was proven only against a synthetic Report.
func TestRealProbeRefusesStrictExecUnderStrictWhenUnsupported(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	script := filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(script, []byte("echo RAN\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	e := sandboxEnforcer(t)
	run := func(opts enforce.Options) (string, error) {
		var out strings.Builder
		_, err := enforce.Run(context.Background(), e,
			&policy.Policy{
				Entrypoint:  script,
				Interpreter: "sh",
				Read:        []string{dir},
				Exec:        policy.ExecNoneStrict,
			},
			enforce.Process{Stdout: &out, Stderr: &out}, opts)
		return out.String(), err
	}

	// A positive control: this host must run the same policy under --strict while the
	// filter IS available, or the refusal below would be some other shortfall talking
	// and would hold for a Probe that never consults the strict-exec check at all.
	if out, err := run(enforce.Options{Strict: true}); err != nil {
		t.Skipf("this host cannot run a none-strict policy under --strict anyway (%v, out=%q), so losing the filter proves nothing", err, out)
	}

	swap(t, &seccompStrictExecSupported, false)

	out, err := run(enforce.Options{Strict: true})
	var refusal *enforce.Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("want a Refusal driven by the real probe, got err=%v out=%q", err, out)
	}
	named := false
	for _, l := range refusal.Short {
		if l.Layer == enforce.LayerExecStrict {
			named = true
		}
	}
	if !named {
		t.Errorf("the refusal must name the exec-strict layer that fell short; got %v", refusal.Short)
	}
	if strings.Contains(out, "RAN") {
		t.Error("a refused run must not execute the target")
	}

	// The other half of the decision: without --strict the run proceeds, because the
	// execve block is still enforced and only the strict extra is missing. Asserting
	// it here is what makes the refusal above a posture rather than a host that
	// refuses everything.
	if out, err := run(enforce.Options{}); err != nil || !strings.Contains(out, "RAN") {
		t.Errorf("the default posture must run with only the hardening-tier extra missing; got err=%v out=%q", err, out)
	}
}

// One manifest must mean one thing in both tiers. The "a write grant naming an
// existing file is refused" rule lived in the bwrap argv builder and in the full
// tier's own preparation, never in checkGrants, so the degraded tier accepted the
// same grant and granted RWFiles. Both tiers now prepare write grants through
// prepareWriteDirs: an existing file is refused in the same words, and a grant for a
// path that does not exist yet is created as a directory - which is what a write
// grant means, in both tiers, rather than each deciding for itself.
func TestDegradedRefusesFileWriteGrantLikeTheFullTier(t *testing.T) {
	requireDegraded(t)

	dir := t.TempDir()
	existing := filepath.Join(dir, "state.json")
	if err := os.WriteFile(existing, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: buildDegradedProbe(t), Write: []string{existing}, Exec: policy.ExecNone}

	var out strings.Builder
	_, err := enforcerUsing(testBento(t)).runDegraded(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out}, "")
	if err == nil {
		t.Fatal("the degraded tier accepted a write grant naming an existing file; the full tier refuses it")
	}
	if !strings.Contains(err.Error(), "grant its parent directory instead") {
		t.Errorf("refusal should be the full tier's own message, got %v", err)
	}

	// The not-yet-existing case: created as a directory, the same as under bwrap.
	absent := filepath.Join(dir, "unborn.json")
	p.Write = []string{absent}
	if _, err := enforcerUsing(testBento(t)).runDegraded(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out}, ""); err != nil {
		t.Fatalf("a write grant for a not-yet-existing path should still be prepared: %v", err)
	}
	if fi, err := os.Stat(absent); err == nil && !fi.IsDir() {
		t.Errorf("%s exists but is not a directory", absent)
	} else if err != nil {
		t.Errorf("the write grant was not created at all: %v", err)
	}
}

// An interpreter outside the system paths (pyenv, mise, conda) loads its stdlib from
// its own install prefix. The launcher grants the interpreter FILE, so the binary
// starts - and then fails on the first stdlib read unless the prefix is granted too.
// The bwrap tier ro-binds that prefix; this tier has to give Landlock the same. It
// matters because Synthesize strips the runtime tree from its proposals, so a manifest
// profiled against such a runtime carries no read grant that would cover it.
func TestDegradedRunsInterpreterOutsideSystemPaths(t *testing.T) {
	requireDegraded(t)
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	// A runtime laid out the way interpreterPrefix recognizes: <prefix>/bin/rt, with its
	// "stdlib" beside it under <prefix>/lib. The temp dir is not under $HOME, so it does
	// not hit the home floor that deliberately narrows a ~/bin wrapper to a single file.
	prefix := t.TempDir()
	for _, d := range []string{"bin", "lib"} {
		if err := os.Mkdir(filepath.Join(prefix, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	stdlib := filepath.Join(prefix, "lib", "stdlib.sh")
	if err := os.WriteFile(stdlib, []byte("greet() { echo ran-outside-fhs; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	interp := filepath.Join(prefix, "bin", "rt")
	if err := os.WriteFile(interp, []byte("#!/bin/sh\n. "+stdlib+"\ngreet\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "s.sh")
	if err := os.WriteFile(script, []byte("# the runtime does the work\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: interp, Read: []string{dir}, Exec: policy.ExecAll}
	var out strings.Builder
	res, err := enforcerUsing(testBento(t)).runDegraded(context.Background(), p,
		enforce.Process{Stdout: &out, Stderr: &out}, "")
	if err != nil {
		t.Fatalf("runDegraded: %v\noutput:\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "ran-outside-fhs") {
		t.Errorf("the runtime could not read its own stdlib; exit=%d output:\n%s", res.ExitCode, out.String())
	}
}

// The degraded tier has no network namespace and no proxy, so it has nothing to
// consult a gate with. enforce.Run cannot pair the two - a gate requires LayerNetwork,
// which is Unavailable exactly where this tier is selected - but Run is an exported
// entry point an embedder reaches directly, and running with the gate silently dropped
// would tell a supervising caller its prompt was never needed when it was never
// possible.
func TestDegradedRefusesANetworkGate(t *testing.T) {
	entry := filepath.Join(t.TempDir(), "entry.sh")
	if err := os.WriteFile(entry, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: entry, Exec: policy.ExecNone}
	_, err := enforcerUsing("/bin/true").Run(context.Background(), p, enforce.Process{}, enforce.RunOptions{
		Degraded: true,
		Gate:     func(context.Context, string, string) bool { return true },
	})
	if err == nil || !strings.Contains(err.Error(), "network gate cannot be honored") {
		t.Fatalf("the degraded tier must refuse a gate it cannot consult; got err=%v", err)
	}
}
