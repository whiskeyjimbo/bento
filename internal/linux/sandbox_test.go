package linux

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/internal/enforce"
	"github.com/whiskeyjimbo/bento-v2/internal/observe"
	"github.com/whiskeyjimbo/bento-v2/internal/policy"
	"github.com/whiskeyjimbo/bento-v2/internal/profile"
	"github.com/whiskeyjimbo/bento-v2/internal/seccomp"
)

// These tests assert that the sandbox actually denies what it claims to. They
// run a real script under a real bubblewrap, because a policy compiler that
// produces plausible argv proves nothing about whether the boundary holds.

func requireSandbox(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not installed")
	}
	if err := canUnshare(context.Background(), "bwrap"); err != nil {
		t.Skip("unprivileged user namespaces unavailable on this host")
	}
}

// runScript writes sh source to a temp file and runs it under the given policy,
// returning its exit code and combined output.
func runScript(t *testing.T, p *policy.Policy, src string) (int, string) {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(script, []byte(src), 0o755); err != nil {
		t.Fatal(err)
	}
	p.Entrypoint = script
	p.Interpreter = "sh"
	p.Read = append(p.Read, dir)
	// These tests exercise filesystem and network boundaries, and their scripts
	// invoke external helpers (cat, mkdir, getent) that are themselves
	// subprocesses. Run with exec: all so a blocked helper cannot masquerade as a
	// passing security assertion - the boundary under test must be what denies,
	// not the exec filter.
	p.Exec = policy.ExecAll

	var out bytes.Buffer
	res, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out})
	if err != nil {
		t.Fatalf("Run: %v (output: %s)", err, out.String())
	}
	return res.ExitCode, out.String()
}

func TestSandboxRunsAndPropagatesExitCode(t *testing.T) {
	requireSandbox(t)
	code, out := runScript(t, &policy.Policy{}, "echo hello; exit 3\n")
	if code != 3 {
		t.Errorf("exit code = %d, want 3", code)
	}
	if !strings.Contains(out, "hello") {
		t.Errorf("output = %q, want it to contain hello", out)
	}
}

// Deny-by-default: a path the policy never granted must not be readable, even
// though it plainly exists on the host.
func TestUngrantedPathIsNotReadable(t *testing.T) {
	requireSandbox(t)

	secret := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(secret, []byte("TOPSECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, out := runScript(t, &policy.Policy{}, "cat "+secret+" 2>&1 || true\n")
	if strings.Contains(out, "TOPSECRET") {
		t.Fatalf("sandbox read a path that was never granted: %q", out)
	}
}

// A read grant is read-only: writing to it must fail.
func TestReadGrantIsNotWritable(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	target := filepath.Join(dir, "file")
	if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{Read: []string{dir}}
	runScript(t, p, "echo MUTATED > "+target+" 2>&1 || true\n")

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original" {
		t.Fatalf("a read-only grant was written through: file now %q", got)
	}
}

// A write grant works: this is the control proving the denials above are not
// simply a broken sandbox that can do nothing at all.
func TestWriteGrantPersistsToHost(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	out := filepath.Join(dir, "result.txt")

	p := &policy.Policy{Write: []string{dir}}
	if code, output := runScript(t, p, "echo WROTE > "+out+"\n"); code != 0 {
		t.Fatalf("write to a granted path failed: exit=%d out=%s", code, output)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("granted write did not reach the host: %v", err)
	}
	if strings.TrimSpace(string(got)) != "WROTE" {
		t.Fatalf("file = %q, want WROTE", got)
	}
}

// Profiling always runs through the launcher, so the bento binary must be bound
// even for exec:all + no network - the one case where the policy alone would not
// require the launcher and newSandbox leaves bentoPath unset. Without the fix this
// emitted an empty bind source for /bento and bwrap aborted.
func TestProfileExecAllNoNetworkRuns(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	script := filepath.Join(dir, "p.sh")
	if err := os.WriteFile(script, []byte("echo hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir}, Exec: policy.ExecAll}

	obs, err := sandboxEnforcer(t).Profile(context.Background(), p, enforce.Process{}, false)
	if err != nil {
		t.Fatalf("Profile with exec:all and no network failed: %v", err)
	}
	// Assert the target actually ran under the launcher. An empty /bento bind aborts
	// bwrap, but Profile swallows the exit error and returns an empty observation, so
	// a bare err==nil check would pass even unfixed; a run that reached the
	// interpreter always opens its runtime files.
	if len(obs.Reads) == 0 {
		t.Fatal("no file accesses observed - the target did not run (empty /bento bind?)")
	}
}

// A profiled run that exits nonzero or dies from a signal may have stopped before
// exercising all its paths, so Profile must surface the exit status end-to-end (the
// launcher writes it into the report, parseObservations reads it) for the frontend
// to warn on. Otherwise the profiler proposes a silently over-tight manifest.
func TestProfileSurfacesExitStatus(t *testing.T) {
	requireSandbox(t)

	run := func(t *testing.T, body string) profile.Observation {
		dir := t.TempDir()
		script := filepath.Join(dir, "p.sh")
		if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir}, Exec: policy.ExecAll}
		obs, err := sandboxEnforcer(t).Profile(context.Background(), p, enforce.Process{}, false)
		if err != nil {
			t.Fatalf("Profile: %v", err)
		}
		return obs
	}

	if obs := run(t, "exit 7\n"); obs.Signaled || obs.ExitCode != 7 {
		t.Errorf("nonzero exit: got Signaled=%v ExitCode=%d, want ExitCode 7", obs.Signaled, obs.ExitCode)
	}
	if obs := run(t, "kill -TERM $$\n"); !obs.Signaled || obs.Signal != int(syscall.SIGTERM) {
		t.Errorf("signaled run: got Signaled=%v Signal=%d, want signaled by SIGTERM (%d)", obs.Signaled, obs.Signal, syscall.SIGTERM)
	}
}

// The observation report must be unreachable from the profiled target: the report
// path must not exist in the sandbox, and the inherited report descriptor must be
// closed in the target, so a malicious profiled run cannot forge the observations.
// This fix fails invisibly (the happy path passes whether or not the target can
// still reach the channel), so the assertions here are the fix.
func TestProfileTargetCannotReachReport(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	script := filepath.Join(dir, "p.sh")
	// (a) the report path must be gone; (b) FD 3 must be closed in the target;
	// (c) a well-formed forged report the target CAN write must not become the
	// observations.
	forge := "printf 'R \"/FORGED-BY-TARGET\"\\n" + observe.ReportStart + "\\n'"
	procForge := "printf 'R \"/PROCFS-FORGE\"\\n" + observe.ReportStart + "\\n'"
	body := "#!/bin/sh\n" +
		"[ -e /observe.report ] && echo REPORT_EXISTS || echo REPORT_ABSENT\n" +
		"echo forged >&3 2>/dev/null && echo FD3_WRITABLE || echo FD3_CLOSED\n" +
		forge + " > /tmp/forge\n" +
		// Also try to reach the report through whichever process still holds it open,
		// via /proc/<pid>/fd. The launcher truncates after the target exits, so this
		// must not leak either.
		"for pid in 1 2 3; do " + procForge + " > /proc/$pid/fd/3 2>/dev/null || true; done\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir}, Exec: policy.ExecAll}

	var out bytes.Buffer
	obs, err := sandboxEnforcer(t).Profile(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out}, false)
	if err != nil {
		t.Fatalf("profile: %v (out: %q)", err, out.String())
	}
	if got := out.String(); !strings.Contains(got, "REPORT_ABSENT") || strings.Contains(got, "REPORT_EXISTS") {
		t.Errorf("the report path is still reachable in the sandbox; output: %q", got)
	}
	if got := out.String(); !strings.Contains(got, "FD3_CLOSED") || strings.Contains(got, "FD3_WRITABLE") {
		t.Errorf("the report descriptor is still open in the target; output: %q", got)
	}
	// No forged record the target wrote - to a file it could reach, or through a
	// /proc/<pid>/fd handle to the report - may appear in the synthesized observations.
	for _, r := range append(append([]string{}, obs.Reads...), obs.Writes...) {
		if strings.Contains(r, "FORGED-BY-TARGET") || strings.Contains(r, "PROCFS-FORGE") {
			t.Errorf("a target-forged record leaked into observations: %q", r)
		}
	}
	// Sanity: profiling still captured the run (the FD channel works), so the
	// negative assertions above are not vacuously true on an empty report.
	if len(obs.Reads) == 0 {
		t.Fatal("no observations captured; the FD report channel is broken")
	}
}

// bwrap starts the sandbox root as a writable tmpfs; bento remounts it read-only
// so a run cannot create files at "/" that no grant allows. Writes stay confined
// to the runtime scratch and grants. (This exercises the direct exec:all path; the
// launcher path shares the same remount, and its Landlock rw-set matches.)
func TestSandboxRootIsReadOnly(t *testing.T) {
	requireSandbox(t)

	_, out := runScript(t, &policy.Policy{}, "mkdir /rootdir 2>&1 || true\n")
	if !strings.Contains(out, "Read-only file system") {
		t.Errorf("a write to the sandbox root should be denied (read-only), got: %q", out)
	}
	// Sanity: /tmp (a writable submount) still works, so only the root was locked.
	_, out2 := runScript(t, &policy.Policy{}, "echo x > /tmp/probe && echo TMP_OK\n")
	if !strings.Contains(out2, "TMP_OK") {
		t.Errorf("/tmp should remain writable under a read-only root, got: %q", out2)
	}
}

// A write grant to a directory that does not exist yet is created on the host so
// the run can persist into it. This is the case a profiled manifest hits: the
// script writes a new output file, and the grant is that file's directory.
func TestWriteGrantToMissingDirIsCreatedAndPersists(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	outDir := filepath.Join(dir, "generated") // does not exist yet
	result := filepath.Join(outDir, "result.txt")

	p := &policy.Policy{Write: []string{outDir}}
	if code, output := runScript(t, p, "echo WROTE > "+result+"\n"); code != 0 {
		t.Fatalf("write into a granted-but-missing directory failed: exit=%d out=%s", code, output)
	}
	got, err := os.ReadFile(result)
	if err != nil {
		t.Fatalf("write into a created grant directory did not persist: %v", err)
	}
	if strings.TrimSpace(string(got)) != "WROTE" {
		t.Fatalf("file = %q, want WROTE", got)
	}
}

// Saving via write-temp-then-rename - what editors and os.replace do - must work
// under a write grant. This is the whole reason write grants are directory-
// granular: a file-level bind mount makes rename onto the target fail with EBUSY.
func TestAtomicRenameSaveWorksUnderWriteGrant(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	target := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(target, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{Write: []string{dir}}
	tmp := filepath.Join(dir, ".data.tmp")
	if code, output := runScript(t, p, "echo new > "+tmp+" && mv -f "+tmp+" "+target+"\n"); code != 0 {
		t.Fatalf("atomic save-and-rename failed under a write grant: exit=%d out=%s", code, output)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != "new" {
		t.Fatalf("target = %q, want new after an atomic rename save", got)
	}
}

// The mandatory deny-list must hold even when the policy grants the whole home
// directory. A credential file that does not exist yet must not be creatable -
// this is the v1 hole, where an absent ~/.ssh could be created and a key planted.
// A write grant of $HOME is above the credential shields (~/.ssh, ~/.aws, ...), so
// it must be refused rather than run: honoring it would bind their parent
// read-write, letting a run plant or replace them on the host. This is the
// end-to-end form of the refusal, replacing the old "plant under write:$HOME"
// tests whose scenario no longer runs.
func TestWriteGrantAboveCredentialsIsRefused(t *testing.T) {
	requireSandbox(t)

	// Stand in a fake home so the test never touches the developer's real one.
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "p.sh")
	if err := os.WriteFile(script, []byte("echo hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir}, Write: []string{home}}
	_, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{})
	if err == nil {
		t.Fatal("a write grant of $HOME (above the credential shields) must be refused, not run")
	}
	if !strings.Contains(err.Error(), "always-shielded") {
		t.Errorf("error = %v, want it to explain the shield conflict", err)
	}
}

// A write-denied dotfile that is a symlink (the home-manager / nix layout, where
// ~/.gitconfig points into an immutable store) must be shielded without aborting
// the run: bwrap cannot mount over a symlink path, so the shield binds the
// resolved target. Content stays readable; the write is refused.
// A symlinked credential directory must be shielded at its resolved target without
// aborting bwrap (which cannot mount over a symlink). Under a read grant of $HOME
// the DenyAll shield still applies, so this keeps the symlink-resolution coverage.
func TestSymlinkedDenyDirIsShieldedWithoutCrashing(t *testing.T) {
	requireSandbox(t)

	home := t.TempDir()
	t.Setenv("HOME", home)
	real := filepath.Join(home, "store-aws")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "credentials"), []byte("SECRETKEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, ".aws")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{Read: []string{home}}
	_, out := runScript(t, p, "cat "+filepath.Join(link, "credentials")+" 2>&1 || true\n")

	if strings.Contains(out, "bwrap:") {
		t.Fatalf("shielding a symlinked credential dir aborted bwrap: %s", out)
	}
	if strings.Contains(out, "SECRETKEY") {
		t.Fatalf("a symlinked credential dir was readable despite the deny-list: %q", out)
	}
}

// A deny-list dotfile that is a DANGLING symlink (target not created yet - the
// half-populated home-manager / stow layout) must still be shielded: the shield
// follows the symlink to its target and blocks a write through it, rather than
// silently no-opping (letting a credential be planted) or aborting the run.
func TestDanglingSymlinkDenyFileBlocksPlantThrough(t *testing.T) {
	requireSandbox(t)

	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, "store"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, "store", "netrc") // does not exist yet
	if err := os.Symlink(target, filepath.Join(home, ".netrc")); err != nil {
		t.Fatal(err)
	}

	// Read $HOME to reach the ~/.netrc symlink and write its target directory (a
	// write grant of $HOME itself is refused). ~/.netrc's shield resolves to
	// store/netrc, so a write through the symlink into the granted dir is absorbed.
	p := &policy.Policy{Read: []string{home}, Write: []string{filepath.Join(home, "store")}}
	_, out := runScript(t, p, "echo MALICIOUS > "+filepath.Join(home, ".netrc")+" 2>&1 || true\n")

	if strings.Contains(out, "bwrap:") {
		t.Fatalf("a dangling-symlink shield aborted the run: %s", out)
	}
	if b, err := os.ReadFile(target); err == nil && strings.Contains(string(b), "MALICIOUS") {
		t.Fatalf("a credential was planted through a dangling symlink: %q", b)
	}
}

// A deny-list dotfile symlinked to a target OUTSIDE every grant must not be bound
// into the sandbox by its shield: the target is unreachable to begin with, so
// shielding it would expose content at a path no grant named. The shield is
// simply skipped, and the target stays invisible.
func TestSymlinkDenyTargetOutsideGrantsNotExposed(t *testing.T) {
	requireSandbox(t)

	home := t.TempDir()
	t.Setenv("HOME", home)
	outside := t.TempDir() // not under any grant
	secret := filepath.Join(outside, "gitconfig")
	if err := os.WriteFile(secret, []byte("SECRET_TOKEN"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(home, ".gitconfig")); err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{Read: []string{home}}
	_, out := runScript(t, p, "cat "+secret+" 2>&1 || true\n")

	if strings.Contains(out, "SECRET_TOKEN") {
		t.Fatalf("a shield exposed a symlink target outside all grants: %q", out)
	}
}

// A grant that names the resolved target of a symlinked shield (~/.ssh -> a real
// key store, then write to that store) must still be refused: the deny rule and
// the grant are compared after both are symlink-resolved, so the shield cannot be
// side-stepped by naming what the symlink points to.
func TestGrantOnSymlinkedShieldTargetIsRejected(t *testing.T) {
	requireSandbox(t)

	home := t.TempDir()
	t.Setenv("HOME", home)
	keys := filepath.Join(t.TempDir(), "keystore")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(home, ".ssh")); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "s.sh")
	if err := os.WriteFile(script, []byte("true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Write: []string{keys}}

	_, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{})
	if err == nil {
		t.Fatal("granting write to ~/.ssh's symlink target should be rejected")
	}
	if !strings.Contains(err.Error(), "always-shielded") {
		t.Errorf("error = %v, want the shield-conflict message", err)
	}
}

// The same for a shell profile, the classic persistence vector.
// An existing credential must be unreadable under a home grant: the deny-list
// covers exfiltration, not just persistence.
func TestDenyListHidesExistingCredentialUnderHomeGrant(t *testing.T) {
	requireSandbox(t)

	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".aws"), 0o700); err != nil {
		t.Fatal(err)
	}
	creds := filepath.Join(home, ".aws", "credentials")
	if err := os.WriteFile(creds, []byte("SECRETKEY"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A read grant of $HOME is the case that still reaches the shields (a write grant
	// above them is refused); the credential must stay hidden under it.
	p := &policy.Policy{Read: []string{home}}
	_, out := runScript(t, p, "cat "+creds+" 2>&1 || true\n")

	if strings.Contains(out, "SECRETKEY") {
		t.Fatalf("credentials were readable despite the mandatory deny-list: %q", out)
	}
}

// A write-denied file that exists must still be READABLE. v1 shadowed these with
// /dev/null, so git saw an empty ~/.gitconfig. Read and write denial are
// different things and must stay so.
// A DenyWrite shield under a WRITE grant keeps a file readable but not writable.
// This lives under a workspace grant now (a write grant above a home shield is
// refused): a project's .git/config stays readable while writes to it are denied.
func TestWriteDeniedFileRemainsReadable(t *testing.T) {
	requireSandbox(t)

	home := t.TempDir()
	t.Setenv("HOME", home)
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(proj, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(proj, ".git", "config")
	if err := os.WriteFile(cfg, []byte("[user]\n\tname = Real Name\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{Write: []string{proj}}
	_, out := runScript(t, p, "cat "+cfg+" 2>&1 || true\n")

	if !strings.Contains(out, "Real Name") {
		t.Fatalf("a write-denied file should stay readable, but reads were blinded: %q", out)
	}

	// ...and still not writable.
	runScript(t, p, "echo TAMPERED >> "+cfg+" 2>&1 || true\n")
	got, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "TAMPERED") {
		t.Fatalf("a write-denied file was modified: %q", got)
	}
}

// With no network rules the sandbox has no network namespace at all, so egress
// is impossible rather than merely discouraged.
func TestNoNetworkRulesDeniesEgress(t *testing.T) {
	requireSandbox(t)
	if _, err := exec.LookPath("getent"); err != nil {
		t.Skip("getent not available")
	}

	// Connecting to a routable address must fail with no network namespace.
	_, out := runScript(t, &policy.Policy{}, "getent hosts example.com 2>&1; echo rc=$?\n")
	if !strings.Contains(out, "rc=") || strings.Contains(out, "rc=0") {
		t.Fatalf("expected name resolution to fail with no network, got %q", out)
	}
}

// The environment is not inherited: a secret in the parent's environment must not
// leak into the sandbox unless the policy allowed that name through.
func TestHostEnvironmentIsNotInherited(t *testing.T) {
	requireSandbox(t)
	t.Setenv("BENTO_TEST_SECRET", "LEAKED")

	_, out := runScript(t, &policy.Policy{}, "echo \"[${BENTO_TEST_SECRET}]\"\n")
	if strings.Contains(out, "LEAKED") {
		t.Fatalf("host environment leaked into the sandbox: %q", out)
	}
}

// Probe must report honestly: what is enforced as enforced, what is not yet
// built as unavailable. Exec-blocking is now implemented (seccomp), so on a
// seccomp-capable host it must report enforced; resource limits are not built, so
// each layer's reported state must match what this host can actually do: a claim
// of enforced only where the capability is present, unavailable otherwise.
func TestProbeReportsLayersHonestly(t *testing.T) {
	report := New().Probe(context.Background())

	states := map[enforce.Layer]enforce.State{}
	for _, l := range report.Layers {
		states[l.Layer] = l.State
	}

	wantExec := enforce.Unavailable
	if seccomp.Supported() {
		wantExec = enforce.Enforced
	}
	if states[enforce.LayerExec] != wantExec {
		t.Errorf("exec-block state = %v, want %v", states[enforce.LayerExec], wantExec)
	}

	wantLimits := enforce.Unavailable
	if ok, _ := canCreateScope(); ok {
		wantLimits = enforce.Enforced
	}
	if states[enforce.LayerLimits] != wantLimits {
		t.Errorf("limits state = %v, want %v", states[enforce.LayerLimits], wantLimits)
	}

	// The cpu-limits layer is a refinement reported only when a scope can be created
	// (memory/pids delegated); when the whole limits layer is unavailable the cpu gap
	// is subsumed by it and no separate limits-cpu entry is emitted.
	_, cpuReported := states[enforce.LayerLimitsCPU]
	if wantLimits == enforce.Unavailable {
		if cpuReported {
			t.Errorf("limits-cpu should not be reported when the scope is unavailable")
		}
	} else {
		wantCPU := enforce.Enforced
		if ctrls, known := delegatedControllers(); known && !ctrls["cpu"] {
			wantCPU = enforce.Unavailable
		}
		if states[enforce.LayerLimitsCPU] != wantCPU {
			t.Errorf("limits-cpu state = %v, want %v", states[enforce.LayerLimitsCPU], wantCPU)
		}
	}
}

// A run leaves no host artifact: the shield mount point bwrap creates for a
// nonexistent shielded path under a write grant (an unborn .git/hooks) is removed
// after the run. Best effort by design - a kill could leave it - but a normal exit
// must clean it up.
func TestNonexistentShieldLeavesNoHostArtifact(t *testing.T) {
	requireSandbox(t)
	proj := t.TempDir()
	if err := os.MkdirAll(filepath.Join(proj, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	hooks := filepath.Join(proj, ".git", "hooks") // deliberately absent

	p := &policy.Policy{Write: []string{proj}}
	runScript(t, p, "echo hi\n")

	if _, err := os.Stat(hooks); err == nil {
		t.Errorf("bento left a host artifact at %s after the run", hooks)
	}
}

// The cleanup must never remove a pre-existing shield path or its contents: it only
// removes leaves that did not exist before the run, and only when empty.
func TestExistingShieldedDirIsNotRemoved(t *testing.T) {
	requireSandbox(t)
	proj := t.TempDir()
	hooks := filepath.Join(proj, ".git", "hooks")
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(hooks, "pre-commit")
	if err := os.WriteFile(marker, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{Write: []string{proj}}
	runScript(t, p, "echo hi\n")

	if _, err := os.Stat(marker); err != nil {
		t.Errorf("cleanup removed a pre-existing shielded path's contents: %v", err)
	}
}
