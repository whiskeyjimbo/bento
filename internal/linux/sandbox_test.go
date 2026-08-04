//go:build linux

package linux

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/landlock"
	"github.com/whiskeyjimbo/bento/internal/observe"
	"github.com/whiskeyjimbo/bento/internal/seccomp"
	"github.com/whiskeyjimbo/bento/policy"
	"github.com/whiskeyjimbo/bento/profile"
)

// These tests assert that the sandbox actually denies what it claims to. They
// run a real script under a real bubblewrap, because a policy compiler that
// produces plausible argv proves nothing about whether the boundary holds.

func requireSandbox(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("bwrap"); err != nil {
		skipMissingDep(t, "bwrap not installed")
	}
	if err := canUnshare(context.Background(), "bwrap"); err != nil {
		skipMissingDep(t, "the bwrap sandbox cannot be built on this host (user namespace or /proc mount refused)")
	}
}

// skipMissingDep skips for a missing host dependency, or fails when
// BENTO_REQUIRE_TEST_DEPS is set. A behavioral test that self-skips reports a pass having
// asserted nothing, so on a host without bwrap or unprivileged user namespaces a run is
// indistinguishable from one that exercised the shield; the variable is how a host that
// is supposed to have them - CI, and `make test` - says so.
func skipMissingDep(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("BENTO_REQUIRE_TEST_DEPS") != "" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

// runScript writes sh source to a temp file and runs it under the given policy,
// returning its exit code and combined output.
// runScriptExpectingRefusal is runScript for the policies compile rejects: it returns
// Run's error instead of failing the test on it, so a refusal can be asserted as the
// behavior rather than showing up as an unexplained fatal.
func runScriptExpectingRefusal(t *testing.T, p *policy.Policy, src string) error {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(script, []byte(src), 0o755); err != nil {
		t.Fatal(err)
	}
	p.Entrypoint = script
	p.Interpreter = "sh"
	p.Read = append(p.Read, dir)
	p.Exec = policy.ExecAll

	var out bytes.Buffer
	_, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out}, enforce.RunOptions{})
	return err
}

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
	res, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out}, enforce.RunOptions{})
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

// The enforced run reports the always-on shields it engaged all the way out to the
// Result, so an operator can confirm the boundary worked. A home grant reaches the
// credential shields under it, so a real run must surface ~/.ssh as hidden - the
// compile-level test proves the set is computed; this proves Run threads it to Result.
func TestRunResultReportsAppliedShields(t *testing.T) {
	requireSandbox(t)

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
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{home, dir}, Exec: policy.ExecAll}

	res, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{}, enforce.RunOptions{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	ssh := filepath.Join(home, ".ssh")
	found := false
	for _, s := range res.Shields {
		if s.Path == ssh && s.Kind == "hidden" {
			found = true
		}
	}
	if !found {
		t.Errorf("Run result did not report the ~/.ssh shield the home grant reached; Shields=%v", res.Shields)
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

// Profiling runs the target under the launcher's observer, so the bento binary
// must be bound and actually reached even for exec:all + no network. A broken
// /bento bind would abort bwrap; Profile swallows the exit error, so this asserts
// the target ran by checking it observed file accesses.
func TestProfileExecAllNoNetworkRuns(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	script := filepath.Join(dir, "p.sh")
	if err := os.WriteFile(script, []byte("echo hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir}, Exec: policy.ExecAll}

	obs, err := sandboxEnforcer(t).Profile(context.Background(), p, enforce.Process{}, false, nil, nil)
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

// Profiling runs under the same default-deny as a real run: an ungranted $HOME path
// is never mounted, so the target's read attempt is recorded (the consent surface)
// while the content stays hidden. This is the keystone that lets profiling drop the
// old Read:["/"] trial, which leaked any credential the deny-list did not enumerate.
// Both halves must hold at once - the path IS recorded, the secret is NOT in output.
func TestProfileDefaultDenyRecordsHomePathWithoutExposure(t *testing.T) {
	requireSandbox(t)

	home := t.TempDir()
	const secret = "SUPER-SECRET-TOKEN-do-not-leak"
	token := filepath.Join(home, ".mytoken")
	if err := os.WriteFile(token, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "p.sh")
	// Print the token to stdout: under default-deny the file is unmounted and cat
	// finds nothing; were home mounted, the secret would surface here.
	if err := os.WriteFile(script, []byte("cat \"$HOME/.mytoken\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A real run's policy: only the script's own directory is granted, nothing under home.
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir}, Exec: policy.ExecAll}

	var out bytes.Buffer
	obs, err := sandboxEnforcer(t).Profile(context.Background(), p,
		enforce.Process{Env: map[string]string{"HOME": home}, Stdout: &out}, false, nil, nil)
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	if strings.Contains(out.String(), secret) {
		t.Fatalf("the token content leaked into the target's output - home was mounted; got %q", out.String())
	}
	if !slices.Contains(obs.Reads, token) {
		t.Errorf("the attempted read of %q was not recorded; Reads=%v", token, obs.Reads)
	}
}

// The profiling home is an empty tmpfs, not absent: a program that stats $HOME or
// writes a dotfile on startup proceeds (fuller manifest) instead of bailing at an
// absent home, while the overlay reveals none of the real home's contents.
func TestProfileHomeIsEmptyOverlay(t *testing.T) {
	requireSandbox(t)

	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".realrc"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "p.sh")
	// The overlay must exist, be empty (real dotfiles hidden), and be writable scratch -
	// a program that drops a dotfile on startup must proceed, not fail on a read-only home.
	body := "[ -d \"$HOME\" ] && echo HOME_EXISTS\n" +
		"ls -A \"$HOME\" | grep -q . && echo HOME_NONEMPTY || echo HOME_EMPTY\n" +
		"echo x > \"$HOME/.startup\" && echo HOME_WRITABLE\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir}, Exec: policy.ExecAll}

	var out bytes.Buffer
	if _, err := sandboxEnforcer(t).Profile(context.Background(), p,
		enforce.Process{Env: map[string]string{"HOME": home}, Stdout: &out, Stderr: &out}, false, nil, nil); err != nil {
		t.Fatalf("profile: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "HOME_EXISTS") {
		t.Errorf("profiling HOME should exist as an empty overlay; output: %q", got)
	}
	if !strings.Contains(got, "HOME_EMPTY") || strings.Contains(got, "HOME_NONEMPTY") {
		t.Errorf("profiling HOME should be empty (real dotfiles hidden); output: %q", got)
	}
	if !strings.Contains(got, "HOME_WRITABLE") {
		t.Errorf("profiling HOME should be writable scratch; output: %q", got)
	}
	// The overlay write must stay in the sandbox - the real home must not gain the file.
	if _, err := os.Stat(filepath.Join(home, ".startup")); !os.IsNotExist(err) {
		t.Errorf("a write to the overlay HOME leaked to the real home directory (err=%v)", err)
	}
}

// Round-trip: a non-shielded home path that profiling records can be granted and then
// actually read at enforce time, as long as the same HOME is carried through both
// phases (env consistency - the recorded path is the literal $HOME expansion). A
// non-shielded path is used deliberately: a deny-list shield cannot be granted until
// the checkNotShielded softening (bv2-yz3.2).
func TestProfileThenEnforceHomePathRoundTrip(t *testing.T) {
	requireSandbox(t)

	home := t.TempDir()
	cfg := filepath.Join(home, ".myapp", "config") // under home, not a deny-list shield
	if err := os.MkdirAll(filepath.Dir(cfg), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte("APPDATA-123"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "p.sh")
	if err := os.WriteFile(script, []byte("cat \"$HOME/.myapp/config\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"HOME": home}

	// Phase 1: profile under default-deny. The path is recorded; the content is hidden.
	var pout bytes.Buffer
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir}, Exec: policy.ExecAll}
	obs, err := sandboxEnforcer(t).Profile(context.Background(), p,
		enforce.Process{Env: env, Stdout: &pout}, false, nil, nil)
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	if !slices.Contains(obs.Reads, cfg) {
		t.Fatalf("profiling did not record %q; Reads=%v", cfg, obs.Reads)
	}
	if strings.Contains(pout.String(), "APPDATA-123") {
		t.Fatalf("content leaked during profiling: %q", pout.String())
	}

	// Phase 2: grant the discovered path and enforce with the same HOME. The read now
	// succeeds - the path profiling named is exactly the one the grant covers.
	var rout bytes.Buffer
	enforced := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir, cfg}, Exec: policy.ExecAll}
	if _, err := sandboxEnforcer(t).Run(context.Background(), enforced,
		enforce.Process{Env: env, Stdout: &rout, Stderr: &rout}, enforce.RunOptions{}); err != nil {
		t.Fatalf("enforced run: %v (output: %s)", err, rout.String())
	}
	if !strings.Contains(rout.String(), "APPDATA-123") {
		t.Fatalf("the granted home path did not read back at enforce time; output: %q", rout.String())
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
		obs, err := sandboxEnforcer(t).Profile(context.Background(), p, enforce.Process{}, false, nil, nil)
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
	forge := "printf 'R \"/FORGED-BY-TARGET\"\\n" + observe.ReportEnd + "\\n'"
	procForge := "printf 'R \"/PROCFS-FORGE\"\\n" + observe.ReportEnd + "\\n'"
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
	obs, err := sandboxEnforcer(t).Profile(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out}, false, nil, nil)
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
	_, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{}, enforce.RunOptions{})
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

// yz3.2 end-to-end: an explicit grant of ~/.ssh is a deliberate opt-in - the program
// reads the real key through it (the shield is skipped, not overmounted empty), and Run
// reports the opt-in in ShieldedGrants so a frontend can warn. Exercises the whole path:
// checkNotShielded allows it, denyArgs skips the shield, the content binds, the run
// surfaces the exposure.
func TestRunHonorsExplicitShieldGrant(t *testing.T) {
	requireSandbox(t)

	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(sshDir, "id_test")
	if err := os.WriteFile(key, []byte("PRIVATE-KEY-BODY"), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "s.sh")
	if err := os.WriteFile(script, []byte("cat \""+key+"\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The script dir plus an explicit exact grant of the ~/.ssh shield - nothing broad.
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir, sshDir}, Exec: policy.ExecAll}

	var out bytes.Buffer
	res, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out}, enforce.RunOptions{})
	if err != nil {
		t.Fatalf("run: %v (output %q)", err, out.String())
	}
	if !strings.Contains(out.String(), "PRIVATE-KEY-BODY") {
		t.Fatalf("an explicit ~/.ssh grant should read the real key through the skipped shield; got %q", out.String())
	}
	if !slices.ContainsFunc(res.ShieldedGrants, func(g enforce.ShieldedGrant) bool { return g.Path == sshDir && g.Holds == "credentials" }) {
		t.Errorf("Run must report the ~/.ssh opt-in in ShieldedGrants, named as a credential store so a frontend can warn; got %v", res.ShieldedGrants)
	}
}

// yz3.2 regression (the write-opt-in hole): granting WRITE to a shield by its literal
// name, when that name is a symlink to a real store, must be refused - not honored as an
// opt-in - or a run could plant keys in the real ~/.ssh. checkWriteNotAboveShield's
// literal-vs-resolved compare misses this, so scoping the opt-in to read grants is the
// guard, and this proves it holds end-to-end.
func TestWriteGrantOfSymlinkedShieldNameIsRefused(t *testing.T) {
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
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Write: []string{filepath.Join(home, ".ssh")}}

	_, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{}, enforce.RunOptions{})
	if err == nil {
		t.Fatal("write to a symlinked ~/.ssh must be refused - a write opt-in would plant keys in the real store")
	}
	if !strings.Contains(err.Error(), "always-shielded") {
		t.Errorf("error = %v, want the shield-conflict message", err)
	}
}

// An opt-in names a shield by its deny-list spelling, which is built from $HOME - so
// where that spelling is a symlink the grant names one path and the run binds another.
// The Result has to carry the pair, and carry the store as it stood when the grant was
// bound: a frontend that stat'd the path again after the target exited would name
// whatever it points at then, which a run that moved the link underneath itself has
// changed. Reporting the wrong store understates a credential exposure.
func TestRunReportsWhatAnOptedInGrantBound(t *testing.T) {
	requireSandbox(t)

	home := t.TempDir()
	t.Setenv("HOME", home)
	store := filepath.Join(t.TempDir(), "keystore")
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	granted := filepath.Join(home, ".ssh")
	if err := os.Symlink(store, granted); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "s.sh")
	if err := os.WriteFile(script, []byte("sleep 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{granted, dir}, Exec: policy.ExecAll}

	// Repoint the link on the HOST while the target runs. The bind already happened, so
	// the run's exposure is unchanged; only a report that resolves afterwards would move.
	decoy := filepath.Join(t.TempDir(), "decoy")
	if err := os.MkdirAll(decoy, 0o700); err != nil {
		t.Fatal(err)
	}
	relinked := make(chan error, 1)
	go func() {
		time.Sleep(time.Second)
		relinked <- os.Symlink(decoy, granted+".new")
		_ = os.Rename(granted+".new", granted)
	}()

	res, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{}, enforce.RunOptions{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := <-relinked; err != nil {
		t.Fatalf("repointing the link mid-run: %v", err)
	}
	if now, _ := filepath.EvalSymlinks(granted); now != decoy {
		t.Fatalf("the link was not repointed before the run finished (now %q); the test proves nothing", now)
	}
	want := []enforce.ShieldedGrant{{Path: granted, OnHost: store, Holds: "credentials"}}
	if !slices.Equal(res.ShieldedGrants, want) {
		t.Errorf("ShieldedGrants = %v, want %v - the store bound at mount time, not what the link points at now", res.ShieldedGrants, want)
	}
}

// Where the HOME DIRECTORY itself is a symlink (/home/u -> /data/u), the shield's
// resolved location leaves the granted tree while its literal name stays inside it, so
// a compare in the resolved namespace alone sees no containment. The grant still holds
// the home symlink: a run can point it at a directory it controls and plant a real .ssh
// there, which is what checkWriteNotAboveShield exists to stop.
func TestWriteGrantAboveSymlinkedHomeIsRefused(t *testing.T) {
	requireSandbox(t)

	base := t.TempDir()
	homes := filepath.Join(base, "homes")
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(real, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(homes, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(homes, "u")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", filepath.Join(homes, "u"))

	dir := t.TempDir()
	script := filepath.Join(dir, "s.sh")
	if err := os.WriteFile(script, []byte("true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Write: []string{homes}}

	_, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{}, enforce.RunOptions{})
	if err == nil {
		t.Fatal("a write grant above a symlinked home must be refused - the run could repoint home and plant keys")
	}
	if !strings.Contains(err.Error(), "always-shielded") {
		t.Errorf("error = %v, want the shield-conflict message", err)
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

	_, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{}, enforce.RunOptions{})
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

	// Network confinement needs bwrap's user namespace strictly: no userns, no netns
	// to fence egress into, so it is Unavailable - never Degraded, the guardrail that
	// keeps a network manifest refusing even under --allow-degraded.
	ns, _ := usableNamespaces(context.Background())
	wantNet := enforce.Unavailable
	if ns == namespacesUsable {
		wantNet = enforce.Enforced
	}
	if states[enforce.LayerNetwork] != wantNet {
		t.Errorf("network state = %v, want %v (must track namespace availability, not be unconditionally enforced)", states[enforce.LayerNetwork], wantNet)
	}

	// Filesystem is three-stated: bwrap when userns works, else the Landlock-only
	// degraded tier when the kernel has Landlock, else no confinement at all.
	wantFS := enforce.Unavailable
	switch {
	case ns == namespacesUsable:
		wantFS = enforce.Enforced
	// Only a host that ANSWERED "blocked" is offered the degraded tier; a probe that
	// could not answer fails closed, so it keeps the Unavailable default here too.
	case ns == namespacesBlocked && landlock.Available():
		wantFS = enforce.Degraded
	}
	if states[enforce.LayerFilesystem] != wantFS {
		t.Errorf("filesystem state = %v, want %v", states[enforce.LayerFilesystem], wantFS)
	}

	wantExec := enforce.Unavailable
	if seccomp.Supported() {
		wantExec = enforce.Enforced
	}
	if states[enforce.LayerExec] != wantExec {
		t.Errorf("exec-block state = %v, want %v", states[enforce.LayerExec], wantExec)
	}

	// Limits ride a systemd scope, which both tiers wrap their command in, so the
	// state tracks scope creation and nothing about the namespace.
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

// Profiling applies the same shields as a run, so it must clean up the same host
// artifacts. This guards the cleanup at the profile.go site independently: its scan
// must also run before bwrap, and no Profile test otherwise exercises it.
func TestProfileLeavesNoHostArtifact(t *testing.T) {
	requireSandbox(t)
	proj := t.TempDir()
	if err := os.MkdirAll(filepath.Join(proj, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	hooks := filepath.Join(proj, ".git", "hooks") // deliberately absent
	script := filepath.Join(proj, "p.sh")
	if err := os.WriteFile(script, []byte("echo hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Write: []string{proj}, Exec: policy.ExecAll}
	if _, err := sandboxEnforcer(t).Profile(context.Background(), p, enforce.Process{}, false, nil, nil); err != nil {
		t.Fatalf("Profile failed: %v", err)
	}

	if _, err := os.Stat(hooks); err == nil {
		t.Errorf("profiling left a host artifact at %s", hooks)
	}
}

// A read grant naming a symlink must be readable at the name that was granted.
// Grants are bound at their resolved target, so without recreating the symlink
// the granted name itself is absent and a script reading the standard path it
// was given fails - the home-manager / stow dotfile layout.
func TestSymlinkedReadGrantIsReadableAtGrantedName(t *testing.T) {
	requireSandbox(t)

	data := t.TempDir()
	store := filepath.Join(data, "store")
	if err := os.MkdirAll(store, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(store, "bashrc")
	if err := os.WriteFile(target, []byte("RCCONTENT"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(data, ".bashrc")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{Read: []string{link}}
	_, out := runScript(t, p, "cat "+link+" 2>&1 || true\n")

	if !strings.Contains(out, "RCCONTENT") {
		t.Errorf("granted symlink %s was not readable at the granted name: %q", link, out)
	}
}

// Recreating a granted symlink must not become a way around the deny-list. The
// symlink points at the resolved target, so a read through it lands on the real
// path where the shield is mounted. Binding the target at the granted name
// instead would alias the content to a second name no shield covers.
func TestSymlinkedGrantDoesNotAliasPastShield(t *testing.T) {
	requireSandbox(t)

	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_rsa"), []byte("PRIVATEKEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Read through the same symlink, so a link that simply does not work cannot
	// masquerade as the shield holding.
	if err := os.WriteFile(filepath.Join(home, "notes.txt"), []byte("PLAINNOTES"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A grant naming a symlink to $HOME: the shielded ~/.ssh sits under its target.
	link := filepath.Join(t.TempDir(), "homelink")
	if err := os.Symlink(home, link); err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{Read: []string{link}}
	_, out := runScript(t, p,
		"cat "+filepath.Join(link, "notes.txt")+" 2>&1 || true\n"+
			"cat "+filepath.Join(link, ".ssh", "id_rsa")+" 2>&1 || true\n")

	if strings.Contains(out, "bwrap:") {
		t.Fatalf("a symlinked grant aborted bwrap: %s", out)
	}
	if !strings.Contains(out, "PLAINNOTES") {
		t.Fatalf("granted symlink did not reach unshielded content, so the shield assertion below proves nothing: %q", out)
	}
	if strings.Contains(out, "PRIVATEKEY") {
		t.Fatalf("the deny-list was bypassed by reading through a granted symlink: %q", out)
	}
}

// A write grant naming a symlink to a directory must be writable at the granted
// name, and the write must land on the host at the symlink's target.
func TestSymlinkedWriteGrantReachesHostTarget(t *testing.T) {
	requireSandbox(t)

	data := t.TempDir()
	target := filepath.Join(data, "store")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(data, "out")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{Write: []string{link}}
	if code, out := runScript(t, p, "echo WROTE > "+filepath.Join(link, "result.txt")+"\n"); code != 0 {
		t.Fatalf("write through a granted symlink failed: exit=%d out=%s", code, out)
	}

	got, err := os.ReadFile(filepath.Join(target, "result.txt"))
	if err != nil {
		t.Fatalf("write through a granted symlink did not reach the host target: %v", err)
	}
	if strings.TrimSpace(string(got)) != "WROTE" {
		t.Fatalf("file = %q, want WROTE", got)
	}
}

// Granting both a symlink and a broader path that already contains it must not
// abort the run: bwrap refuses --symlink onto an existing destination, so the
// recreated link has to be emitted before any bind that could materialize it.
func TestSymlinkGrantOverlappingBroaderGrantDoesNotAbort(t *testing.T) {
	requireSandbox(t)

	data := t.TempDir()
	store := filepath.Join(data, "store")
	if err := os.MkdirAll(store, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(store, "bashrc")
	if err := os.WriteFile(target, []byte("RCCONTENT"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(data, ".bashrc")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{Read: []string{data, link}}
	_, out := runScript(t, p, "cat "+link+" 2>&1 || true\n")

	if strings.Contains(out, "bwrap:") {
		t.Fatalf("overlapping symlink and directory grants aborted bwrap: %s", out)
	}
	if !strings.Contains(out, "RCCONTENT") {
		t.Errorf("granted symlink unreadable under an overlapping grant: %q", out)
	}
}

// Granting a symlink and a second symlink nested under it must not abort the
// run: the recreated parent link already leads to the target, so the nested name
// resolves through it - while trying to recreate the nested link as well would
// have to create it through the parent link, whose target is not yet mounted.
func TestNestedSymlinkGrantsDoNotAbort(t *testing.T) {
	requireSandbox(t)

	data := t.TempDir()
	if err := os.MkdirAll(filepath.Join(data, "store", "cfg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(data, "store", "gh"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "store", "gh", "config"), []byte("GHCONFIG"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(data, "store", "gh"), filepath.Join(data, "store", "cfg", "gh")); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(data, ".config")
	if err := os.Symlink(filepath.Join(data, "store", "cfg"), config); err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{Read: []string{config, filepath.Join(config, "gh")}}
	_, out := runScript(t, p, "cat "+filepath.Join(config, "gh", "config")+" 2>&1 || true\n")

	if strings.Contains(out, "bwrap:") {
		t.Fatalf("nested symlink grants aborted bwrap: %s", out)
	}
	if !strings.Contains(out, "GHCONFIG") {
		t.Errorf("nested symlink grant unreadable at the granted name: %q", out)
	}
}

// A grant naming a path that some mount already fills must not be turned into a
// recreated symlink. On a usrmerge host /bin is a symlink to usr/bin and is also
// bound unconditionally by systemMounts; recreating it would both collide with
// that bind and make bwrap resolve the bind's destination through the link, which
// aborted the run. /dev/stdout is the same shape against --dev.
func TestGrantOnMountedSymlinkPathStillRuns(t *testing.T) {
	requireSandbox(t)

	for _, path := range []string{"/bin", "/sbin", "/lib", "/lib64", "/dev/stdout"} {
		t.Run(path, func(t *testing.T) {
			fi, err := os.Lstat(path)
			if err != nil || fi.Mode()&os.ModeSymlink == 0 {
				t.Skipf("%s is not a symlink on this host", path)
			}
			code, out := runScript(t, &policy.Policy{Read: []string{path}}, "echo ok\n")
			if strings.Contains(out, "bwrap:") {
				t.Fatalf("read grant on %s aborted bwrap: %s", path, out)
			}
			if code != 0 || !strings.Contains(out, "ok") {
				t.Fatalf("read grant on %s: exit=%d out=%q", path, code, out)
			}
		})
	}
}

// A read grant of "/" must not suppress the symlink a narrower grant needs. "/"
// is never bound at "/" - it is carried for deny-list reachability and bound as
// its children, which deliberately omit the empty /tmp - so treating it as a
// filled path would cover every name there is and erode the grant again.
func TestRootReadGrantDoesNotErodeSymlinkGrant(t *testing.T) {
	requireSandbox(t)

	data := t.TempDir()
	target := filepath.Join(data, "rc")
	if err := os.WriteFile(target, []byte("RCCONTENT"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(data, ".bashrc")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{Read: []string{"/", link}}
	_, out := runScript(t, p, "cat "+link+" 2>&1 || true\n")

	if strings.Contains(out, "bwrap:") {
		t.Fatalf("a symlink grant alongside read \"/\" aborted bwrap: %s", out)
	}
	if !strings.Contains(out, "RCCONTENT") {
		t.Errorf("read \"/\" suppressed the symlink a narrower grant needed: %q", out)
	}
}

// Profiling compiles the same argv as a run, so a symlinked grant must reach the
// target there too - a profile that cannot read its own grants observes nothing
// and proposes a manifest built from silence.
func TestProfileReadsSymlinkedGrant(t *testing.T) {
	requireSandbox(t)

	data := t.TempDir()
	target := filepath.Join(data, "rc")
	if err := os.WriteFile(target, []byte("RCCONTENT"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(data, ".bashrc")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "p.sh")
	if err := os.WriteFile(script, []byte("cat "+link+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir, link}, Exec: policy.ExecAll}

	var out bytes.Buffer
	obs, err := sandboxEnforcer(t).Profile(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out}, false, nil, nil)
	if err != nil {
		t.Fatalf("Profile: %v (output: %s)", err, out.String())
	}
	if obs.ExitCode != 0 {
		t.Fatalf("profiled run failed to read its symlinked grant: exit=%d out=%s", obs.ExitCode, out.String())
	}
}

// A grant that resolves into a host process's procfs directory must be refused
// with a bento error naming the grant as written. /etc/mtab and /dev/fd are host
// symlinks through /proc/self, which resolves to this bento's pid - a path the
// sandbox's own pid namespace does not have, so bwrap aborted the whole run.
// /proc/1 is the other half: the sandbox has a pid 1 of its own, so the grant
// bound the host's init over it and the run read the host's systemd.
func TestProcessPathGrantIsRefused(t *testing.T) {
	requireSandbox(t)

	for _, path := range []string{"/proc/self", "/etc/mtab", "/dev/fd", "/proc/1"} {
		t.Run(path, func(t *testing.T) {
			if _, err := os.Lstat(path); err != nil {
				t.Skipf("%s does not exist on this host", path)
			}
			dir := t.TempDir()
			script := filepath.Join(dir, "probe.sh")
			if err := os.WriteFile(script, []byte("echo ok\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir, path}, Exec: policy.ExecAll}

			_, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{}, enforce.RunOptions{})
			if err == nil {
				t.Fatalf("grant %s was accepted; want a refusal", path)
			}
			if !strings.Contains(err.Error(), "host process's directory in /proc") {
				t.Fatalf("grant %s: got %v, want a refusal naming the procfs process directory", path, err)
			}
			if !strings.Contains(err.Error(), path) {
				t.Errorf("refusal does not name the grant as written (%s): %v", path, err)
			}
		})
	}
}

// The refusal above must not catch procfs paths that bind fine: system-wide files
// under /proc and /dev/stdin (a symlink that resolves through the process's fd on to
// a real file, so it never lands on a process directory). A grant of the whole /proc
// is a separate case, refused by checkGrantNotManagedMount.
func TestNonProcessProcfsGrantsStillRun(t *testing.T) {
	requireSandbox(t)

	for _, path := range []string{"/proc/cpuinfo", "/dev/stdin"} {
		t.Run(path, func(t *testing.T) {
			code, out := runScript(t, &policy.Policy{Read: []string{path}}, "echo ok\n")
			if code != 0 || !strings.Contains(out, "ok") {
				t.Fatalf("read grant on %s: exit=%d out=%q", path, code, out)
			}
		})
	}
}

// A grant naming a symlink chain must reach its target even when a broader grant
// also covers the head. The head is then the host's own link, which points at the
// next link rather than at the resolved target, so the walk breaks in the middle
// unless that middle name is recreated too.
func TestSymlinkChainGrantReachesTargetUnderBroaderGrant(t *testing.T) {
	requireSandbox(t)

	t.Run("absolute targets", func(t *testing.T) {
		home, other := t.TempDir(), t.TempDir()
		t.Setenv("HOME", home)
		target := filepath.Join(other, "real")
		if err := os.WriteFile(target, []byte("CHAINCONTENT"), 0o644); err != nil {
			t.Fatal(err)
		}
		mid := filepath.Join(other, "mid")
		if err := os.Symlink(target, mid); err != nil {
			t.Fatal(err)
		}
		head := filepath.Join(home, "head")
		if err := os.Symlink(mid, head); err != nil {
			t.Fatal(err)
		}

		_, out := runScript(t, &policy.Policy{Read: []string{home, head}}, "cat "+head+" 2>&1 || true\n")
		if !strings.Contains(out, "CHAINCONTENT") {
			t.Errorf("chain grant unreadable at the granted name: %q", out)
		}
	})

	// Relative targets resolve from the link's own directory, so the recreated name
	// has to land where the kernel will actually look, not where lexical cleaning
	// of ".." would put it.
	t.Run("relative targets", func(t *testing.T) {
		base := t.TempDir()
		home, store := filepath.Join(base, "home"), filepath.Join(base, "store")
		for _, d := range []string{home, store} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		t.Setenv("HOME", home)
		if err := os.WriteFile(filepath.Join(store, "real"), []byte("RELCONTENT"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("real", filepath.Join(store, "mid")); err != nil {
			t.Fatal(err)
		}
		head := filepath.Join(home, "head")
		if err := os.Symlink("../store/mid", head); err != nil {
			t.Fatal(err)
		}

		_, out := runScript(t, &policy.Policy{Read: []string{home, head}}, "cat "+head+" 2>&1 || true\n")
		if !strings.Contains(out, "RELCONTENT") {
			t.Errorf("relative chain unreadable at the granted name: %q", out)
		}
	})

	// The link is reached through a symlinked parent directory, so the directory it
	// is read in is not the one its path spells. A relative target resolved by
	// lexical cleaning lands somewhere the kernel never looks, and the chain stays
	// broken.
	t.Run("relative target under a symlinked parent", func(t *testing.T) {
		base := t.TempDir()
		for _, d := range []string{"home", "other/dir", "nowhere", "store"} {
			if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(base, "store", "real"), []byte("PARENTCHAIN"), 0o644); err != nil {
			t.Fatal(err)
		}
		for _, l := range [][2]string{
			{filepath.Join(base, "store", "real"), filepath.Join(base, "nowhere", "mid2")},
			{filepath.Join(base, "nowhere", "mid2"), filepath.Join(base, "other", "mid")},
			{"../mid", filepath.Join(base, "other", "dir", "head")},
			{filepath.Join(base, "other", "dir"), filepath.Join(base, "home", "dirlink")},
		} {
			if err := os.Symlink(l[0], l[1]); err != nil {
				t.Fatal(err)
			}
		}

		head := filepath.Join(base, "home", "dirlink", "head")
		p := &policy.Policy{Read: []string{filepath.Join(base, "home"), filepath.Join(base, "other"), head}}
		_, out := runScript(t, p, "cat "+head+" 2>&1 || true\n")
		if !strings.Contains(out, "PARENTCHAIN") {
			t.Errorf("chain through a symlinked parent unreadable: %q", out)
		}
	})

	// Every hop already inside the broader grant: the host's own links connect the
	// whole way, so nothing is recreated and it must still work.
	t.Run("every hop covered", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		target := filepath.Join(home, "real")
		if err := os.WriteFile(target, []byte("COVEREDCONTENT"), 0o644); err != nil {
			t.Fatal(err)
		}
		mid := filepath.Join(home, "mid")
		if err := os.Symlink(target, mid); err != nil {
			t.Fatal(err)
		}
		head := filepath.Join(home, "head")
		if err := os.Symlink(mid, head); err != nil {
			t.Fatal(err)
		}

		_, out := runScript(t, &policy.Policy{Read: []string{home, head}}, "cat "+head+" 2>&1 || true\n")
		if !strings.Contains(out, "COVEREDCONTENT") {
			t.Errorf("fully covered chain unreadable: %q", out)
		}
	})
}

// Recreating a chain's middle name must not become a way past the deny-list: when
// that name lives inside a shielded directory the shield is mounted over it, so
// the chain breaks there rather than the credential becoming reachable.
func TestSymlinkChainHopUnderShieldStaysShielded(t *testing.T) {
	requireSandbox(t)

	home, other := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_rsa"), []byte("PRIVATEKEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(other, "real")
	if err := os.WriteFile(target, []byte("SHIELDPROBE"), 0o644); err != nil {
		t.Fatal(err)
	}
	mid := filepath.Join(home, ".ssh", "mid")
	if err := os.Symlink(target, mid); err != nil {
		t.Fatal(err)
	}
	head := filepath.Join(other, "head")
	if err := os.Symlink(mid, head); err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{Read: []string{other, head}}
	_, out := runScript(t, p, "cat "+filepath.Join(home, ".ssh", "id_rsa")+" 2>&1 || true\n")

	if strings.Contains(out, "bwrap:") {
		t.Fatalf("a chain hop under a shield aborted bwrap: %s", out)
	}
	if strings.Contains(out, "PRIVATEKEY") {
		t.Fatalf("the deny-list was bypassed via a recreated chain hop: %q", out)
	}
}

// A grant that names a symlink loop must be refused by bento, not left to abort
// bwrap. pathresolve.Existing leaves a loop unresolved on purpose (a shield on one
// still fails closed), so the grant would be bound at the looping path itself and
// --ro-bind-try - which tolerates only a missing source, not ELOOP - killed the
// run with an error naming bwrap instead of the grant. Read and write find this
// at different points in the run, so both are checked: they must agree.
func TestLoopedGrantIsRefused(t *testing.T) {
	requireSandbox(t)

	loop := func(t *testing.T) string {
		t.Helper()
		d := t.TempDir()
		a, b := filepath.Join(d, "a"), filepath.Join(d, "b")
		if err := os.Symlink(b, a); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(a, b); err != nil {
			t.Fatal(err)
		}
		return a
	}
	run := func(t *testing.T, p *policy.Policy) error {
		t.Helper()
		dir := t.TempDir()
		script := filepath.Join(dir, "probe.sh")
		if err := os.WriteFile(script, []byte("echo ok\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		p.Entrypoint, p.Interpreter, p.Exec = script, "sh", policy.ExecAll
		p.Read = append(p.Read, dir)
		_, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{}, enforce.RunOptions{})
		return err
	}

	t.Run("read", func(t *testing.T) {
		a := loop(t)
		err := run(t, &policy.Policy{Read: []string{a}})
		if err == nil {
			t.Fatalf("looped read grant %s was accepted; want a refusal", a)
		}
		if !strings.Contains(err.Error(), "loops through itself") || !strings.Contains(err.Error(), a) {
			t.Fatalf("got %v, want a refusal naming the looping grant %s", err, a)
		}
	})

	t.Run("write", func(t *testing.T) {
		a := loop(t)
		err := run(t, &policy.Policy{Write: []string{a}})
		if err == nil {
			t.Fatalf("looped write grant %s was accepted; want a refusal", a)
		}
		if !strings.Contains(err.Error(), "loops through itself") || !strings.Contains(err.Error(), a) {
			t.Fatalf("got %v, want the same refusal a looping read grant gets: %v", err, err)
		}
	})

	// A loop the grant merely contains is not the grant's problem: nothing binds
	// at the loop, so the run proceeds.
	t.Run("loop inside a granted directory", func(t *testing.T) {
		a := loop(t)
		dir := filepath.Dir(a)
		if err := os.WriteFile(filepath.Join(dir, "real.txt"), []byte("REALFILE"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, out := runScript(t, &policy.Policy{Read: []string{dir}}, "cat "+filepath.Join(dir, "real.txt")+" 2>&1 || true\n")
		if !strings.Contains(out, "REALFILE") {
			t.Errorf("a loop inside a granted directory broke the grant: %q", out)
		}
	})

	// A dangling symlink is not a loop: it names a target that does not exist yet,
	// which stays supported (the half-populated home-manager / stow layout).
	t.Run("dangling symlink still granted", func(t *testing.T) {
		d := t.TempDir()
		link := filepath.Join(d, "link")
		if err := os.Symlink(filepath.Join(d, "store", "later"), link); err != nil {
			t.Fatal(err)
		}
		if err := run(t, &policy.Policy{Read: []string{link}}); err != nil {
			t.Errorf("a dangling symlink grant was refused: %v", err)
		}
	})
}

// A read grant of "/" binds the host's root children, and /run holds the control
// sockets of the host's services (the docker daemon, the session bus, gpg-agent).
// A read-only bind does not stop connect() to a unix socket - the kernel refuses
// writes through a read-only mount only for regular files, directories, and
// symlinks - and the network namespace does not fence one either, since a
// path-named socket is scoped by the filesystem. So an exposed /run would make
// "read: /" a channel to whatever those daemons can do, which for docker is host
// root. The shield must leave nothing of the host's /run reachable.
func TestReadRootDoesNotExposeHostRuntime(t *testing.T) {
	requireSandbox(t)

	entries, err := os.ReadDir("/run")
	if err != nil {
		t.Skipf("cannot read the host's /run: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) == 0 {
		t.Skip("the host's /run is empty, so the shield would pass vacuously")
	}

	_, out := runScript(t, &policy.Policy{Read: []string{"/"}}, "ls -A /run 2>&1 || true\n")
	for _, name := range names {
		if strings.Contains(out, name) {
			t.Fatalf("the host's /run/%s is reachable under a read: / grant; got %q", name, out)
		}
	}
}

// leakInheritedFd opens a host secret and clears close-on-exec so the descriptor is
// inherited across the exec into bwrap, mimicking a parent that opened it with
// `exec N< secret.key`. It returns the descriptor number, which the target then
// tries to reach.
func leakInheritedFd(t *testing.T) (dir string, fd int) {
	t.Helper()
	dir = t.TempDir()
	secret := filepath.Join(dir, "secret.key")
	if err := os.WriteFile(secret, []byte("SECRET_XYZZY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(secret)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(f.Fd(), unix.F_SETFD, flags&^unix.FD_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	return dir, int(f.Fd())
}

// runExec runs src under the given exec mode, without runScript's forced exec: all,
// so the exec: none path (where the launcher execveats the target) is genuinely
// exercised. The script must use only shell builtins under exec: none, where the
// seccomp filter blocks spawning any helper.
func runExec(t *testing.T, mode policy.ExecMode, readDir, src string) string {
	t.Helper()
	scriptDir := t.TempDir()
	script := filepath.Join(scriptDir, "probe.sh")
	if err := os.WriteFile(script, []byte(src), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{
		Entrypoint:  script,
		Interpreter: "sh",
		Read:        []string{scriptDir, readDir},
		Exec:        mode,
	}
	var out bytes.Buffer
	if _, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out}, enforce.RunOptions{}); err != nil {
		t.Fatalf("Run: %v (output: %s)", err, out.String())
	}
	return out.String()
}

// A file descriptor bento's parent leaked without O_CLOEXEC - an editor, a CI
// runner, a server embedding bento - passes through bwrap into the sandbox. The
// mount namespace and the deny-list revoke paths, but neither closes an open
// descriptor, so its content would be an ungranted read channel out of the sandbox.
// The launcher drops every inherited descriptor before the target runs. This reads
// THROUGH the descriptor with a dup redirect (a shell builtin, so it works even
// under exec: none where subprocesses are blocked) - the actual exploit, not merely
// whether the path is visible - on both the exec: all path (which used to run the
// target directly, with no launcher) and the exec: none path.
func TestInheritedFdContentUnreadable(t *testing.T) {
	requireSandbox(t)

	for _, mode := range []policy.ExecMode{policy.ExecAll, policy.ExecNone} {
		t.Run(string(mode), func(t *testing.T) {
			dir, fd := leakInheritedFd(t)
			src := fmt.Sprintf("if read line <&%d 2>/dev/null; then echo \"LEAK:$line\"; else echo clean; fi\n", fd)
			out := runExec(t, mode, dir, src)
			if strings.Contains(out, "LEAK:") {
				t.Errorf("read an inherited host descriptor's content inside the sandbox: %q", out)
			}
			if !strings.Contains(out, "clean") {
				t.Errorf("probe did not run as expected: %q", out)
			}
		})
	}
}

// On the exec: all path the launcher survives as the sandbox's pid 2 holding the
// leaked descriptor open (close-on-exec only drops it at an exec, and supervise does
// not exec). The kernel blocks the target from reading its content across the
// process boundary, but the path behind the descriptor is still disclosed by a
// readlink of the launcher's procfs unless the launcher is non-dumpable. This
// asserts the target cannot learn the host path that way.
func TestSupervisorFdPathNotDisclosed(t *testing.T) {
	requireSandbox(t)

	dir, fd := leakInheritedFd(t)
	// The target is a direct child of the launcher under supervise, so $PPID is the
	// launcher. readlink is a subprocess, which exec: all permits.
	src := fmt.Sprintf("readlink /proc/$PPID/fd/%d 2>/dev/null || echo clean\n", fd)
	out := runExec(t, policy.ExecAll, dir, src)
	if strings.Contains(out, "secret.key") {
		t.Errorf("the launcher disclosed a leaked descriptor's host path to the target: %q", out)
	}
}
