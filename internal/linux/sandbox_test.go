package linux

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/internal/enforce"
	"github.com/whiskeyjimbo/bento-v2/internal/policy"
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
	// passing security assertion — the boundary under test must be what denies,
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

// The mandatory deny-list must hold even when the policy grants the whole home
// directory. A credential file that does not exist yet must not be creatable —
// this is the v1 hole, where an absent ~/.ssh could be created and a key planted.
func TestDenyListShieldsUnbornCredentialUnderHomeGrant(t *testing.T) {
	requireSandbox(t)

	// Stand in a fake home so the test never touches the developer's real one.
	home := t.TempDir()
	t.Setenv("HOME", home)

	planted := filepath.Join(home, ".ssh", "authorized_keys")
	p := &policy.Policy{Write: []string{home}}
	runScript(t, p, "mkdir -p "+filepath.Join(home, ".ssh")+" && echo PLANTED > "+planted+" 2>&1 || true\n")

	if b, err := os.ReadFile(planted); err == nil && strings.Contains(string(b), "PLANTED") {
		t.Fatalf("a key was planted in ~/.ssh despite the mandatory deny-list: %q", b)
	}
}

// The same for a shell profile, the classic persistence vector.
func TestDenyListShieldsShellProfileUnderHomeGrant(t *testing.T) {
	requireSandbox(t)

	home := t.TempDir()
	t.Setenv("HOME", home)
	rc := filepath.Join(home, ".bashrc")

	p := &policy.Policy{Write: []string{home}}
	runScript(t, p, "echo APPENDED >> "+rc+" 2>&1 || true\n")

	if b, err := os.ReadFile(rc); err == nil && strings.Contains(string(b), "APPENDED") {
		t.Fatalf("a shell profile was modified despite the mandatory deny-list: %q", b)
	}
}

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

	p := &policy.Policy{Write: []string{home}}
	_, out := runScript(t, p, "cat "+creds+" 2>&1 || true\n")

	if strings.Contains(out, "SECRETKEY") {
		t.Fatalf("credentials were readable despite the mandatory deny-list: %q", out)
	}
}

// A write-denied file that exists must still be READABLE. v1 shadowed these with
// /dev/null, so git saw an empty ~/.gitconfig. Read and write denial are
// different things and must stay so.
func TestWriteDeniedFileRemainsReadable(t *testing.T) {
	requireSandbox(t)

	home := t.TempDir()
	t.Setenv("HOME", home)
	gitconfig := filepath.Join(home, ".gitconfig")
	if err := os.WriteFile(gitconfig, []byte("[user]\n\tname = Real Name\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{Write: []string{home}}
	_, out := runScript(t, p, "cat "+gitconfig+" 2>&1 || true\n")

	if !strings.Contains(out, "Real Name") {
		t.Fatalf("a write-denied file should stay readable, but reads were blinded: %q", out)
	}

	// ...and still not writable.
	runScript(t, p, "echo TAMPERED >> "+gitconfig+" 2>&1 || true\n")
	got, err := os.ReadFile(gitconfig)
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
	if ok, _ := limitsAvailable(); ok {
		wantLimits = enforce.Enforced
	}
	if states[enforce.LayerLimits] != wantLimits {
		t.Errorf("limits state = %v, want %v", states[enforce.LayerLimits], wantLimits)
	}
}
