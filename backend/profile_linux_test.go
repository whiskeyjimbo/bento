//go:build linux

package backend

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/enforce"
	"github.com/whiskeyjimbo/bento-v2/policy"
)

// The linux backend confines a target by re-executing this binary as a hidden
// launch stage, so the test process must itself dispatch those stages - the same
// contract an embedder honors in its own main(). Without this, Profile's sandbox
// re-execs the test binary and it runs the test suite again instead of the launcher.
func TestMain(m *testing.M) {
	DispatchReexec()
	os.Exit(m.Run())
}

func requireSandbox(t *testing.T) {
	t.Helper()
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		t.Skip("bwrap not installed")
	}
	// bwrap alone is not enough: a host with unprivileged user namespaces disabled has
	// bwrap in PATH but cannot create the namespace, so Profile fails to complete rather
	// than shielding anything. Probe the same way the enforcer's admission does, so this
	// test skips (not fails) on that supported-but-degraded host class.
	if err := exec.Command(bwrap, "--unshare-user", "--unshare-net", "--bind", "/", "/", "/bin/true").Run(); err != nil {
		t.Skip("unprivileged user namespaces unavailable on this host")
	}
}

// Profile forwards ProfileOptions.DenyPaths to the enforcer, and a dropped DenyPath
// is a silent fail-open: a supervising embedder's store shield relies on it, so the
// grant-broad Read the profiling policy carries would otherwise expose the store. This
// guards the forwarding end-to-end (backend.Profile -> a real sandbox), the seam the
// internal enforcement test cannot see. The store lives under $HOME, not /tmp, because
// the sandbox always overmounts /tmp with its own tmpfs.
func TestProfileForwardsDenyPaths(t *testing.T) {
	requireSandbox(t)

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	storeDir, err := os.MkdirTemp(home, "bento-backend-denytest-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(storeDir)
	const secret = "TOPSECRET-BACKEND-STORE"
	storeFile := filepath.Join(storeDir, "perms.json")
	if err := os.WriteFile(storeFile, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(script, []byte("cat "+storeFile+" 2>&1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{"/"}, Exec: policy.ExecAll}

	run := func(deny []string) string {
		var out bytes.Buffer
		if _, err := Profile(context.Background(), p,
			enforce.Process{Stdout: &out, Stderr: &out},
			ProfileOptions{DenyPaths: deny}); err != nil {
			t.Fatalf("Profile: %v", err)
		}
		return out.String()
	}

	// Baseline: with the broad Read and no deny path the trial reads the store, so a
	// dropped DenyPath would look identical to a passing shield if we only checked the
	// shielded case.
	if base := run(nil); !strings.Contains(base, secret) {
		t.Fatalf("baseline: the trial should read the store with no deny path; got %q", base)
	}
	if shielded := run([]string{storeDir}); strings.Contains(shielded, secret) {
		t.Errorf("DenyPaths did not reach the sandbox: store leaked %q", shielded)
	}
}
