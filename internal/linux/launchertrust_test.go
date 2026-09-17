//go:build linux

package linux

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// The binary that builds the sandbox was resolved with a bare exec.LookPath("bwrap"), and
// nothing ruled on the image it found. A program running as this user - including a
// sandboxed target holding a write grant for a bin directory the user's PATH carries, a
// project's node_modules/.bin or a .venv/bin a direnv profile adds - could plant a bwrap
// there and have the NEXT run build no sandbox at all. It would also inherit the
// descriptors the host passes: the applied-layer report and the bridge liveness pipe. So it
// decides both what the sandbox is and what the run says it was, and the report the user
// reads afterwards to decide whether the run was confined would say every layer was
// Enforced.
//
// No authenticator on the report can close this - a substituted launcher shares the host's
// argv and environment, so a nonce goes to the forger too. The provenance of the binary is
// the only thing that cannot be forged from inside, which is why the check is on the path.
func TestResolveBwrapRefusesAUserWritableLauncher(t *testing.T) {
	dir := t.TempDir()
	shim := filepath.Join(dir, "bwrap")
	if err := os.WriteFile(shim, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	path, notInstalled, err := resolveBwrap()
	if err == nil {
		t.Fatalf("resolveBwrap accepted a bwrap planted in a directory this user can write (%s), so the next run builds no sandbox and reports every layer enforced", path)
	}
	if notInstalled {
		// blocked is the permissive verdict in usableNamespaces: it offers the
		// Landlock-only tier and sends the user off to flip AppArmor sysctls. A hijacked
		// launcher must not land there.
		t.Error("a hijackable launcher was reported as one that is not installed, which is the permissive verdict")
	}
	if !strings.Contains(err.Error(), dir) {
		t.Errorf("refusal = %q, want it to name the writable directory so the user can act on it", err)
	}

	ns, reason := usableNamespaces(context.Background())
	if ns != namespacesUnknown {
		t.Errorf("ns = %v, want unknown: unknown refuses the run, where blocked would offer a tier over a launcher nothing vouches for", ns)
	}
	if !strings.Contains(reason, dir) {
		t.Errorf("probe reason = %q, want the refusal carried into the host report", reason)
	}
}

// The decision above is worth nothing if the launch site does not consult it: a Run that
// still resolved the name itself would pass every assertion in the test above. Run refuses
// before anything is launched, so this needs no sandbox.
func TestRunRefusesAUserWritableLauncher(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bwrap"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	p := &policy.Policy{Entrypoint: "/bin/true"}
	_, err := enforcerUsing("/bin/true").Run(context.Background(), p,
		enforce.Process{Stdout: os.Stderr, Stderr: os.Stderr}, enforce.RunOptions{})
	if err == nil {
		t.Fatal("Run launched with a bwrap this user can replace")
	}
	if !strings.Contains(err.Error(), "writable by this user") {
		t.Errorf("Run error = %q, want the launcher-provenance refusal", err)
	}
}

// The positive control, and the reason the check is a per-component write test for this uid
// rather than a list of blessed directories: a false refusal here refuses every run on a
// working machine, which is worse than the hole it closes. /nix/store and
// /run/current-system/sw/bin pass this for being root-owned, not for being spelled a way
// this package recognises.
func TestResolveBwrapAcceptsTheHostsOwnBwrap(t *testing.T) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		skipMissingDep(t, "bwrap not installed")
	}
	if os.Getuid() == 0 {
		t.Skip("running as root, where every path is writable and the question is vacuous")
	}
	if got, _, err := resolveBwrap(); err != nil {
		t.Fatalf("resolveBwrap refused this host's own bwrap at %s, which would refuse every run here: %v", bwrap, err)
	} else if got != bwrap {
		t.Errorf("resolveBwrap = %q, want %q", got, bwrap)
	}
}

// The absence of bwrap and the hijackability of the one found land on opposite verdicts, and
// a relative PATH entry looks like the first while being the second: LookPath stops at the
// "." entry with ErrDot instead of going on to /usr/bin, so bwrap IS installed and the one it
// found sits in whatever directory bento happened to be run in. Reported as not installed it
// would reach the permissive verdict - which offers the Landlock-only tier - and tell the
// user to install a package they already have.
func TestResolveBwrapRefusesARelativePathEntry(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bwrap"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	t.Setenv("PATH", ".")

	_, notInstalled, err := resolveBwrap()
	if err == nil {
		t.Fatal("resolveBwrap accepted a bwrap resolved relative to the current directory")
	}
	if notInstalled {
		t.Error("a bwrap resolved out of the cwd was reported as not installed, which is the permissive verdict")
	}

	if ns, reason := usableNamespaces(context.Background()); ns != namespacesUnknown {
		t.Errorf("ns = %v (%q), want unknown", ns, reason)
	}
}
