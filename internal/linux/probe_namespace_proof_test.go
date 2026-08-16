//go:build linux

package linux

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The namespace probe used to take a zero exit as proof: it was empirical about the HOST
// but not about the BINARY, and could not tell "bwrap built the namespaces" from "something
// named bwrap exited 0". Run re-resolves the same name and execs it, so a wrapper that
// swallows an unrecognised flag - a Nix or distro shim, a container entrypoint, a bwrap
// older than one of namespaceFlags - gets the target a report claiming the filesystem and
// network layers Enforced over no mount namespace and no netns at all.
//
// The canary now reports from inside something only a real user namespace produces, so a
// bwrap that builds nothing lands on the unknown verdict. Unknown is the strict one: it
// refuses outright, where blocked would have offered the Landlock-only tier over a host
// whose namespaces were never measured.
func TestCanUnshareNeedsProofTheNamespaceWasBuilt(t *testing.T) {
	dir := t.TempDir()
	shim := filepath.Join(dir, "bwrap")
	if err := os.WriteFile(shim, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	err := canUnshare(context.Background(), shim)
	if err == nil {
		t.Fatal("canUnshare passed a bwrap that exits 0 and builds nothing; exit status is the whole oracle again")
	}

	ns, reason := classifyUnshare(err)
	if ns != namespacesUnknown {
		t.Errorf("ns = %v, want unknown: a bwrap that proved nothing is not a host that refused the namespace, and blocked would offer a tier over an unmeasured host", ns)
	}
	if !strings.Contains(reason, "did not report a user namespace") {
		t.Errorf("reason = %q, want it to name what was missing", reason)
	}
}

// The positive control for the assertion above, and the check that the proof is not
// something a legitimate host can fail: real bwrap on this host must still report the
// namespace as usable. A predicate that false-negatives here refuses every network manifest
// on a working machine, which is worse than the bug it closes.
// requireSandbox is deliberately not used: it calls canUnshare itself, so a broken proof
// would turn this into a skip - a pass that asserted nothing, which is the one failure mode
// indistinguishable from success. Only a host that genuinely REFUSES the namespace skips
// here; a probe that could not answer is the failure being guarded against.
func TestCanUnshareStillPassesOnARealBwrap(t *testing.T) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		skipMissingDep(t, "bwrap not installed")
	}
	cerr := canUnshare(context.Background(), bwrap)
	if cerr == nil {
		return
	}
	if ns, reason := classifyUnshare(cerr); ns == namespacesBlocked {
		skipMissingDep(t, "this host refuses the namespace: %s", reason)
	}
	t.Fatalf("real bwrap did not satisfy the namespace proof, which would refuse every network manifest on a working host: %v", cerr)
}
