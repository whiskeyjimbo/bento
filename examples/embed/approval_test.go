package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/manifest"
	"github.com/whiskeyjimbo/bento/policy"
)

// approvedTree writes a runnable manifest, stamped with the fingerprint it is given
// rather than one derived here: that is what lets the caller hand ONE stamp to two
// roots, which is the property under test.
func approvedTree(t *testing.T, p *policy.Policy, stamp string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "noop.sh"), []byte("exit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := manifest.Marshal(p, manifest.Provenance{Approves: stamp})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "bento.yaml")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// runCapturingStderr drives run with the process's own stderr redirected, which is where
// the approval refusal renders. A temp file rather than a pipe: run hands os.Stderr to the
// target too, and a pipe nobody drains would block the run instead of failing the test.
func runCapturingStderr(t *testing.T, manifestPath string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = f
	defer func() { os.Stderr = saved }()
	run(manifestPath, false)
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// THE ORDERING INVARIANT this example's comments claim and nothing else here holds:
// the approval switch in run reads the manifest AS WRITTEN, and manifest.Resolve rewrites
// its entrypoint and grants to absolute paths. That order is what makes an approval
// relocatable - the same tree at two roots fingerprints identically, so one stamp covers
// both. Resolving first would refuse every approved manifest carrying a relative path, and
// refuse it differently at every root.
//
// Asserted on the refusal text, not the exit code: whether the sandbox itself can be built
// is a property of the host, and the run is past the approval switch either way.
func TestOneStampCoversTheSameTreeAtTwoRoots(t *testing.T) {
	p := &policy.Policy{Entrypoint: "./noop.sh", Interpreter: "sh", Read: []string{"./data"}}
	// Taken once, over the policy as written, and handed to both trees.
	stamp := p.Fingerprint()

	for _, root := range []string{approvedTree(t, p, stamp), approvedTree(t, p, stamp)} {
		out := runCapturingStderr(t, root)
		if strings.Contains(out, "permissions changed since it was approved") {
			t.Errorf("one stamp must cover the same tree at any root; %s was refused as drifted:\n%s", root, out)
		}
	}

	// The other half of the same order, and what keeps the assertion above from holding
	// vacuously: a stamp that does not match is still caught here.
	out := runCapturingStderr(t, approvedTree(t, p, "sha256:stale"))
	if !strings.Contains(out, "permissions changed since it was approved") {
		t.Errorf("a manifest edited after approval must be refused; got:\n%s", out)
	}
}

// The stamp lives in the manifest, so a target able to rewrite the manifest can widen its
// policy and re-stamp it for the next run. A write grant rooted at the manifest's own
// directory covers it, and the read-only bind is all that stops the rewrite.
func TestTheTargetCannotRewriteItsManifest(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("needs bwrap")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tamper.sh"), []byte("echo '# widened' >> bento.yaml\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: "./tamper.sh", Interpreter: "sh", Write: []string{"."}, Workdir: "."}
	data, err := manifest.Marshal(p, manifest.Provenance{Approves: p.Fingerprint()})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "bento.yaml")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	stderr := runCapturingStderr(t, path)
	// A host that cannot build the sandbox leaves the manifest untouched too, for no
	// reason this test is about.
	if !strings.Contains(stderr, "sandbox engaged") {
		t.Skipf("the sandbox did not engage on this host:\n%s", stderr)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(data) {
		t.Errorf("the target rewrote its manifest under a write grant covering it:\n%s\nstderr:\n%s", after, stderr)
	}
}

// A write grant above the manifest's directory can rename that directory, and the bind
// moves with it, so the run is refused before it starts rather than bound and trusted.
func TestAGrantThatReachesAroundTheBindIsRefused(t *testing.T) {
	p := &policy.Policy{Entrypoint: "./noop.sh", Interpreter: "sh", Write: []string{".."}}
	stderr := runCapturingStderr(t, approvedTree(t, p, p.Fingerprint()))
	if !strings.Contains(stderr, "read-only bind over the manifest would not hold") {
		t.Errorf("a write grant above the manifest's directory must be refused; stderr:\n%s", stderr)
	}
}
