//go:build linux && amd64

package observe

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/whiskeyjimbo/bento/profile"
)

// The walk resolveAt's anchor check exists to stop, driven end to end: a traced run opens
// a relative path through a descriptor on a REGULAR FILE, and the proposal synthesized
// from what the observer recorded must not name the path that anchor lexically joins to.
//
// The two halves are pinned separately - TestResolveAtAnchorsAndDrops on the refusal,
// FuzzResolveAt on its generality - and neither says what the refusal is worth, because
// neither reaches profile.Synthesize. That is where the harm would land: openat(2) answers
// ENOTDIR on this anchor, so the file was never opened, and a lexical join would put a
// path the tracee merely spelled with ".." into a grant a reviewer is asked to approve.
// The drop is the honest answer, and it is only honest if it also arrives - hence the
// Dropped assertion, which separates a refusal that was counted from a silent one.
//
// The observation is assembled here from Result rather than round-tripped through the
// launcher's report text, so this covers the observer-to-Synthesize leg and not the
// serialization between them.
func TestDroppedAnchorProposesNoGrant(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		skipMissingDep(t, "python3 not available")
	}
	dir := t.TempDir()
	anchor := filepath.Join(dir, "anchor")
	if err := os.WriteFile(anchor, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The path the lexical join would name. It has to EXIST: profile.SandboxScratch drops
	// a /tmp path nothing is at, which is where t.TempDir() lives, and the test would then
	// pass for that reason whatever resolveAt did.
	fabricated := filepath.Join(dir, "secret")
	if err := os.WriteFile(fabricated, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	entrypoint := filepath.Join(dir, "run.py")
	if err := os.WriteFile(entrypoint, []byte(fmt.Sprintf(`
import os
fd = os.open(%q, os.O_RDONLY)
try:
    os.open("../secret", os.O_RDONLY, dir_fd=fd)
except OSError:
    pass
os.close(fd)
`, anchor)), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Trace([]string{py, entrypoint}, os.Environ(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}
	if res.Dropped == 0 {
		t.Errorf("the run opened a relative path through a regular-file anchor and nothing was counted dropped; accesses: %v", res.Accesses)
	}

	obs := profile.Observation{Interpreter: py, ExitCode: res.ExitCode, Dropped: res.Dropped}
	for _, a := range res.Accesses {
		if a.Write {
			obs.Writes = append(obs.Writes, a.Path)
			continue
		}
		obs.Reads = append(obs.Reads, a.Path)
		if a.Probed {
			obs.Probed = append(obs.Probed, a.Path)
		}
		if a.Absent {
			obs.Absent = append(obs.Absent, a.Path)
		}
	}
	pol, err := profile.Synthesize(entrypoint, py, nil, obs)
	if err != nil {
		t.Fatalf("Synthesize: %v", err)
	}
	if slices.Contains(pol.Read, fabricated) || slices.Contains(pol.Write, fabricated) {
		t.Errorf("the proposal grants %q, a path the kernel answered ENOTDIR on; read %v write %v", fabricated, pol.Read, pol.Write)
	}
}
