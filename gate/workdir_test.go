//go:build unix

package gate_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/gate"
	"github.com/whiskeyjimbo/bento/policy"
)

// workdirPolicy is an otherwise clean manifest - the entrypoint exists, no interpreter -
// so every problem the check reports is the workdir's.
func workdirPolicy(t *testing.T, workdir string, write []string) *policy.Policy {
	t.Helper()
	entrypoint := filepath.Join(t.TempDir(), "run.sh")
	if err := os.WriteFile(entrypoint, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return &policy.Policy{Entrypoint: entrypoint, Workdir: workdir, Write: write}
}

func workdirProblem(t *testing.T, r gate.Runnability) string {
	t.Helper()
	for _, p := range r.Problems {
		if strings.Contains(p, "workdir") {
			return p
		}
	}
	return ""
}

// The failure this closes: the backend chdirs into the workdir once the sandbox is
// already built, so a manifest naming a directory this host has not got validated clean,
// reported runnable, and died at a step that had already paid for the mount namespace.
func TestCheckReportsAWorkdirThisHostHasNot(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nowhere")
	got := workdirProblem(t, gate.Check(workdirPolicy(t, missing, nil)))
	if got == "" {
		t.Fatalf("a workdir that is not on this host must be a problem; got %+v", gate.Check(workdirPolicy(t, missing, nil)).Problems)
	}
	if !strings.Contains(got, missing) {
		t.Errorf("the problem must name the workdir so the reader can go and look; got %q", got)
	}
}

// The other direction, and the one that matters more under this package's contract: a
// gate that invents a refusal is worse than one that misses it. `workdir: ./out` beside
// `write: [./out]` is the shape `bento profile` writes, the directory does not exist
// until the run creates it, and that run starts fine - so nothing here may call it
// unrunnable.
func TestCheckPassesAnAbsentWorkdirAWriteGrantCreates(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(root, "out")
	if got := workdirProblem(t, gate.Check(workdirPolicy(t, out, []string{out}))); got != "" {
		t.Errorf("a write grant AT the workdir creates it before the sandbox exists; got %q", got)
	}
	// Beneath it too: the backend's MkdirAll makes the parents, and bwrap binding the
	// grant creates its mount point inside the box.
	under := filepath.Join(out, "logs")
	if got := workdirProblem(t, gate.Check(workdirPolicy(t, out, []string{under}))); got != "" {
		t.Errorf("a write grant BENEATH the workdir creates it too; got %q", got)
	}
	// A write grant above the workdir does not: prepareWriteDirs makes the grant, not
	// the directory under it the manifest wants to start in.
	if got := workdirProblem(t, gate.Check(workdirPolicy(t, under, []string{root}))); got == "" {
		t.Error("a write grant ABOVE the workdir leaves the workdir itself uncreated, so the chdir still fails")
	}
}

// An unset workdir is the ordinary manifest: the run starts in the entrypoint's own
// directory and there is no second path to stat.
func TestCheckSaysNothingAboutAnUnsetWorkdir(t *testing.T) {
	if got := workdirProblem(t, gate.Check(workdirPolicy(t, "", nil))); got != "" {
		t.Errorf("a manifest setting no workdir has none to refuse; got %q", got)
	}
}
