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
// `write: [./out]` is what a re-profile of a manifest already setting that workdir writes
// back, the directory does not exist until the run creates it, and that run starts fine -
// so nothing here may call it unrunnable.
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

// bwrap chdirs into the workdir once the sandbox is built, and into a non-directory that
// is "Can't chdir to ...: Not a directory" (measured against bwrap 0.11 on this host, exit
// 1) - a run that has already paid for the mount namespace, which is the class Runnability
// reports first. Stat alone passes it: a file is a path that exists.
//
// Safe in the direction this package rules out, because nothing turns the host file into a
// sandbox directory: a write grant naming it is refused as a file, and a shield over a
// file binds an empty file.
func TestCheckRefusesAWorkdirThatIsAFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "out")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	got := workdirProblem(t, gate.Check(workdirPolicy(t, file, []string{file})))
	if got == "" {
		t.Fatalf("a workdir that is a file fails bwrap's chdir and must be a problem; got %+v", gate.Check(workdirPolicy(t, file, []string{file})).Problems)
	}
	if !strings.Contains(got, file) {
		t.Errorf("the problem must name the workdir so the reader can go and look; got %q", got)
	}

	// The symlink is the case a Lstat would break: it names a directory, and the run
	// starts there.
	dir := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if got := workdirProblem(t, gate.Check(workdirPolicy(t, link, nil))); got != "" {
		t.Errorf("a workdir that is a symlink to a directory is a directory to the chdir; got %q", got)
	}
}

// unreadableWorkdir plants a directory that DOES exist behind a parent nothing can read,
// so os.Stat on it fails with EACCES rather than ENOENT. It is the only locally
// constructible errno on pathresolve's Unreadable arm; EIO and ESTALE reach it by the
// same branch.
func unreadableWorkdir(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root reads through a 000 directory, so the barrier this needs does not exist")
	}
	locked := filepath.Join(t.TempDir(), "locked")
	wd := filepath.Join(locked, "wd")
	if err := os.MkdirAll(wd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	return wd
}

// The failure this closes: every os.Stat error read as absence, so a directory that is
// there behind an unreadable parent was reported as one this host has not got. A reader
// who trusts that creates the directory or adds a grant, and neither is the problem.
func TestCheckSaysAWorkdirCouldNotBeReadRatherThanThatItIsAbsent(t *testing.T) {
	wd := unreadableWorkdir(t)
	got := workdirProblem(t, gate.Check(workdirPolicy(t, wd, nil)))
	if got == "" {
		t.Fatalf("a workdir whose existence could not be determined must be reported; got %+v", gate.Check(workdirPolicy(t, wd, nil)).Problems)
	}
	if strings.Contains(got, "does not exist") {
		t.Errorf("the directory is there; the reason must not send the reader off to create it: %q", got)
	}
	if !strings.Contains(got, "could not be read") {
		t.Errorf("the report must say what stayed unknown; got %q", got)
	}
}

// The other half of the same cell, and the more dangerous one: the first says something
// false, this says nothing at all. pathresolve hands back the caller's own path for both
// the workdir and the grant when neither could be walked - its documented fail-closed
// cutoff - so CoversResolved compared two unwalked strings and the lexical match passed
// for containment.
func TestCheckDoesNotAcceptAnUnreadableWorkdirOnALexicalGrantMatch(t *testing.T) {
	wd := unreadableWorkdir(t)
	if got := workdirProblem(t, gate.Check(workdirPolicy(t, wd, []string{wd}))); got == "" {
		t.Error("a write grant spelled like the workdir is not containment when neither side could be resolved; the gate must not go silent")
	}
}

// gate.Check documents an absolute-path precondition (a relative workdir would be stat'd
// against whatever directory the embedder ran from) and used to enforce nothing. The run
// refuses one outright at internal/linux/linux.go, so answering is the side that agrees
// with the oracle.
func TestCheckRefusesARelativeWorkdir(t *testing.T) {
	got := workdirProblem(t, gate.Check(workdirPolicy(t, "out", nil)))
	if got == "" {
		t.Fatal("a relative workdir must be answered, not stat'd against the embedder's cwd")
	}
	if !strings.Contains(got, "not absolute") {
		t.Errorf("the problem must name the precondition that was broken; got %q", got)
	}
}
