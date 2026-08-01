package observe

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A path the target only stats, accesses, or readlinks - never opens - must land in the
// manifest as a read, because under enforcement an ungranted path is absent rather than
// unreadable and the stat that succeeded during profiling returns ENOENT on the enforced
// run. The mirror requirement is that a probe which already MISSED is not recorded: a
// shell's PATH search misses hundreds of times per command, and carrying those into the
// proposal would bury the paths the run needs.
func TestTraceRecordsSuccessfulExistenceProbes(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		skipMissingDep(t, "python3 not available")
	}
	dir := t.TempDir()
	statted := filepath.Join(dir, "config.toml")
	linked := filepath.Join(dir, "link")
	if err := os.WriteFile(statted, []byte("k = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(statted, linked); err != nil {
		t.Fatal(err)
	}
	accessed := statted
	missing := filepath.Join(dir, "absent.toml")

	script := fmt.Sprintf(`
import os
os.stat(%q)
os.access(%q, os.R_OK)
os.readlink(%q)
try:
    os.stat(%q)
except FileNotFoundError:
    pass
`, statted, accessed, linked, missing)

	res, err := Trace([]string{py, "-c", script}, os.Environ(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}
	for _, path := range []string{statted, linked} {
		if a, ok := find(res, path); !ok {
			t.Errorf("no access recorded for the probed path %q; accesses: %v", path, res.Accesses)
		} else if a.Write {
			t.Errorf("existence probe of %q recorded as a write, want a read", path)
		}
	}
	if _, ok := find(res, missing); ok {
		t.Errorf("a probe that returned ENOENT was recorded: %q", missing)
	}
}

// chdir is decoded at the entry stop, unlike the other existence syscalls, because it
// moves the directory resolveAt reads back out of /proc. A relative chdir must therefore
// be anchored at the directory the process was in BEFORE the call, not after it - the
// exit stop would name dir/sub/sub.
func TestTraceAnchorsRelativeChdirBeforeTheMove(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		skipMissingDep(t, "python3 not available")
	}
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf("import os\nos.chdir(%q)\nos.chdir('sub')\n", dir)

	res, err := Trace([]string{py, "-c", script}, os.Environ(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}
	if _, ok := find(res, sub); !ok {
		t.Errorf("relative chdir not anchored at %q; accesses: %v", sub, res.Accesses)
	}
	if _, ok := find(res, filepath.Join(sub, "sub")); ok {
		t.Errorf("relative chdir anchored at the post-move directory: %q", filepath.Join(sub, "sub"))
	}
}

// A failed open is still recorded - the program meant to open that file, and enforcement
// has to reproduce the same answer - but a path nothing was ever found at needs to be
// distinguishable from one that resolved, so a reporting layer can tell a search miss
// from a file the run read. The probe-then-create case is the one that decides the key:
// the two opens differ in their write bit, and letting each carry its own answer would
// report a file the run created as absent.
func TestTraceMarksPathsNothingWasFoundAt(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		skipMissingDep(t, "python3 not available")
	}
	dir := t.TempDir()
	present := filepath.Join(dir, "there.toml")
	missing := filepath.Join(dir, "gone.toml")
	created := filepath.Join(dir, "made.toml")
	if err := os.WriteFile(present, []byte("k = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	script := fmt.Sprintf(`
import os
open(%q).close()
try:
    open(%q).close()
except FileNotFoundError:
    pass
try:
    open(%q).close()
except FileNotFoundError:
    pass
open(%q, "w").close()
`, present, missing, created, created)

	res, err := Trace([]string{py, "-c", script}, os.Environ(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}
	for _, path := range []string{present, created} {
		for _, a := range res.Accesses {
			if a.Path == path && a.Absent {
				t.Errorf("%q was opened successfully but is marked absent (write=%v)", path, a.Write)
			}
		}
	}
	a, ok := find(res, missing)
	if !ok {
		t.Fatalf("a failed open was not recorded: %q; accesses: %v", missing, res.Accesses)
	}
	if !a.Absent {
		t.Errorf("open of %q returned ENOENT and was not marked absent", missing)
	}
}
