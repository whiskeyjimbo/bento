package observe

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func find(res Result, path string) (Access, bool) {
	for _, a := range res.Accesses {
		if a.Path == path {
			return a, true
		}
	}
	return Access{}, false
}

// The observer must see the files a program opens (distinguishing read from
// write) and notice when it spawns a subprocess. It runs a real shell script and
// checks the observations against what the script did.
func TestTraceObservesOpensAndExec(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}

	dir := t.TempDir()
	readable := filepath.Join(dir, "input.txt")
	if err := os.WriteFile(readable, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	written := filepath.Join(dir, "output.txt")

	// Read one file, write another, and spawn a subprocess (the `true` binary).
	script := "cat " + readable + " > /dev/null; echo hi > " + written + "; true\n"
	sh, _ := exec.LookPath("sh")

	res, err := Trace([]string{sh, "-c", script}, os.Environ(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}

	if a, ok := find(res, readable); !ok {
		t.Errorf("did not observe the read of %s", readable)
	} else if a.Write {
		t.Errorf("%s was read, but observed as a write", readable)
	}

	if a, ok := find(res, written); !ok {
		t.Errorf("did not observe the write of %s", written)
	} else if !a.Write {
		t.Errorf("%s was written, but observed as read-only", written)
	}

	if !res.Execed {
		t.Error("the script spawned `true` but no exec was observed")
	}
}

// A path opened relative to a real directory descriptor (openat with a dirfd,
// not AT_FDCWD) must be anchored at that directory, not left bare — otherwise the
// profiler would anchor it at the working directory and grant the wrong path.
func TestTraceResolvesOpenatDirfd(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "viadir.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Open the directory, then open the file relative to that descriptor.
	script := fmt.Sprintf("import os\nd=os.open(%q,os.O_RDONLY)\nos.close(os.open('viadir.txt',os.O_RDONLY,dir_fd=d))\n", dir)

	res, err := Trace([]string{py, "-c", script}, os.Environ(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}

	var anchored bool
	for _, a := range res.Accesses {
		if a.Path == "viadir.txt" {
			t.Errorf("dirfd-relative open recorded bare-relative, not anchored: %q", a.Path)
		}
		if strings.HasPrefix(a.Path, "/") && strings.HasSuffix(a.Path, "/viadir.txt") {
			anchored = true
		}
	}
	if !anchored {
		t.Errorf("dirfd-relative open was not anchored to an absolute path; accesses: %v", res.Accesses)
	}
}

func TestTracePropagatesExitCode(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	res, err := Trace([]string{sh, "-c", "exit 5"}, os.Environ(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}
	if res.ExitCode != 5 {
		t.Errorf("exit code = %d, want 5", res.ExitCode)
	}
}
