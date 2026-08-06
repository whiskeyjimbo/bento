//go:build linux && amd64

package observe

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The kernel opens a script's #! interpreter and a dynamic binary's PT_INTERP loader
// inside execve, with no syscall for the decoder to see, so both used to be absent from
// every profile - and the enforced run then failed closed with ENOENT on a file the
// profiling run demonstrably needed, with Dropped at 0 to say nothing was missed.
//
// Both halves are exercised at once: the script's own exec is the root's, which retired
// before the tracer attached, and `ls` is a descendant exec reaching the decoder normally.
func TestTraceObservesInterpreterAndLoader(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		skipMissingDep(t, "sh not available")
	}
	loader, ok := execImage(sh)
	if !ok || loader == "" {
		t.Skipf("%s names no ELF interpreter on this host", sh)
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "run.sh")
	if err := os.WriteFile(script, []byte("#!"+sh+"\nls "+dir+" > /dev/null\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	res, err := Trace([]string{script}, os.Environ(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}
	for _, want := range []string{sh, loader} {
		if _, ok := find(res, want); !ok {
			t.Errorf("did not observe %s; the kernel opened it to run the script", want)
		}
	}
	if res.Dropped != 0 {
		t.Errorf("Dropped = %d, want 0: every image was nameable", res.Dropped)
	}
}

// A shebang the walk cannot resolve is a lost observation, not a file that is not needed:
// the kernel resolves a relative interpreter against the tracee's working directory, which
// nothing here tracks. Reporting it as a drop is what stops the manifest reading complete.
func TestExecImageChainReportsAnUnresolvableShebang(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "rel.sh")
	if err := os.WriteFile(script, []byte("#!bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if paths, complete := execImageChain(script); complete {
		t.Errorf("a relative shebang reported complete, with %v", paths)
	}
}

// The three ways the walk can fail to see what the kernel will. Each must count as a
// dropped observation, because the manifest is short either way and only this says so.
// A path that is simply not there is the one case that is not a loss: the exec answers
// ENOENT too, so there is no image to record.
func TestExecImageReportsWhatItCouldNotSee(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, body []byte, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, body, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// The kernel execs a binary it can read but the observer cannot; reporting that
	// complete puts the loader back out of the manifest with nothing to say it is missing.
	unreadable := write("exec-only", []byte("#!/bin/sh\n"), 0o111)
	if os.Geteuid() == 0 {
		t.Log("running as root, so the unreadable case cannot be provoked")
	} else if _, ok := execImage(unreadable); ok {
		t.Error("an unreadable exec target reported complete")
	}

	// A shebang line longer than the kernel's own buffer: the exec fails ENOEXEC, and
	// the truncated first field would name a file nothing ever opened.
	long := write("long.sh", append([]byte("#!/"), make([]byte, 512)...), 0o755)
	if _, ok := execImage(long); ok {
		t.Error("a shebang with no line ending reported complete")
	}

	if _, ok := execImage(filepath.Join(dir, "absent")); !ok {
		t.Error("a path that is not there was counted as a lost observation; the exec fails the same way")
	}
}

// A #! chain is walked, not resolved once: the kernel opens the interpreter, then the
// interpreter's own loader. A static binary ends the walk with nothing to add.
func TestExecImageChainWalksToTheLoader(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		skipMissingDep(t, "sh not available")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "run.sh")
	if err := os.WriteFile(script, []byte("#!"+sh+" -eu\ntrue\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	paths, complete := execImageChain(script)
	if !complete {
		t.Fatal("the chain reported an unresolvable image")
	}
	if len(paths) < 2 || paths[0] != sh {
		t.Errorf("chain = %v, want %s followed by its ELF interpreter", paths, sh)
	}
}
