//go:build linux && amd64

package observe

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
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
	// the truncated first field would name a file nothing ever opened. The filler is
	// printable because a NUL ends the line for binfmt_script exactly as a newline does,
	// which would make this pass without testing anything.
	long := write("long.sh", append([]byte("#!/"), bytes.Repeat([]byte("a"), 512)...), 0o755)
	if _, ok := execImage(long); ok {
		t.Error("a shebang with no line ending reported complete")
	}

	// The same read, ending honestly: a script whose last line has no newline is ordinary,
	// and the kernel ends the line on its zero-padded buffer.
	short := write("noeol.sh", []byte("#!/bin/sh"), 0o755)
	if got, ok := execImage(short); !ok || got != "/bin/sh" {
		t.Errorf("a script with no trailing newline = %q %v, want /bin/sh true", got, ok)
	}

	if _, ok := execImage(filepath.Join(dir, "absent")); !ok {
		t.Error("a path that is not there was counted as a lost observation; the exec fails the same way")
	}
}

// The ELF an exec'd target names is untrusted input, and its PT_INTERP gets the same
// absoluteness check the shebang branch has always applied: a relative loader is resolved
// against the tracee's working directory, and recording it would name a file the sandbox
// cannot bind and send the chain walk on to open it against the observer's own cwd.
//
// The absolute case is here too because the segment is a C string in a padded field, and a
// guard that read past its NUL would refuse every ordinary dynamic binary.
func TestExecImagePT_INTERPMustBeAbsolute(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name   string
		interp string
		want   string
		ok     bool
	}{
		{name: "relative", interp: "lib/ld.so\x00", ok: false},
		{name: "empty", interp: "\x00", ok: false},
		{name: "newline", interp: "/lib/ld.so\nlib/evil.so\x00", ok: false},
		{name: "padded", interp: "/lib64/ld.so\x00\x00\x00\x00", want: "/lib64/ld.so", ok: true},
		// The segment ends at its first NUL and the kernel reads no further, so bytes
		// planted past it are not part of the loader's name - and a check that only
		// trimmed from the right would carry them into the manifest, absolute prefix and
		// all.
		{name: "junk after the NUL", interp: "/lib64/ld.so\x00/evil\x00", want: "/lib64/ld.so", ok: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := execImage(writeELFWithInterp(t, filepath.Join(dir, tc.name), tc.interp))
			if got != tc.want || ok != tc.ok {
				t.Errorf("execImage = %q %v, want %q %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

// writeELFWithInterp builds the smallest ELF64 debug/elf will parse that carries one
// PT_INTERP segment holding interp verbatim - including its NUL padding, which is what
// distinguishes a well-formed loader name from a segment the decoder must refuse.
func writeELFWithInterp(t *testing.T, path, interp string) string {
	t.Helper()
	const ehdrSize, phdrSize = 64, 56
	var b bytes.Buffer
	b.Write([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	put := func(vals ...any) {
		for _, v := range vals {
			if err := binary.Write(&b, binary.LittleEndian, v); err != nil {
				t.Fatal(err)
			}
		}
	}
	// ET_EXEC on EM_X86_64, with no section headers: Progs is all execImage reads.
	put(uint16(elf.ET_EXEC), uint16(elf.EM_X86_64), uint32(1), uint64(0), uint64(ehdrSize), uint64(0),
		uint32(0), uint16(ehdrSize), uint16(phdrSize), uint16(1), uint16(0), uint16(0), uint16(0))
	put(uint32(elf.PT_INTERP), uint32(elf.PF_R), uint64(ehdrSize+phdrSize), uint64(0), uint64(0),
		uint64(len(interp)), uint64(len(interp)), uint64(1))
	b.WriteString(interp)

	if err := os.WriteFile(path, b.Bytes(), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
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

// The path is chosen by the target and this decode runs at the exec's ENTRY stop, so the
// exec need not be able to succeed - it only has to be issued. A plain open of a
// writer-less FIFO blocks inside the syscall, with the tracee frozen at its stop, the
// trace lock held, and no timeout anywhere on the path: an interactive profile recovers
// only by cancelling the sandbox, and an unattended one hangs with no diagnostic.
//
// The answer is that there is no image and nothing was lost: open_exec refuses anything
// that is not a regular file, so the exec fails with the kernel having opened nothing.
func TestExecImageDoesNotBlockOnAFifo(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "f")
	if err := syscall.Mkfifo(fifo, 0o755); err != nil {
		t.Fatal(err)
	}
	type answer struct {
		image string
		ok    bool
	}
	done := make(chan answer, 1)
	go func() {
		image, ok := execImage(fifo)
		done <- answer{image, ok}
	}()
	select {
	case got := <-done:
		if got.image != "" || !got.ok {
			t.Errorf("execImage = %q, %v; a FIFO names no image and loses no observation", got.image, got.ok)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("execImage did not return for a writer-less FIFO: the observer is blocked inside its own open, holding the tracee at its entry stop")
	}
}
