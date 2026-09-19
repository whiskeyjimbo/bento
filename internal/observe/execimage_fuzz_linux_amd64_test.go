//go:build linux && amd64

package observe

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// refShebangImage restates fs/binfmt_script.c's decode of a #! header: the one name the
// KERNEL opens, and whether execImage can honestly report it. It is written here rather
// than called out of the implementation on purpose - a differential whose two sides are
// computed by the same code holds by construction and can never fail.
//
// head is the first bytes of the file. The kernel reads its own 256-byte buffer and
// ZEROES the tail, so a file shorter than the buffer always has a terminator; only a file
// that fills the buffer with no '\n' and no NUL is the ENOEXEC case, and the terminator is
// whichever of the two comes first. The name is then the first space-or-tab-delimited
// field, which is a narrower split than "whitespace": a '\r' or a form feed is part of the
// interpreter's name to the kernel, and stopping at one names a file it never opened.
//
// complete is false for what execImage cannot honestly name: a line that never ends, and a
// relative interpreter, which the kernel resolves against the tracee's working directory.
func refShebangImage(head []byte) (image string, complete bool) {
	body := head[2:]
	end := bytes.IndexAny(body, "\n\x00")
	if end < 0 {
		if len(head) >= execHeadSize {
			return "", false
		}
		end = len(body)
	}
	name := strings.TrimLeft(string(body[:end]), " \t")
	if cut := strings.IndexAny(name, " \t"); cut >= 0 {
		name = name[:cut]
	}
	if name == "" {
		// binfmt_script refuses this with ENOEXEC, having opened nothing.
		return "", true
	}
	if !filepath.IsAbs(name) {
		return "", false
	}
	return name, true
}

// imageDecodeViolation grades one execImage answer against the bytes it decoded. It is a
// pure function so the positive control below can hand it a wrong answer and watch it
// object; an oracle only reachable through the code it grades cannot be shown to have
// teeth at all.
//
// file is the whole file rather than the head buffer because PT_INTERP is read out of the
// segment the program headers point at, which an ordinary dynamic binary carries well past
// the first 256 bytes.
func imageDecodeViolation(file []byte, got string, ok bool) error {
	if got != "" {
		switch {
		case !ok:
			return fmt.Errorf("named %q on a lost observation", got)
		case !filepath.IsAbs(got):
			return fmt.Errorf("named the relative path %q, which resolves against a working directory nothing here tracks", got)
		case strings.ContainsAny(got, "\x00\n"):
			return fmt.Errorf("named %q, which no open(2) can carry", got)
		// The narrowing invariant: a name reported complete is one the bytes really name.
		// A decode that pads, truncates or concatenates fails here.
		case !bytes.Contains(file, []byte(got)):
			return fmt.Errorf("named %q, which does not appear in the file it decoded", got)
		}
	}
	if !bytes.HasPrefix(file, []byte("#!")) {
		return nil
	}
	head := file
	if len(head) > execHeadSize {
		head = head[:execHeadSize]
	}
	wantImage, wantComplete := refShebangImage(head)
	if got != wantImage || ok != wantComplete {
		return fmt.Errorf("decoded %q %v; binfmt_script opens %q %v", got, ok, wantImage, wantComplete)
	}
	return nil
}

// FuzzExecImageDecode differentials execImage's decode of an exec target's first bytes
// against binfmt_script's own, and holds both branches to the narrowing invariant that a
// name reported complete is one the decoded bytes actually contain.
//
// The file is fuzzer-chosen but never executed: the fuzzer reaches `#!` lines naming real
// interpreters within seconds, and running one would hand it a shell. That the reference
// above is the kernel's rule and not a restatement of the Go is pinned separately, by
// TestBinfmtReferenceMatchesTheKernel, which execs a handful of hand-built files whose
// interpreters are chosen rather than generated - the "enumerate small, fuzz large" split.
func FuzzExecImageDecode(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("#!/bin/sh\n"),
		[]byte("#!/bin/sh"),
		[]byte("#!  /bin/sh  -eu\n"),
		[]byte("#!/bin/true\x00junk\n"),
		[]byte("#!/bin/sh\rx\n"),
		[]byte("#!\n"),
		[]byte("#!/\n"),
		[]byte("#!bin/sh\n"),
		append([]byte("#!/"), bytes.Repeat([]byte("a"), 512)...),
		[]byte("\x7fELF"),
		{},
	} {
		f.Add(seed)
	}

	pid := os.Getpid()
	// One file, rewritten per iteration: a temp directory per execution would leave the
	// budget in the filesystem, the way anchorKinds' descriptors would leave it in the fd
	// table.
	path := filepath.Join(f.TempDir(), "image")

	f.Fuzz(func(t *testing.T, file []byte) {
		if err := os.WriteFile(path, file, 0o755); err != nil {
			t.Fatal(err)
		}
		got, ok := execImage(pid, path)
		if err := imageDecodeViolation(file, got, ok); err != nil {
			t.Errorf("execImage %s", err)
		}

		paths, complete := execImageChain(pid, path)
		if !complete {
			return
		}
		// The walk appends on every pass that does not return, and the pass that fills the
		// bound falls through to the incomplete arm, so a complete chain is shorter than it.
		if len(paths) >= execChainDepth {
			t.Errorf("chain reported complete at the depth bound with %v", paths)
		}
		if len(paths) > 0 && paths[0] != got {
			t.Errorf("chain starts at %q, but the image of the file itself is %q", paths[0], got)
		}
		for _, p := range paths {
			if !filepath.IsAbs(p) {
				t.Errorf("chain reported complete naming the relative path %q in %v", p, paths)
			}
		}
	})
}

// The reference the fuzz target differentials against is worth exactly what it costs to
// check it against the kernel, so it is checked against the kernel. Every interpreter here
// is chosen rather than generated: /bin/echo reports the name it was invoked as, and the
// cases that must fail name something nothing can resolve.
func TestBinfmtReferenceMatchesTheKernel(t *testing.T) {
	echo, err := exec.LookPath("echo")
	if err != nil {
		skipMissingDep(t, "echo not available")
	}
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		body string
	}{
		{"plain", "#!" + echo + "\n"},
		{"no trailing newline", "#!" + echo},
		{"argument", "#!" + echo + " -n\n"},
		{"leading space", "#!  " + echo + " -n\n"},
		{"tab before the argument", "#!" + echo + "\t-n\n"},
		// The terminator is the earlier of the newline and the NUL, so the kernel opens
		// the name and not the padding after it.
		{"nul before the newline", "#!" + echo + "\x00junk\n"},
		// A carriage return is not a field separator to the kernel: it is part of the
		// name, which then resolves to nothing.
		{"carriage return in the name", "#!" + echo + "\rx\n"},
		{"relative", "#!bin/echo\n"},
		{"empty name", "#!\n"},
		{"line past the buffer", "#!/" + strings.Repeat("a", 512) + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := filepath.Join(dir, "s")
			if err := os.WriteFile(script, []byte(tc.body), 0o755); err != nil {
				t.Fatal(err)
			}
			image, complete := refShebangImage([]byte(tc.body))

			runErr := exec.Command(script).Run()
			var opened bool
			switch {
			case runErr == nil:
				opened = true
			case errors.Is(runErr, os.ErrNotExist):
				// The kernel resolved an interpreter name and it was not there.
			case errors.Is(runErr, unix.ENOEXEC):
				// binfmt_script refused the header outright, having opened nothing.
			default:
				var ee *exec.ExitError
				if !errors.As(runErr, &ee) {
					t.Fatalf("exec: %v", runErr)
				}
				opened = true
			}

			// The reference names an existing absolute interpreter exactly when the kernel
			// got one open. The arms it reports incomplete, and the empty name, are the
			// ones no exec can reach at all.
			wantOpened := complete && image != "" && fileExists(image)
			if opened != wantOpened {
				t.Errorf("refShebangImage = %q %v, but exec %v", image, complete, runErr)
			}
		})
	}
}

// The oracle's own teeth. Each answer below is one a plausibly broken decode would return
// for these bytes, and the oracle has to object to every one of them; a grader that
// accepts them grades nothing, and a fuzz run under it passes for the wrong reason.
func TestImageDecodeOracleRejectsAWrongAnswer(t *testing.T) {
	for _, tc := range []struct {
		name string
		file string
		got  string
		ok   bool
	}{
		// What a decode that ends the line on the newline alone returns: a name carrying
		// the padding the kernel stopped at, which no open can even take.
		{"the nul padding carried into the name", "#!/bin/true\x00junk\n", "/bin/true\x00junk", true},
		// What splitting on unicode whitespace returns: a real file, reported complete,
		// while the kernel opened a longer name and found nothing.
		{"a carriage return taken as a field separator", "#!/bin/sh\rx\n", "/bin/sh", true},
		// A truncating decode, and a concatenating one: neither name is in the bytes.
		{"a truncated name", "#!/bin/sh\n", "/bin/s", true},
		{"a name the bytes do not carry", "\x7fELF fake", "/lib64/ld.so", true},
		{"a relative name reported complete", "#!bin/sh\n", "bin/sh", true},
		{"a name reported alongside a lost observation", "#!/bin/sh\n", "/bin/sh", false},
		// The kernel opens the interpreter here; reporting no image at all drops it from
		// the manifest with nothing saying it is missing.
		{"an image dropped silently", "#!/bin/sh\n", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := imageDecodeViolation([]byte(tc.file), tc.got, tc.ok); err == nil {
				t.Errorf("the oracle accepted %q %v for %q", tc.got, tc.ok, tc.file)
			}
		})
	}
	// And it must accept the right answer, or it objects to everything and is just as blind.
	if err := imageDecodeViolation([]byte("#!/bin/sh -eu\n"), "/bin/sh", true); err != nil {
		t.Errorf("the oracle rejected the correct decode: %v", err)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
