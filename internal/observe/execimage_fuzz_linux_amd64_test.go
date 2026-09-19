//go:build linux && amd64

package observe

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
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
// KERNEL opens, and whether execImage can honestly report it.
//
// It is written out here rather than called out of the implementation, but the two are
// necessarily the same small algorithm, so the differential's value does not come from
// their being independent - it comes from TestBinfmtReferenceMatchesTheKernel, which holds
// THIS side against real execs. That table is the oracle; the fuzz target is what carries
// it across every input the fuzzer reaches. A blind spot shared by both sides survives
// until the table grows a case for it, which is how the full-buffer rule below was found.
//
// The rule: the kernel reads its own 256-byte buffer and ZEROES the tail, then ends the
// name at the first of newline, NUL, space or tab - a narrower separator set than
// "whitespace", so a '\r' or a form feed is part of the interpreter's NAME. It refuses the
// header (ENOEXEC, nothing opened) only when the whole buffer holds none of the four: a
// full buffer whose line runs on but carries a space still execs the name before it.
//
// complete is false for what execImage cannot honestly name: that unterminated buffer, and
// a relative interpreter, which the kernel resolves against the tracee's working directory.
// The second is the contract's answer, not the kernel's - the kernel opens it fine.
func refShebangImage(head []byte) (image string, complete bool) {
	body := string(head[2:])
	if !strings.ContainsAny(body, "\n\x00 \t") && len(head) >= execHeadSize {
		return "", false
	}
	name := strings.TrimLeft(body, " \t")
	if end := strings.IndexAny(name, "\n\x00 \t"); end >= 0 {
		name = name[:end]
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

// refELFInterp restates the PT_INTERP decode over the RAW bytes: the ELF64 little-endian
// program header table walked by hand, rather than through debug/elf as execImage does.
// Reading the same field by a different route is the whole point - a reference that called
// debug/elf back would agree with the implementation whatever either of them did.
//
// known is false where this declines to answer: anything that is not ELF64 little-endian,
// or a header table that runs off the end. The caller gates on debug/elf having parsed the
// file at all, which is execImage's own precondition for reaching this branch.
func refELFInterp(file []byte) (name string, complete, known bool) {
	const ehdrSize = 64
	if len(file) < ehdrSize || string(file[:4]) != "\x7fELF" || file[4] != 2 || file[5] != 1 {
		return "", false, false
	}
	phoff := binary.LittleEndian.Uint64(file[32:])
	phentsize := uint64(binary.LittleEndian.Uint16(file[54:]))
	phnum := uint64(binary.LittleEndian.Uint16(file[56:]))
	if phentsize < 56 || phoff+phentsize*phnum > uint64(len(file)) {
		return "", false, false
	}
	for i := range phnum {
		ph := file[phoff+i*phentsize:]
		if binary.LittleEndian.Uint32(ph) != uint32(elf.PT_INTERP) {
			continue
		}
		off := binary.LittleEndian.Uint64(ph[8:])
		size := binary.LittleEndian.Uint64(ph[32:])
		// The bound execImage puts on Filesz, and the short read past it: an ELF the
		// profiled target execs is not trusted input, so neither is a loss the observer
		// reports rather than a name it invents.
		if size > unix.PathMax || off+size > uint64(len(file)) {
			return "", false, true
		}
		interp, _, _ := strings.Cut(string(file[off:off+size]), "\x00")
		if !filepath.IsAbs(interp) || strings.ContainsRune(interp, '\n') {
			return "", false, true
		}
		return interp, true, true
	}
	// No PT_INTERP: a static binary, which names no image and loses nothing.
	return "", true, true
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
		// execImage reaches PT_INTERP only for a file debug/elf parsed, and answers
		// ("", true) for one it did not - so that is the precondition, not an answer to
		// grade. Without it the reference would object to every ELF only one of the two
		// parsers accepts, which is a disagreement about ELF and not about the image.
		if _, err := elf.NewFile(bytes.NewReader(file)); err != nil {
			return nil
		}
		wantInterp, wantOK, known := refELFInterp(file)
		if !known {
			return nil
		}
		if got != wantInterp || ok != wantOK {
			return fmt.Errorf("decoded %q %v; the program headers name the loader %q %v", got, ok, wantInterp, wantOK)
		}
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
		append([]byte("#!/bin/sh "), bytes.Repeat([]byte("a"), 512)...),
		[]byte("\x7fELF"),
		{},
	} {
		f.Add(seed)
	}
	// The PT_INTERP branch is unreachable from random bytes - a parseable ELF carrying a
	// segment is not something a mutator builds - so the seed is built with the helper the
	// hand-written ELF test already uses, giving the fuzzer a base to mutate from.
	for _, interp := range []string{"/lib64/ld.so\x00", "/lib64/ld.so\x00\x00\x00"} {
		elf, err := os.ReadFile(writeELFWithInterp(f, filepath.Join(f.TempDir(), "elf"), interp))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(elf)
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

		// The chain's own elements are each an execImage answer the invariant above already
		// covers, so the one thing left to hold it to is its bound: the walk appends on
		// every pass that does not return and the pass that fills the bound falls through
		// to the incomplete arm, so complete and at the bound is a walk that stopped early
		// and said nothing was missed.
		if paths, complete := execImageChain(pid, path); complete && len(paths) >= execChainDepth {
			t.Errorf("chain reported complete at the depth bound with %v", paths)
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
		// A full buffer is not by itself unreadable: the name still ends at the first
		// space or tab, and the kernel opens it. Only a buffer holding none of the four
		// terminators is the ENOEXEC case the line above is.
		{"buffer filled past a space", "#!" + echo + " " + strings.Repeat("a", 512)},
		{"buffer filled past a tab", "#!" + echo + "\t" + strings.Repeat("a", 512)},
		{"buffer filled past a nul", "#!" + echo + "\x00" + strings.Repeat("a", 512)},
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
	// The ELF branch's own teeth, on the harm the shebang cases cannot reach: a loader the
	// program headers name, silently dropped. The file has to be a real parseable ELF, so
	// it is built with the helper the hand-written PT_INTERP test already uses.
	withInterp, err := os.ReadFile(writeELFWithInterp(t, filepath.Join(t.TempDir(), "elf"), "/lib64/ld.so\x00"))
	if err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []struct {
		name string
		got  string
		ok   bool
	}{
		{"a named loader dropped silently", "", true},
		{"a named loader reported as a loss", "", false},
		{"a different loader than the headers name", "/lib64/ld-other.so", true},
	} {
		t.Run(wrong.name, func(t *testing.T) {
			if err := imageDecodeViolation(withInterp, wrong.got, wrong.ok); err == nil {
				t.Errorf("the oracle accepted %q %v for an ELF naming /lib64/ld.so", wrong.got, wrong.ok)
			}
		})
	}
	if err := imageDecodeViolation(withInterp, "/lib64/ld.so", true); err != nil {
		t.Errorf("the oracle rejected the correct ELF decode: %v", err)
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
