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
// header (ENOEXEC, nothing opened) when the buffer fills before a terminator arrives AFTER
// the name starts: a full buffer whose line runs on but carries a space still execs the
// name before it, while `#!  ` plus a name that runs to the end is refused, the leading
// space notwithstanding. A header of nothing but space and tab is refused too.
//
// complete is false for what execImage cannot honestly name: that unterminated buffer, and
// a relative interpreter, which the kernel resolves against the tracee's working directory.
// The second is the contract's answer, not the kernel's - the kernel opens it fine.
func refShebangImage(head []byte) (image string, complete bool) {
	name := strings.TrimLeft(string(head[2:]), " \t")
	if name == "" {
		// binfmt_script refuses this with ENOEXEC, having opened nothing.
		return "", true
	}
	end := strings.IndexAny(name, "\n\x00 \t")
	if end < 0 {
		if len(head) >= execHeadSize {
			return "", false
		}
		end = len(name)
	}
	if name = name[:end]; name == "" {
		return "", true
	}
	if !filepath.IsAbs(name) {
		return "", false
	}
	return name, true
}

// refELFInterp restates the PT_INTERP decode over the RAW bytes: the ELF64 little-endian
// program header table walked by hand.
//
// execImage walks the same table, so this is no longer a second route to the field and the
// comparison it feeds holds by construction - see imageDecodeViolation, which says what
// still has teeth on that arm. It is kept because it is the only reader here that works on
// a byte slice, which is what lets the fuzz target grade a file it never opened; the
// oracle for the decode itself is TestPT_INTERPTerminationMatchesTheKernel, which execs
// real images and reads the kernel's verdict off the errno.
//
// known is false where this declines to answer: anything that is not ELF64 little-endian,
// or a header table that runs off the end. execImage decodes ELF32 too, so this is a
// narrower reader than the implementation and the caller grades only what both understand.
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
		if size > unix.PathMax || off > uint64(len(file)) || off+size > uint64(len(file)) {
			return "", false, true
		}
		// binfmt_elf refuses a segment whose last byte is not a NUL: there is no C string
		// in it, and the exec opens nothing.
		if size < 2 || file[off+size-1] != 0 {
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
		// A loss the decoder DECLARES is acceptable here: the manifest is short and says
		// so. What is not acceptable is a silent drop, and that is what this arm grades.
		// Since execImage walks the program headers itself, this reference is no longer an
		// independent route to the same field and the comparison below holds by
		// construction; the teeth on this arm are the narrowing invariant above, over the
		// raw bytes, and the oracle for the decode proper is the exec-backed
		// TestPT_INTERPTerminationMatchesTheKernel.
		if !ok {
			return nil
		}
		wantInterp, wantOK, known := refELFInterp(file)
		if !known {
			return nil
		}
		if got != wantInterp || !wantOK {
			return fmt.Errorf("decoded %q complete; the program headers name the loader %q %v", got, wantInterp, wantOK)
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
	for _, interp := range []string{"/lib64/ld.so\x00", "/lib64/ld.so\x00\x00\x00", "/lib64/ld.so"} {
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

// The exec table above cannot see a truncated name that happens to EXIST: it folds "the
// kernel refused the header" and "the kernel resolved a name that was not there" into one
// outcome, and a truncation of a path nothing created is absent either way. This builds the
// one shape that tells them apart - a header whose leading spaces are followed by the path
// of a real file, running to the end of the buffer with no terminator after it.
//
// The kernel refuses that outright, having opened nothing. A decode that tests the whole
// body for a terminator finds the LEADING space, calls the header terminated, and reports
// the real file complete: a manifest naming a file the run never opened, which is the
// failure this whole file exists to stop and is worse than the drop it replaces.
func TestExecImageRefusesATruncatedNameThatExists(t *testing.T) {
	dir := t.TempDir()
	const lead = "#!  "
	name := strings.Repeat("n", execHeadSize-len(lead)-len(dir)-1)
	if len(name) < 1 || len(name) > 255 {
		t.Skipf("a %d-byte temp dir leaves no room for the boundary case", len(dir))
	}
	image := filepath.Join(dir, name)
	if err := os.WriteFile(image, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := lead + image + strings.Repeat("a", 64)
	if len(lead+image) != execHeadSize {
		t.Fatalf("the header is %d bytes, not the %d the buffer holds", len(lead+image), execHeadSize)
	}
	script := filepath.Join(dir, "s")
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(exec.Command(script).Run(), unix.ENOEXEC) {
		t.Skip("the kernel did not refuse the header, so there is nothing to disagree with")
	}
	if got, ok := execImage(os.Getpid(), script); ok && got != "" {
		t.Errorf("execImage named %q complete for a header the kernel refused with ENOEXEC", got)
	}
	if image, complete := refShebangImage([]byte(body)); complete && image != "" {
		t.Errorf("refShebangImage named %q complete for a header the kernel refused with ENOEXEC", image)
	}
}

// The ELF side's counterpart to TestBinfmtReferenceMatchesTheKernel: binfmt_elf takes
// PT_INTERP as a C string and refuses the image when the segment's last byte is not a NUL,
// so a decoder that cuts at the first NUL and accepts a segment without one names a loader
// no exec ever opened. These ELFs cannot run - nothing is mapped in them - but the errno
// still says which way the kernel went: ENOEXEC is the refusal, and anything else means it
// accepted the name and went looking for the file.
func TestPT_INTERPTerminationMatchesTheKernel(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name     string
		interp   string
		complete bool
	}{
		{name: "nul terminated", interp: "/lib64/ld.so\x00", complete: true},
		{name: "not terminated", interp: "/lib64/ld.so"},
		{name: "one byte", interp: "\x00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeELFWithInterp(t, filepath.Join(dir, tc.name), tc.interp)
			refused := errors.Is(exec.Command(path).Run(), unix.ENOEXEC)
			if refused == tc.complete {
				t.Fatalf("the kernel refused = %v for a %s segment; the case assumes the opposite", refused, tc.name)
			}
			file, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, complete, _ := refELFInterp(file); complete != tc.complete {
				t.Errorf("refELFInterp complete = %v, want %v", complete, tc.complete)
			}
			// The name as well as the verdict: with the walk in execImage this table is the
			// only check on the ELF decode that the kernel itself backs, so a decode that
			// agreed about refusing and then named the wrong loader would pass it.
			got, complete := execImage(os.Getpid(), path)
			if complete != tc.complete {
				t.Errorf("execImage ok = %v, want %v", complete, tc.complete)
			}
			want, _, _ := strings.Cut(tc.interp, "\x00")
			if tc.complete && got != want {
				t.Errorf("execImage named %q, but the segment the kernel accepted holds %q", got, want)
			}
		})
	}
}

// An ELF debug/elf cannot parse is not an ELF that will not RUN, and the decoder names
// its loader anyway. The kernel's loader reads the program headers and never the section
// headers debug/elf validates, so a binary whose e_shstrndx is corrupt execs perfectly
// well and opens its PT_INTERP loader - and this asserts the decoder opens the same one,
// against a real exec and a real debug/elf refusal rather than a claim about either.
//
// The weaker answer the walk replaced - reporting it a lost observation - kept the run
// short for an image nothing was wrong with. The answer before THAT, "nothing names an
// image", dropped the loader from the manifest with Dropped at 0, which is the one
// failure this file exists to stop; a regression to it fails the loader comparison here.
func TestExecImageNamesTheLoaderOfAnELFDebugELFRefuses(t *testing.T) {
	binary_, err := os.ReadFile("/bin/true")
	if err != nil {
		skipMissingDep(t, "/bin/true not readable")
	}
	loader, ok := execImage(os.Getpid(), "/bin/true")
	if !ok || loader == "" {
		t.Skip("/bin/true names no loader the observer can read here")
	}
	// e_shstrndx, which the kernel never looks at and debug/elf refuses out of range.
	binary.LittleEndian.PutUint16(binary_[62:], 0xfff0)
	path := filepath.Join(t.TempDir(), "corrupt-shstrndx")
	if err := os.WriteFile(path, binary_, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command(path).Run(); err != nil {
		t.Skipf("the kernel did not run it either: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := elf.NewFile(f); err == nil {
		t.Fatal("debug/elf parsed the corrupted image, so this proves nothing about the walk")
	}
	got, complete := execImage(os.Getpid(), path)
	if got != loader || !complete {
		t.Errorf("execImage = %q %v for an image the kernel runs and opens %q for", got, complete, loader)
	}
}

// The walk's depth bound, which no fuzzer input can reach: the file it writes is at a path
// the fuzzer does not know, so it cannot name itself. A script whose interpreter IS itself
// is the #! cycle the bound exists for, and the answer has to be that the chain is short
// and says so - a walk that stopped at the bound and reported complete would hand out a
// manifest missing whatever the exec would have gone on to open, with Dropped at 0.
func TestExecImageChainReportsACycleAsIncomplete(t *testing.T) {
	script := filepath.Join(t.TempDir(), "loop.sh")
	if err := os.WriteFile(script, []byte("#!"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	paths, complete := execImageChain(os.Getpid(), script)
	if complete {
		t.Errorf("a #! cycle reported complete with %v", paths)
	}
	if len(paths) != execChainDepth {
		t.Errorf("the walk named %d images, want the bound's %d", len(paths), execChainDepth)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
