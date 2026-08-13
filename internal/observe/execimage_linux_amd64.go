package observe

import (
	"debug/elf"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// execImageChain names the files the KERNEL opens on the tracee's behalf when it execs
// path, and which therefore reach no syscall stop at all: open_exec runs inside execve,
// so a script's #! interpreter and a dynamic ELF's PT_INTERP loader are read without a
// syscall the decoder could see. Every profile of a dynamically linked target omitted its
// loader and every profile of a script omitted the interpreter binary, and the enforced
// run then failed closed with ENOENT on a file the profiling run demonstrably needed -
// with Dropped at 0, because nothing had been observed to drop.
//
// The chain is walked rather than resolved once because the kernel walks it: a script
// names /bin/sh, whose own exec then wants /lib64/ld-linux-x86-64.so.2. It ends at the
// loader, which is statically linked and names no interpreter of its own; the depth bound
// is a backstop against a #! cycle, and matches what the kernel itself will run.
//
// This is deliberately NOT profile.GuessInterpreter. That answers "which interpreter
// should bento invoke", and for `#!/usr/bin/env python3` it answers python3 - correct for
// a manifest, wrong here, where the file the kernel opens is /usr/bin/env and python3
// arrives later through an execve the decoder already sees. It also guesses from the
// extension when there is no shebang, and a guess is not an observation.
//
// complete is false when the run needed a file this could not name: a shebang whose
// interpreter is not absolute (the kernel resolves it against the tracee's working
// directory, which this does not track). The caller counts that as a dropped observation,
// because an incomplete manifest that says so beats one that reads as complete.
func execImageChain(path string) (paths []string, complete bool) {
	// Six: the kernel's BINPRM_MAX_RECURSION allows four nested scripts, and the binary
	// they reach plus its loader are two more opens.
	for range 6 {
		next, ok := execImage(path)
		if !ok {
			return paths, false
		}
		if next == "" {
			return paths, true
		}
		paths = append(paths, next)
		path = next
	}
	// The bound was reached with an image still to resolve, so what it names is unrecorded
	// - the same lost observation as an unresolvable shebang, and reported the same way.
	return paths, false
}

// execImage names the one file the kernel opens to run path, or "" when path is its own
// image - a static binary, or a path the exec will fail on too.
//
// Only ENOENT and ENOTDIR mean the latter: the exec answers the same and there is nothing
// to record. Every other error means the observer could not see what the kernel will,
// which is a lost observation and not a file that is not needed. EACCES is the case that
// matters - the kernel execs a mode-0111 binary the observer cannot read - and reporting
// it complete would put the loader back out of the manifest with Dropped at 0, which is
// the failure this file exists to stop.
func execImage(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
	}
	defer f.Close()

	// One short read is enough for either decision: the kernel reads the shebang out of a
	// buffer of this size itself, and an ELF's program headers are found through the header
	// this leaves to debug/elf.
	var buf [256]byte
	n, _ := io.ReadFull(f, buf[:])
	head := string(buf[:n])
	if interp, ok := strings.CutPrefix(head, "#!"); ok {
		line, _, found := strings.Cut(interp, "\n")
		if !found && n == len(buf) {
			// The line ran past the buffer, so what is here is a truncated path the kernel
			// never opened - unreadable rather than absent. The kernel refuses this outright
			// (its own buffer is no larger), but only the full-buffer case is that: a file
			// that simply ends without a trailing newline is an ordinary script, which
			// binfmt_script accepts because it ends the line on the NUL padding.
			return "", false
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			return "", true
		}
		// A relative interpreter is resolved against the tracee's working directory at the
		// moment of the exec, which is not knowable from here.
		if !filepath.IsAbs(fields[0]) {
			return "", false
		}
		return fields[0], true
	}
	e, err := elf.NewFile(f)
	if err != nil {
		// Not an ELF the observer can parse, and not a script: nothing names an image.
		return "", true
	}
	for _, p := range e.Progs {
		if p.Type != elf.PT_INTERP {
			continue
		}
		// PT_INTERP holds a pathname, and Filesz comes straight out of the file - an ELF
		// the profiled target execs is not trusted input, and an unbounded make() here
		// would let one kill the observer rather than be recorded by it.
		if p.Filesz > unix.PathMax {
			return "", false
		}
		name := make([]byte, p.Filesz)
		if _, err := p.ReadAt(name, 0); err != nil {
			return "", false
		}
		// The kernel takes the segment as a C string, so it ends at the FIRST NUL and
		// whatever pads the segment after it is not part of the name.
		interp, _, _ := strings.Cut(string(name), "\x00")
		// The same hostile input the bound above guards against, held to what the shebang
		// branch already holds its own interpreter to: a relative path resolves against the
		// tracee's working directory, and recording it would both put an unbindable name in
		// the manifest and send the next loop iteration to open it against the OBSERVER's
		// cwd. An empty or newline-bearing segment is a malformed image rather than one
		// naming no interpreter, which is why this is a lost observation and not the
		// shebang's ("", true).
		if !filepath.IsAbs(interp) || strings.ContainsRune(interp, '\n') {
			return "", false
		}
		return interp, true
	}
	return "", true
}
