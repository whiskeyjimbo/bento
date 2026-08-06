package observe

import (
	"debug/elf"
	"os"
	"path/filepath"
	"strings"
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
// is a backstop against a #! cycle, which the kernel refuses at 4 anyway.
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
	for range 4 {
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
// image - a static binary, or anything unreadable, which is an exec that fails rather
// than an observation lost.
func execImage(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", true
	}
	defer f.Close()

	var buf [256]byte
	n, _ := f.Read(buf[:])
	head := string(buf[:n])
	if interp, ok := strings.CutPrefix(head, "#!"); ok {
		line, _, _ := strings.Cut(interp, "\n")
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
		return "", true
	}
	for _, p := range e.Progs {
		if p.Type != elf.PT_INTERP {
			continue
		}
		name := make([]byte, p.Filesz)
		if _, err := p.ReadAt(name, 0); err != nil {
			return "", false
		}
		return strings.TrimRight(string(name), "\x00"), true
	}
	return "", true
}
