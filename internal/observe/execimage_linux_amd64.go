package observe

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	// execChainDepth bounds the walk: the kernel's BINPRM_MAX_RECURSION allows four nested
	// scripts, and the binary they reach plus its loader are two more opens. The walk
	// appends on every pass that does not return and falls through at the bound, so a
	// chain reported complete names fewer images than this.
	execChainDepth = 6
	// execHeadSize is BINPRM_BUF_SIZE: the buffer binfmt_script decodes a #! line out of,
	// and the reason a longer line is unreadable rather than absent. It is also enough of
	// an ELF to reach the program header table from, which is all the loader itself reads.
	// The decode below is held to the kernel's rules over the same span, which
	// FuzzExecImageDecode differentials against a restatement of them.
	execHeadSize = 256
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
// Every image is resolved through the TRACEE's root (/proc/<pid>/root), not the
// observer's: the tracee can unshare(2) into a fresh mount namespace - runObserve
// installs only BlockIoUring, and a new user namespace hands back CAP_FULL_SET over it -
// and then the same name is one file to the tracee and another to the observer. Reading
// the shebang or PT_INTERP out of the observer's file would put an interpreter the run
// never opened into the manifest. This is the rule fdIsDir already states for a
// descriptor's kind: ask through something that answers in the tracee's namespace.
//
// complete is false when the run needed a file this could not name: a shebang whose
// interpreter is not absolute (the kernel resolves it against the tracee's working
// directory, which this does not track). The caller counts that as a dropped observation,
// because an incomplete manifest that says so beats one that reads as complete.
func execImageChain(pid int, path string) (paths []string, complete bool) {
	for range execChainDepth {
		next, ok := execImage(pid, path)
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
//
// The path is a TARGET-CHOSEN name and this runs at the exec's ENTRY stop, before the
// kernel has validated anything, so the exec need not even be able to succeed. A plain
// open of it would have the OBSERVER actuate whatever the name points at: open(2) on a
// writer-less FIFO blocks inside the syscall with the tracee frozen at its stop and no
// timeout anywhere on this path, and an open-time-side-effect device node is armed by
// being looked at. O_PATH resolves the name without opening the file at all, and the
// image is reopened through /proc only once the fstat says it is a regular file - which
// is also open_exec's own rule, so anything else is an exec that fails with nothing
// opened and no image to name.
func execImage(pid int, path string) (string, bool) {
	rootFD, err := unix.Open(fmt.Sprintf("/proc/%d/root", pid), unix.O_PATH|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
	if err != nil {
		// No root to resolve under is never "the file is absent" - the exec would find it
		// perfectly well - so it is a lost observation whatever the errno, including the
		// ENOENT of a tracee that has already gone. Reading it as absence is what would
		// put a loader out of the manifest with Dropped at 0.
		return "", false
	}
	defer unix.Close(rootFD)
	// RESOLVE_IN_ROOT is what makes the descriptor an actual root rather than a prefix:
	// the kernel re-roots an absolute path at it, clamps ".." there the way it does at a
	// real root, and - the case a lexical join cannot reach at all - resolves an ABSOLUTE
	// SYMLINK inside it too, where a name walked through /proc/<pid>/root jumps back to
	// the OBSERVER's root the moment it meets one. Each of those is the same wrong file
	// this resolution exists to stop naming. An ENOSYS from a kernel without openat2
	// lands in the lost-observation arm below, which is the honest answer: the observer
	// cannot see what the kernel will.
	pathFD, err := unix.Openat2(rootFD, path, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_IN_ROOT})
	if err != nil {
		return "", errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
	}
	defer unix.Close(pathFD)
	var st unix.Stat_t
	if err := unix.Fstat(pathFD, &st); err != nil {
		return "", false
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return "", true
	}
	// An O_PATH descriptor is reopened by its /proc name, which is what keeps this read on
	// the file the fstat above answered for rather than on whatever the name resolves to
	// now. A mode-0111 image the observer cannot read fails here, which is the EACCES case
	// above: a lost observation, not an absent file.
	f, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", pathFD))
	if err != nil {
		return "", false
	}
	defer f.Close()

	// One short read is enough for either decision: execHeadSize is the kernel's own
	// shebang buffer, and it covers an ELF header of either class, which is where the
	// program header table's location is written.
	var buf [execHeadSize]byte
	n, _ := io.ReadFull(f, buf[:])
	head := string(buf[:n])
	if interp, ok := strings.CutPrefix(head, "#!"); ok {
		// The header ends at the first of newline, NUL, space or tab AFTER the name starts,
		// and binfmt_script refuses it outright when the buffer fills before one arrives.
		// Each of the four is load-bearing and each was got wrong here once: the kernel
		// zeroes its buffer's tail and takes the name as a C string, so a NUL ends the line
		// exactly as a newline does, and space and tab - ONLY those two, not strings.Fields'
		// unicode whitespace - separate the interpreter from its argument, so a '\r' is part
		// of the NAME. Cutting on the newline alone carries the padding after it into the
		// name, and the openat2 of that fails EINVAL: a drop counted against a file the
		// kernel opened perfectly well. Stopping at a '\r' is worse - it names a shorter path
		// that may well exist and reports it COMPLETE, while the kernel opened the longer one
		// and found nothing.
		//
		// The leading run of space and tab comes off FIRST, and the terminator is looked for
		// after it, because that is where the kernel looks: `#!  /very/long/name` filling the
		// buffer is refused, and testing the whole body would find the leading space, call
		// the header terminated, and report a truncated path complete.
		name := strings.TrimLeft(interp, " \t")
		if name == "" {
			// A header that is all space and tab: ENOEXEC, with nothing opened to record.
			return "", true
		}
		end := strings.IndexAny(name, "\n\x00 \t")
		if end < 0 {
			if n == len(buf) {
				// The buffer filled with no terminator after the name began, so what is here
				// is a truncated path the kernel never opened - unreadable rather than absent,
				// and the kernel refuses it for that reason. A file that simply ends without a
				// trailing newline is not this: it is an ordinary script, which the zero
				// padding terminates.
				return "", false
			}
			end = len(name)
		}
		if name = name[:end]; name == "" {
			return "", true
		}
		// A relative interpreter is resolved against the tracee's working directory at the
		// moment of the exec, which is not knowable from here.
		if !filepath.IsAbs(name) {
			return "", false
		}
		return name, true
	}
	return elfInterp(f, buf[:n])
}

// elfInterp names the PT_INTERP loader the kernel's ELF loader will open for this image,
// or "" when the image names none.
//
// The program header table is walked out of the raw bytes rather than through debug/elf,
// because debug/elf validates what the loader never reads: it refuses an e_shstrndx out
// of range ($GOROOT/src/debug/elf/file.go), while fs/binfmt_elf.c reaches PT_INTERP from
// e_phoff alone and never touches a section header. A binary with a corrupt e_shstrndx
// execs perfectly well and opens its loader, and a decoder that cannot see that either
// drops the loader from the manifest or reports the run short for no reason. Walking the
// headers accepts every image the kernel does.
//
// The cost is that the fuzz target's ELF reference is now this same algorithm, so that
// side of the differential holds by construction. What still has teeth there is the
// narrowing invariant over the raw bytes; the ELF decode's oracle is the exec-backed
// table, which runs real images and reads the kernel's own verdict off the errno.
//
// ok is false for what cannot be named honestly: an image this does not understand (an
// ELF class or byte order it cannot decode is still an image some loader on this host
// runs), a header table that will not read, and a segment binfmt_elf itself refuses. A
// silent "" there would put a loader out of the manifest with nothing saying it is
// missing, which is the failure this file exists to stop.
func elfInterp(f *os.File, head []byte) (string, bool) {
	if !strings.HasPrefix(string(head), elf.ELFMAG) {
		// No magic: no image to name, and no exec that could have succeeded either. This
		// is the shebang branch's answer for a header naming nothing.
		return "", true
	}
	// The two layouts of the same table. Only little-endian is decoded: this file builds
	// for amd64 alone, where every image the kernel loads - native or through the 32-bit
	// compat loader - is ELFDATA2LSB.
	// ehdrSize is also where the header ends; phSize is the width of the offset and size
	// fields, which is the only thing that differs between the two layouts besides where
	// the fields sit.
	var ehdrSize, phSize, phdrSize, phoffAt, phentAt, offAt, fileszAt int
	switch {
	case len(head) < 6 || head[5] != byte(elf.ELFDATA2LSB):
		return "", false
	case head[4] == byte(elf.ELFCLASS64):
		ehdrSize, phSize, phdrSize, phoffAt, phentAt, offAt, fileszAt = 64, 8, 56, 32, 54, 8, 32
	case head[4] == byte(elf.ELFCLASS32):
		ehdrSize, phSize, phdrSize, phoffAt, phentAt, offAt, fileszAt = 52, 4, 32, 28, 42, 4, 16
	default:
		return "", false
	}
	if len(head) < ehdrSize {
		return "", false
	}
	num := func(b []byte, at, size int) uint64 {
		if size == 4 {
			return uint64(binary.LittleEndian.Uint32(b[at:]))
		}
		return binary.LittleEndian.Uint64(b[at:])
	}
	phoff := num(head, phoffAt, phSize)
	phentsize := int(binary.LittleEndian.Uint16(head[phentAt:]))
	phnum := int(binary.LittleEndian.Uint16(head[phentAt+2:]))
	// The table's size is binfmt_elf's own bound, and the reason an unbounded read of a
	// fuzzer-chosen e_phnum cannot happen here: the kernel refuses an image whose header
	// table does not fit in 64KiB, so one that claims more is not an image that runs.
	//
	// The entry size is the kernel's own, EXACTLY: load_elf_phdrs refuses an image whose
	// e_phentsize is not sizeof(struct elf_phdr) and answers ENOEXEC having read nothing,
	// so a table at any other stride belongs to no exec that can happen. Equality cannot
	// lose a real loader - an image the kernel loads has this stride by definition - and
	// a floor instead would walk that table anyway and name a loader for an image the
	// kernel refuses, which is the truncated-shebang shape this file refuses on the other
	// branch. That the two verdicts agree is held against a real exec's errno by
	// TestPT_INTERPTerminationMatchesTheKernel's oversized-stride case.
	if phentsize != phdrSize || phnum < 1 || phnum*phentsize > 65536 {
		return "", false
	}
	table := make([]byte, phnum*phentsize)
	if _, err := f.ReadAt(table, int64(phoff)); err != nil {
		// A table that runs off the end is not a table; the exec reads the same bytes and
		// finds the same nothing, but the observer cannot say what it would have opened.
		return "", false
	}
	for i := range phnum {
		ph := table[i*phentsize:]
		if binary.LittleEndian.Uint32(ph) != uint32(elf.PT_INTERP) {
			continue
		}
		off := num(ph, offAt, phSize)
		filesz := num(ph, fileszAt, phSize)
		// binfmt_elf's own bounds on the segment: PATH_MAX above, and at least two bytes
		// so that a name and its terminator fit. Filesz comes straight out of the file -
		// an ELF the profiled target execs is not trusted input, and an unbounded make()
		// here would let one kill the observer rather than be recorded by it.
		if filesz > unix.PathMax || filesz < 2 {
			return "", false
		}
		name := make([]byte, filesz)
		if _, err := f.ReadAt(name, int64(off)); err != nil {
			return "", false
		}
		// The kernel takes the segment as a C string, so it ends at the FIRST NUL and
		// whatever pads the segment after it is not part of the name - and it REFUSES the
		// image outright when the segment's last byte is not a NUL, because there is then
		// no C string in it at all. Accepting that names a loader the exec never opened.
		if name[len(name)-1] != 0 {
			return "", false
		}
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
	// No PT_INTERP: a static binary, which names no image and loses nothing.
	return "", true
}
