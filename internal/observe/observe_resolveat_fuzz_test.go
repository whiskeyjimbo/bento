//go:build linux && amd64

package observe

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// anchorKinds opens one descriptor of every kind a tracee can hand openat as a dirfd, and
// returns them with a name for failure messages. They are opened once for the whole fuzz
// run: a per-iteration open would exhaust the fd table long before the budget is spent.
//
// The nonexistent kind is a plain out-of-range number rather than a closed descriptor, so
// the run cannot accidentally match one the runtime reopened underneath it.
func anchorKinds(t testing.TB) map[string]int32 {
	t.Helper()
	dir := t.TempDir()

	keep := func(f *os.File, err error) int32 {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		return int32(f.Fd())
	}

	reg := filepath.Join(dir, "regular")
	if err := os.WriteFile(reg, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	gone := filepath.Join(dir, "unlinked")
	if err := os.WriteFile(gone, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	goneFd := keep(os.Open(gone))
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}

	sockPath := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	sockFile, err := ln.(*net.UnixListener).File()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sockFile.Close() })

	// O_PATH on a directory: a descriptor openat still resolves against, so the oracle
	// only ever early-returns on it. It is here so the generator covers the kind rather
	// than to assert anything about it; the anchoring it must keep doing is pinned by
	// TestResolveAtAnchorsAndDrops.
	pathFd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(pathFd) })

	return map[string]int32{
		"directory":   keep(os.Open(dir)),
		"regular":     keep(os.Open(reg)),
		"socket":      int32(sockFile.Fd()),
		"deleted":     goneFd,
		"opath-dir":   int32(pathFd),
		"nonexistent": 0x7ffffff0,
	}
}

// FuzzResolveAt is the generalisation of TestResolveAtAnchorsAndDrops' regular-file case:
// rather than one hand-picked (fd kind, path) pair, it asserts the property over every
// pair the fuzzer reaches.
//
// Oracle: the kernel is asked, for real, whether anything resolves against the anchor -
// openat(fd, ".", O_RDONLY). If that errors (ENOTDIR for a regular file, socket or deleted
// file; EBADF for a descriptor that is not open), the kernel would resolve nothing through
// this fd, so resolveAt must refuse it. The implication is one-directional: a good anchor
// plus a path naming nothing is still ok=true, because the observer records attempted
// opens, so the converse is deliberately not asserted.
func FuzzResolveAt(f *testing.F) {
	kinds := anchorKinds(f)
	pid := os.Getpid()

	for name := range kinds {
		f.Add(name, "x")
		f.Add(name, "../../../../etc/shadow")
		f.Add(name, ".")
		f.Add(name, "a/b/../c")
	}

	f.Fuzz(func(t *testing.T, kind, path string) {
		dirfd, ok := kinds[kind]
		if !ok {
			t.Skip("not one of the opened anchor kinds")
		}
		// resolveAt short-circuits these before it ever looks at the anchor, and does so
		// correctly: an absolute path needs no anchor and an empty one names no file.
		if path == "" || strings.HasPrefix(path, "/") || strings.ContainsRune(path, 0) {
			t.Skip("not anchored against the dirfd")
		}

		fd, err := unix.Openat(int(dirfd), ".", unix.O_RDONLY, 0)
		if err == nil {
			unix.Close(fd)
			return // the kernel resolves through this anchor; resolveAt may too.
		}
		if !errors.Is(err, unix.ENOTDIR) && !errors.Is(err, unix.EBADF) && !errors.Is(err, unix.ENOENT) {
			t.Skipf("anchor probe gave an unexpected error: %v", err)
		}
		if got, ok := resolveAt(pid, dirfd, path); ok {
			t.Errorf("resolveAt(%s fd, %q) = %q, true, but openat on that anchor gives %v - the observation names a file the kernel would never open", kind, path, got, err)
		}
	})
}
