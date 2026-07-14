// Package seccomp installs the exec-blocking syscall filter and performs the
// execveat transition that lets the launcher start the target under it.
//
// The filter denies execve(2) but allows execveat(2). That asymmetry is the
// whole trick: the launcher installs the filter, then transitions to the target
// via execveat, so the target starts normally while any subprocess it later
// spawns through the standard exec path is refused. This is a *soft* block —
// stated plainly — because execveat itself stays open by construction; it stops
// the ~100% of real-world exec paths (glibc/musl execve, subprocess, fork+exec,
// os.system) that go through execve.
package seccomp

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	seccomp "github.com/elastic/go-seccomp-bpf"
	"golang.org/x/sys/unix"
)

// Supported reports whether this kernel supports seccomp BPF filters.
func Supported() bool { return seccomp.Supported() }

// BlockExec installs the exec-blocking filter for this process and all its
// threads. It sets no-new-privs and uses TSYNC, so the Go runtime's background
// threads are covered and the filter survives the coming execveat. The syscall
// numbers and architecture gate are handled by the library per GOARCH.
func BlockExec() error {
	filter := seccomp.Filter{
		NoNewPrivs: true,
		Flag:       seccomp.FilterFlagTSync,
		Policy: seccomp.Policy{
			DefaultAction: seccomp.ActionAllow,
			Syscalls: []seccomp.SyscallGroup{
				{Action: seccomp.ActionErrno, Names: []string{"execve"}},
			},
		},
	}
	if err := seccomp.LoadFilter(filter); err != nil {
		return fmt.Errorf("seccomp: installing exec-block filter: %w", err)
	}
	return nil
}

// Exec replaces the current process with argv via execveat(2). The exec-block
// filter permits execveat (it denies only execve), so this transition succeeds
// while the target's later execve attempts do not. argv[0] must be an absolute
// path. Exec returns only on failure.
func Exec(argv, envp []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("seccomp: empty argv")
	}
	pathPtr, err := syscall.BytePtrFromString(argv[0])
	if err != nil {
		return err
	}
	argvPtr, err := syscall.SlicePtrFromStrings(argv)
	if err != nil {
		return err
	}
	envpPtr, err := syscall.SlicePtrFromStrings(envp)
	if err != nil {
		return err
	}

	// The kernel reads the argv/envp arrays during the syscall; keep them alive
	// across it, and pin the thread since execveat replaces the whole process.
	// AT_FDCWD is negative, so it must wrap to uintptr through a variable rather
	// than as an untyped constant.
	dirfd := unix.AT_FDCWD
	runtime.LockOSThread()
	_, _, errno := unix.Syscall6(
		unix.SYS_EXECVEAT,
		uintptr(dirfd),
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&argvPtr[0])),
		uintptr(unsafe.Pointer(&envpPtr[0])),
		0, // flags
		0,
	)
	runtime.KeepAlive(pathPtr)
	runtime.KeepAlive(argvPtr)
	runtime.KeepAlive(envpPtr)
	return fmt.Errorf("seccomp: execveat %q: %w", argv[0], errno)
}
