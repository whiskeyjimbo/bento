// Package seccomp installs the exec-blocking syscall filter and performs the
// execveat transition that lets the launcher start the target under it.
//
// The filter denies execve(2) but allows execveat(2). That asymmetry is the
// whole trick: the launcher installs the filter, then transitions to the target
// via execveat, so the target starts normally while any subprocess it later
// spawns through the standard exec path is refused. This is a *soft* block -
// stated plainly - because execveat itself stays open by construction; it stops
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

// tsyncFlags is TSYNC with ESRCH: without ESRCH a partial thread-sync returns the
// offending TID in the syscall's r1 with errno 0, and the library's LoadFilter
// checks only errno - so it would report success while installing no filter. ESRCH
// turns that partial sync into an ESRCH errno the library does surface, so a
// failed install is refused instead of silently proceeding unfiltered. The
// hand-rolled sibling filters (strict, egress) check r1 directly for the same
// reason; the library-backed ones can only reach r1 through this flag.
const tsyncFlags = seccomp.FilterFlagTSync | seccomp.FilterFlag(unix.SECCOMP_FILTER_FLAG_TSYNC_ESRCH)

// BlockExec installs the exec-blocking filter for this process and all its
// threads. It sets no-new-privs and uses TSYNC, so the Go runtime's background
// threads are covered and the filter survives the coming execveat. The syscall
// numbers and architecture gate are handled by the library per GOARCH.
func BlockExec() error {
	if err := blockForeignArch(); err != nil {
		return err
	}
	filter := seccomp.Filter{
		NoNewPrivs: true,
		Flag:       tsyncFlags,
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

// BlockProcessReach installs a filter denying the syscalls that reach into another
// process's memory, execution, or descriptors: ptrace (attach/inject),
// process_vm_readv / process_vm_writev (cross-process memory read/write),
// process_madvise (evict/manipulate another process's pages via a pidfd), kcmp
// (compare and leak process state), and pidfd_getfd (steal a descriptor another
// process holds - a socket to egress through, or a handle to a Landlock-denied
// path). It also denies two cross-process oracles: move_pages (with a NULL nodes
// argument it reports another process's page residency) and get_robust_list (leaks
// another process's robust-futex head pointer, an ASLR disclosure). Neither the Go
// runtime nor bento calls either - glibc registers robust lists with set_robust_list,
// not get - so denying them with EPERM costs nothing here.
//
// It is for the degraded tier only: the bwrap tier's PID namespace already
// isolates every process from the target, so nothing outside the sandbox is
// reachable there.
//
// It blocks pidfd_getfd but deliberately NOT pidfd_open or pidfd_send_signal: Go's
// os/exec manages a child with those two plus waitid, which the launcher's exec:all
// supervise path relies on; blocking the whole pidfd family would break bento's own
// child management. The remaining cross-process reach vectors - /proc/<pid>/mem and
// /proc/<pid>/fd/<n> - are FILE accesses, already denied because /proc is not in the
// degraded Landlock read set. seccomp and Landlock split the work.
func BlockProcessReach() error {
	if err := blockForeignArch(); err != nil {
		return err
	}
	filter := seccomp.Filter{
		NoNewPrivs: true,
		Flag:       tsyncFlags,
		Policy: seccomp.Policy{
			DefaultAction: seccomp.ActionAllow,
			Syscalls: []seccomp.SyscallGroup{
				{Action: seccomp.ActionErrno, Names: []string{
					"ptrace", "process_vm_readv", "process_vm_writev", "process_madvise", "kcmp", "pidfd_getfd",
					"move_pages", "get_robust_list",
				}},
			},
		},
	}
	if err := seccomp.LoadFilter(filter); err != nil {
		return fmt.Errorf("seccomp: installing the cross-process block: %w", err)
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
