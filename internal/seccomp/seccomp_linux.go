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
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	seccomp "github.com/elastic/go-seccomp-bpf"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// Supported reports whether this build can install this package's syscall filters
// on this kernel. Every Block* here installs the foreign-arch guard first and fails
// when it cannot, so the guard's availability is part of the answer: without this
// term a probe on a non-amd64 build reports the exec layer present, admission passes,
// and the launcher then refuses to run for a filter it was never able to install.
func Supported() bool { return seccomp.Supported() && foreignArchSupported() }

// installPolicy assembles p and attaches it to this process and all of its threads,
// under no-new-privs so the filter survives the coming execveat.
//
// The load is done by hand rather than through the library's LoadFilter because
// LoadFilter reads only seccomp(2)'s errno, and under TSYNC a partial thread-sync is
// not an errno: the kernel returns the offending TID in r1 with errno 0 and attaches
// the filter to nothing, which LoadFilter reports as success. Checking r1 is the only
// way to refuse that, and it is what the hand-rolled filters in this package already
// do. SECCOMP_FILTER_FLAG_TSYNC_ESRCH would turn the partial sync into an errno the
// library surfaces, but it is absent from SECCOMP_FILTER_FLAG_MASK before kernel 5.0,
// where it makes every filter using it fail with EINVAL on every run - so the degraded
// tier, which exists to serve exactly those older kernels, could not install its
// mandatory cross-process block at all. Policy.Assemble emits the AUDIT_ARCH gate and
// the x32 block, so nothing the library contributed to the filter is lost here.
func installPolicy(p seccomp.Policy, what string) error {
	insts, err := p.Assemble()
	if err != nil {
		return fmt.Errorf("seccomp: assembling the %s filter: %w", what, err)
	}
	raw, err := bpf.Assemble(insts)
	if err != nil {
		return fmt.Errorf("seccomp: assembling the %s filter: %w", what, err)
	}
	filter := make([]unix.SockFilter, 0, len(raw))
	for _, i := range raw {
		filter = append(filter, unix.SockFilter{Code: i.Op, Jt: i.Jt, Jf: i.Jf, K: i.K})
	}

	if _, _, e := unix.Syscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); e != 0 {
		return fmt.Errorf("seccomp: setting no_new_privs: %w", e)
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	r1, _, e := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&prog)))
	if e != 0 {
		return fmt.Errorf("seccomp: installing the %s filter: %w", what, e)
	}
	if r1 != 0 {
		return fmt.Errorf("seccomp: the %s filter could not be synced to thread %d; no filter was installed", what, r1)
	}
	return nil
}

// BlockExec installs the exec-blocking filter for this process and all its
// threads. It sets no-new-privs and uses TSYNC, so the Go runtime's background
// threads are covered and the filter survives the coming execveat. The syscall
// numbers and architecture gate come from the policy assembler, per GOARCH.
func BlockExec() error {
	if err := blockForeignArch(); err != nil {
		return err
	}
	return installPolicy(seccomp.Policy{
		DefaultAction: seccomp.ActionAllow,
		Syscalls: []seccomp.SyscallGroup{
			{Action: seccomp.ActionErrno, Names: []string{"execve"}},
		},
	}, "exec-block")
}

// BlockProcessReach installs a filter denying the syscalls that reach into another
// process's memory, execution, or descriptors: ptrace (attach/inject),
// process_vm_readv / process_vm_writev (cross-process memory read/write),
// process_madvise (evict/manipulate another process's pages via a pidfd), kcmp
// (compare and leak process state), and pidfd_getfd (steal a descriptor another
// process holds - a socket to egress through, or a handle to a Landlock-denied
// path). It also denies three cross-process oracles: perf_event_open (samples
// another process's instruction pointers, defeating ASLR when perf_event_paranoid
// permits it), move_pages (with a NULL nodes
// argument it reports another process's page residency) and get_robust_list (leaks
// another process's robust-futex head pointer, an ASLR disclosure). Neither the Go
// runtime nor bento calls any of these - glibc registers robust lists with set_robust_list,
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
// /proc/<pid>/fd/<n> - are FILE accesses, denied by Landlock's ptrace check rather than
// by this filter: both go through ptrace_may_access, and Landlock refuses that against
// any process outside the domain the degraded tier creates. Every host process is
// outside it, and only processes whose domain the target's is an ancestor of - its own
// descendants - stay reachable. The read SET does not cover this and must not be
// credited with it: it is user-supplied, and a manifest saying read: / grants /proc
// recursively with nothing refusing it. TestRestrictDegradedDeniesOutsideProcessMemory
// pins the distinction.
//
// One procfs read is not covered and is a residual rather than a gap this filter should
// close: /proc/<pid>/cmdline reads another process's argv memory through
// access_remote_vm with no ptrace check at all, by design, since that is how ps works.
// A target can therefore read a host process's command line, and its environ window if
// that process rewrote its own argv. environ, auxv, maps, smaps, syscall and the fd
// links all take the check and are denied; cmdline is the exception, and it is bounded
// to argv rather than being general memory reach.
func BlockProcessReach() error {
	if err := blockForeignArch(); err != nil {
		return err
	}
	return installPolicy(seccomp.Policy{
		DefaultAction: seccomp.ActionAllow,
		Syscalls: []seccomp.SyscallGroup{
			{Action: seccomp.ActionErrno, Names: []string{
				"ptrace", "process_vm_readv", "process_vm_writev", "process_madvise", "kcmp", "pidfd_getfd",
				"move_pages", "get_robust_list", "perf_event_open",
			}},
		},
	}, "cross-process block")
}

// Exec replaces the current process with argv via execveat(2). The exec-block
// filter permits execveat (it denies only execve), so this transition succeeds
// while the target's later execve attempts do not. Exec returns only on failure.
//
// argv[0] must be absolute, and that is enforced here rather than assumed:
// execveat(AT_FDCWD, path, ..., 0) resolves a relative path against the caller's
// working directory exactly as execve would, so nothing about this path makes an
// absolute argv[0] intrinsic. The supervising sibling refuses a relative target to
// keep exec.Command off a $PATH lookup; refusing it here too is what actually stops
// the two exec modes from diverging.
func Exec(argv, envp []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("seccomp: empty argv")
	}
	if !filepath.IsAbs(argv[0]) {
		return fmt.Errorf("seccomp: target command must be an absolute path, got %q", argv[0])
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
