package seccomp

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// StrictExecSupported reports whether this build can enforce the exec: none-strict
// filter (execve blocked plus fork/vfork/process-clone blocked). The classic-BPF
// filter is architecture-specific; only amd64 is implemented.
func StrictExecSupported() bool { return true }

// x86-64 syscall numbers and clone flags the strict filter matches on.
const (
	nrClone     = 56
	nrFork      = 57
	nrVfork     = 58
	nrExecve    = 59
	nrClone3    = 435
	cloneThread = 0x00010000 // CLONE_THREAD: set for thread creation, clear for a new process

	auditArchX8664 = 0xC000003E
	x32SyscallBit  = 0x40000000 // set on x32-ABI syscall numbers, which share the amd64 audit arch

	// Offsets into struct seccomp_data. args[0] is a u64; on little-endian amd64
	// the clone flags live in its low 32 bits.
	offNr     = 0
	offArch   = 4
	offArg0Lo = 16

	seccompRetAllow       = 0x7fff0000
	seccompRetErrnoBase   = 0x00050000
	seccompRetKillProcess = 0x80000000

	seccompSetModeFilter   = 1
	seccompFilterFlagTSync = 1
)

func errnoRet(e unix.Errno) uint32 { return seccompRetErrnoBase | uint32(uint16(e)) }

// strictFilter builds the classic-BPF program for exec: none-strict. It blocks
// execve, fork, and vfork with EPERM; forces clone3 to ENOSYS so glibc falls back
// to clone (which BPF can inspect); and permits clone only when CLONE_THREAD is
// set, so threads work while a new process is refused with EPERM. Everything else
// is allowed. A wrong architecture is killed, as is any x32-ABI syscall: x32 shares
// the amd64 audit arch but tags its syscall numbers, so without this an x32 execve
// or clone would miss the equality checks and slip through.
func strictFilter() []unix.SockFilter {
	ld := func(off uint32) unix.SockFilter {
		return unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: off}
	}
	jeq := func(k uint32, jt, jf uint8) unix.SockFilter {
		return unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: k, Jt: jt, Jf: jf}
	}
	jset := func(k uint32, jt, jf uint8) unix.SockFilter {
		return unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, K: k, Jt: jt, Jf: jf}
	}
	ret := func(k uint32) unix.SockFilter {
		return unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: k}
	}
	and := func(k uint32) unix.SockFilter {
		return unix.SockFilter{Code: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, K: k}
	}
	eperm := ret(errnoRet(unix.EPERM))
	kill := ret(seccompRetKillProcess)
	return []unix.SockFilter{
		/*0*/ ld(offArch),
		/*1*/ jeq(auditArchX8664, 1, 0), // arch ok -> skip the kill
		/*2*/ kill,
		/*3*/ ld(offNr),
		/*4*/ jset(x32SyscallBit, 0, 1), // x32 syscall -> kill (idx 5); else continue (idx 6)
		/*5*/ kill,
		/*6*/ jeq(nrExecve, 0, 1),
		/*7*/ eperm,
		/*8*/ jeq(nrFork, 0, 1),
		/*9*/ eperm,
		/*10*/ jeq(nrVfork, 0, 1),
		/*11*/ eperm,
		/*12*/ jeq(nrClone3, 0, 1),
		/*13*/ ret(errnoRet(unix.ENOSYS)),
		/*14*/ jeq(nrClone, 0, 4), // not clone -> fall through to allow (idx 19)
		/*15*/ ld(offArg0Lo),
		/*16*/ and(cloneThread),
		/*17*/ jeq(cloneThread, 1, 0), // CLONE_THREAD set -> allow (idx 19); else EPERM
		/*18*/ eperm,
		/*19*/ ret(seccompRetAllow),
	}
}

// BlockExecStrict installs the none-strict filter for this process and all its
// threads (TSYNC), surviving the coming execveat. Like BlockExec it sets
// no-new-privs; unlike BlockExec it also refuses fork/vfork and process-creating
// clone, permitting only thread creation.
func BlockExecStrict() error {
	if _, _, e := unix.Syscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); e != 0 {
		return fmt.Errorf("seccomp: setting no_new_privs: %w", e)
	}
	f := strictFilter()
	prog := unix.SockFprog{Len: uint16(len(f)), Filter: &f[0]}
	r1, _, e := unix.Syscall(unix.SYS_SECCOMP, seccompSetModeFilter, seccompFilterFlagTSync, uintptr(unsafe.Pointer(&prog)))
	if e != 0 {
		return fmt.Errorf("seccomp: installing the none-strict filter: %w", e)
	}
	// Under TSYNC a thread-sync failure is not an errno: the kernel returns the TID
	// of a thread it could not sync (a nonzero value) and attaches the filter to
	// nothing. Treat that as failure so the run is refused rather than proceeding
	// unfiltered while claiming the filter holds.
	if r1 != 0 {
		return fmt.Errorf("seccomp: none-strict filter could not be synced to thread %d; no filter was installed", r1)
	}
	return nil
}
