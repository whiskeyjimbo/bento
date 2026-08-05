package seccomp

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	nrIoctl = 16

	// TIOCSTI pushes a byte into a terminal's input queue as if typed; TIOCLINUX
	// subfunction 2 pastes the console selection the same way. On a shared controlling
	// terminal either one lets the target inject a command line that the parent shell
	// runs after the sandbox exits.
	tiocsti   = 0x5412
	tioclinux = 0x541c

	// Offset into struct seccomp_data of ioctl()'s second argument (request). args is
	// a []u64; on little-endian amd64 the low 32 bits of the request sit here, and both
	// request codes fit in 32 bits.
	offArg1Request = 24
)

// terminalInjectionFilter builds the classic-BPF program that denies the two ioctl
// requests that inject into a terminal, TIOCSTI and TIOCLINUX, with EPERM. It is a
// denylist on the ioctl request (every other ioctl passes) because only these two
// forge terminal input; a broad ioctl block would break ordinary terminal use
// (window size, line discipline). A wrong architecture is killed (whole-process from
// 4.14, thread-only below it - see seccompRetKillProcess), as is any x32-ABI
// ioctl: x32 shares the amd64 audit arch but tags its syscall numbers, so an x32
// ioctl would miss the nr equality check and slip past the request filter.
func terminalInjectionFilter() []unix.SockFilter {
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
	eperm := ret(errnoRet(unix.EPERM))
	kill := ret(seccompRetKillProcess)
	return []unix.SockFilter{
		/*0*/ ld(offArch),
		/*1*/ jeq(auditArchX8664, 1, 0), // arch ok -> skip the kill
		/*2*/ kill,
		/*3*/ ld(offNr),
		/*4*/ jset(x32SyscallBit, 0, 1), // x32 syscall -> kill (idx 5); else continue
		/*5*/ kill,
		/*6*/ jeq(nrIoctl, 0, 4), // not ioctl -> allow (idx 11)
		/*7*/ ld(offArg1Request),
		/*8*/ jeq(tiocsti, 1, 0), // TIOCSTI -> EPERM (idx 10)
		/*9*/ jeq(tioclinux, 0, 1), // TIOCLINUX -> EPERM (idx 10); else allow (idx 11)
		/*10*/ eperm,
		/*11*/ ret(seccompRetAllow),
	}
}

// BlockTerminalInjection installs the terminal-injection filter for this process and
// all its threads (TSYNC), surviving the coming execveat, and sets no-new-privs.
//
// It is for the degraded (no-bwrap) tier only. The bwrap tier runs the target in a
// new session (bwrap --new-session), which detaches the controlling terminal so
// TIOCSTI has nothing to inject into; the degraded tier execs the target directly and
// it inherits the parent's terminal on stdin, so the block is the substitute. Landlock
// would also cover this via its ioctl_dev right, but only at ABI 5 (kernel 6.10) and
// above - far newer than the kernels this tier exists to serve - so the guarantee
// cannot rest on it.
func BlockTerminalInjection() error {
	if _, _, e := unix.Syscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); e != 0 {
		return fmt.Errorf("seccomp: setting no_new_privs: %w", e)
	}
	f := terminalInjectionFilter()
	prog := unix.SockFprog{Len: uint16(len(f)), Filter: &f[0]}
	r1, _, e := unix.Syscall(unix.SYS_SECCOMP, seccompSetModeFilter, seccompFilterFlagTSync, uintptr(unsafe.Pointer(&prog)))
	if e != 0 {
		return fmt.Errorf("seccomp: installing the terminal-injection filter: %w", e)
	}
	// Under TSYNC a sync failure is not an errno: the kernel returns the TID of a
	// thread it could not sync and attaches the filter to nothing. Treat that as
	// failure so the run is refused rather than proceeding unfiltered.
	if r1 != 0 {
		return fmt.Errorf("seccomp: terminal-injection filter could not be synced to thread %d; no filter was installed", r1)
	}
	return nil
}
