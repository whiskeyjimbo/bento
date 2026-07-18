package seccomp

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// x86-64 socket(2) number and the address families the egress filter allows.
const (
	nrSocket = 41

	afUnix    = 1  // local IPC; path-scoped, cannot reach an IP network
	afNetlink = 16 // kernel<->user IPC; cannot egress, but runtimes enumerate interfaces with it

	// Offset into struct seccomp_data of socket()'s first argument (domain). args
	// is a []u64; on little-endian amd64 the int domain sits in the low 32 bits.
	offArg0Domain = 16
)

// EgressSupported reports whether this build can install the egress filter. Like
// exec-strict, the classic-BPF program is architecture-specific and only amd64 is
// implemented; the degraded tier gates on this and fails loud where it is false,
// since a no-network manifest cannot get its no-egress guarantee otherwise.
func EgressSupported() bool { return true }

// egressFilter builds the classic-BPF program that denies IP and raw-link egress.
// It is an ALLOWLIST on socket()'s domain: only AF_UNIX and AF_NETLINK pass, every
// other family (AF_INET, AF_INET6, AF_PACKET, AF_XDP, AF_VSOCK, ...) is refused with
// EPERM. An allowlist is the guarantee: a denylist would miss an address family we
// did not enumerate, and "no egress" must not depend on remembering every wire
// family. Blocking creation is the whole chokepoint - with no INET socket, later
// connect/sendto have nothing to send through. A wrong architecture is killed, as is
// any x32-ABI syscall (x32 shares the amd64 audit arch but tags its numbers, so an
// x32 socket() would miss the equality check and slip through).
func egressFilter() []unix.SockFilter {
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
		/*6*/ jeq(nrSocket, 0, 4), // not socket -> allow (idx 11)
		/*7*/ ld(offArg0Domain),
		/*8*/ jeq(afUnix, 2, 0), // AF_UNIX -> allow
		/*9*/ jeq(afNetlink, 1, 0), // AF_NETLINK -> allow
		/*10*/ eperm,
		/*11*/ ret(seccompRetAllow),
	}
}

// BlockEgress installs the egress filter for this process and all its threads
// (TSYNC), surviving the coming execveat, and sets no-new-privs. It is applied only
// on a no-network manifest in the degraded (no-bwrap) tier, where there is no netns
// to fence egress: it substitutes a seccomp chokepoint so even a proxy-ignoring
// static binary cannot open a network socket.
func BlockEgress() error {
	if _, _, e := unix.Syscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); e != 0 {
		return fmt.Errorf("seccomp: setting no_new_privs: %w", e)
	}
	f := egressFilter()
	prog := unix.SockFprog{Len: uint16(len(f)), Filter: &f[0]}
	r1, _, e := unix.Syscall(unix.SYS_SECCOMP, seccompSetModeFilter, seccompFilterFlagTSync, uintptr(unsafe.Pointer(&prog)))
	if e != 0 {
		return fmt.Errorf("seccomp: installing the egress filter: %w", e)
	}
	// Under TSYNC a sync failure is not an errno: the kernel returns the TID of a
	// thread it could not sync and attaches the filter to nothing. Treat that as
	// failure so the run is refused rather than proceeding unfiltered.
	if r1 != 0 {
		return fmt.Errorf("seccomp: egress filter could not be synced to thread %d; no filter was installed", r1)
	}
	return nil
}
