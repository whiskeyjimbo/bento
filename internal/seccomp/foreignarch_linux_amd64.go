package seccomp

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// blockForeignArch installs a filter that kills any syscall issued through a
// non-native ABI. The library-backed filters (BlockExec, BlockProcessReach) match
// syscalls by their amd64 numbers and default-allow everything else, and
// go-seccomp-bpf jumps any non-x86_64 audit arch straight to that default - so an
// i386 syscall via `int 0x80` (execve is 11 there, ptrace 26) reaches the allow
// path and bypasses the block. This companion filter, installed alongside those
// two, closes that: it kills on a foreign arch, so the compat ABI cannot reach the
// default-allow. The kill is whole-process from kernel 4.14 and thread-only below it
// (see seccompRetKillProcess); the block holds either way, only its scope narrows.
// The hand-rolled strict/egress filters already carry this arch guard inline; this
// gives the library-backed ones the same.
//
// KILL, not EPERM, matches the egress filter's treatment of a foreign arch: a
// 32-bit x86 target is refused under the exec-block just as it already is under the
// degraded-tier egress block. x32 (which shares the amd64 audit arch but tags its
// syscall numbers) is not a foreign arch here; the library filter already forces
// x32 syscall numbers to ENOSYS, so it stays covered.
//
// Installed via SYS_SECCOMP with a checked r1 (matching strictFilter/egressFilter),
// so a partial TSYNC thread-sync is treated as a failed install rather than a
// silent no-op.
func blockForeignArch() error {
	if _, _, e := unix.Syscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); e != 0 {
		return fmt.Errorf("seccomp: setting no_new_privs: %w", e)
	}
	f := []unix.SockFilter{
		/*0*/ {Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offArch},
		/*1*/ {Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: auditArchX8664, Jt: 1, Jf: 0}, // native -> defer to next filter (idx 3)
		/*2*/ {Code: unix.BPF_RET | unix.BPF_K, K: seccompRetKillProcess}, // foreign arch -> kill
		/*3*/ {Code: unix.BPF_RET | unix.BPF_K, K: seccompRetAllow},
	}
	prog := unix.SockFprog{Len: uint16(len(f)), Filter: &f[0]}
	r1, _, e := unix.Syscall(unix.SYS_SECCOMP, seccompSetModeFilter, seccompFilterFlagTSync, uintptr(unsafe.Pointer(&prog)))
	if e != 0 {
		return fmt.Errorf("seccomp: installing the foreign-arch block: %w", e)
	}
	if r1 != 0 {
		return fmt.Errorf("seccomp: foreign-arch filter could not be synced to thread %d; no filter was installed", r1)
	}
	return nil
}
