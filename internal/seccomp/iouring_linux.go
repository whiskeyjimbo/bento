//go:build linux

package seccomp

import (
	seccomp "github.com/elastic/go-seccomp-bpf"
)

// BlockIoUring installs a filter that refuses the io_uring setup syscalls with EPERM,
// for this process and all its threads (TSYNC), surviving a coming exec.
//
// It exists for the profiler, not as a security fence (the egress filter blocks
// io_uring separately for that). io_uring dispatches its file operations from a kernel
// worker thread, so they never surface as syscall stops in the target's own threads -
// invisible to the ptrace-based observer, which would then synthesize a manifest that
// silently omits every file the target touched through a ring. Blocking ring creation
// forces the target onto the synchronous syscalls the observer records, keeping the
// manifest complete. A program that hard-requires io_uring instead fails loudly (a
// nonzero exit the host warns on), which beats a quietly incomplete manifest.
//
// The foreign-arch guard carries the same completeness argument, which is why this
// is not the security-fence exception to it. The observer decodes syscall numbers as
// amd64 and refuses to decode any other ABI, so a tracee issuing i386 syscalls - a
// 32-bit helper, or int 0x80 from a 64-bit process - has every one of those accesses
// dropped rather than recorded. Nothing is fabricated, but the manifest is missing them,
// and it becomes enforcement policy on the next run. Killing the process is what turns
// that silent gap into a refused run: seccomp keys on the syscall ABI rather than the
// code segment, so it catches the int 0x80 case a register check would miss, and a
// profile that cannot be trusted must not complete. It also closes i386 io_uring_setup,
// which is 425 there too.
func BlockIoUring() error {
	if err := blockForeignArch(); err != nil {
		return err
	}
	return installPolicy(seccomp.Policy{
		DefaultAction: seccomp.ActionAllow,
		Syscalls: []seccomp.SyscallGroup{
			{Action: seccomp.ActionErrno, Names: []string{"io_uring_setup", "io_uring_enter", "io_uring_register"}},
		},
	}, "io_uring block")
}
