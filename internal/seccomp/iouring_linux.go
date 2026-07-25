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
func BlockIoUring() error {
	return installPolicy(seccomp.Policy{
		DefaultAction: seccomp.ActionAllow,
		Syscalls: []seccomp.SyscallGroup{
			{Action: seccomp.ActionErrno, Names: []string{"io_uring_setup", "io_uring_enter", "io_uring_register"}},
		},
	}, "io_uring block")
}
