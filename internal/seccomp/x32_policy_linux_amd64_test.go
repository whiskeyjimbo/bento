//go:build linux && amd64

package seccomp

import (
	"encoding/binary"
	"testing"

	seccomp "github.com/elastic/go-seccomp-bpf"
	"golang.org/x/net/bpf"
)

// The library-backed filters - BlockExec, BlockProcessReach, BlockIoUring - get their
// x32 coverage entirely from go-seccomp-bpf, which prepends a JGE __X32_SYSCALL_BIT ->
// RET ENOSYS to every policy it assembles. blockForeignArch explicitly declines to cover
// x32 on the strength of that, and installPolicy's comment asserts it. A dependency bump
// that dropped or narrowed the prepend would silently reopen x32 execve, x32 ptrace and
// x32 io_uring_setup with both comments still claiming coverage, and nothing else in the
// tree would fail.
//
// This asserts the assembled program rather than a live syscall because ENOSYS is also
// what a kernel built without CONFIG_X86_X32 answers by itself: a running probe would
// pass identically on a host where the filter contributed nothing, which is the vacuous
// pin this exists to avoid. The hand-rolled filters (strict, egress, terminal) carry the
// prepend inline and are pinned by their own Test*KillsX32Syscalls against a live kernel,
// where the verdict is a kill and no kernel produces that on its own.
//
// The syscall lists are copied from the three Block* functions rather than shared with
// them, as the other filter tests copy their syscall numbers: what is under test is the
// assembler's treatment of a default-allow policy, and reading the policy back out of the
// code that builds it would let a wrong one agree with itself.
func TestAssembledPolicyForcesX32ToENOSYS(t *testing.T) {
	for _, tc := range []struct {
		what     string
		syscalls []string
	}{
		{"exec-block", []string{"execve"}},
		{"cross-process block", []string{
			"ptrace", "process_vm_readv", "process_vm_writev", "process_madvise", "kcmp", "pidfd_getfd",
			"move_pages", "get_robust_list", "perf_event_open",
		}},
		{"io_uring block", []string{"io_uring_setup", "io_uring_enter", "io_uring_register"}},
	} {
		t.Run(tc.what, func(t *testing.T) {
			policy := seccomp.Policy{
				DefaultAction: seccomp.ActionAllow,
				Syscalls:      []seccomp.SyscallGroup{{Action: seccomp.ActionErrno, Names: tc.syscalls}},
			}
			insts, err := policy.Assemble()
			if err != nil {
				t.Fatalf("assembling the %s policy: %v", tc.what, err)
			}
			vm, err := bpf.NewVM(insts)
			if err != nil {
				t.Fatalf("loading the %s program into the interpreter: %v", tc.what, err)
			}

			// getpid, which no policy here names: an x32 verdict on a syscall the policy
			// itself denies would be indistinguishable from the policy's own errno.
			const nrGetpid = 39
			// The control. Without it a program that answered ENOSYS to everything -
			// a wrong arch gate, an assembler that emitted only the prepend - would
			// satisfy the x32 case while denying every native syscall too.
			if got := runProgram(t, vm, nrGetpid); got != retAllow {
				t.Errorf("native getpid under the %s program returned %#x, want RET_ALLOW %#x", tc.what, got, retAllow)
			}
			if got := runProgram(t, vm, x32SyscallTag|nrGetpid); got != retErrnoENOSYS {
				t.Errorf("x32-tagged getpid under the %s program returned %#x, want ENOSYS %#x - "+
					"go-seccomp-bpf's x32 block is gone, and blockForeignArch does not cover x32",
					tc.what, got, retErrnoENOSYS)
			}
		})
	}
}

// The verdicts the assembled program can return, spelled out rather than taken from the
// package's own constants for the reason the syscall numbers are.
const (
	retAllow       = 0x7fff0000
	retErrnoENOSYS = 0x00050000 | 38 // SECCOMP_RET_ERRNO | ENOSYS
)

// runProgram interprets the program over a seccomp_data carrying nr and the native audit
// arch. The buffer is the full 64-byte struct - nr, arch, instruction_pointer, six args -
// so a load at any offset the program uses stays in bounds; only the first two words
// matter to what is asserted here.
//
// Big-endian, unlike the little-endian struct the kernel actually hands the filter: this
// interpreter is a packet filter, so its absolute loads read network byte order. Writing
// the words the way the kernel lays them out makes the arch gate miss and every verdict
// comes back RET_ALLOW - which the control above is what catches.
func runProgram(t *testing.T, vm *bpf.VM, nr uint32) int {
	t.Helper()
	data := make([]byte, 64)
	binary.BigEndian.PutUint32(data[0:], nr)
	binary.BigEndian.PutUint32(data[4:], auditArchX8664)
	verdict, err := vm.Run(data)
	if err != nil {
		t.Fatalf("interpreting the program for nr %#x: %v", nr, err)
	}
	return verdict
}
