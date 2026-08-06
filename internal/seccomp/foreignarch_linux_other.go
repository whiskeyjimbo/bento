//go:build linux && !amd64

package seccomp

import "fmt"

// blockForeignArch is unavailable off amd64. The library-backed filters it
// accompanies (BlockExec, BlockProcessReach, BlockIoUring) match syscalls by their
// native numbers and default-allow everything else, so without an arch guard a
// compat ABI - aarch32 on an arm64 kernel built with CONFIG_COMPAT, exactly as
// i386 is on amd64 - reaches the default-allow and bypasses all three. Returning
// nil here would install those filters and report them applied while the bypass
// stayed open, so this refuses instead: the guard is amd64-only, as the
// strict/egress ones already are, and an unenforceable block fails loud rather
// than quietly.
func foreignArchSupported() bool { return false }

func blockForeignArch() error {
	return fmt.Errorf("seccomp: the foreign-arch guard is not implemented for this architecture, so the syscall filters it protects cannot be enforced")
}
