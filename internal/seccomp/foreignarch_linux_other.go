//go:build linux && !amd64

package seccomp

// blockForeignArch is a no-op off amd64. The compat-ABI bypass it closes is the
// x86 i386 path (int 0x80); an arm64 kernel built with CONFIG_COMPAT has the
// analogous aarch32 bypass, but the hand-rolled arch guard is only implemented for
// amd64 (as with the strict/egress filters). That residual is documented rather
// than silently closed here.
func blockForeignArch() error { return nil }
