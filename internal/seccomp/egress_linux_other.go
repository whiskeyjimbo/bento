//go:build linux && !amd64

package seccomp

import "fmt"

// EgressSupported reports whether this build can install the egress filter. The
// classic-BPF program is architecture-specific and only amd64 is implemented, so
// the degraded tier's no-egress guarantee is unavailable here and callers must fail
// loud rather than run a no-network manifest with the host network reachable.
func EgressSupported() bool { return false }

// BlockEgress is unavailable off amd64; callers gate on EgressSupported.
func BlockEgress() error {
	return fmt.Errorf("seccomp: the egress filter is not implemented for this architecture")
}
