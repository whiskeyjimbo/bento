//go:build linux && !amd64

package seccomp

import "fmt"

// StrictExecSupported reports whether this build can enforce exec: none-strict.
// The classic-BPF filter is architecture-specific and only amd64 is implemented,
// so on other architectures none-strict falls back to the execve-only block and
// the exec-strict layer is reported unavailable.
func StrictExecSupported() bool { return false }

// BlockExecStrict is unavailable off amd64; callers gate on StrictExecSupported.
func BlockExecStrict() error {
	return fmt.Errorf("seccomp: the none-strict filter is not implemented for this architecture")
}
