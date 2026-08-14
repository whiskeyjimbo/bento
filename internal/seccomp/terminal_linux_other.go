//go:build linux && !amd64

package seccomp

import "fmt"

// TerminalInjectionSupported reports whether this build can install the terminal-injection
// filter. The classic-BPF program is architecture-specific and only amd64 is implemented,
// so the degraded tier - which execs the target onto the caller's own controlling terminal,
// with no bwrap --new-session to detach it - cannot fence terminal injection here and must
// refuse rather than run without it.
func TerminalInjectionSupported() bool { return false }

// BlockTerminalInjection is unavailable off amd64; callers gate on
// TerminalInjectionSupported.
func BlockTerminalInjection() error {
	return fmt.Errorf("seccomp: the terminal-injection filter is not implemented for this architecture")
}
