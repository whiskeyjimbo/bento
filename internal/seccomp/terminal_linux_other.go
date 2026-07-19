//go:build linux && !amd64

package seccomp

import "fmt"

// BlockTerminalInjection is unavailable off amd64; the degraded tier gates on
// EgressSupported (also amd64-only) and refuses before reaching it.
func BlockTerminalInjection() error {
	return fmt.Errorf("seccomp: the terminal-injection filter is not implemented for this architecture")
}
