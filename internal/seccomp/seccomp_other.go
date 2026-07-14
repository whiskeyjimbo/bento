//go:build !linux

package seccomp

import "fmt"

// Supported reports false: seccomp is Linux-only.
func Supported() bool { return false }

// BlockExec is unavailable off Linux.
func BlockExec() error { return fmt.Errorf("seccomp: exec-blocking is only available on Linux") }

// Exec is unavailable off Linux.
func Exec(argv, envp []string) error {
	return fmt.Errorf("seccomp: not available on this platform")
}
