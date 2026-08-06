//go:build !linux

package seccomp

import "fmt"

// Supported reports false: seccomp is Linux-only.
func Supported() bool { return false }

// BlockExec is unavailable off Linux.
func BlockExec() error { return fmt.Errorf("seccomp: exec-blocking is only available on Linux") }

// BlockProcessReach is unavailable off Linux.
func BlockProcessReach() error {
	return fmt.Errorf("seccomp: the cross-process block is only available on Linux")
}

// EgressSupported reports false: seccomp is Linux-only.
func EgressSupported() bool { return false }

// BlockEgress is unavailable off Linux.
func BlockEgress() error { return fmt.Errorf("seccomp: the egress filter is only available on Linux") }

// Exec is unavailable off Linux.
func Exec(argv, envp []string) error {
	return fmt.Errorf("seccomp: not available on this platform")
}

// The rest of the package's surface, stubbed for the same reason the calls above are: the
// build tags on the Linux files are "linux" and "linux && amd64", so nothing here declares
// these off Linux and any non-Linux caller fails to compile rather than getting the
// unavailable answer the package promises. Omitting them compiled only because nothing in
// this package refers to them.

// StrictExecSupported reports false: seccomp is Linux-only.
func StrictExecSupported() bool { return false }

// BlockExecStrict is unavailable off Linux.
func BlockExecStrict() error {
	return fmt.Errorf("seccomp: the none-strict filter is only available on Linux")
}

// BlockIoUring is unavailable off Linux.
func BlockIoUring() error {
	return fmt.Errorf("seccomp: the io_uring block is only available on Linux")
}

// BlockTerminalInjection is unavailable off Linux.
func BlockTerminalInjection() error {
	return fmt.Errorf("seccomp: the terminal-injection filter is only available on Linux")
}
