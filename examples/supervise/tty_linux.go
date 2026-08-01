//go:build linux

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// isTerminal reports whether f is a terminal, by asking for its line discipline -
// the only test that distinguishes a tty from the other character devices. The
// os.ModeCharDevice bit is a device-type test that /dev/null also sets, so under
// systemd's StandardInput=null, cron, or setsid it answers yes with no human
// present, which is exactly where this wrapper must not start asking questions.
func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}
