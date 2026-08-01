//go:build !linux

package main

import "os"

// isTerminal falls back to the device-type bit off Linux. It over-reports (/dev/null
// sets it too), but the sandbox backend itself is Linux-only, so run never gets far
// enough here for the difference to matter.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
