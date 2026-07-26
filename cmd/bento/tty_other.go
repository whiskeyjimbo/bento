//go:build !linux

package main

import "os"

// isTerminal falls back to the device-type bit off Linux. It over-reports (/dev/null
// sets it too), but the sandbox backend itself is Linux-only, so profiling never
// reaches its interactive loop here.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
