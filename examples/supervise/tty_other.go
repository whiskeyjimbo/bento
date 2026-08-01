//go:build !linux

package main

import "os"

// isTerminal falls back to the device-type bit off Linux. It over-reports (/dev/null
// sets it too), so a piped run gets past the terminal check here and fails a step
// later on the Linux-only sandbox backend instead. This file exists to keep the
// module compiling for a cross-platform vet, not to make the wrapper work off Linux.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
