//go:build !linux

package main

import (
	"fmt"
	"runtime"
)

// checkPlatform refuses every command that does real work off Linux, in the same words
// backend.New uses, before the command reaches anything else.
//
// The tree deliberately builds for darwin (see backend/backend_other.go), so a macOS
// developer gets a binary - and then meets the first stub that happens to be in the way,
// which is trust_other.go complaining that where a manifest lives cannot be checked here.
// That is a true sentence about a detail nobody asked about; the answer they need is that
// this platform has no sandbox at all. Said once, here, rather than left to whichever
// stub each command reaches first.
func checkPlatform() error {
	return fmt.Errorf("no sandbox backend for %s yet (macOS support is planned; Linux requires bubblewrap)", runtime.GOOS)
}
