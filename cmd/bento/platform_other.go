//go:build !linux

package main

import (
	"fmt"
	"runtime"
)

// checkPlatform refuses the commands that build or probe a sandbox off Linux, in the same
// words backend.New uses, before the command reaches anything else.
//
// The tree deliberately builds for darwin (see backend/backend_other.go), so a macOS
// developer gets a binary - and without this would meet whichever platform stub happened
// to be in the way of the command they ran, each a true sentence about a detail nobody
// asked about. The answer they need is that this platform has no sandbox at all, said
// once and up front. It is not called by validate or approve, which build no sandbox and
// answer from what they can read here instead.
func checkPlatform() error {
	return fmt.Errorf("no sandbox backend for %s yet (macOS support is planned; Linux requires bubblewrap)", runtime.GOOS)
}
