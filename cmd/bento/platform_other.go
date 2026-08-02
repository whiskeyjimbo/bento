//go:build !linux

package main

import "fmt"

// checkPlatform refuses the commands that build or probe a sandbox off Linux, before the
// command reaches anything else. It says what backend.New says (modulo that one's package
// prefix), deliberately and by hand: nothing enforces the two staying in step, since
// neither file compiles on the host the tests run on.
//
// The tree deliberately builds for darwin (see backend/backend_other.go), so a macOS
// developer gets a binary - and without this would meet whichever platform stub happened
// to be in the way of the command they ran, each a true sentence about a detail nobody
// asked about. The answer they need is that this platform has no sandbox at all, said
// once and up front. It is not called by validate or approve, which build no sandbox and
// answer from what they can read here instead.
//
// The refusal names GOOS/GOARCH, not GOOS alone: what bento stands behind is a
// platform pair (see verifiedPlatform), and doctor --json already answers this host
// with that pair in its platform field. Naming only the OS here would leave the human
// on a broken host told less than the script beside them.
func checkPlatform() error {
	return fmt.Errorf("no sandbox backend for %s yet (macOS support is planned; Linux requires bubblewrap)", platformName())
}
