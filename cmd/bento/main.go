// Command bento runs a script under a sandbox described by a manifest.
package main

import (
	"fmt"
	"os"
)

// exitUsage is returned for anything that stopped bento itself from running the
// target: a bad manifest, an unenforceable policy, a missing sandbox. The
// target's own exit code is passed through untouched, so a script that exits 2 is
// not confused with bento refusing to run it — use --json when a caller needs to
// tell those apart without ambiguity.
const exitUsage = 2

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "bento: %v\n", err)
		os.Exit(exitUsage)
	}
}
