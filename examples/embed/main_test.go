package main

import (
	"os"
	"testing"

	"github.com/whiskeyjimbo/bento/backend"
)

// TestMain shows the pattern an embedder's own tests must follow. Under `go test`
// the test binary is the executable bento re-execs into the sandbox; without this
// hook the hidden launch stage would be swallowed by the testing package's flag
// parsing and fail cryptically. TestMain runs before those flags are parsed, so
// dispatching here routes a re-exec sub-invocation correctly and simply returns
// for an ordinary test run.
func TestMain(m *testing.M) {
	backend.DispatchReexec()
	os.Exit(m.Run())
}
