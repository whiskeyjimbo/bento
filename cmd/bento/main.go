// Command bento runs a script under a sandbox described by a manifest.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/whiskeyjimbo/bento/backend"
)

// bentoFailed is the exit code when bento itself could not run the target - a
// bad manifest, or a guarantee this host cannot enforce. It is deliberately high
// and distinct so a caller can tell "bento refused" from the target's own exit
// code, which is passed through untouched. 125 follows the convention env(1) and
// docker use for "the command could not be executed".
const bentoFailed = 125

// doctorCoreShortfall is doctor's exit code when a core guarantee is not fully
// enforced on this host (runs that need it are refused by default). Distinct from
// bentoFailed and from a target's own code so a CI wrapper can gate on host
// readiness. A hardening-only gap, where runs still proceed, stays exit 0.
const doctorCoreShortfall = 3

// strictShortfall is `run --strict`'s exit code when the target ran but a guarantee
// strict required lapsed during the run (a proxy listener that died mid-run). It is
// distinct from bentoFailed, which says the target never ran, and from the target's
// own code, which must not stand in for a posture that did not hold.
const strictShortfall = 126

// exitError carries a target's exit code up to main so all deferred cleanup runs
// before the process exits. Returning it instead of calling os.Exit inside a
// command keeps the frontend from bypassing the sandbox's own teardown.
type exitError struct{ code int }

func (e *exitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

func main() {
	// The linux backend confines a target by re-executing this binary inside the
	// sandbox as a hidden launch/bridge stage. Dispatch those before any flag
	// parsing; a normal invocation falls through and returns here.
	backend.DispatchReexec()

	err := newRootCmd().Execute()
	if err == nil {
		return
	}
	var ee *exitError
	if errors.As(err, &ee) {
		os.Exit(ee.code)
	}
	fmt.Fprintf(os.Stderr, "bento: %v\n", err)
	os.Exit(bentoFailed)
}
