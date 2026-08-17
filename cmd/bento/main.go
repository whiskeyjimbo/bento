// Command bento runs a script under a sandbox described by a manifest.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

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

// profileIncomplete is `bento profile`'s exit code when it wrote a manifest it cannot
// vouch for: the profiled run was killed or exited nonzero, the observer dropped
// accesses it could not name, the convergence loop hit its round cap, or the user quit
// before it converged. The manifest is still written - it is the starting point for the
// next pass - but `profile && approve` must not stamp it. It sits beside
// doctorCoreShortfall as a per-command outcome code rather than reusing 125 (bento did
// run the target and did write the file) or 124 (which is run --strict's verdict).
const profileIncomplete = 4

// postureShortfall is run's exit code when the target ran but a guarantee the run was
// admitted on lapsed during it (a proxy listener that died mid-run, a Landlock ruleset
// that failed to apply). Not strict's alone: the default posture refuses a degraded
// core layer at admission, so it gets the same verdict when one arrives from the
// backend instead. It sits next to bentoFailed because it is the same kind of answer -
// bento's verdict on the run rather than the script's own code, which must not stand in
// for a posture that did not hold. It stays out of the shell's reserved 126/127/128+n
// band, where a script that merely failed to exec something returns 126 on its own.
const postureShortfall = 124

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

	// Ctrl-C, or a supervisor's SIGTERM, must not default-terminate this process. Every
	// artifact a run leaves on the host is removed by a deferred call - the run directory
	// holding the proxy socket, and the mount points bwrap created in the user's own
	// write-granted tree for paths that did not exist yet - and a default-terminated bento
	// runs none of them, so every aborted run adds more. Cancelling the command's context
	// instead kills the sandbox and lets that cleanup happen.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Handling is released the moment the first signal lands, so a second one takes the
	// default action: cleanup is not instant (the proxy waits for its in-flight handlers)
	// and the user must not be left with a process that ignores Ctrl-C.
	go func() {
		<-ctx.Done()
		stop()
	}()

	// ExecuteContextC rather than ExecuteContext: a usage error is raised against the
	// command the user was trying to reach, and that command is the only thing that knows
	// how it should have been called.
	root := newRootCmd()
	cmd, err := root.ExecuteContextC(ctx)
	if err == nil {
		return
	}
	// A usage error is raised before RunE, so a command whose --json contract is the
	// refusal envelope has written nothing to stdout yet; this is the last place that
	// can. It answers in the envelope, and stderr carries nothing but the report an
	// envelope that could not be written earns - exactly as a refusal raised inside RunE
	// does.
	err = refuseUsageJSON(os.Stdout, os.Stderr, root, cmd, os.Args, err)
	var ee *exitError
	if errors.As(err, &ee) {
		os.Exit(ee.code)
	}
	fmt.Fprintf(os.Stderr, "bento: %v\n", err)
	if isUsageMistake(root, cmd, err) {
		writeUsageHint(os.Stderr, cmd, err)
	}
	os.Exit(bentoFailed)
}
