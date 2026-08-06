//go:build linux

package backend

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/launcher"
	"github.com/whiskeyjimbo/bento/policy"
)

// On Linux, New must return a usable enforcer and no error. Pins that the Linux
// build selects the real backend (the package previously had no tests).
func TestNewReturnsLinuxEnforcer(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatalf("New on linux: unexpected error %v", err)
	}
	if e == nil {
		t.Fatal("New on linux returned a nil enforcer")
	}
}

// An embedder that never called DispatchReexec must be told so when it asks for the
// backend, not after a run: the stages have nowhere to land, so the run it would go on
// to start attests nothing, and the Refusal that comes back can only offer the missed
// call as one candidate cause among several.
//
// It clears the package's own record, so it must not run beside a parallel test that
// needs an enforcer; no test in this package calls t.Parallel().
func TestNewRefusesWithoutDispatchReexec(t *testing.T) {
	defer dispatched.Store(dispatched.Swap(false))

	e, err := New()
	if err == nil {
		t.Fatal("New must refuse a process that never dispatched")
	}
	if e != nil {
		t.Error("New returned an enforcer beside its error")
	}
	if !strings.Contains(err.Error(), "DispatchReexec") {
		t.Errorf("err = %v, want the missed call named", err)
	}
	p := &policy.Policy{Entrypoint: "/bin/true"}
	if _, err := Profile(t.Context(), p, enforce.Process{}, ProfileOptions{}); err == nil ||
		!strings.Contains(err.Error(), "DispatchReexec") {
		t.Errorf("Profile err = %v, want the same refusal", err)
	}
}

// A stage whose argv does not decode must exit 125 with the reason on stderr, and must
// never fall through to the embedder's own startup. Falling through is the dangerous
// failure: the sandbox has already handed this process the target's job, so a program
// that resumed its normal main() would run as the confined child with none of the
// confinement, and the host would read the embedder's own exit code as the target's.
// Only a real re-exec reaches this - DispatchReexec exits the process - so the test
// re-invokes its own binary the way the sandbox does, which needs no seam.
func TestDispatchReexecFailsSetupWith125(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for name, argv := range map[string][]string{
		"launch with an unparsable flag":   {launcher.SentinelLaunch, "--no-such-flag"},
		"degraded with an unparsable flag": {launcher.SentinelLaunchDegraded, "--no-such-flag"},
		// The bridge takes exactly one socket argument; the count check is its own.
		"bridge with no socket": {launcher.SentinelBridge},
	} {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command(self, argv...)
			var stdout, stderr strings.Builder
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatalf("want an exit error, got %v (stderr %q)", err, stderr.String())
			}
			if code := exit.ExitCode(); code != 125 {
				t.Errorf("exit code = %d, want 125 (stderr %q)", code, stderr.String())
			}
			if !strings.HasPrefix(stderr.String(), "bento: ") {
				t.Errorf("stderr = %q, want the failure named on bento's own prefix", stderr.String())
			}
			// A backstop, not the primary check: the exit code above is what actually
			// pins the fall-through, since this binary's own startup is the test suite
			// and a suite that ran would not exit 125.
			if strings.Contains(stdout.String(), "PASS") {
				t.Errorf("a stage that failed setup fell through to the embedding program's startup: %q", stdout.String())
			}
		})
	}
}

// An embedder that never calls DispatchReexec gets the cause named on stderr and exit
// 125, not a silent hang. The staged child otherwise runs the embedding program
// normally while still carrying the sentinel, and for a test binary that means
// re-running the suite, which stages again - so the diagnosis has to come from the
// entry points the resumed program reaches, which are New and Profile.
//
// Run as a subprocess because the guard exits: an exit is what stops an embedder's own
// recover() from resuming the program here and starting that fork bomb, so there is
// nothing in-process left to observe.
func TestUndispatchedStageExitsWith125(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for name, sentinel := range map[string]string{
		"launch":   launcher.SentinelLaunch,
		"degraded": launcher.SentinelLaunchDegraded,
		"bridge":   launcher.SentinelBridge,
	} {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command(self, "-test.run=TestUndispatchedStageHelper")
			cmd.Env = append(os.Environ(), undispatchedStageEnv+"="+sentinel)
			var stdout, stderr strings.Builder
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatalf("want an exit error, got %v (stderr %q)", err, stderr.String())
			}
			if code := exit.ExitCode(); code != 125 {
				t.Errorf("exit code = %d, want 125 (stderr %q)", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), "DispatchReexec") {
				t.Errorf("stderr = %q, want the missed call named", stderr.String())
			}
			if strings.Contains(stdout.String(), "PASS") {
				t.Errorf("an undispatched stage fell through to the embedding program's startup: %q", stdout.String())
			}
		})
	}
}

// undispatchedStageEnv carries the sentinel the helper below should wear. A test flag
// cannot do it: the guard reads os.Args[1], and an argument in that position stops the
// testing package's own flag parsing.
const undispatchedStageEnv = "BENTO_TEST_UNDISPATCHED_STAGE"

// TestUndispatchedStageHelper is the embedder TestUndispatchedStageExitsWith125 runs.
// It never returns when it does its job, so it only runs in that child process.
func TestUndispatchedStageHelper(t *testing.T) {
	sentinel := os.Getenv(undispatchedStageEnv)
	if sentinel == "" {
		t.Skip("runs only as the child of TestUndispatchedStageExitsWith125")
	}
	swapArgs(t, []string{"embedder", sentinel})
	_, _ = New()
	t.Fatal("an undispatched stage reached New and went on running")
}

// An ordinary invocation must not trip the guard, whatever its arguments - only the
// reserved sentinel namespace does.
func TestOrdinaryArgsDoNotTripTheGuard(t *testing.T) {
	for name, argv := range map[string][]string{
		"no arguments":     {"embedder"},
		"a normal flag":    {"embedder", "--verbose"},
		"a sentinel later": {"embedder", "run", launcher.SentinelLaunch},
	} {
		t.Run(name, func(t *testing.T) {
			swapArgs(t, argv)
			if _, err := New(); err != nil {
				t.Fatalf("New: %v", err)
			}
		})
	}
}

// swapArgs points os.Args at argv for the duration of the test. The guard reads the
// real os.Args because that is what a re-exec stage is handed; there is no seam.
func swapArgs(t *testing.T, argv []string) {
	t.Helper()
	saved := os.Args
	t.Cleanup(func() { os.Args = saved })
	os.Args = argv
}
