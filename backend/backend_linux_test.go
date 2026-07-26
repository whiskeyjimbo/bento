//go:build linux

package backend

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/launcher"
)

// On Linux, New must return a usable enforcer and no error. Pins that the Linux
// build selects the real backend (bv2-6f7 - the package previously had no tests).
func TestNewReturnsLinuxEnforcer(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatalf("New on linux: unexpected error %v", err)
	}
	if e == nil {
		t.Fatal("New on linux returned a nil enforcer")
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
			// This binary's own startup is the test suite, which announces itself on
			// stdout - so its silence is what proves the stage did not fall through.
			if strings.Contains(stdout.String(), "PASS") || strings.Contains(stdout.String(), "RUN") {
				t.Errorf("a stage that failed setup fell through to the embedding program's startup: %q", stdout.String())
			}
		})
	}
}
