//go:build linux

package linux

import (
	"context"
	"strings"
	"testing"
)

// A scope propagates its command's exit status, so "the probe failed" is two host facts
// wearing one exit code: the user manager would not create the scope, or the canary the
// probe runs inside it would not run. measureScope used to word both as the first, which
// sends an operator to debug a user manager that is fine - and the canary failure is the
// rarer cause, so the common wording hides the one worth acting on.
//
// The verdict is the same either way (answered=false, nothing cached), which is why this
// asserts only the wording: the cost of the conflation is the diagnosis and nothing else.
func TestMeasureScopeSeparatesTheCanaryFromTheUserManager(t *testing.T) {
	// A systemd-run that propagates its command's status, which is what a real scope does
	// and what makes the two causes indistinguishable from the exit code alone.
	const propagating = "#!/bin/sh\nfor a in \"$@\"; do last=$a; done\nexec \"$last\"\n"

	t.Run("a canary that will not run", func(t *testing.T) {
		dir := shimPATH(t, "systemd-run", propagating)
		writeShim(t, dir, "true", "#!/bin/sh\nexit 3\n")

		v, answered := measureScope(context.Background())
		if answered {
			t.Fatal("measureScope reached a verdict from a probe that never created a scope")
		}
		if !strings.Contains(v.reason, "canary") {
			t.Errorf("reason = %q, want the canary named; blaming the user manager sends the operator to a host component that is fine", v.reason)
		}
	})

	// The positive control: the same shim shape, a canary that runs, and a systemd-run that
	// refuses. The user manager really is the cause here and must still be named.
	t.Run("a user manager that will not create the scope", func(t *testing.T) {
		shimPATH(t, "systemd-run", "#!/bin/sh\necho 'Failed to start transient scope unit' >&2\nexit 1\n")

		v, answered := measureScope(context.Background())
		if answered {
			t.Fatal("measureScope reached a verdict from a probe that never created a scope")
		}
		if !strings.Contains(v.reason, "no usable systemd user manager") {
			t.Errorf("reason = %q, want the user manager named", v.reason)
		}
	})
}
