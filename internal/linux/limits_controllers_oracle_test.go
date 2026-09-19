//go:build linux

package linux

import (
	"context"
	"testing"
)

// This reading is the only thing between a requested limit and an unbounded target, and
// its oracle used to be "the command exited 0": whatever landed on stdout became the
// delegated set, and hostSafetyDelegationState then answered Enforced for a cap the host
// will not apply. The snippet now announces itself before the read, so output that did not
// come from a cgroup.controllers read is not a controller list.
//
// What this does NOT claim: the marker is no defense against a deliberate impostor, which
// can print it as easily as anything else. What it closes is the accidental host - a
// stand-in, a wrapper, or a scope whose shell died before the read.
//
// The impostor is no longer out of the threat model, though, which is where this comment
// used to stop: a writable $PATH directory is exactly what a sandboxed target with a write
// grant produces, so the shell is held to trustLauncherPath by trustedProbeBinary and a
// planted one is refused before it runs (TestProbesRefuseARefusedCanary). The systemd-run
// this reading resolves is still not, and cannot forge more than this reading, which
// noteScopeLimits then answers from the kernel.
func TestDelegatedControllersNeedsTheReadToHaveHappened(t *testing.T) {
	t.Run("stdout that is not a controller read", func(t *testing.T) {
		plantProbeCanary(t, "systemd-run", "#!/bin/sh\necho 'memory pids cpu io hugetlb misc'\nexit 0\n")

		ctrls, known := measureDelegatedControllers(context.Background())
		if known {
			t.Errorf("known=true with ctrls=%v from a scope that never read cgroup.controllers; every one of those would be reported enforced", ctrls)
		}
	})

	// The positive control: the same shim shape, this time producing what the real snippet
	// produces. Without it the assertion above is satisfied by a reading that never answers.
	t.Run("a real controller read", func(t *testing.T) {
		plantProbeCanary(t, "systemd-run", "#!/bin/sh\necho '"+controllersMarker+"'\necho 'memory pids'\nexit 0\n")

		ctrls, known := measureDelegatedControllers(context.Background())
		if !known {
			t.Fatal("known=false from output carrying the marker and a controller list")
		}
		if !ctrls["memory"] || !ctrls["pids"] || ctrls["cpu"] {
			t.Errorf("ctrls = %v, want memory and pids only", ctrls)
		}
	})
}
