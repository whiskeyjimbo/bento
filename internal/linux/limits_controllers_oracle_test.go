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
// What this does NOT claim: it is not a defense against a deliberate impostor on $PATH,
// which can print the marker as easily as anything else. That premise needs write access
// to a host $PATH directory and is out of the threat model, the same boundary bv2-lufru
// draws. What it closes is the accidental host: a stand-in, a wrapper, or a scope whose
// shell died before the read.
func TestDelegatedControllersNeedsTheReadToHaveHappened(t *testing.T) {
	t.Run("stdout that is not a controller read", func(t *testing.T) {
		shimPATH(t, "systemd-run", "#!/bin/sh\necho 'memory pids cpu io hugetlb misc'\nexit 0\n")

		ctrls, known := measureDelegatedControllers(context.Background())
		if known {
			t.Errorf("known=true with ctrls=%v from a scope that never read cgroup.controllers; every one of those would be reported enforced", ctrls)
		}
	})

	// The positive control: the same shim shape, this time producing what the real snippet
	// produces. Without it the assertion above is satisfied by a reading that never answers.
	t.Run("a real controller read", func(t *testing.T) {
		shimPATH(t, "systemd-run", "#!/bin/sh\necho '"+controllersMarker+"'\necho 'memory pids'\nexit 0\n")

		ctrls, known := measureDelegatedControllers(context.Background())
		if !known {
			t.Fatal("known=false from output carrying the marker and a controller list")
		}
		if !ctrls["memory"] || !ctrls["pids"] || ctrls["cpu"] {
			t.Errorf("ctrls = %v, want memory and pids only", ctrls)
		}
	})
}
