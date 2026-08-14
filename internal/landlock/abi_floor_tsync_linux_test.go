//go:build landlocktsync

package landlock

import "testing"

// The tsync floor and the ABI at which go-landlock switches to the kernel's TSYNC flag
// are the same number for one reason: that build tag exists to make the library refuse
// the userspace fan-out, so its floor is exactly where the kernel takes over. Written
// out twice - here as the availability gate's floor, and as tsyncABI where the probe
// tests reason about which mechanism runs - so a go-landlock bump that moves the
// threshold has to move both. Nothing else compares them, and below the floor
// BestEffort is a silent no-op, so drift means the gate admits a run that enforces
// nothing.
func TestTheTsyncFloorIsTheTsyncThreshold(t *testing.T) {
	if got := minRequiredABI(); got != tsyncABI {
		t.Errorf("the landlocktsync availability floor is %d but go-landlock switches to kernel TSYNC at ABI %d; below the floor BestEffort silently enforces nothing", got, tsyncABI)
	}
}
