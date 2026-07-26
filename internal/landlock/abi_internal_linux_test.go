package landlock

import (
	"errors"
	"testing"
)

// The availability gate and the enforcement path must detect the same effective ABI.
// If they diverge, the gate can admit a degraded run that BestEffort then downgrades to
// a silent no-op, running the target with the whole host filesystem exposed.
func TestFlooredABI(t *testing.T) {
	if got := flooredABI(3, errors.New("ENOSYS")); got != 0 {
		t.Errorf("a syscall error must floor to 0 (unavailable); got %d", got)
	}
	floor := minRequiredABI()
	if got := flooredABI(floor+2, nil); got != floor+2 {
		t.Errorf("a version above the floor must pass through; got %d, want %d", got, floor+2)
	}
	if floor > 0 {
		if got := flooredABI(floor-1, nil); got != 0 {
			t.Errorf("a version below the floor must read as unavailable (fail-closed); got %d", got)
		}
	}
}

// Available must report exactly what effectiveABI (the value RestrictDegraded gates on)
// makes usable, so the two never disagree.
func TestAvailableMatchesEffectiveABI(t *testing.T) {
	if Available() != (effectiveABI() >= 1) {
		t.Errorf("Available()=%v but effectiveABI()=%d; the gate and enforcement detection disagree", Available(), effectiveABI())
	}
}

// The degraded tier's sole filesystem guarantee is Landlock, so it must refuse rather
// than run unconfined when the effective ABI is unavailable. Only the refusal branch is
// exercised here: applying a real ruleset would irreversibly Landlock the test process
// and poison every later test. The probe binary covers RestrictTo only, so the
// confinement half of RestrictDegraded is reached solely through the end-to-end
// degraded-tier runs, never from this package.
func TestRestrictDegradedRefusesWithoutABI(t *testing.T) {
	if effectiveABI() >= 1 {
		t.Skip("Landlock available; the refusal guard fires only when it is not")
	}
	if err := RestrictDegraded([]string{"/"}, nil, nil); !errors.Is(err, errUnavailableABI) {
		t.Errorf("RestrictDegraded must refuse with errUnavailableABI when ABI is unavailable; got %v", err)
	}
}
