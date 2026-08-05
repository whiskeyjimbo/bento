package landlock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	ll "github.com/landlock-lsm/go-landlock/landlock"
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

// A path that cannot be stat'd is not the same fact as a path that is absent. Dropping
// it builds a ruleset that denies a granted path, and the target then gets EACCES with
// nothing naming Landlock - so the errno has to reach the caller. ENOTDIR is the arm
// used here because it does not depend on the test's uid.
func TestClassifyRulesSeparatesMissingFromUnstattable(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "regular")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	rules, err := classifyRules(nil, []string{filepath.Join(dir, "absent")}, ll.RODirs, ll.ROFiles)
	if err != nil {
		t.Errorf("a missing path must be skipped, not refused; got %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("a missing path must contribute no rule; got %d", len(rules))
	}

	under := filepath.Join(file, "child")
	if _, err := classifyRules(nil, []string{under}, ll.RWDirs, ll.RWFiles); err == nil {
		t.Errorf("a path under a regular file must be refused, not silently dropped")
	}
	if _, err := existing([]string{under}); err == nil {
		t.Errorf("an entrypoint that cannot be stat'd must be refused, not silently dropped")
	}
	if got, err := existing([]string{filepath.Join(dir, "absent"), file}); err != nil || len(got) != 1 {
		t.Errorf("existing must keep the paths that exist and skip the absent one; got %v, %v", got, err)
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
