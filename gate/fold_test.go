package gate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/shield"
)

// Both halves of the gate have to carry the case-folding refusal, and the write half is
// the one that can lose it: it enumerates the verdicts it knows and reports no problem
// for any other, so a verdict added to shield without a case here turns into silence -
// the gate passing a manifest the run refuses, which is the one thing the gate exists to
// prevent. Asked of writeShieldProblem directly because ShieldSet builds shield.Host()
// and a folding mount cannot be staged on the test host's own filesystem.
func TestBothHalvesOfTheGateCarryTheFoldingRefusal(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	fs := shield.Host()
	fs.SameFile = func(a, b string) bool { return strings.EqualFold(a, b) }
	set := shield.Assemble(fs, []string{home}, denylist.RuntimeDir(), nil)

	problem, ok := writeShieldProblem(set, home)
	if !ok {
		t.Fatal("a write grant containing a shield on a folding mount is refused by the run; the gate reported no problem")
	}
	if !strings.Contains(problem, "case-insensitive") {
		t.Errorf("the gate must refuse it in the run's words; got %q", problem)
	}
}
