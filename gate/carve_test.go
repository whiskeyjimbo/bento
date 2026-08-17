package gate_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/gate"
	"github.com/whiskeyjimbo/bento/policy"
)

// A write grant on a directory this uid cannot create entries in is refused by the run at
// its first step: bwrap cannot make the mount points for the shields the grant exposes and
// dies during setup, and the launcher then reports only an unattested silent stage, whose
// sentence blames a placement API the manifest author has no relationship with. So the gate
// has to reach the same verdict here, or validate and approve both stamp a manifest that
// cannot start.
//
// The grant is on ~/.config/go, whose one shield (the go env file) is DenyWrite: a write grant ABOVE a
// DenyAll shield is already refused by writeShieldProblem, so a DenyWrite mount point is
// where this refusal is the only one that fires and the manifest otherwise passes clean.
//
// Driven through Refusals rather than ShieldCarveProblems directly, because the point is
// that the refusal reaches the readers of the whole set - a validate verdict, a refusal to
// stamp an approval, an embedder's preflight - and a check wired into only the exported
// helper reaches none of them.
func TestAWriteGrantThatCannotCarveItsShieldsIsRefused(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root creates entries in any directory, so no host directory refuses the carve")
	}
	home := t.TempDir()
	grant := filepath.Join(home, ".config", "go")
	if err := os.MkdirAll(grant, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	p := &policy.Policy{Write: []string{grant}}

	if refusals := gate.Refusals(p); len(refusals) != 0 {
		t.Fatalf("a grant whose shields can be carved was refused: %v", refusals)
	}

	// Read-execute only: the mount points' parent is now a directory this uid cannot
	// mkdir in, which is what a system tree such as /etc is on a real host and what this
	// test cannot otherwise construct without being root.
	if err := os.Chmod(grant, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(grant, 0o755) })

	refusals := gate.Refusals(p)
	var carve []string
	for _, r := range refusals {
		if strings.Contains(r, "and creating that mount point needs write permission on") {
			carve = append(carve, r)
		}
	}
	if len(carve) == 0 {
		t.Fatalf("no carve refusal for a write grant whose shield mount points cannot be created; the run refuses this manifest at its first step while validate stamps it. Got: %v", refusals)
	}
	if !strings.Contains(carve[0], grant) {
		t.Errorf("the refusal does not quote the grant the author wrote: %s", carve[0])
	}
}
