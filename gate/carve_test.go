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

	if refusals := gate.Refusals(hostShieldSet(t), nil, p).Grants; len(refusals) != 0 {
		t.Fatalf("a grant whose shields can be carved was refused: %v", refusals)
	}

	// Read-execute only: the mount points' parent is now a directory this uid cannot
	// mkdir in, which is what a system tree such as /etc is on a real host and what this
	// test cannot otherwise construct without being root.
	if err := os.Chmod(grant, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(grant, 0o755) })

	refusals := gate.Refusals(hostShieldSet(t), nil, p).Grants
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

// The carve refusal is answered over the built-in shields only, and a run's shield set also
// holds what internal/linux derives from the checkout under each write grant that is a
// directory (shieldRules appends workspaceShields). The gate cannot reach that half, so the
// one thing it must not do is answer as though it had: a grant whose only uncarvable mount
// point is a git hook directory is refused at the run's first step while Refusals is empty.
//
// The negative arm is the load-bearing one. shieldRules skips a write grant that is not a
// directory, so such a manifest derives no shields and the carve answer is whole - an
// unknown raised there would be a constant rather than a report.
func TestTheDerivedHalfOfTheCarveCheckIsReportedUnknown(t *testing.T) {
	checkout := t.TempDir()
	entrypoint := filepath.Join(checkout, "run.sh")
	if err := os.WriteFile(entrypoint, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	derived := gate.Check(&policy.Policy{Entrypoint: entrypoint, Write: []string{checkout}})
	if !derived.ShieldCarveUnknown {
		t.Errorf("a write grant on a directory derives workspace shields the gate never sees, "+
			"and the carve verdict came back as though it had judged them: %+v", derived)
	}

	// A write grant naming a host file, and one naming nothing at all: neither is a
	// checkout, so the run derives no shields from either and there is nothing unknown.
	for _, w := range []string{entrypoint, filepath.Join(checkout, "absent")} {
		whole := gate.Check(&policy.Policy{Entrypoint: entrypoint, Write: []string{w}})
		if whole.ShieldCarveUnknown {
			t.Errorf("write grant %q derives no workspace shields, so the carve answer is whole "+
				"and must not be marked unknown", w)
		}
	}
}

// The carve check stats a mount point only where a write grant reaches it: reachability is
// pure, and on a real host almost no rule is reached by any one grant, so statting first
// paid a syscall per rule - ~545 per call on validate's path - to answer nothing. A stat
// allocates, so a check that stats every rule allocates at least once per rule.
func TestShieldCarveProblemsStatsOnlyReachedMountPoints(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	set := hostShieldSet(t)
	mounts := len(set.Mount(set.Rules()))
	if mounts < 100 {
		t.Fatalf("only %d mount points: too few for the per-rule cost to stand out from the fixed one", mounts)
	}
	// A sibling of the home, so no rule sits under the grant or above it.
	writes := []string{t.TempDir()}

	allocs := testing.AllocsPerRun(10, func() { gate.ShieldCarveProblems(set, nil, writes) })
	if allocs >= float64(mounts) {
		t.Errorf("ShieldCarveProblems allocated %v times over %d mount points no grant reaches; it is paying a stat per rule before asking whether any grant reaches it", allocs, mounts)
	}
}
