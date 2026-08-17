package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/gate"
	"github.com/whiskeyjimbo/bento/policy"
)

// The one-sided invariant the clamp exists to hold: it may withhold a grant the run would
// honor, but it must never propose one the run refuses at its first step. gate.Refusals is
// the oracle - the same set `bento validate` and `bento approve` answer from - so the
// property is stated as "nothing gate.Refusals names survives clampProposal", per refusal
// family rather than per observed bug. A family that grows a new member in gate is covered
// here the moment it is added, which is the point of routing through the shipped oracle
// instead of restating its checks.
//
// AboveWriteShield is deliberately absent from gate.Refusals (gate.go's writeShieldProblem
// says why: only the degraded tier refuses it, and the gate does not know the tier), so the
// clamp's own aboveWriteShield flag channel is not in tension with this.
func TestClampProposalProposesNothingTheRunRefuses(t *testing.T) {
	dir := t.TempDir()

	loop := filepath.Join(dir, "loop")
	other := filepath.Join(dir, "other")
	if err := os.Symlink(other, loop); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := os.Symlink(loop, other); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	shmAlias := filepath.Join(dir, "shmalias")
	if err := os.Symlink("/dev/shm", shmAlias); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	ptsAlias := filepath.Join(dir, "ptsalias")
	if err := os.Symlink("/dev/pts", ptsAlias); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	file := filepath.Join(dir, "out.dat")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cases := []struct {
		family string
		read   []string
		write  []string
	}{
		{"Looped", []string{loop}, []string{filepath.Join(loop, "sub")}},
		{"GrantIsManagedMount", []string{shmAlias, ptsAlias}, nil},
		{"WriteIsFile", nil, []string{file}},
		{"WriteUnstattable", nil, []string{unstattableWriteGrant(t, dir)}},
	}
	for _, c := range cases {
		t.Run(c.family, func(t *testing.T) {
			if len(c.read) == 0 && len(c.write) == 0 {
				t.Skip("no grant of this family is constructible here")
			}
			p := &policy.Policy{Read: c.read, Write: c.write}
			clampProposal(p)
			if problems := gate.Refusals(p); len(problems) > 0 {
				t.Errorf("clampProposal proposed a grant run refuses (%s):\n  %s", c.family, strings.Join(problems, "\n  "))
			}
		})
	}
}

// unstattableWriteGrant returns a write grant under a directory this uid cannot traverse,
// or "" where none can be built. It is the same host fact `sudo bento profile` produces -
// the observer stats as the profiling user and the run stats as the invoker - staged with
// one uid instead of two, because FileWriteGrantProblems' unstattable arm fires on any
// stat error that is neither ENOENT nor ELOOP.
func unstattableWriteGrant(t *testing.T, dir string) string {
	t.Helper()
	if os.Geteuid() == 0 {
		return "" // root traverses regardless of the mode bits
	}
	closed := filepath.Join(dir, "closed")
	if err := os.Mkdir(closed, 0o000); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(closed, 0o700); err != nil {
			t.Errorf("chmod: %v", err) // else TempDir cleanup fails with a less readable error
		}
	})
	return filepath.Join(closed, "scratch")
}

// A withheld grant is reported, never silently dropped: a grant that vanishes with no
// message leaves the script failing at enforce time with nothing to read - and under
// converge, mid-session with the round's work spent.
func TestARunRefusedGrantIsReportedNotSilentlyDropped(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "out.dat")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	p := &policy.Policy{Write: []string{file}}
	_, _, _, _, _, refused := clampProposal(p)

	if len(refused) != 1 || refused[0].Path != file {
		t.Fatalf("the file write must be reported as run-refused, got %+v", refused)
	}
	if refused[0].Kind != "write" || refused[0].Problem == "" {
		t.Errorf("the report must carry the kind and the run's own sentence, got %+v", refused[0])
	}
}

// The clamp order is load-bearing in a third place. DropCovered removes a read a write
// already covers, and it has no report channel - so a withhold that runs after it takes
// the read with the write, silently. The read is what the script actually did, and the
// write it hid under is the one being withheld: leaving it out is the same failure
// TestClampProposalDedupsReadsOnlyAfterDroppingBroadWrites pins for the broad clamp, one
// clamp later. That test uses a broad write and so cannot see this one.
func TestAReadUnderARunRefusedWriteSurvivesTheDedup(t *testing.T) {
	dir := t.TempDir()
	// A write grant that is a file, which converge reaches by ordinary sequence: one round
	// collapses a file write to its parent, and the parent is a file by the next round.
	file := filepath.Join(dir, "sub")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	read := filepath.Join(file, "config")

	p := &policy.Policy{Read: []string{read}, Write: []string{file}}
	_, _, _, _, _, refused := clampProposal(p)

	if len(refused) != 1 || refused[0].Path != file {
		t.Fatalf("the file write must be withheld as run-refused, got %+v", refused)
	}
	if !slices.Contains(p.Read, read) {
		t.Errorf("the read under the withheld write must survive - nothing else reports it; Read=%v", p.Read)
	}
}

// The fifth family, kept apart from the table above because it needs its own $HOME: the
// shields anchor there, and a grant whose shield mount points cannot be carved has to be
// staged under an anchor this test controls. The clamp inherits the refusal through
// withholdRunRefused's gate.Refusals call rather than knowing anything about it, which is
// exactly what this asserts - the routing, not a restatement of the check.
func TestClampProposalWithholdsAGrantWhoseShieldsCannotBeCarved(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root creates entries in any directory, so no host directory refuses the carve")
	}
	home := t.TempDir()
	// A DenyWrite shield (the go env file) rather than a DenyAll one: a grant above a
	// DenyAll shield is already withheld by the clamp's own above-shield reasoning, so a
	// DenyWrite mount point is where the carve refusal is the only thing that withholds it.
	grant := filepath.Join(home, ".config", "go")
	if err := os.MkdirAll(grant, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	if err := os.Chmod(grant, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(grant, 0o755) })

	p := &policy.Policy{Write: []string{grant}}
	clampProposal(p)
	if problems := gate.Refusals(p); len(problems) > 0 {
		t.Errorf("clampProposal proposed a grant run refuses (ShieldNotCarvable):\n  %s", strings.Join(problems, "\n  "))
	}
	// Stated positively as well, because the check above shares its oracle with the clamp:
	// a refusal missing from gate.Refusals passes it while the proposal still dies at the
	// run's first step. This one fails in that case.
	if slices.Contains(p.Write, grant) {
		t.Errorf("the proposal kept %q, whose shield mount points this uid cannot create; the run refuses it at its first step", grant)
	}
}
