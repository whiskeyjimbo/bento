package main

import (
	"os"
	"path/filepath"
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
