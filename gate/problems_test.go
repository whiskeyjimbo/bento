package gate_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/gate"
)

// The gate's refusals, asserted against the gate rather than through the CLI that prints
// them. They were written where they were first read - beside validate's and the report's
// rendering, in package main - and moved here when the gate did: what they pin is that a
// manifest the gate passes is one a run does not refuse at its first step, which is the
// gate's property whether or not a CLI is in the picture.

// The gate's whole claim is that it does not pass a manifest run refuses at its first
// step, so the three shield refusals have to be predicted here in the sentences run
// raises them with - and only where run raises them. The pairs that look alike are what
// this pins: a read naming a shield exactly is the honored opt-in, the same path as a
// write is not; a read containing shields is an ordinary broad grant, a write containing
// one makes the shield's own name writable and is refused.
func TestShieldedGrantProblemsMirrorTheRunsRefusals(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	inHome := func(name string) string { return filepath.Join(home, name) }

	reads := map[string]struct {
		grant string
		want  string
	}{
		"the shield itself is the opt-in": {inHome(".ssh"), ""},
		"a path inside a shield":          {inHome(".ssh/id_rsa"), "is inside the always-shielded path"},
		"a grant containing the shields":  {home, ""},
		"a grant nowhere near a shield":   {"/srv/app", ""},
	}
	for name, tc := range reads {
		t.Run("read: "+name, func(t *testing.T) {
			got, err := gate.ShieldedReadProblems([]string{tc.grant})
			if err != nil {
				t.Fatalf("gate.ShieldedReadProblems: %v", err)
			}
			assertProblem(t, got, tc.want)
		})
	}

	writes := map[string]struct {
		grant string
		want  string
	}{
		"the shield itself, which no write opts into": {inHome(".ssh"), "no opt-in for a write"},
		"a path inside a shield":                      {inHome(".ssh/sub"), "is inside the always-shielded path"},
		"a write-shielded startup file":               {inHome(".bashrc"), "is at or inside the write-shielded path"},
		"a grant containing a shield":                 {home, "contains the always-shielded path"},
		"a grant nowhere near a shield":               {"/srv/app", ""},
	}
	for name, tc := range writes {
		t.Run("write: "+name, func(t *testing.T) {
			got, err := gate.ShieldedWriteProblems([]string{tc.grant})
			if err != nil {
				t.Fatalf("gate.ShieldedWriteProblems: %v", err)
			}
			assertProblem(t, got, tc.want)
		})
	}
}

func assertProblem(t *testing.T, got []string, want string) {
	t.Helper()
	if want == "" {
		if len(got) != 0 {
			t.Errorf("a grant the run honors must be reported as no problem; got %v", got)
		}
		return
	}
	if len(got) != 1 || !strings.Contains(got[0], want) {
		t.Errorf("problems = %v, want one containing %q", got, want)
	}
}

// The backend runs its shield checks on grants it has already made symlink-free, so the
// gate has to compare where a grant lands rather than how it is spelled. Both directions
// are the same defect with the sides swapped: a link out of a shield refused here would
// have the gate rejecting what run accepts, and a link into one honored here would put
// the refusal back at run's first step.
func TestShieldedGrantProblemsFollowTheGrantsSymlinks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "backups")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	escaping := filepath.Join(sshDir, "backup")
	if err := os.Symlink(outside, escaping); err != nil {
		t.Fatal(err)
	}
	entering := filepath.Join(t.TempDir(), "keys")
	if err := os.Symlink(sshDir, entering); err != nil {
		t.Fatal(err)
	}

	got, err := gate.ShieldedWriteProblems([]string{escaping})
	if err != nil {
		t.Fatalf("gate.ShieldedWriteProblems: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("a grant whose link leaves the shield is honored by the run; got %v", got)
	}
	got, err = gate.ShieldedWriteProblems([]string{entering})
	if err != nil {
		t.Fatalf("gate.ShieldedWriteProblems: %v", err)
	}
	assertProblem(t, got, "is inside the always-shielded path")
}

// The refusals the gate used to pass over in silence: a whole pseudo-filesystem, a host
// process directory, and the host root. Each one dies at run's first step, so a manifest
// carrying one is a manifest the CI gate green-lit and the run refuses.
func TestMountAndRootGrantProblems(t *testing.T) {
	// The refusals are about Linux's own pseudo-filesystems; this package builds and tests
	// everywhere, and elsewhere /tmp is a symlink and there is no procfs to grant.
	if runtime.GOOS != "linux" {
		t.Skip("the managed mounts and /proc/<pid> are Linux facts")
	}
	self := "/proc/" + strconv.Itoa(os.Getpid())
	cases := map[string]struct {
		read, write []string
		want        string
	}{
		"a whole tmpfs":               {read: []string{"/tmp"}, want: "a pseudo-filesystem the sandbox mounts fresh"},
		"a whole procfs":              {read: []string{"/proc"}, want: "a pseudo-filesystem the sandbox mounts fresh"},
		"a whole devtmpfs, for write": {write: []string{"/dev"}, want: "a pseudo-filesystem the sandbox mounts fresh"},
		"a running host process":      {read: []string{self}, want: "a host process's directory in /proc"},
		"a path inside a managed one": {read: []string{"/tmp/work"}, want: ""},
		"a system-wide procfs file":   {read: []string{"/proc/cpuinfo"}, want: ""},
		"a pid that is not running":   {read: []string{"/proc/4294967290"}, want: ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assertProblem(t, gate.MountGrantProblems(tc.read, tc.write), tc.want)
		})
	}

	t.Run("the host root, for write", func(t *testing.T) {
		assertProblem(t, gate.RootWriteProblems([]string{"/"}), "would make the entire host root writable")
	})
	t.Run("a symlink into the host root", func(t *testing.T) {
		// The backend refuses this: it checks grants it has already made symlink-free, so
		// testing the spelling alone here would pass a manifest run kills at its first step.
		link := filepath.Join(t.TempDir(), "everything")
		if err := os.Symlink("/", link); err != nil {
			t.Fatal(err)
		}
		assertProblem(t, gate.RootWriteProblems([]string{link}), "would make the entire host root writable")
	})
	t.Run("a directory that is not the host root", func(t *testing.T) {
		assertProblem(t, gate.RootWriteProblems([]string{"/srv/app"}), "")
	})
}
