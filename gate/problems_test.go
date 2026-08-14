package gate_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/gate"
	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/shield"
)

// hostShieldSet is the set the gate builds for the run being validated, off the $HOME the
// case relocated. Asked per assertion rather than once per test, because a case that moves
// HOME after it must get the new one - which is what ShieldSet walking fresh gives it.
func hostShieldSet(t *testing.T) shield.Set {
	t.Helper()
	set, err := gate.ShieldSet()
	if err != nil {
		t.Fatalf("gate.ShieldSet: %v", err)
	}
	return set
}

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
			assertProblem(t, gate.ShieldedReadProblems(hostShieldSet(t), []string{tc.grant}), tc.want)
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
			assertProblem(t, gate.ShieldedWriteProblems(hostShieldSet(t), []string{tc.grant}), tc.want)
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

	if got := gate.ShieldedWriteProblems(hostShieldSet(t), []string{escaping}); len(got) != 0 {
		t.Errorf("a grant whose link leaves the shield is honored by the run; got %v", got)
	}
	assertProblem(t, gate.ShieldedWriteProblems(hostShieldSet(t), []string{entering}), "is inside the always-shielded path")
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

// A write grant the invoking user cannot stat refuses the run - prepareWriteDirs' default
// arm - so the gate has to name it. The narrowing that makes an unstattable READ silence
// here does not carry: the sandbox binds a read tree as another user's view, while the
// write grant is statted by the invoker before any sandbox exists.
func TestAnUnstattableWriteGrantIsReported(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root traverses a directory with no permissions, so the grant stats fine")
	}
	parent := filepath.Join(t.TempDir(), "closed")
	grant := filepath.Join(parent, "out")
	if err := os.MkdirAll(grant, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })

	assertProblem(t, gate.FileWriteGrantProblems([]string{grant}), "cannot be checked on this host")
}

// A caller-denied read has to be refused in its own sentence: the InsideShield wording
// offers the read opt-in, and an embedder's deny has none, so one sentence for every
// non-Honored verdict points this grant at an escape that does not exist for it.
// Unreachable through ShieldSet, which assembles with nil caller denies, so the set is
// built directly with one.
func TestACallerDeniedReadIsNotOfferedTheBuiltInOptIn(t *testing.T) {
	home := t.TempDir()
	denied := filepath.Join(home, "vault")
	set := shield.Assemble(shield.Host(), []string{home}, denylist.RuntimeDir(),
		[]denylist.Rule{{Path: denied, Deny: denylist.DenyAll, Dir: true}})

	problems := gate.ShieldedReadProblems(set, []string{filepath.Join(denied, "key")})
	if len(problems) != 1 {
		t.Fatalf("a read inside a caller-supplied deny must be refused; got %v", problems)
	}
	if !strings.Contains(problems[0], "the program running bento shields") {
		t.Errorf("refusal must name the embedder's shield, not the built-in opt-in; got %q", problems[0])
	}
}

// A write inside a caller's deny is refused for the reason the read is, and the backend
// words it the same way for both kinds (checkNotShielded's InsideCallerShield arm is
// unconditional on kind). The built-in write sentence calls the path "always-shielded"
// and explains the missing opt-in as the credential plant, and neither is true of an
// embedder's deny - whose reason is a trust domain the manifest cannot argue with.
func TestACallerDeniedWriteIsRefusedInTheCallersWords(t *testing.T) {
	home := t.TempDir()
	denied := filepath.Join(home, "vault")
	set := shield.Assemble(shield.Host(), []string{home}, denylist.RuntimeDir(),
		[]denylist.Rule{{Path: denied, Deny: denylist.DenyAll, Dir: true}})

	problems := gate.ShieldedWriteProblems(set, []string{filepath.Join(denied, "keys")})
	if len(problems) != 1 {
		t.Fatalf("a write inside a caller-supplied deny must be refused; got %v", problems)
	}
	if !strings.Contains(problems[0], "the program running bento shields") {
		t.Errorf("refusal must name the embedder's shield rather than a built-in; got %q", problems[0])
	}
}

// The shield mirrors skip a write of "/" so RootWriteProblems can refuse it in a sentence
// naming the whole filesystem, and the backend makes that skip on grants resolveGrants has
// already made symlink-free. Asked of the spelling alone, a link into the root reaches
// Contains and comes back AboveShield - a true sentence about whichever dotfile sorts
// first, printed ahead of the one about the grant that hands over the filesystem.
func TestASymlinkedRootWriteIsLeftToTheRootRefusal(t *testing.T) {
	link := filepath.Join(t.TempDir(), "everything")
	if err := os.Symlink("/", link); err != nil {
		t.Fatal(err)
	}
	assertProblem(t, gate.ShieldedWriteProblems(hostShieldSet(t), []string{link}), "")
}

// filepath.Clean pops ".." lexically, over a symlink; the backend resolves the grant
// physically and lands somewhere else entirely. The gate refusing on the lexical answer is
// the one direction this package rules out - a refusal the run does not make - so the
// managed-mount and root checkers ask where the grant lands, not how it is spelled. The
// link has to sit directly under /tmp: only a landing inside denylist.ManagedMounts
// reaches the refusal at all, which is what the second half asserts still fires.
func TestMountGrantProblemsResolveDotDotPhysically(t *testing.T) {
	target := filepath.Join(t.TempDir(), "work")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join("/tmp", "bento-gate-"+strconv.Itoa(os.Getpid()))
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(link) })

	// Not filepath.Join, which cleans the ".." away before the gate ever sees it.
	escaping := link + "/.."
	if got := gate.MountGrantProblems(nil, []string{escaping}); len(got) != 0 {
		t.Errorf("%q lands on %q for the run, which honors it; got %v", escaping, filepath.Dir(target), got)
	}
	assertProblem(t, gate.MountGrantProblems([]string{"/tmp"}, nil), "mounts fresh")

	// RootWriteProblems asks the same question of the same spelling, and a lexical answer
	// splits it both ways: this grant lands on the host root for the run - "/" is its own
	// parent - and Clean pops it to the link's own directory instead, passing the one
	// grant that defeats the sandbox outright.
	toRoot := filepath.Join("/tmp", "bento-root-"+strconv.Itoa(os.Getpid()))
	if err := os.Symlink("/", toRoot); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(toRoot) })
	assertProblem(t, gate.RootWriteProblems([]string{toRoot + "/.."}), "entire host root")
	if got := gate.RootWriteProblems([]string{escaping}); len(got) != 0 {
		t.Errorf("a write whose \"..\" lands inside a temp tree is not a grant of the host root; got %v", got)
	}
}
