//go:build linux

package linux

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/policy"
)

// Property fuzz for the WRITE-GRANT persistence class, the DenyWrite half the read-grant
// shield fuzz (FuzzShieldCoversReachableSecrets) deliberately leaves out. A write grant on
// a checkout must make every host code-execution surface it reaches - git hooks/config for
// the repo AND for each submodule gitdir and linked worktree, plus the fail-closed subtree
// under an unreadable directory - appear in argv as a NON-writable mount (a DenyWrite
// ro-bind onto itself, or a tmpfs), so the target cannot plant a hook that runs on the host
// after the sandbox exits.
//
// The oracle is hide-vs-rebind INVERTED from the read fuzz: there "covered" meant the
// secret was HIDDEN; here "covered" means the surface is NOT WRITABLE, so a DenyWrite
// ro-bind of a path onto itself (still readable, which git needs) counts. shieldDests with
// hidingOnly=false collects exactly those (every --ro-bind/--tmpfs destination), and
// coveredBy is ancestor-aware so the fail-closed whole-subtree ro-bind covers a config
// hidden beneath an unreadable dir.
//
// The ground truth is recorded at PLANT time, not re-derived from gitDirShields, so the
// oracle cannot go tautological against the emitter it checks: the fuzzer knows it wrote a
// config file at .git/modules/X, therefore it expects config and hooks there shielded. The
// walk runs on the REAL filesystem via the host* seams (the fake testSandbox cannot model
// an unreadable-but-traversable directory - its listDir always succeeds), mirroring the
// existing TestGitDirShields* real-FS tests.

// persistenceSurface is one discovery-dimension repo shape the fuzzer may plant under the
// grant. plant creates its real files and returns the paths that MUST end up non-writable;
// the top-level Workspace shields (.git/hooks, .git/config, .vscode, .idea) are static -
// shielded whether present or absent - so they are not part of the masked menu.
type persistenceSurface struct {
	name  string
	plant func(t *testing.T, root string) []string
}

// mkGitdir writes a config FILE (what identifies a gitdir) and a hooks/ directory at gd,
// and returns the two paths that must be shielded. A regular file placed in hooks/ makes
// it a real directory the fake-FS gotcha cannot flip to a file - though on real FS an
// os.MkdirAll already suffices, it keeps the shape explicit.
func mkGitdir(t *testing.T, gd string) []string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(gd, "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gd, "config"), []byte("[core]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return []string{filepath.Join(gd, "config"), filepath.Join(gd, "hooks")}
}

var persistenceSurfaces = []persistenceSurface{
	{"submodule", func(t *testing.T, root string) []string {
		return mkGitdir(t, filepath.Join(root, ".git", "modules", "sub"))
	}},
	{"nested-submodule", func(t *testing.T, root string) []string {
		return mkGitdir(t, filepath.Join(root, ".git", "modules", "sub", "modules", "deep"))
	}},
	{"store-name-submodule", func(t *testing.T, root string) []string {
		// A submodule whose path segment collides with a git store name (logs/): the walk
		// is unconditional, so it must still be shielded where a name-based prune would skip it.
		return mkGitdir(t, filepath.Join(root, ".git", "modules", "logs", "mylib"))
	}},
	{"worktree-config", func(t *testing.T, root string) []string {
		wt := filepath.Join(root, ".git", "worktrees", "wt")
		if err := os.MkdirAll(wt, 0o755); err != nil {
			t.Fatal(err)
		}
		cw := filepath.Join(wt, "config.worktree")
		if err := os.WriteFile(cw, []byte("[core]\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return []string{cw}
	}},
	{"submodule-worktree-config", func(t *testing.T, root string) []string {
		// A linked worktree of a submodule keeps its own config.worktree, shielded only once
		// the submodule's own config identifies its gitdir - so plant that config too.
		sub := filepath.Join(root, ".git", "modules", "sub")
		expect := mkGitdir(t, sub)
		w := filepath.Join(sub, "worktrees", "w")
		if err := os.MkdirAll(w, 0o755); err != nil {
			t.Fatal(err)
		}
		cw := filepath.Join(w, "config.worktree")
		if err := os.WriteFile(cw, []byte("[core]\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return append(expect, cw)
	}},
	{"unreadable-subtree", func(t *testing.T, root string) []string {
		// A prior run can chmod a real directory 0111: traversable by name (host git still
		// reaches gitdirs inside), unreadable to the scan. The whole subtree must be shielded
		// read-only, covering a config planted beneath it that the scan cannot see.
		modules := filepath.Join(root, ".git", "modules")
		blind := filepath.Join(modules, "blind")
		if err := os.MkdirAll(filepath.Join(blind, "hooks"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(blind, "config"), []byte("[core]\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(blind, 0o111); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(blind, 0o755) }) // let t.TempDir cleanup recurse
		if _, err := os.ReadDir(blind); err == nil {
			t.Skip("filesystem did not enforce the unreadable mode")
		}
		// The scan fails closed by shielding the unreadable dir itself; the hidden config is
		// covered by that ancestor ro-bind.
		return []string{blind}
	}},
}

// persistenceSandbox builds a real-FS sandbox rooted at a checkout dir, the same host-seam
// construction the TestGitDirShields* tests use.
func persistenceSandbox(root string) sandbox {
	return sandbox{
		homes:     []string{"/home/u"}, // unrelated to the temp grant, so no home shield sits above it
		emptyFile: filepath.Join(root, ".shield-empty"),
		exists:    hostExists,
		isDir:     hostIsDir,
		listDir:   hostListDir,
		resolve:   hostResolve,
		statID:    hostStatIDOK,
	}
}

// checkPersistenceShielded plants every surface selected by mask under a fresh checkout,
// runs the full grant-admission sequence (which must accept - the grant is a plain temp dir
// with no symlink components and no home shield above it), compiles the deny args, and
// asserts every planted execution surface is non-writable. Shared by the fuzz and the
// exhaustive test.
func checkPersistenceShielded(t *testing.T, mask int) {
	root := canonTempDir(t)
	// A real checkout so the grant is a directory that earns its Workspace + gitDir shields.
	if err := os.MkdirAll(filepath.Join(root, ".git", "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".git", "config"), []byte("[core]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var expected []string
	for i, s := range persistenceSurfaces {
		if mask&(1<<i) == 0 {
			continue
		}
		if s.name == "unreadable-subtree" && os.Geteuid() == 0 {
			continue // root bypasses the unreadable mode, so the fail-closed path cannot be posed
		}
		expected = append(expected, s.plant(t, root)...)
	}
	// The static top-level Workspace surfaces are shielded on every checkout, present or not
	// (an absent one is tmpfs'd so it cannot be planted).
	expected = append(
		expected,
		filepath.Join(root, ".git", "hooks"),
		filepath.Join(root, ".git", "config"),
		filepath.Join(root, ".vscode"),
		filepath.Join(root, ".idea"),
	)

	sb := persistenceSandbox(root)
	writes := []string{root}
	p := &policy.Policy{Entrypoint: filepath.Join(root, "run.sh"), Write: writes}

	if err := checkGrants(sb, p, nil, writes); err != nil {
		t.Fatalf("mask %d: a plain temp-dir write grant must be accepted, got: %v", mask, err)
	}

	args, _ := denyArgs(sb, exposedPaths(sb, nil, writes), writes, nil)
	dests := shieldDests(args, sb.emptyFile, false)
	for _, path := range expected {
		if !coveredBy(path, dests) {
			t.Fatalf("mask %d: execution surface %q left writable (not covered by a shield); shield dests=%v", mask, path, dests)
		}
	}
}

func FuzzPersistenceShieldsCoverReachableSurfaces(f *testing.F) {
	f.Add(0)                               // bare checkout: only the static Workspace shields
	f.Add(1)                               // one submodule
	f.Add(1 << 5)                          // the unreadable-subtree fail-closed path
	f.Add(1<<len(persistenceSurfaces) - 1) // every surface at once
	f.Add(1<<1 | 1<<3)                     // nested submodule + a worktree config
	f.Fuzz(func(t *testing.T, mask int) {
		checkPersistenceShielded(t, ((mask%(1<<len(persistenceSurfaces)))+(1<<len(persistenceSurfaces)))%(1<<len(persistenceSurfaces)))
	})
}

// TestPersistenceShieldsExhaustive enumerates every subset of the discovery-dimension
// surfaces - the menu is small enough that coverage is guaranteed rather than left to the
// fuzz corpus, matching TestShieldInvariantsExhaustive.
func TestPersistenceShieldsExhaustive(t *testing.T) {
	for mask := 0; mask < 1<<len(persistenceSurfaces); mask++ {
		t.Run(fmt.Sprintf("mask%d", mask), func(t *testing.T) {
			checkPersistenceShielded(t, mask)
		})
	}
}

// The workspace shields must anchor at the CHECKOUT, not at whatever the policy spelled.
// Anchored at the grant, "write: <repo>/.git" put them at <repo>/.git/.git/hooks and left
// the real hooks dir under a writable bind with no rule, so a planted pre-commit ran on
// the host at the developer's next commit. checkPersistenceShielded hard-codes
// writes := []string{root}, so no fuzz case varies the grant's depth.
func TestWorkspaceShieldsAnchorAtTheCheckoutNotTheGrant(t *testing.T) {
	root := canonTempDir(t)
	gitDir := filepath.Join(root, ".git")
	if err := os.MkdirAll(filepath.Join(gitDir, "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "config"), []byte("[core]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	sb := persistenceSandbox(root)
	writes := []string{gitDir}
	p := &policy.Policy{Entrypoint: filepath.Join(root, "run.sh"), Write: writes}
	if err := checkGrants(sb, p, nil, writes); err != nil {
		t.Fatalf("a write grant of the gitdir itself must be admitted: %v", err)
	}

	args, _ := denyArgs(sb, exposedPaths(sb, nil, writes), writes, nil)
	dests := shieldDests(args, sb.emptyFile, false)
	for _, surface := range []string{filepath.Join(gitDir, "hooks"), filepath.Join(gitDir, "config")} {
		if !coveredBy(surface, dests) {
			t.Errorf("%q left writable by a grant spelled one directory deeper; shield dests=%v", surface, dests)
		}
	}
}

// A second write grant at or inside a workspace shield the first grant derives was
// neither refused nor honored: the ro-bind lands after the grant's bind, so every write
// failed EROFS at runtime with the manifest reporting the grant as honored.
func TestWriteGrantInsideAWorkspaceShieldRefused(t *testing.T) {
	root := canonTempDir(t)
	hooks := filepath.Join(root, ".git", "hooks")
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		t.Fatal(err)
	}

	sb := persistenceSandbox(root)
	writes := []string{root, hooks}
	p := &policy.Policy{Entrypoint: filepath.Join(root, "run.sh"), Write: writes}
	if err := checkGrants(sb, p, nil, writes); err == nil {
		t.Error("a write grant of a shielded hooks dir must be refused, not silently neutered")
	}

	// The checkout grant on its own, which derives those shields, stays admitted.
	only := []string{root}
	if err := checkGrants(sb, &policy.Policy{Entrypoint: p.Entrypoint, Write: only}, nil, only); err != nil {
		t.Errorf("a plain checkout write grant must still be accepted: %v", err)
	}
}

// The shield derivation must not depend on the grant already being a directory. Gated on
// isDir, a solo "write: <repo>/.git/hooks" naming a directory that does not exist yet was
// admitted at preflight, created by prepareWriteDirs, and only then refused on compile's
// second pass - with the artifact already on the host, which is exactly what preflight
// exists to prevent.
func TestWriteGrantInsideAWorkspaceShieldRefusedBeforeItExists(t *testing.T) {
	root := canonTempDir(t)
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	hooks := filepath.Join(root, ".git", "hooks") // absent

	sb := persistenceSandbox(root)
	writes := []string{hooks}
	p := &policy.Policy{Entrypoint: filepath.Join(root, "run.sh"), Write: writes}
	if err := checkGrants(sb, p, nil, writes); err == nil {
		t.Error("an absent shielded hooks dir must be refused before anything creates it")
	}
}

// Where a symlink redirects a workspace shield, the redirect refusal must win. It
// compares literal paths and names the symlink; checkWriteNotUnderReadOnlyShield compares
// resolved ones, so it fires on the target and tells the author to remove a grant that is
// not the problem - and removing it just re-refuses through the redirect check.
func TestRedirectedWorkspaceShieldRefusalWinsOverTheGrantRefusal(t *testing.T) {
	root := canonTempDir(t)
	if err := os.MkdirAll(filepath.Join(root, ".git", "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(out, filepath.Join(root, ".vscode")); err != nil {
		t.Skipf("cannot symlink on this filesystem: %v", err)
	}

	sb := persistenceSandbox(root)
	writes := []string{root, out}
	p := &policy.Policy{Entrypoint: filepath.Join(root, "run.sh"), Write: writes}
	err := checkGrants(sb, p, nil, writes)
	if err == nil {
		t.Fatal("a symlink redirecting a workspace shield must be refused")
	}
	if !strings.Contains(err.Error(), "symlinked directory component") {
		t.Errorf("the refusal must name the symlink, whose removal is the remedy that works; got %v", err)
	}
}
