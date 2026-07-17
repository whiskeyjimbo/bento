package linux

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whiskeyjimbo/bento-v2/internal/denylist"
	"github.com/whiskeyjimbo/bento-v2/enforce"
	"github.com/whiskeyjimbo/bento-v2/policy"
)

// testSandbox compiles argv against a hypothetical filesystem, so the
// security-critical argv decisions can be asserted without launching anything.
func testSandbox(existing ...string) sandbox {
	set := make(map[string]bool, len(existing))
	for _, p := range existing {
		set[p] = true
	}
	return sandbox{
		home:       "/home/u",
		emptyFile:  "/tmp/shield",
		entrypoint: "/work/run.py",
		exists:     func(p string) bool { return set[p] },
		// A path is a directory if the fake filesystem has an entry strictly under
		// it; a leaf entry is a file. This lets a write grant that is a project
		// directory get its workspace shields while a plain-file grant does not.
		isDir: func(p string) bool {
			for e := range set {
				if e != p && under(e, p) {
					return true
				}
			}
			return false
		},
		rootDirs: func() []string { return []string{"/usr", "/home", "/etc"} },
		// The hypothetical filesystem has no symlinks, so shields bind in place.
		resolve: func(p string) string { return p },
		// listDir returns the immediate SUBDIRECTORY names of p implied by the fake
		// entries (a segment with something under it), matching hostListDir which
		// excludes files and symlinks. ok is true when p is a directory (has any entry
		// under it); the fake has no unreadable directories. A bare leaf entry directly
		// under p is a file.
		listDir: func(p string) ([]string, bool) {
			prefix := p + "/"
			seen := map[string]bool{}
			var names []string
			isDir := false
			for e := range set {
				if !strings.HasPrefix(e, prefix) {
					continue
				}
				isDir = true
				rest := e[len(prefix):]
				i := strings.IndexByte(rest, '/')
				if i < 0 {
					continue // a leaf directly under p is a file, not a subdirectory
				}
				if name := rest[:i]; !seen[name] {
					seen[name] = true
					names = append(names, name)
				}
			}
			return names, isDir
		},
	}
}

// resolve must stay kernel-accurate when a relative symlink target has to
// traverse a parent that is itself a symlink: a lexical join against the
// unresolved path would land on the wrong sibling, leaving the real credential
// target unshielded and un-caught by checkNotShielded.
func TestResolveFollowsRelativeDanglingLeafThroughSymlinkedParent(t *testing.T) {
	base := t.TempDir()
	canon, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(canon, "data", "cfg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(canon, "home"), 0o755); err != nil {
		t.Fatal(err)
	}
	// home/.config -> data/cfg (real); data/cfg/gh -> ../secrets/gh (dangling).
	if err := os.Symlink(filepath.Join(canon, "data", "cfg"), filepath.Join(canon, "home", ".config")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../secrets/gh", filepath.Join(canon, "data", "cfg", "gh")); err != nil {
		t.Fatal(err)
	}

	got, err := resolve(filepath.Join(canon, "home", ".config", "gh"))
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(canon, "data", "secrets", "gh")
	if got != want {
		t.Errorf("resolve = %q, want %q (relative dangling leaf through a symlinked parent)", got, want)
	}
}

// resolve must follow a multi-hop symlink chain whose final link is dangling, not
// stop at the first hop (which would leave the shield on an intermediate symlink,
// aborting the run).
func TestResolveFollowsMultiHopDanglingChain(t *testing.T) {
	base := t.TempDir()
	canon, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	a, b, c := filepath.Join(canon, "a"), filepath.Join(canon, "b"), filepath.Join(canon, "c")
	if err := os.Symlink(c, b); err != nil { // b -> c (c missing)
		t.Fatal(err)
	}
	if err := os.Symlink(b, a); err != nil { // a -> b
		t.Fatal(err)
	}

	got, err := resolve(a)
	if err != nil {
		t.Fatal(err)
	}
	if got != c {
		t.Errorf("resolve(a) = %q, want %q (chain followed to the final dangling target)", got, c)
	}
}

// A ".." in a dangling symlink's target must be applied only AFTER the symlink
// component before it is followed - not cleaned away lexically, which would land
// the shield on the wrong path and leave the real target unshielded.
func TestResolveFollowsSymlinkBeforeDotDotInDanglingTarget(t *testing.T) {
	base := t.TempDir()
	canon, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(canon, "elsewhere"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(canon, "home"), 0o755); err != nil {
		t.Fatal(err)
	}
	// home/linkdir -> elsewhere (real); home/.bad -> linkdir/../planted (dangling).
	// A write through .bad resolves linkdir to <canon>/elsewhere, then ".." to
	// <canon>, then "planted": target is <canon>/planted, NOT <canon>/home/planted.
	if err := os.Symlink(filepath.Join(canon, "elsewhere"), filepath.Join(canon, "home", "linkdir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("linkdir/../planted", filepath.Join(canon, "home", ".bad")); err != nil {
		t.Fatal(err)
	}

	got, err := resolve(filepath.Join(canon, "home", ".bad"))
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(canon, "planted")
	if got != want {
		t.Errorf("resolve = %q, want %q (\"..\" applied after the symlink is followed)", got, want)
	}
}

func compileOrFail(t *testing.T, p *policy.Policy, sb sandbox) []string {
	t.Helper()
	args, err := compile(p, enforce.Process{}, sb)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return args
}

// pairIndex returns the index of the first occurrence of `flag target` in args.
func pairIndex(args []string, flag, target string) int {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == target {
			return i
		}
	}
	return -1
}

func has(args []string, flag, target string) bool { return pairIndex(args, flag, target) >= 0 }

// The post-run cleanup targets only DIRECTORY shield mount points: os.Remove on a
// directory is empty-only (rmdir), so it can never delete host data, whereas an
// os.Remove of a FILE is unconditional and would race a host-side atomic save over
// that path. So file shields must never be scheduled for removal.
func TestCreatedShieldDirsExcludesFileShields(t *testing.T) {
	sb := testSandbox("/home/u/proj/src") // an entry under proj makes it a workspace dir
	grants := []string{"/home/u/proj"}
	dirs := createdShieldDirs(sb, grants, grants)

	if !containsStr(dirs, "/home/u/proj/.git/hooks") {
		t.Errorf("the .git/hooks directory shield should be scheduled for cleanup; got %v", dirs)
	}
	for _, f := range []string{"/home/u/proj/.git/config", "/home/u/proj/.vscode/tasks.json"} {
		if containsStr(dirs, f) {
			t.Errorf("file shield %s must not be scheduled for cleanup (os.Remove would delete a real file)", f)
		}
	}
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func TestNoNetworkRulesUnsharesNetwork(t *testing.T) {
	args := compileOrFail(t, &policy.Policy{Entrypoint: "/work/run.py"}, testSandbox())
	found := false
	for _, a := range args {
		if a == "--unshare-net" {
			found = true
		}
	}
	if !found {
		t.Error("a policy with no network rules must unshare the network namespace")
	}
}

func TestGrantsAreBound(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/data"}, Write: []string{"/out"}}
	args := compileOrFail(t, p, testSandbox())

	if !has(args, "--ro-bind-try", "/data") {
		t.Error("read grant not bound read-only")
	}
	if !has(args, "--bind-try", "/out") {
		t.Error("write grant not bound")
	}
}

// The deny-list must be applied after the policy's own grants, because bwrap
// resolves mounts in argv order and the last one wins. If this inverts, a grant
// of $HOME silently re-exposes ~/.ssh.
func TestDenyListIsAppliedAfterGrants(t *testing.T) {
	// A read grant of $HOME is the case that still reaches the shields (a write grant
	// above them is refused); the shield must be applied after the grant.
	p := &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/home/u"}}
	args := compileOrFail(t, p, testSandbox("/home/u/.ssh"))

	grant := pairIndex(args, "--ro-bind-try", "/home/u")
	shield := pairIndex(args, "--tmpfs", "/home/u/.ssh")
	if grant < 0 || shield < 0 {
		t.Fatalf("expected both a $HOME grant and a ~/.ssh shield; grant=%d shield=%d", grant, shield)
	}
	if shield < grant {
		t.Error("deny-list is applied before the grant, so the grant would win and re-expose ~/.ssh")
	}
}

// A broad grant must shield credential directories even when they do not exist
// on the host: otherwise a script can create ~/.ssh and plant a key. This is the
// v1 hole.
// A write grant above a home credential shield is refused, so the "shield an
// unborn path so it cannot be planted" case now lives under a workspace grant: a
// project directory whose hooks dir does not exist yet must still be shielded.
func TestUnbornWorkspaceDirIsShielded(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/home/u/proj"}}
	// Note: .git/hooks is deliberately absent from the fake filesystem.
	args := compileOrFail(t, p, testSandbox("/home/u/proj/src"))

	if !has(args, "--tmpfs", "/home/u/proj/.git/hooks") {
		t.Error("a workspace hooks directory that does not exist yet must still be shielded")
	}
}

// Likewise an unborn shell profile: a script must not be able to create ~/.bashrc
// and gain persistence.
// The unborn write-denied FILE shield (an empty read-only file) likewise now lives
// under a workspace grant: an editor-tasks file that does not exist yet must be
// shielded against creation.
func TestUnbornWorkspaceFileIsShielded(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/home/u/proj"}}
	args := compileOrFail(t, p, testSandbox("/home/u/proj/src"))

	found := false
	for j := 0; j+2 < len(args); j++ {
		if args[j] == "--ro-bind" && args[j+1] == "/tmp/shield" && args[j+2] == "/home/u/proj/.vscode/tasks.json" {
			found = true
		}
	}
	if !found {
		t.Error("an unborn write-denied workspace file must be shielded by an empty read-only file")
	}
}

// A write-denied file that DOES exist stays readable. v1 shadowed these with
// /dev/null, which also destroyed reads and left git seeing an empty config.
func TestExistingWriteDeniedFileStaysReadable(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/home/u/proj"}}
	sb := testSandbox("/home/u/proj/src", "/home/u/proj/.git/config")
	args := compileOrFail(t, p, sb)

	found := false
	for j := 0; j+2 < len(args); j++ {
		if args[j] == "--ro-bind" && args[j+1] == "/home/u/proj/.git/config" && args[j+2] == "/home/u/proj/.git/config" {
			found = true
		}
	}
	if !found {
		t.Error("an existing write-denied file must be re-bound read-only (readable, unwritable), not blanked")
	}
	if has(args, "--ro-bind", "/dev/null") {
		t.Error("write-denied files must not be shadowed with /dev/null: that destroys legitimate reads")
	}
}

// A deny-list path no grant can reach is already invisible under deny-by-default.
// Shielding it anyway would make bwrap create a mount point with no parent.
func TestUnreachableDenyPathIsNotShielded(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/data"}}
	args := compileOrFail(t, p, testSandbox())

	if has(args, "--tmpfs", "/home/u/.ssh") {
		t.Error("no grant reaches ~/.ssh, so it should not be shielded")
	}
}

// Granting write to a repository must not let a script install a git hook.
func TestWorkspaceHooksAreProtected(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/work"}}
	sb := testSandbox("/work/.git/hooks")
	args := compileOrFail(t, p, sb)

	found := false
	for j := 0; j+2 < len(args); j++ {
		if args[j] == "--ro-bind" && args[j+1] == "/work/.git/hooks" && args[j+2] == "/work/.git/hooks" {
			found = true
		}
	}
	if !found {
		t.Error("an existing .git/hooks under a write grant must be re-bound read-only")
	}
}

// A write grant on a repo with submodules must also shield each submodule gitdir's
// hooks and config under .git/modules/<name>/: a submodule's working-tree .git is a
// gitfile into that gitdir, whose hooks/config run on the host when the developer
// uses the submodule - a code-execution surface the top-level .git shields miss.
// Nested submodules and linked-worktree config.worktree are covered too.
func TestSubmoduleGitDirsAreProtected(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/work"}}
	sb := testSandbox(
		"/work/src", // makes /work a directory workspace
		"/work/.git/modules/sub/config",
		"/work/.git/modules/sub/hooks", // the hooks dir itself, plus a child below
		"/work/.git/modules/sub/hooks/pre-commit",
		"/work/.git/modules/sub/objects/pack/x", // a pruned store: must not break discovery
		"/work/.git/modules/sub/modules/inner/config",
		"/work/.git/modules/sub/modules/inner/hooks",
		"/work/.git/modules/sub/modules/inner/hooks/post-commit",
		"/work/.git/worktrees/wt/config.worktree",
	)
	args := compileOrFail(t, p, sb)

	roBound := func(path string) bool {
		for j := 0; j+2 < len(args); j++ {
			if args[j] == "--ro-bind" && args[j+1] == path && args[j+2] == path {
				return true
			}
		}
		return false
	}
	for _, path := range []string{
		"/work/.git/modules/sub/config",
		"/work/.git/modules/sub/hooks",
		"/work/.git/modules/sub/modules/inner/config",
		"/work/.git/modules/sub/modules/inner/hooks",
		"/work/.git/worktrees/wt/config.worktree",
	} {
		if !roBound(path) {
			t.Errorf("submodule/worktree gitdir surface %q must be re-bound read-only", path)
		}
	}
}

// gitDirShields' traversal runs on the real filesystem via the host* seams, which
// the fake testSandbox never exercises. This drives it against a real tree with two
// cases the fake cannot represent: a submodule whose path segment is a git store
// name ("logs/mylib" - the gitdir is .git/modules/logs/mylib, and a name-based
// prune would skip it), and a gitdir with a config but NO hooks/ dir (which must
// still be shielded so the dir cannot be planted). A large object store is present
// to confirm the walk never descends into it.
func TestGitDirShieldsRealFilesystem(t *testing.T) {
	root := t.TempDir()
	gitdir := filepath.Join(root, ".git", "modules", "logs", "mylib")
	if err := os.MkdirAll(filepath.Join(gitdir, "objects", "pack"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitdir, "config"), []byte("[core]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Deliberately no hooks/ dir: the shield must be emitted regardless.

	sb := sandbox{
		home:      "/home/u",
		emptyFile: "/tmp/shield",
		exists:    hostExists,
		isDir:     hostIsDir,
		listDir:   hostListDir,
		resolve:   hostResolve,
	}
	got := make(map[string]bool) // path -> Dir
	for _, r := range gitDirShields(sb, root) {
		if r.Deny == denylist.DenyWrite {
			got[r.Path] = r.Dir
		}
	}

	for path, wantDir := range map[string]bool{
		filepath.Join(gitdir, "config"): false,
		filepath.Join(gitdir, "hooks"):  true,
	} {
		d, ok := got[path]
		if !ok {
			t.Errorf("%s not shielded (store-name path segment or absent hooks dir was skipped)", path)
		} else if d != wantDir {
			t.Errorf("%s: Dir=%v, want %v", path, d, wantDir)
		}
	}
	if _, walked := got[filepath.Join(gitdir, "objects", "pack")]; walked {
		t.Error("the walk descended into a gitdir's object store")
	}
}

// A submodule named "config" puts its gitdir at .git/modules/config/, so
// .git/modules/config is a DIRECTORY. Identifying a gitdir by mere existence of a
// "config" child would then misread .git/modules itself as a gitdir and skip every
// sibling submodule. The gitdir predicate must require a regular file, so both the
// config-named submodule and its siblings stay shielded.
func TestGitDirShieldsConfigNamedSubmoduleDoesNotMaskSiblings(t *testing.T) {
	root := t.TempDir()
	modules := filepath.Join(root, ".git", "modules")
	for _, name := range []string{"config", "normal"} {
		gd := filepath.Join(modules, name)
		if err := os.MkdirAll(filepath.Join(gd, "hooks"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(gd, "config"), []byte("[core]\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sb := sandbox{
		home: "/home/u", emptyFile: "/tmp/shield",
		exists: hostExists, isDir: hostIsDir, listDir: hostListDir, resolve: hostResolve,
	}
	got := make(map[string]bool)
	for _, r := range gitDirShields(sb, root) {
		if r.Deny == denylist.DenyWrite {
			got[r.Path] = true
		}
	}
	for _, sub := range []string{"config", "normal"} {
		for _, leaf := range []string{"config", "hooks"} {
			path := filepath.Join(modules, sub, leaf)
			if !got[path] {
				t.Errorf("%s not shielded (a config-named submodule masked the sibling scan)", path)
			}
		}
	}
	// The container .git/modules must NOT be treated as a gitdir itself.
	if got[filepath.Join(modules, "hooks")] {
		t.Error(".git/modules was misidentified as a gitdir (bogus hooks shield emitted)")
	}
}

// .git/modules is writable and unshielded across runs, so a prior run can plant a
// decoy regular file named "config" in a container to try to make the scanner
// misidentify that container as a gitdir and stop descending into real siblings.
// Traversal is unconditional, so the decoy only adds a harmless shield and every
// real submodule gitdir is still found and shielded.
func TestGitDirShieldsPlantedConfigDoesNotMaskSiblings(t *testing.T) {
	root := t.TempDir()
	modules := filepath.Join(root, ".git", "modules")
	// The decoy: a regular file at .git/modules/config (as if the container were a gitdir).
	if err := os.MkdirAll(modules, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modules, "config"), []byte("[core]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A real sibling submodule gitdir that must still be shielded.
	real := filepath.Join(modules, "plainsub")
	if err := os.MkdirAll(filepath.Join(real, "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "config"), []byte("[core]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sb := sandbox{
		home: "/home/u", emptyFile: "/tmp/shield",
		exists: hostExists, isDir: hostIsDir, listDir: hostListDir, resolve: hostResolve,
	}
	got := make(map[string]bool)
	for _, r := range gitDirShields(sb, root) {
		got[r.Path] = true
	}
	for _, leaf := range []string{"config", "hooks"} {
		if !got[filepath.Join(real, leaf)] {
			t.Errorf("%s not shielded: a planted decoy config truncated the walk", filepath.Join(real, leaf))
		}
	}
}

// A prior run can plant a symlink under .git/modules pointing outside the tree; the
// unconditional walk must not follow it (which would traverse the whole target and
// emit shields for paths outside the checkout, or loop). listDir excludes symlinks.
func TestGitDirShieldsDoesNotFollowSymlinkedChild(t *testing.T) {
	root := t.TempDir()
	// A real gitdir OUTSIDE .git/modules, that a planted symlink points at.
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(filepath.Join(outside, "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "config"), []byte("[core]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	modules := filepath.Join(root, ".git", "modules")
	if err := os.MkdirAll(modules, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(modules, "escape")); err != nil {
		t.Fatal(err)
	}
	sb := sandbox{
		home: "/home/u", emptyFile: "/tmp/shield",
		exists: hostExists, isDir: hostIsDir, listDir: hostListDir, resolve: hostResolve,
	}
	for _, r := range gitDirShields(sb, root) {
		if strings.HasPrefix(r.Path, outside) || strings.Contains(r.Path, "escape") {
			t.Errorf("the walk followed a symlink out of .git/modules and emitted %q", r.Path)
		}
	}
}

// A prior run can chmod a directory under .git/modules to mode 0111 - traversable
// by name (so host git still reaches hooks inside it) but unlistable, so the scan
// cannot enumerate the gitdirs within. The scan must not silently treat that as
// empty; it fails closed by shielding the unreadable directory read-only so nothing
// new can be planted under it.
func TestGitDirShieldsFailsClosedOnUnreadableDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory read permissions")
	}
	root := t.TempDir()
	modules := filepath.Join(root, ".git", "modules")
	sub := filepath.Join(modules, "sub")
	if err := os.MkdirAll(filepath.Join(sub, "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "config"), []byte("[core]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(modules, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(modules, 0o755) }) // so t.TempDir cleanup can recurse
	if _, err := os.ReadDir(modules); err == nil {
		t.Skip("filesystem did not enforce the unreadable mode")
	}

	sb := sandbox{
		home: "/home/u", emptyFile: "/tmp/shield",
		exists: hostExists, isDir: hostIsDir, listDir: hostListDir, resolve: hostResolve,
	}
	shieldsModules := false
	for _, r := range gitDirShields(sb, root) {
		if r.Path == modules && r.Deny == denylist.DenyWrite && r.Dir {
			shieldsModules = true
		}
	}
	if !shieldsModules {
		t.Error("an unreadable .git/modules must be shielded read-only (fail closed), not treated as empty")
	}
}

// The same fail-closed rule applies to an unreadable .git/worktrees: the scan must
// shield it read-only rather than silently miss a config.worktree it cannot see.
func TestGitDirShieldsFailsClosedOnUnreadableWorktrees(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory read permissions")
	}
	root := t.TempDir()
	worktrees := filepath.Join(root, ".git", "worktrees")
	if err := os.MkdirAll(filepath.Join(worktrees, "w"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(worktrees, "w", "config.worktree"), []byte("[core]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(worktrees, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(worktrees, 0o755) })
	if _, err := os.ReadDir(worktrees); err == nil {
		t.Skip("filesystem did not enforce the unreadable mode")
	}

	sb := sandbox{
		home: "/home/u", emptyFile: "/tmp/shield",
		exists: hostExists, isDir: hostIsDir, listDir: hostListDir, resolve: hostResolve,
	}
	shielded := false
	for _, r := range gitDirShields(sb, root) {
		if r.Path == worktrees && r.Deny == denylist.DenyWrite && r.Dir {
			shielded = true
		}
	}
	if !shielded {
		t.Error("an unreadable .git/worktrees must be shielded read-only (fail closed)")
	}
}

// A prior write-grant run can plant a symlink loop under .git/modules (which is not
// itself shielded); the scan on the next launch must not recurse forever. The depth
// bound makes gitDirShields return instead of spinning until the path overflows.
func TestGitDirShieldsTerminatesOnSymlinkLoop(t *testing.T) {
	root := t.TempDir()
	modules := filepath.Join(root, ".git", "modules")
	if err := os.MkdirAll(modules, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(modules, filepath.Join(modules, "loop")); err != nil {
		t.Fatal(err)
	}
	sb := sandbox{
		home: "/home/u", emptyFile: "/tmp/shield",
		exists: hostExists, isDir: hostIsDir, listDir: hostListDir, resolve: hostResolve,
	}
	done := make(chan struct{})
	go func() { gitDirShields(sb, root); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("gitDirShields did not terminate on a symlink loop under .git/modules")
	}
}

// Write grants are directory-granular: binding a file makes it a mount point,
// which breaks save-via-rename. A grant naming an existing file is refused,
// pointing the user at the directory.
func TestFileWriteGrantIsRejected(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/work/out.txt"}}
	sb := testSandbox("/work/out.txt") // exists as a file (no children)
	_, err := compile(p, enforce.Process{}, sb)
	if err == nil {
		t.Fatal("a write grant naming an existing file should be rejected")
	}
	if !strings.Contains(err.Error(), "parent directory") {
		t.Errorf("error = %v, want it to point at the parent directory", err)
	}
}

// A "/" write grant would make the entire host root writable, defeating the
// sandbox; unlike a "/" read grant it is never expanded, only refused.
func TestRootWriteGrantIsRejected(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/"}}
	_, err := compile(p, enforce.Process{}, testSandbox())
	if err == nil {
		t.Fatal("a \"/\" write grant should be rejected")
	}
	if !strings.Contains(err.Error(), "host root") {
		t.Errorf("error = %v, want it to explain the whole-root-writable refusal", err)
	}
}

// A read-only grant already makes a write-denied path unwritable, so no shield
// mount is needed - and adding one over a read-only parent would abort bwrap.
func TestReadOnlyDenyWritePathIsNotShielded(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/home/u"}}
	sb := testSandbox("/home/u/.gitconfig")
	args := compileOrFail(t, p, sb)

	if has(args, "--ro-bind", "/home/u/.gitconfig") {
		t.Error("a write-denied file reached only by a read grant needs no shield: the read-only bind already blocks writes")
	}
}

// A "/" read grant must bind the root's children individually, never the host
// root onto the sandbox root - and never the mounts baseFlags manages, or the
// host's /proc, /dev, /tmp would overmount the sandbox's own.
func TestRootReadGrantExpandsToChildren(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/"}}
	args := compileOrFail(t, p, testSandbox())

	if has(args, "--ro-bind-try", "/") {
		t.Error("a \"/\" read grant must not bind the host root onto the sandbox root")
	}
	if !has(args, "--ro-bind-try", "/home") {
		t.Error("a \"/\" read grant must bind the root's children individually")
	}
	for _, managed := range []string{"/proc", "/dev", "/tmp"} {
		if has(args, "--ro-bind-try", managed) {
			t.Errorf("%s is managed by baseFlags and must not be overmounted from the host", managed)
		}
	}
}

// A grant inside an always-shielded directory cannot be honored, so it must be a
// hard error rather than silently vanishing behind the shield.
func TestGrantInsideShieldedPathIsRejected(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/home/u/.ssh/pubkeys"}}
	_, err := compile(p, enforce.Process{}, testSandbox())
	if err == nil {
		t.Fatal("a grant inside ~/.ssh should be rejected, not silently dropped")
	}
	if !strings.Contains(err.Error(), "always-shielded") {
		t.Errorf("error = %v, want it to explain the shield conflict", err)
	}
}

// A READ grant that contains a shielded path is the normal deny-list case and
// must be allowed: the shield is applied inside it and a read grant cannot mutate
// the parent.
func TestReadGrantContainingShieldedPathIsAllowed(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/home/u"}}
	if _, err := compile(p, enforce.Process{}, testSandbox()); err != nil {
		t.Fatalf("reading $HOME (with ~/.ssh shielded inside) should be allowed: %v", err)
	}
}

// A WRITE grant that contains a credential shield is refused: it binds the
// shield's parent read-write, so a run could create the shield on the host or
// replace a symlinked one, bypassing it.
func TestWriteGrantContainingShieldedPathIsRejected(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/home/u"}}
	_, err := compile(p, enforce.Process{}, testSandbox())
	if err == nil {
		t.Fatal("a write grant of $HOME (above ~/.ssh) should be rejected")
	}
	if !strings.Contains(err.Error(), "always-shielded") {
		t.Errorf("error = %v, want it to explain the shield conflict", err)
	}
}

// The refusal must catch a write grant above a SYMLINKED shield. The shield is
// applied at the symlink's target (outside the grant), so the resolved-path check
// for a grant-inside-a-shield does not fire; the grant-contains-a-shield check
// must use the shield's location (~/.ssh) so the symlink cannot be deleted and
// replaced inside the writable parent.
func TestWriteGrantAboveSymlinkedShieldIsRejected(t *testing.T) {
	sb := testSandbox()
	sb.resolve = func(p string) string {
		if p == "/home/u/.ssh" { // ~/.ssh is a symlink pointing out of $HOME
			return "/data/keys"
		}
		return p
	}
	p := &policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/home/u"}}
	_, err := compile(p, enforce.Process{}, sb)
	if err == nil {
		t.Fatal("a write grant above a symlinked ~/.ssh should be rejected (the symlink is deletable in the writable parent)")
	}
	if !strings.Contains(err.Error(), "always-shielded") {
		t.Errorf("error = %v, want it to explain the shield conflict", err)
	}
}

func TestEnvIsClearedAndAllowlistApplied(t *testing.T) {
	proc := enforce.Process{Env: map[string]string{"LANG": "C", "TOKEN": "abc"}}
	args, err := compile(&policy.Policy{Entrypoint: "/work/run.py"}, proc, testSandbox())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if args[0] != "--die-with-parent" {
		t.Errorf("argv should start with the isolation flags, got %q", args[0])
	}
	cleared := false
	for _, a := range args {
		if a == "--clearenv" {
			cleared = true
		}
	}
	if !cleared {
		t.Error("the inherited environment must be cleared")
	}
	if !has(args, "--setenv", "LANG") || !has(args, "--setenv", "TOKEN") {
		t.Error("allowlisted env values were not passed through")
	}
	// HOME must never point at the host's home directory.
	i := pairIndex(args, "--setenv", "HOME")
	if i < 0 || args[i+2] != "/tmp" {
		t.Error("HOME inside the sandbox must not be the host home directory")
	}
}

func TestEntrypointBoundReadOnly(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/work"}}
	args := compileOrFail(t, p, testSandbox())

	entry := -1
	grant := pairIndex(args, "--bind-try", "/work")
	for j := 0; j+2 < len(args); j++ {
		if args[j] == "--ro-bind" && args[j+1] == "/work/run.py" && args[j+2] == "/work/run.py" {
			entry = j
		}
	}
	if entry < 0 {
		t.Fatal("entrypoint must be bound read-only")
	}
	if entry < grant {
		t.Error("a write grant covering the script's directory would leave the script itself writable")
	}
}

func TestCommandUsesInterpreterWhenSet(t *testing.T) {
	sb := testSandbox()
	sb.interpreter = "/usr/bin/python3"
	p := &policy.Policy{Entrypoint: "/work/run.py", Args: []string{"--flag"}}
	args := compileOrFail(t, p, sb)

	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
		}
	}
	if sep < 0 {
		t.Fatal("argv must contain the -- separator")
	}
	got := strings.Join(args[sep+1:], " ")
	if got != "/usr/bin/python3 /work/run.py --flag" {
		t.Errorf("command = %q", got)
	}
}

func TestCompiledBinaryRunsItself(t *testing.T) {
	sb := testSandbox()
	sb.entrypoint = "/work/tool"
	p := &policy.Policy{Entrypoint: "/work/tool"}
	args := compileOrFail(t, p, sb)

	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
		}
	}
	if got := strings.Join(args[sep+1:], " "); got != "/work/tool" {
		t.Errorf("a binary with no interpreter should run itself, got %q", got)
	}
}

func TestUnderPathContainment(t *testing.T) {
	cases := []struct {
		child, parent string
		want          bool
	}{
		{"/home/u/.ssh", "/home/u", true},
		{"/home/u", "/home/u", true},
		{"/home/user2", "/home/u", false}, // prefix-string trap: must not match
		{"/tmp", "/home/u", false},
	}
	for _, tc := range cases {
		if got := under(tc.child, tc.parent); got != tc.want {
			t.Errorf("under(%q, %q) = %v, want %v", tc.child, tc.parent, got, tc.want)
		}
	}
}

func TestInterpreterPrefix(t *testing.T) {
	cases := map[string]string{
		"/usr/bin/python3":                    "",
		"/home/u/.pyenv/versions/3.12/bin/py": "/home/u/.pyenv/versions/3.12",
		"":                                    "",
	}
	for in, want := range cases {
		if got := interpreterPrefix(in); got != want {
			t.Errorf("interpreterPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

// A pip --user runtime at ~/.local/bin/python3 makes the prefix mount bind
// ~/.local read-only. The deny-list must still shield the credential directories
// inside it: the mount exposes them just as a read grant would, and skipping the
// shield as "not exposed by any grant" would put the GitHub CLI's tokens in the
// sandbox of a policy that granted only /work.
func TestInterpreterPrefixExposingHomeSubtreeIsShielded(t *testing.T) {
	sb := testSandbox("/home/u/.local", "/home/u/.local/bin/python3",
		"/home/u/.local/share/gh", "/home/u/.local/share/gh/hosts.yml", "/work")
	sb.interpreter = "/home/u/.local/bin/python3"
	args := compileOrFail(t, &policy.Policy{Read: []string{"/work"}}, sb)

	if !has(args, "--ro-bind", "/home/u/.local") {
		t.Fatalf("the interpreter prefix should be bound; got %v", args)
	}
	if !has(args, "--tmpfs", "/home/u/.local/share/gh") {
		t.Errorf("~/.local/share/gh must be shielded when the prefix mount exposes ~/.local; got %v", args)
	}
	// The prefix is exposed read-only, so it must not be treated as a grant.
	if has(args, "--bind", "/home/u/.local") || has(args, "--bind-try", "/home/u/.local") {
		t.Errorf("the interpreter prefix must never be bound writable; got %v", args)
	}
}

// An interpreter directly under the home directory (a hand-written ~/bin/python3
// wrapper) would make the prefix the whole of $HOME. Binding that would hand a
// policy that granted only /work every file in the home directory - the shields
// cover the deny-list, but nothing covers ~/.bash_history or another project's
// .env. Only the interpreter itself is bound.
func TestInterpreterUnderHomeBindsOnlyItself(t *testing.T) {
	sb := testSandbox("/home/u", "/home/u/bin", "/home/u/bin/python3", "/home/u/notes.txt", "/work")
	sb.interpreter = "/home/u/bin/python3"
	args := compileOrFail(t, &policy.Policy{Read: []string{"/work"}}, sb)

	if has(args, "--ro-bind", "/home/u") {
		t.Errorf("$HOME must never be bound as an interpreter prefix; got %v", args)
	}
	if !has(args, "--ro-bind", "/home/u/bin/python3") {
		t.Errorf("the interpreter itself must be bound so the run can exec it; got %v", args)
	}
}

// On a host where the home directory is reached through a symlink (/home ->
// var/home on Silverblue, or a relocated home) the interpreter resolves to the real
// tree while os.UserHomeDir still reports the linked name. The floor must compare
// the two on the same footing, or it misses and binds the whole home tree.
func TestInterpreterUnderSymlinkedHomeBindsOnlyItself(t *testing.T) {
	sb := testSandbox("/var/home/u", "/var/home/u/bin", "/var/home/u/bin/python3", "/work")
	sb.home = "/home/u"
	sb.interpreter = "/var/home/u/bin/python3"
	sb.resolve = func(p string) string {
		if p == "/home/u" || under(p, "/home/u") {
			return filepath.Join("/var", p)
		}
		return p
	}
	args := compileOrFail(t, &policy.Policy{Read: []string{"/work"}}, sb)

	if has(args, "--ro-bind", "/var/home/u") {
		t.Errorf("a symlinked $HOME must never be bound as an interpreter prefix; got %v", args)
	}
	if !has(args, "--ro-bind", "/var/home/u/bin/python3") {
		t.Errorf("the interpreter itself must be bound so the run can exec it; got %v", args)
	}
}

// A read grant of "/" binds the host's root children, including /run and its
// service sockets. connect() to a unix socket succeeds through a read-only bind
// and is not fenced by the network namespace, so an unshielded /run would turn
// "read: /" into control of the docker daemon - and thereby host root. The shield
// is what keeps a read grant read-only in effect as well as in name.
func TestReadRootShieldsHostRuntimeSockets(t *testing.T) {
	sb := testSandbox("/run", "/run/docker.sock", "/usr", "/home", "/etc")
	args := compileOrFail(t, &policy.Policy{Read: []string{"/"}}, sb)

	if !has(args, "--tmpfs", "/run") {
		t.Errorf("/run must be shielded under a read: / grant; got %v", args)
	}
	if i, j := pairIndex(args, "--ro-bind-try", "/run"), pairIndex(args, "--tmpfs", "/run"); i >= 0 && i > j {
		t.Errorf("the /run bind must come before its shield so the shield wins; got bind at %d, shield at %d", i, j)
	}
}

// A grant naming the runtime directory itself cannot be honored - the shield wins -
// so it is refused rather than silently emptied, per the same rule that refuses a
// grant inside ~/.ssh.
func TestGrantOfRuntimeDirIsRefused(t *testing.T) {
	sb := testSandbox("/run", "/run/docker.sock")
	_, err := compile(&policy.Policy{Read: []string{"/run/docker.sock"}}, enforce.Process{}, sb)
	if err == nil {
		t.Fatalf("a grant of /run/docker.sock must be refused, not silently shielded")
	}
	if !strings.Contains(err.Error(), "/run") {
		t.Errorf("the error should name the shielded path; got %v", err)
	}
}

// An extra deny (a supervising embedder shielding its own state) can name a path
// under a system mount, which no grant reaches. The mount exposes it, so it needs
// a shield: reachability must follow the mounts, not just the grants.
func TestExtraDenyUnderSystemMountIsShielded(t *testing.T) {
	sb := testSandbox("/usr", "/usr/share/secret", "/work")
	sb.extraDeny = []denylist.Rule{{Path: "/usr/share/secret", Deny: denylist.DenyAll, Dir: true}}
	args := compileOrFail(t, &policy.Policy{Read: []string{"/work"}}, sb)

	if !has(args, "--tmpfs", "/usr/share/secret") {
		t.Errorf("an extra deny under a system mount must be shielded; got %v", args)
	}
}

// What systemMountPaths binds for an interpreter is what exposedPaths hands the
// deny-list, so each layout must bind exactly what the interpreter needs and no
// user data beyond it.
func TestSystemMountPathsForInterpreter(t *testing.T) {
	cases := []struct {
		name        string
		interpreter string
		existing    []string
		want        string // the interpreter-driven mount, "" for none beyond the system paths
		unwanted    string
	}{
		{"pip --user prefix", "/home/u/.local/bin/python3", []string{"/home/u/.local"}, "/home/u/.local", ""},
		{"pyenv", "/home/u/.pyenv/versions/3.12/bin/py", []string{"/home/u/.pyenv/versions/3.12"}, "/home/u/.pyenv/versions/3.12", ""},
		{"home wrapper binds the file, never $HOME", "/home/u/bin/python3", []string{"/home/u", "/home/u/bin/python3"}, "/home/u/bin/python3", "/home/u"},
		{"nix binds the store, not the package prefix", "/nix/store/abc/bin/python3", []string{"/nix/store", "/nix/store/abc"}, "/nix/store", "/nix/store/abc"},
		{"system interpreter", "/usr/bin/python3", []string{"/usr"}, "", ""},
		{"prefix absent from the host", "/opt/py/bin/python3", nil, "", "/opt/py"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sb := testSandbox(tc.existing...)
			sb.interpreter = tc.interpreter
			got := systemMountPaths(sb)
			if tc.want != "" && !containsStr(got, tc.want) {
				t.Errorf("systemMountPaths(%q) = %v, want it to bind %q", tc.interpreter, got, tc.want)
			}
			if tc.unwanted != "" && containsStr(got, tc.unwanted) {
				t.Errorf("systemMountPaths(%q) = %v, must not bind %q", tc.interpreter, got, tc.unwanted)
			}
		})
	}
}

func TestResolveFollowsSymlinkedGrant(t *testing.T) {
	// A grant that does not exist resolves to its absolute form rather than
	// failing: write targets are routinely created by the script itself.
	got, err := resolve("relative/path")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("resolve(%q) = %q, want an absolute path", "relative/path", got)
	}
}
