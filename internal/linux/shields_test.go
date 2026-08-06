//go:build linux

package linux

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/policy"
)

// The deny-list's own tests: which shields a run emits, where they land in argv, and
// the host artifacts they leave behind. The counterpart refusals - a grant a shield
// makes unhonorable - are in grants_test.go, and the caller-supplied denies in
// deny_test.go.

// shieldArgs builds just the deny-list arguments for a set of grants, the way compile
// does, skipping the checkGrants refusals. The carve tests need it because the policies
// that reach the forced-child branch are exactly the ones checkGrants now rejects; the
// argv property they pin is still the one a run depends on.
func shieldArgs(sb sandbox, reads, writes []string) []string {
	args, _ := denyArgs(sb, exposedPaths(sb, reads, writes), writes, nil)
	return args
}

// The post-run cleanup has to schedule the FILE shield mount points too, not just the
// directories: a write grant on a plain directory made bwrap create .git/config and
// .git/config.worktree, and excluding them left those - and the .git/ holding them -
// on the host after every run. Existence is read here, before the run, so a path that
// was already on the host is never scheduled; removeCreatedShields adds the
// still-empty check that makes the removal itself safe.
func TestCreatedShieldsSchedulesBothKinds(t *testing.T) {
	sb := testSandbox("/home/u/proj/src") // an entry under proj makes it a workspace dir
	grants := []string{"/home/u/proj"}
	dirs, files := createdShields(sb, grants, grants, nil)

	if !containsStr(dirs, "/home/u/proj/.git/hooks") {
		t.Errorf("the .git/hooks directory shield should be scheduled for cleanup; got %v", dirs)
	}
	for _, f := range []string{"/home/u/proj/.git/config", "/home/u/proj/.git/config.worktree"} {
		if !containsStr(files, f) {
			t.Errorf("file shield %s should be scheduled for cleanup; got %v", f, files)
		}
		if containsStr(dirs, f) {
			t.Errorf("file shield %s must not be removed as a directory; got %v", f, dirs)
		}
	}
}

// A shielded path that ALREADY exists on the host is not an artifact of the run, so it
// must never reach the cleanup - this is the check that keeps removeCreatedShields from
// deleting a real .git/config.
func TestCreatedShieldsExcludesPreexistingPaths(t *testing.T) {
	sb := testSandbox("/home/u/proj/src", "/home/u/proj/.git", "/home/u/proj/.git/config")
	grants := []string{"/home/u/proj"}
	dirs, files := createdShields(sb, grants, grants, nil)

	if containsStr(files, "/home/u/proj/.git/config") {
		t.Errorf("an existing .git/config must never be scheduled for removal; got %v", files)
	}
	if !containsStr(files, "/home/u/proj/.git/config.worktree") {
		t.Errorf("the absent .git/config.worktree should still be scheduled; got %v", files)
	}
	if !containsStr(dirs, "/home/u/proj/.git/hooks") {
		t.Errorf("the absent .git/hooks should still be scheduled; got %v", dirs)
	}
}

// The intermediate directories bwrap creates to hold a shield mount point are part of
// the artifact - a write grant on a plain directory otherwise left an empty .git/
// behind - but a directory the user ALREADY had is not, even when a shield lands
// inside it and leaves it empty. Both answers are decided here, before the run, which
// is the only moment they can be told apart.
func TestCreatedShieldsClaimsOnlyTheDirectoriesItCauses(t *testing.T) {
	unborn := testSandbox("/home/u/proj/src")
	grants := []string{"/home/u/proj"}
	dirs, _ := createdShields(unborn, grants, grants, nil)
	if !containsStr(dirs, "/home/u/proj/.git") {
		t.Errorf("the .git/ bwrap must create to hold the shields is part of the artifact; got %v", dirs)
	}
	if i, j := slices.Index(dirs, "/home/u/proj/.git/hooks"), slices.Index(dirs, "/home/u/proj/.git"); i > j {
		t.Errorf("dirs must be deepest first so a parent is tried last; got %v", dirs)
	}
	if containsStr(dirs, "/home/u/proj") {
		t.Errorf("the write grant itself is the user's directory and must never be scheduled; got %v", dirs)
	}

	// The same run against a host that already has an (empty) .git/.
	existing := testSandbox("/home/u/proj/src", "/home/u/proj/.git")
	dirs, _ = createdShields(existing, grants, grants, nil)
	if containsStr(dirs, "/home/u/proj/.git") {
		t.Errorf("a directory the user already had must never be scheduled for removal; got %v", dirs)
	}
	if !containsStr(dirs, "/home/u/proj/.git/hooks") {
		t.Errorf("the shield mount point inside it is still the run's artifact; got %v", dirs)
	}
}

// A write grant nested inside another write grant is still the user's own directory,
// so the ancestor walk must stop at it rather than treating it as an intermediate
// directory of the outer grant.
func TestCreatedShieldsStopsAtANestedWriteGrant(t *testing.T) {
	sb := testSandbox("/home/u/proj/src", "/home/u/proj/sub")
	writes := []string{"/home/u/proj", "/home/u/proj/sub"}
	dirs, _ := createdShields(sb, writes, writes, nil)

	if containsStr(dirs, "/home/u/proj/sub") {
		t.Errorf("a nested write grant must never be scheduled for removal; got %v", dirs)
	}
}

// removeCreatedShields is the half that touches the host, and its safety rests on
// what it refuses to remove: a file that has content, and a path that is no longer the
// kind of thing bwrap created there.
func TestRemoveCreatedShieldsReclaimsOnlyEmptyArtifacts(t *testing.T) {
	grant := t.TempDir()
	gitDir := filepath.Join(grant, ".git")
	hooks := filepath.Join(gitDir, "hooks")
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(gitDir, "config.worktree")
	written := filepath.Join(gitDir, "config")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(written, []byte("[core]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	removeCreatedShields([]string{hooks, gitDir}, []string{empty, written})

	if _, err := os.Stat(written); err != nil {
		t.Errorf("a file with content must survive cleanup: %v", err)
	}
	if _, err := os.Stat(empty); !os.IsNotExist(err) {
		t.Errorf("the empty artifact should be gone; stat err = %v", err)
	}
	if _, err := os.Stat(gitDir); err != nil {
		t.Errorf(".git still holds the non-empty config, so it must survive: %v", err)
	}

	// With the last file gone, the intermediate .git/ goes too - and the grant itself
	// is not in the list at all, so it cannot.
	if err := os.Remove(written); err != nil {
		t.Fatal(err)
	}
	removeCreatedShields([]string{gitDir}, nil)
	if _, err := os.Stat(gitDir); !os.IsNotExist(err) {
		t.Errorf("the intermediate .git/ should be reclaimed once empty; stat err = %v", err)
	}
	if _, err := os.Stat(grant); err != nil {
		t.Errorf("the write grant itself must never be removed: %v", err)
	}
}

// A directory artifact is removed by rmdir, never by unlink. If a host process
// replaced the empty directory bwrap created with a regular FILE during the run, that
// file is content the run did not put there - os.Remove would have deleted it.
func TestRemoveCreatedShieldsWillNotUnlinkAPathThatIsNoLongerADirectory(t *testing.T) {
	dir := t.TempDir()
	swapped := filepath.Join(dir, "hooks")
	if err := os.WriteFile(swapped, []byte("host content"), 0o644); err != nil {
		t.Fatal(err)
	}

	removeCreatedShields([]string{swapped}, nil)

	if b, err := os.ReadFile(swapped); err != nil || string(b) != "host content" {
		t.Errorf("a file at a directory artifact's path must survive: content=%q err=%v", b, err)
	}
}

// The deny-list must be applied after the policy's own grants, because bwrap
// resolves mounts in argv order and the last one wins. If this inverts, a grant
// of $HOME silently re-exposes ~/.ssh.
func TestDenyListIsAppliedAfterGrants(t *testing.T) {
	// A read grant of $HOME is the case that still reaches the shields (a write grant
	// above them is refused); the shield must be applied after the grant.
	p := &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/home/u"}}
	args := compileOrFail(t, p, testSandbox("/home/u/.ssh", "/home/u/.ssh/id_rsa"))

	grant := pairIndex(args, "--ro-bind-try", "/home/u")
	shield := pairIndex(args, "--tmpfs", "/home/u/.ssh")
	if grant < 0 || shield < 0 {
		t.Fatalf("expected both a $HOME grant and a ~/.ssh shield; grant=%d shield=%d", grant, shield)
	}
	if shield < grant {
		t.Error("deny-list is applied before the grant, so the grant would win and re-expose ~/.ssh")
	}
}

// The shields anchor on $HOME and on the passwd entry, so a caller-chosen environment
// cannot relocate them off the real credential stores: HOME=/ moves one anchor to the
// root and the passwd anchor still shields /home/u/.ssh inside the grant.
func TestShieldsAnchorOnEveryHome(t *testing.T) {
	sb := testSandbox("/home/u/.ssh", "/home/u/.ssh/id_rsa")
	sb.homes = []string{"/", "/home/u"}
	p := &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/home/u"}}
	args := compileOrFail(t, p, sb)

	grant := lastPairIndex(args, "--ro-bind-try", "/home/u")
	shield := pairIndex(args, "--tmpfs", "/home/u/.ssh")
	if grant < 0 || shield < 0 || shield < grant {
		t.Errorf("a relocated $HOME dropped the passwd home's credential shield; grant=%d shield=%d", grant, shield)
	}
}

// v1's allow_exec disabled seccomp AND Landlock AND the FD limit at once, so asking
// for subprocesses silently surrendered filesystem confinement too. In v2 the exec
// policy is an independent layer: exec: all drops only the exec-block, and the
// credential shields stand exactly as they do under exec: none.
func TestExecAllStillShieldsCredentials(t *testing.T) {
	sb := testSandbox("/home/u/.ssh", "/home/u/.ssh/id_rsa")
	p := &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/home/u"}, Exec: policy.ExecAll}
	args := compileOrFail(t, p, sb)

	// The LAST grant of the home tree is the one that matters: bwrap is last-wins, so
	// a re-bind emitted after the shield would re-expose the credential while an
	// assertion against the first grant still saw the shield ordered correctly.
	grant := lastPairIndex(args, "--ro-bind-try", "/home/u")
	shield := pairIndex(args, "--tmpfs", "/home/u/.ssh")
	if grant < 0 || shield < 0 || shield < grant {
		t.Errorf("exec: all lost the credential shield over a home grant; grant=%d shield=%d", grant, shield)
	}
	// The exec-block is the ONLY layer exec: all is allowed to drop.
	if !hasFlagValue(args, "--exec", "all") {
		t.Errorf("exec: all did not reach the launcher: %v", args)
	}
}

// compile reports the always-on shields a run actually engaged, so an operator can
// confirm the boundary is working. A grant reaching the home tree engages the
// credential shields under it; each is reported hidden and the list is sorted. A grant
// that reaches no shield reports none - the audit names what a reachable grant would
// otherwise have exposed, not the whole rule set.
func TestCompileReportsAppliedShields(t *testing.T) {
	sb := testSandbox("/home/u/.ssh", "/home/u/.aws")
	_, shields, err := compile(&policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/home/u"}}, enforce.Process{}, sb)
	if err != nil {
		t.Fatal(err)
	}
	if !hasShield(shields, "/home/u/.ssh", "hidden") || !hasShield(shields, "/home/u/.aws", "hidden") {
		t.Errorf("a home grant must report the credential shields it reaches as hidden; got %v", shields)
	}
	for i := 1; i < len(shields); i++ {
		if shields[i-1].Path > shields[i].Path {
			t.Errorf("shields must be sorted by path; got %v", shields)
		}
	}

	_, none, err := compile(&policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/work"}}, enforce.Process{}, sb)
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Errorf("a grant reaching no shield must report none; got %v", none)
	}
}

func hasShield(shields []enforce.ShieldApplied, path, kind string) bool {
	for _, s := range shields {
		if s.Path == path && s.Kind == kind {
			return true
		}
	}
	return false
}

// A grant that names a credential shield EXACTLY is a deliberate opt-in. It is
// honored rather than refused (compileOrFail would fail on a refusal), and the shield is
// skipped so the grant binds the real content instead of being overmounted empty.
func TestExplicitShieldGrantIsHonored(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/home/u/.ssh"}}
	args := compileOrFail(t, p, testSandbox("/home/u/.ssh", "/home/u/.ssh/id_rsa"))

	if !has(args, "--ro-bind-try", "/home/u/.ssh") {
		t.Error("an explicit grant of ~/.ssh must be bound")
	}
	if has(args, "--tmpfs", "/home/u/.ssh") {
		t.Error("the ~/.ssh shield must be skipped for an explicit opt-in, else it overmounts the grant")
	}
}

// The opt-in covers the runtime-dir shields too (the docker.sock / gpg-agent case): an
// explicit grant of /run is honored and its shield skipped.
func TestExplicitRuntimeShieldGrantIsHonored(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/run"}}
	args := compileOrFail(t, p, testSandbox("/run", "/run/docker.sock"))

	if !has(args, "--ro-bind-try", "/run") {
		t.Error("an explicit grant of the runtime dir must be bound")
	}
	if has(args, "--tmpfs", "/run") {
		t.Error("the /run shield must be skipped for an explicit opt-in")
	}
}

// The opt-in wins even when a broad grant also covers the shield: the user asked for the
// whole shielded directory, so it is exposed via either grant and the carve is skipped.
func TestExplicitShieldGrantWinsUnderBroadGrant(t *testing.T) {
	// ~/.ssh is modeled as a real directory (a child under it), so a regressed shield
	// would emit --tmpfs here rather than an empty-file bind that a tmpfs-only assertion
	// would miss - this exact-opt-in-under-broad-grant combo is not covered by the fuzz
	// oracle, which never passes a broad grant alongside the exact one.
	p := &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/home/u", "/home/u/.ssh"}}
	args := compileOrFail(t, p, testSandbox("/home/u/.ssh", "/home/u/.ssh/id_rsa"))

	if has(args, "--tmpfs", "/home/u/.ssh") {
		t.Error("~/.ssh explicitly granted must not be shielded, even under a broad ~ grant")
	}
}

// The opt-in must NOT widen the broad-grant carve: read: ~ without an explicit ~/.ssh grant
// still shields ~/.ssh. This is the regression guard that the opt-in skip did not leak
// into enclosing grants.
func TestBroadGrantWithoutOptInStillShields(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/home/u"}}
	args := compileOrFail(t, p, testSandbox("/home/u/.ssh", "/home/u/.ssh/id_rsa"))

	if !has(args, "--tmpfs", "/home/u/.ssh") {
		t.Error("read: ~ without an explicit ~/.ssh opt-in must still shield ~/.ssh")
	}
}

// A DenyAll shield must choose tmpfs vs empty-file bind from the REAL filesystem
// kind when the path exists, not the rule's declared Dir. A declared-dir rule on a
// path that is actually a file (or the reverse) would otherwise hand bwrap a
// tmpfs-over-file (or file-over-dir) mount it rejects, aborting the whole run - which
// is what blocked shielding ~/.cert, whose kind varies across hosts.
func TestDenyAllShieldMatchesRealKind(t *testing.T) {
	// Declared dir, real file: bind the empty file, not tmpfs.
	sbFile := testSandbox("/home/u/.cert") // a childless leaf is a file in the fake fs
	if got := shieldMount(denylist.Rule{Path: "/home/u/.cert", Deny: denylist.DenyAll, Dir: true}, sbFile); !slices.Equal(got, []string{"--ro-bind", sbFile.emptyFile, "/home/u/.cert"}) {
		t.Errorf("declared-dir DenyAll on a real file must bind the empty file; got %v", got)
	}
	// Declared file, real dir: tmpfs, not a file bound over a directory.
	sbDir := testSandbox("/home/u/.cert", "/home/u/.cert/client.pem")
	if got := shieldMount(denylist.Rule{Path: "/home/u/.cert", Deny: denylist.DenyAll}, sbDir); !slices.Equal(got, []string{"--tmpfs", "/home/u/.cert"}) {
		t.Errorf("declared-file DenyAll on a real dir must tmpfs; got %v", got)
	}
	// Absent: fall back to the declared kind. An absent credential file stays an empty
	// read-only file rather than becoming a tmpfs directory a reader would choke on.
	sbAbsent := testSandbox()
	if got := shieldMount(denylist.Rule{Path: "/home/u/.netrc", Deny: denylist.DenyAll}, sbAbsent); !slices.Equal(got, []string{"--ro-bind", sbAbsent.emptyFile, "/home/u/.netrc"}) {
		t.Errorf("absent declared-file DenyAll must bind the empty file; got %v", got)
	}
}

// The kind-sensitive shield unblocks ~/.cert (NetworkManager/802.1X client keys) and
// the ~/.mail / ~/.Mail maildirs, directories firejail blacklists. A home read grant
// must report them hidden without the run aborting on a kind mismatch.
func TestCertAndMailDirsAreShielded(t *testing.T) {
	sb := testSandbox("/home/u/.cert", "/home/u/.cert/client.pem",
		"/home/u/.mail", "/home/u/.mail/cur", "/home/u/.Mail", "/home/u/.Mail/cur")
	_, shields, err := compile(&policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/home/u"}}, enforce.Process{}, sb)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/home/u/.cert", "/home/u/.mail", "/home/u/.Mail"} {
		if !hasShield(shields, p, "hidden") {
			t.Errorf("%s must be shielded hidden under a home grant; got %v", p, shields)
		}
	}
}

// fish_history is a DenyAll file nested inside the DenyWrite ~/.local/share/fish tree,
// which stays readable so fish can load its functions and completions. This locks in the two
// simplest grant shapes: a read grant hides the child (and the DenyWrite parent never emits,
// since it shields only where a grant is writable), and a write reaching the whole tree is
// refused for containing the DenyAll child. The sibling-write shape, where the parent's bind
// fires and would otherwise re-expose the child, is carved out by denyArgs and covered by
// TestNestedDenyAllHiddenUnderExposedParent and TestDenyAllChildEmittedAfterExposedDenyWriteParent.
func TestNestedDenyAllHiddenUnderReadGrantWriteRefused(t *testing.T) {
	sb := testSandbox(
		"/home/u/.local/share/fish",
		"/home/u/.local/share/fish/functions/ls.fish", // function tree stays readable
		"/home/u/.local/share/fish/fish_history",
	)
	args := compileOrFail(t, &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/home/u"}}, sb)
	if pairIndex(args, sb.emptyFile, "/home/u/.local/share/fish/fish_history") < 0 {
		t.Error("a read grant must hide the fish history store")
	}
	if pairIndex(args, "--ro-bind", "/home/u/.local/share/fish") >= 0 {
		t.Error("the DenyWrite parent must not emit under a read grant, or its bind would shadow the child shield")
	}

	if _, _, err := compile(&policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/home/u/.local/share/fish"}}, enforce.Process{}, sb); err == nil {
		t.Error("a write grant reaching the DenyAll fish_history child must be refused")
	}
}

// A DenyAll child under a shielded DenyWrite dir must be emitted AFTER the parent bind
// (bwrap last-wins), and must be emitted even when only the parent is grant-reachable -
// a write to a sibling subdir fires the parent's ro-bind, which would otherwise re-expose
// the hidden child.
//
// Driven through denyArgs rather than compile: every write grant that fires an exposed
// DenyWrite parent holding a DenyAll child is now refused by checkGrants (under it by
// checkWriteNotUnderReadOnlyShield, at or above it by checkWriteNotAboveShield), so no
// accepted policy reaches this branch. The ordering property is kept, and pinned here,
// because it is what makes those refusals safe to relax: whichever one a later rule
// shape loosens, the hidden child must still land after the readable parent.
func TestDenyAllChildEmittedAfterExposedDenyWriteParent(t *testing.T) {
	sb := testSandbox(
		"/home/u/.local/share/fish",
		"/home/u/.local/share/fish/functions/ls.fish",
		"/home/u/.local/share/fish/fish_history",
	)
	const parent = "/home/u/.local/share/fish"
	const child = "/home/u/.local/share/fish/fish_history"

	// Sibling write only, no read: the child is not independently reachable, yet is
	// force-emitted because the parent's bind would expose it - and after that bind.
	args := shieldArgs(sb, nil, []string{"/home/u/.local/share/fish/functions"})
	p, c := pairIndex(args, "--ro-bind", parent), pairIndex(args, sb.emptyFile, child)
	if p < 0 || c < 0 {
		t.Fatalf("sibling write must shield both parent (ro-bind idx=%d) and force the child (idx=%d)", p, c)
	}
	if c < p {
		t.Errorf("child shield (idx %d) must be emitted after the parent bind (idx %d), or the parent re-exposes it", c, p)
	}

	// Home read + sibling write: the child is reachable and emitted normally, but must
	// still land after the parent bind.
	args2 := shieldArgs(sb, []string{"/home/u"}, []string{"/home/u/.local/share/fish/functions"})
	p2, c2 := pairIndex(args2, "--ro-bind", parent), pairIndex(args2, sb.emptyFile, child)
	if p2 < 0 || c2 < 0 || c2 < p2 {
		t.Errorf("read+write: child (idx %d) must follow parent (idx %d), both present", c2, p2)
	}

	// XDG_DATA_HOME relocation moves both parent and child to the relocated base, keeping
	// the same nesting - the carve must follow.
	t.Setenv("XDG_DATA_HOME", "/xdg")
	sbx := testSandbox("/xdg/fish", "/xdg/fish/functions/ls.fish", "/xdg/fish/fish_history")
	args3 := shieldArgs(sbx, nil, []string{"/xdg/fish/functions"})
	p3, c3 := pairIndex(args3, "--ro-bind", "/xdg/fish"), pairIndex(args3, sbx.emptyFile, "/xdg/fish/fish_history")
	if p3 < 0 || c3 < 0 || c3 < p3 {
		t.Errorf("relocated pair: child (idx %d) must follow parent (idx %d), both present", c3, p3)
	}
}

// The carve must key on the real filesystem kind, not the declared Rule.Dir: shieldMount()
// ro-binds by what is on disk, so a file-declared DenyWrite rule pointed at a directory
// (an env relocation such as GIT_CONFIG_GLOBAL=~/.local) still binds the whole tree
// read-only and would re-expose a DenyAll store nested inside it. Here the gh token dir
// (~/.local/share/gh) sits under the relocated config path; a sibling write must not let
// the parent bind re-expose it.
//
// Driven through denyArgs for the same reason as the test above: checkGrants refuses the
// sibling write that fires this parent. The relocation makes that refusal reach further
// than the built-in shields do - GIT_CONFIG_GLOBAL pointed at a directory write-shields
// that whole tree - which is exactly why the ordering must stay pinned.
func TestCarveKeysOnRealKindNotDeclaredDir(t *testing.T) {
	t.Setenv("GIT_CONFIG_GLOBAL", "/home/u/.local") // a directory: produces a DenyWrite file-rule over a dir
	sb := testSandbox(
		"/home/u/.local",
		"/home/u/.local/foo/plugin", // write target, makes .local and foo real dirs
		"/home/u/.local/share/gh",
		"/home/u/.local/share/gh/hosts.yml",
	)
	args := shieldArgs(sb, nil, []string{"/home/u/.local/foo"})
	parent := pairIndex(args, "--ro-bind", "/home/u/.local")
	child := pairIndex(args, "--tmpfs", "/home/u/.local/share/gh")
	if parent < 0 || child < 0 {
		t.Fatalf("a file-rule over a real dir must shield parent (ro-bind idx=%d) and force the nested gh store (tmpfs idx=%d)", parent, child)
	}
	if child < parent {
		t.Errorf("the gh store shield (idx %d) must follow the parent bind (idx %d)", child, parent)
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
// under a workspace grant: a git config that does not exist yet must be shielded
// against creation.
func TestUnbornWorkspaceFileIsShielded(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/home/u/proj"}}
	args := compileOrFail(t, p, testSandbox("/home/u/proj/src"))

	found := false
	for j := 0; j+2 < len(args); j++ {
		if args[j] == "--ro-bind" && args[j+1] == "/tmp/shield" && args[j+2] == "/home/u/proj/.git/config" {
			found = true
		}
	}
	if !found {
		t.Error("an unborn write-denied workspace file must be shielded by an empty read-only file")
	}
}

// An env-relocated startup file (GIT_CONFIG_GLOBAL, ZDOTDIR) is the first Home()
// DenyWrite rule a write grant can actually reach - the home defaults sit under home,
// where a write grant is refused. Prove the shield is emitted end-to-end so a write
// grant over the relocation cannot plant a config the host runs, and that the shield
// (an empty read-only file) follows the grant bind so bwrap's last-wins keeps it.
func TestRelocatedStartupFileShieldedUnderWriteGrant(t *testing.T) {
	t.Setenv("GIT_CONFIG_GLOBAL", "/cfg/gitconfig")
	t.Setenv("ZDOTDIR", "/cfg/zsh")
	t.Setenv("BASH_ENV", "/cfg/bashenv")                  // sourced by non-interactive bash
	t.Setenv("ENV", "/cfg/shinit")                        // sourced by POSIX sh/ksh/dash
	t.Setenv("INPUTRC", "/cfg/inputrc")                   // readline macro binding runs on a keypress
	t.Setenv("PYTHONSTARTUP", "/cfg/pystartup")           // sourced at interactive python startup
	t.Setenv("SCREENRC", "/cfg/screenrc")                 // GNU screen runs its commands
	t.Setenv("PSQLRC", "/cfg/psqlrc")                     // psql \! runs a shell command
	t.Setenv("PIP_CONFIG_FILE", "/cfg/pip.conf")          // index-url redirect to a malicious registry
	t.Setenv("MAILCAPS", "/cfg/a.mailcap:/cfg/b.mailcap") // MIME handlers run on attachment open
	p := &policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/cfg"}}
	args := compileOrFail(t, p, testSandbox("/cfg/x")) // /cfg exists as a dir so the grant binds it

	dests := shieldDests(args, "/tmp/shield", true)
	for _, want := range []string{
		"/cfg/gitconfig", "/cfg/zsh/.zshrc",
		"/cfg/bashenv", "/cfg/shinit", "/cfg/inputrc", "/cfg/pystartup",
		"/cfg/screenrc", "/cfg/psqlrc", "/cfg/pip.conf", "/cfg/a.mailcap", "/cfg/b.mailcap",
	} {
		if !slices.Contains(dests, want) {
			t.Errorf("relocated startup file %q must be shielded under a write grant reaching it; shields=%v", want, dests)
		}
	}
	// The shield must land after the write-grant bind of /cfg.
	shield := -1
	for j := 0; j+2 < len(args); j++ {
		if args[j] == "--ro-bind" && args[j+2] == "/cfg/gitconfig" {
			shield = j
		}
	}
	if grant := pairIndex(args, "--bind-try", "/cfg"); grant < 0 || grant > shield {
		t.Errorf("shield at %d must follow the /cfg write-grant bind at %d", shield, grant)
	}
}

// CARGO_HOME relocates the mixed-severity cargo store: the registry tokens
// (credentials{,.toml}) hide, and the build configs stay readable but unwritable. A broad
// read grant reaching the relocation must hide the tokens; a write grant over the relocated
// dir must be refused for containing them - exactly as for the default ~/.cargo.
func TestRelocatedCargoHomeShieldedUnderReadWriteRefused(t *testing.T) {
	t.Setenv("CARGO_HOME", "/cfg/cargo")
	sb := testSandbox(
		"/cfg/cargo",
		"/cfg/cargo/config.toml",
		"/cfg/cargo/credentials.toml",
	)
	args := compileOrFail(t, &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/cfg"}}, sb)
	hidden := shieldDests(args, "/tmp/shield", true)
	if !slices.Contains(hidden, "/cfg/cargo/credentials.toml") {
		t.Errorf("a read grant reaching CARGO_HOME must hide the registry token; hidden=%v", hidden)
	}
	// config.toml stays readable via the read grant (DenyWrite adds nothing under a read)
	// and must not be blanked to the empty file.
	if slices.Contains(hidden, "/cfg/cargo/config.toml") {
		t.Error("cargo config.toml must stay readable, not hidden")
	}

	if _, _, err := compile(&policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/cfg/cargo"}}, enforce.Process{}, sb); err == nil {
		t.Error("a write grant over the relocated CARGO_HOME must be refused for containing the credential shield")
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
		homes:     []string{"/home/u"},
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
		homes: []string{"/home/u"}, emptyFile: "/tmp/shield",
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
		homes: []string{"/home/u"}, emptyFile: "/tmp/shield",
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
// emit shields for paths outside the checkout, or loop). The link itself still gets a
// rule, so checkWorkspaceShieldNotRedirected has something to refuse: dropping the name
// entirely left the planted gitdir covered by nothing at all.
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
		homes: []string{"/home/u"}, emptyFile: "/tmp/shield",
		exists: hostExists, isDir: hostIsDir, listDir: hostListDir, resolve: hostResolve,
	}
	link := filepath.Join(modules, "escape")
	covered := false
	for _, r := range gitDirShields(sb, root) {
		if strings.HasPrefix(r.Path, outside) {
			t.Errorf("the walk followed a symlink out of .git/modules and emitted %q", r.Path)
		}
		if r.Path == link {
			covered = true
		}
	}
	if !covered {
		t.Errorf("the planted link %q must carry a rule, or the redirect check never sees it", link)
	}
	// And that rule is what turns the plant into a refusal.
	if err := checkWorkspaceShieldNotRedirected(sb, []string{root}); err == nil {
		t.Error("a symlinked entry under .git/modules redirects a shield and must be refused")
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
	t.Cleanup(func() { _ = os.Chmod(modules, 0o755) }) // so t.TempDir cleanup can recurse
	if _, err := os.ReadDir(modules); err == nil {
		t.Skip("filesystem did not enforce the unreadable mode")
	}

	sb := sandbox{
		homes: []string{"/home/u"}, emptyFile: "/tmp/shield",
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
	t.Cleanup(func() { _ = os.Chmod(worktrees, 0o755) })
	if _, err := os.ReadDir(worktrees); err == nil {
		t.Skip("filesystem did not enforce the unreadable mode")
	}

	sb := sandbox{
		homes: []string{"/home/u"}, emptyFile: "/tmp/shield",
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
		homes: []string{"/home/u"}, emptyFile: "/tmp/shield",
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

// A read grant of "/" binds the host's root children, including /run and its
// service sockets. connect() to a unix socket succeeds through a read-only bind
// and is not fenced by the network namespace, so an unshielded /run would turn
// "read: /" into control of the docker daemon - and thereby host root. The shield
// is what keeps a read grant read-only in effect as well as in name.
func TestReadRootShieldsHostRuntimeSockets(t *testing.T) {
	sb := testSandbox("/run", "/run/docker.sock", "/usr", "/home", "/etc")
	// The "/" expansion binds the host's root children, which is what puts /run in
	// the sandbox in the first place; the default fake root omits it.
	sb.rootDirs = func() ([]string, error) { return []string{"/usr", "/home", "/etc", "/run"}, nil }
	args := compileOrFail(t, &policy.Policy{Read: []string{"/"}}, sb)

	if !has(args, "--tmpfs", "/run") {
		t.Errorf("/run must be shielded under a read: / grant; got %v", args)
	}
	bind, shield := pairIndex(args, "--ro-bind-try", "/run"), pairIndex(args, "--tmpfs", "/run")
	if bind < 0 {
		t.Fatalf("the / expansion should bind /run, or this test asserts nothing about ordering; got %v", args)
	}
	if bind > shield {
		t.Errorf("the /run bind must come before its shield so the shield wins; got bind at %d, shield at %d", bind, shield)
	}
}

// An extra deny (a supervising embedder shielding its own state) can name a path
// under a system mount, which no grant reaches. The mount exposes it, so it needs
// a shield: reachability must follow the mounts, not just the grants.
func TestExtraDenyUnderSystemMountIsShielded(t *testing.T) {
	sb := testSandbox("/usr", "/usr/share/secret", "/usr/share/secret/key", "/work")
	sb.extraDeny = []denylist.Rule{{Path: "/usr/share/secret", Deny: denylist.DenyAll, Dir: true}}
	args := compileOrFail(t, &policy.Policy{Read: []string{"/work"}}, sb)

	if !has(args, "--tmpfs", "/usr/share/secret") {
		t.Errorf("an extra deny under a system mount must be shielded; got %v", args)
	}
}

// The walk's ROOTS are followed through a symlink too: listDir enumerates whatever the
// link points at. A run that replaces .git/modules with a link to an EMPTY directory it
// controls therefore enumerates clean and emits no rule at all - the same plant as a
// symlinked child, moved one level up, and the one spelling a populated target would
// have given away by producing redirected rules from inside.
func TestGitDirShieldsCoversASymlinkedWalkRoot(t *testing.T) {
	for _, root := range []string{"modules", "worktrees"} {
		t.Run(root, func(t *testing.T) {
			dir := t.TempDir()
			decoy := filepath.Join(dir, "decoy") // empty, so the walk finds nothing inside
			if err := os.MkdirAll(decoy, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
				t.Fatal(err)
			}
			planted := filepath.Join(dir, ".git", root)
			if err := os.Symlink(decoy, planted); err != nil {
				t.Fatal(err)
			}
			sb := sandbox{
				homes: []string{"/home/u"}, emptyFile: "/tmp/shield",
				exists: hostExists, isDir: hostIsDir, listDir: hostListDir, resolve: hostResolve,
			}

			covered := false
			for _, r := range gitDirShields(sb, dir) {
				if r.Path == planted {
					covered = true
				}
			}
			if !covered {
				t.Errorf("a symlinked %q must carry a rule; an empty target emits nothing from inside it", planted)
			}
			if err := checkWorkspaceShieldNotRedirected(sb, []string{dir}); err == nil {
				t.Errorf("a symlinked %q redirects the walk and must be refused", planted)
			}
		})
	}
}

// A workspace-local cargo home (CARGO_HOME=<repo>/.cargo, routine in CI) keeps the
// registry and git checkouts under .cargo, so the plant shields there are named as files.
// Taking the directory instead would refuse a grant of the registry outright - a DenyWrite
// shield has no opt-in - and, where .cargo does not exist yet, tmpfs the downloads and lose
// them at teardown with the build still exiting zero.
func TestWorkspaceCargoRegistryStaysWritable(t *testing.T) {
	sb := testSandbox("/work/.git/config", "/work/.cargo/registry/cache/x")
	writes := []string{"/work/.cargo/registry"}
	if err := checkWriteNotUnderReadOnlyShield(sb, writes); err != nil {
		t.Errorf("a workspace cargo registry must stay grantable: %v", err)
	}

	shielded := make(map[string]bool)
	for _, r := range shieldRules(sb, []string{"/work"}) {
		shielded[r.Path] = true
	}
	for _, p := range []string{"/work/.cargo/config.toml", "/work/.cargo/config"} {
		if !shielded[p] {
			t.Errorf("%s must be shielded whether or not it exists: a plant creates it", p)
		}
	}
	if shielded["/work/.cargo"] {
		t.Error("the workspace .cargo directory must not be shielded whole")
	}
}
