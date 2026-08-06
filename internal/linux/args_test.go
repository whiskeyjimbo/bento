//go:build linux

package linux

import (
	"errors"
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

// testSandbox compiles argv against a hypothetical filesystem, so the
// security-critical argv decisions can be asserted without launching anything.
func testSandbox(existing ...string) sandbox {
	set := make(map[string]bool, len(existing))
	for _, p := range existing {
		set[p] = true
	}
	return sandbox{
		homes:      []string{"/home/u"},
		emptyFile:  "/tmp/shield",
		entrypoint: "/work/run.py",
		exists:     func(p string) bool { return set[p] },
		// A path is a directory if the fake filesystem has an entry strictly under
		// it; a leaf entry is a file. This lets a write grant that is a project
		// directory get its workspace shields while a plain-file grant does not.
		isDir: func(p string) bool {
			for e := range set {
				if e != p && policy.CoversResolved(p, e) {
					return true
				}
			}
			return false
		},
		rootDirs: func() ([]string, error) { return []string{"/usr", "/home", "/etc"}, nil },
		// The hypothetical filesystem has no symlinks, so shields bind in place.
		resolve: func(p string) string { return p },
		// listDir returns the immediate SUBDIRECTORY names of p implied by the fake
		// entries (a segment with something under it), matching hostListDir, which
		// reports files nowhere and symlinks as links. ok is true when p is a directory (has any entry
		// under it); the fake has no unreadable directories. A bare leaf entry directly
		// under p is a file. The fake filesystem has no symlinks, so links is always nil.
		listDir: func(p string) (names, links []string, ok bool) {
			prefix := p + "/"
			seen := map[string]bool{}
			isDir := false
			for e := range set {
				if !strings.HasPrefix(e, prefix) {
					continue
				}
				isDir = true
				rest := e[len(prefix):]
				before, _, ok := strings.Cut(rest, "/")
				if !ok {
					continue // a leaf directly under p is a file, not a subdirectory
				}
				if name := before; !seen[name] {
					seen[name] = true
					names = append(names, name)
				}
			}
			return names, nil, isDir
		},
		// The fake filesystem has no aliased credentials by default; the alias-scan
		// tests override these seams to plant one.
		fileIDs:      func(string) ([]identifiedFile, error) { return nil, nil },
		aliasesUnder: func(string, map[fileID]string) ([]credentialAlias, error) { return nil, nil },
		mountpoints:  func([]uint64) ([]mountPoint, error) { return nil, nil },
		statID:       func(string) (fileID, bool) { return fileID{}, false },
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
	args, _, err := compile(p, enforce.Process{}, sb)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return args
}

// shieldArgs builds just the deny-list arguments for a set of grants, the way compile
// does, skipping the checkGrants refusals. The carve tests need it because the policies
// that reach the forced-child branch are exactly the ones checkGrants now rejects; the
// argv property they pin is still the one a run depends on.
func shieldArgs(sb sandbox, reads, writes []string) []string {
	args, _ := denyArgs(sb, exposedPaths(sb, reads, writes), writes, nil)
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

// lastPairIndex returns the index of the last occurrence of `flag target`, for
// asserting that a re-bind of a path wins over an earlier bind of the same path.
func lastPairIndex(args []string, flag, target string) int {
	last := -1
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == target {
			last = i
		}
	}
	return last
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

func containsStr(ss []string, s string) bool {
	return slices.Contains(ss, s)
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

// The opt-in is READ-only: a WRITE grant of a credential shield is the key-planting
// threat the deny-list exists to stop, so it stays refused even when named exactly.
func TestWriteGrantOfShieldIsRefused(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/home/u/.ssh"}}
	if _, _, err := compile(p, enforce.Process{}, testSandbox("/home/u/.ssh")); err == nil {
		t.Error("a write grant of ~/.ssh must be refused - write opt-in is never honored")
	}
}

// The refusal a write grant gets must not send the author to add a read: grant. The
// opt-in is read-only by construction, so a manifest that follows that advice is refused
// again for the same reason - a loop with no exit. The read grant's own refusal still
// offers it, since there it is the remedy.
func TestWriteGrantRefusalDoesNotOfferTheReadOptIn(t *testing.T) {
	write := &policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/home/u/.ssh"}}
	_, _, err := compile(write, enforce.Process{}, testSandbox("/home/u/.ssh"))
	if err == nil {
		t.Fatal("a write grant of ~/.ssh must be refused")
	}
	if strings.Contains(err.Error(), "opts in") {
		t.Errorf("the write refusal names a remedy a write cannot take: %v", err)
	}
	if !strings.Contains(err.Error(), "no opt-in for a write") {
		t.Errorf("the write refusal must say why there is no way in: %v", err)
	}

	read := &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/home/u/.ssh/pubkeys"}}
	_, _, err = compile(read, enforce.Process{}, testSandbox("/home/u/.ssh"))
	if err == nil {
		t.Fatal("a read grant inside ~/.ssh must be refused")
	}
	if !strings.Contains(err.Error(), "opts in") {
		t.Errorf("the read refusal must keep offering the opt-in: %v", err)
	}
}

// A read opt-in exposes the shield read-only; it must not carry a co-present write
// grant with it. Reading ~/.gnupg does not make its private-key directory writable.
func TestReadOptInDoesNotLiftShieldForWrite(t *testing.T) {
	sb := testSandbox("/home/u/.gnupg", "/home/u/.gnupg/private-keys-v1.d/key")
	p := &policy.Policy{
		Entrypoint: "/work/run.py",
		Read:       []string{"/home/u/.gnupg"},
		Write:      []string{"/home/u/.gnupg/private-keys-v1.d"},
	}
	if _, _, err := compile(p, enforce.Process{}, sb); err == nil {
		t.Error("a write grant inside a read-opted-in credential shield must be refused")
	}
}

// The same, where the shield is a symlink. Needs a real filesystem: grants resolve
// through the package-level resolve() while shields go through sb.resolve, so the
// hypothetical filesystem cannot express a disagreement between the two.
func TestReadOptInDoesNotLiftSymlinkedShieldForWrite(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home", "u")
	keys := filepath.Join(root, "data", "keys")
	if err := os.MkdirAll(keys, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(home, ".ssh")); err != nil {
		t.Fatal(err)
	}

	sb := testSandbox()
	sb.homes = []string{home}
	sb.exists = func(p string) bool { _, err := os.Lstat(p); return err == nil }
	sb.isDir = func(p string) bool { fi, err := os.Stat(p); return err == nil && fi.IsDir() }
	sb.resolve = hostResolve
	sb.listDir = hostListDir

	p := &policy.Policy{
		Entrypoint: "/work/run.py",
		Read:       []string{filepath.Join(home, ".ssh")},
		Write:      []string{filepath.Join(home, ".ssh")},
	}
	if _, _, err := compile(p, enforce.Process{}, sb); err == nil {
		t.Error("a write grant of a read-opted-in symlinked shield must be refused")
	}
}

// The opt-in covers only the built-in credential shields, never a caller's extraDeny (a
// supervising embedder's own control store). Granting an extraDeny path by name must NOT
// lift its shield; the grant stays refused, as it did before the opt-in existed.
func TestExtraDenyIsNotOptInable(t *testing.T) {
	sb := testSandbox("/home/u/proj/store")
	sb.extraDeny = []denylist.Rule{{Path: "/home/u/proj/store", Deny: denylist.DenyAll, Dir: true}}
	p := &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/home/u/proj/store"}}
	if _, _, err := compile(p, enforce.Process{}, sb); err == nil {
		t.Error("a caller extraDeny path must stay refused - it is not an opt-in-able built-in shield")
	}
}

// A caller deny that lands on the same host path as a built-in shield must not be lifted
// when the manifest opts the built-in in. Both consumers of the opt-in set match a bare
// resolved path, so before this was closed the read grant was honored, no shield was
// emitted, and the embedder's store was ro-bound into the sandbox with nothing said.
func TestCallerDenyNotLiftedByBuiltinOptIn(t *testing.T) {
	for _, tc := range []struct{ name, deny string }{
		// The embedder names the built-in store defensively.
		{"same path", "/home/u/.aws"},
		// The embedder names its own store, which is a symlink onto the built-in's.
		{"symlinked onto it", "/opt/agent/state/aws"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sb := testSandbox("/home/u/.aws", "/home/u/.aws/credentials")
			sb.resolve = func(p string) string {
				if p == "/opt/agent/state/aws" {
					return "/home/u/.aws"
				}
				return p
			}
			sb.extraDeny = []denylist.Rule{{Path: tc.deny, Deny: denylist.DenyAll, Dir: true}}
			p := &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/home/u/.aws"}}

			_, _, err := compile(p, enforce.Process{}, sb)
			if err == nil {
				t.Fatal("a read grant of a caller-denied store must be refused, not honored as an opt-in")
			}
			// The built-in refusal offers a read opt-in; naming it here would send the
			// author after an escape a caller deny does not have.
			if strings.Contains(err.Error(), "opts in") {
				t.Errorf("refusal must not offer the built-in opt-in for a caller deny: %v", err)
			}
		})
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

// Write grants are directory-granular: binding a file makes it a mount point,
// which breaks save-via-rename. A grant naming an existing file is refused,
// pointing the user at the directory.
func TestFileWriteGrantIsRejected(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/work/out.txt"}}
	sb := testSandbox("/work/out.txt") // exists as a file (no children)
	_, _, err := compile(p, enforce.Process{}, sb)
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
	_, _, err := compile(p, enforce.Process{}, testSandbox())
	if err == nil {
		t.Fatal("a \"/\" write grant should be rejected")
	}
	if !strings.Contains(err.Error(), "host root") {
		t.Errorf("error = %v, want it to explain the whole-root-writable refusal", err)
	}
}

// The refusal has to live in the shared checks, not in compile: the degraded tier
// never compiles an argv, so a "/" write reaching it is host-root write under
// Landlock with no mount namespace above it.
func TestRootWriteGrantIsRejectedByCheckGrants(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/"}}
	err := checkGrants(testSandbox(), p, nil, []string{"/"})
	if err == nil {
		t.Fatal("checkGrants should reject a \"/\" write grant, or --allow-degraded accepts it")
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

// A root the host cannot enumerate must refuse the run. Expanding it to nothing binds
// nothing while the deny-list still emits shields for the paths a "/" grant reaches, so
// the run would exit 0 reporting confinement over a filesystem it never mounted.
func TestRootReadGrantRefusesAnUnreadableRoot(t *testing.T) {
	sb := testSandbox()
	sb.rootDirs = func() ([]string, error) { return nil, errors.New("permission denied") }
	p := &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/"}}

	if _, _, err := compile(p, enforce.Process{}, sb); err == nil {
		t.Error("a \"/\" read grant whose expansion fails must refuse the run, not bind nothing")
	}
}

// The expansion feeds both the binds and the symlink decision, so it must be read once:
// a second enumeration can disagree with the first, leaving a name bound that the
// symlink pass never accounted for.
func TestRootReadGrantEnumeratesTheRootOnce(t *testing.T) {
	sb := testSandbox()
	calls := 0
	sb.rootDirs = func() ([]string, error) {
		calls++
		return []string{"/usr", "/home", "/etc"}, nil
	}
	compileOrFail(t, &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/"}}, sb)

	if calls != 1 {
		t.Errorf("the root expansion must be read once and carried; got %d reads", calls)
	}
}

// The exec-block is a hardening layer: on a host without seccomp the launcher must
// run the target without the filter (matching the LayerExec=Unavailable warning),
// never hard-refuse to install one it cannot. StrictBlock always implies Block.
func TestExecBlockFlagsGatedOnSeccomp(t *testing.T) {
	for _, mode := range []policy.ExecMode{policy.ExecNone, policy.ExecNoneStrict, policy.ExecAll} {
		if b, s := execBlockFlags(mode, false); b || s {
			t.Errorf("execBlockFlags(%q, seccomp=false) = %v,%v; want false,false - a hardening gap proceeds unblocked", mode, b, s)
		}
	}
	cases := []struct {
		mode          policy.ExecMode
		block, strict bool
	}{
		{policy.ExecNone, true, false},
		{policy.ExecNoneStrict, true, true},
		{policy.ExecAll, false, false},
	}
	for _, c := range cases {
		if b, s := execBlockFlags(c.mode, true); b != c.block || s != c.strict {
			t.Errorf("execBlockFlags(%q, seccomp=true) = %v,%v; want %v,%v", c.mode, b, s, c.block, c.strict)
		}
	}
}

// compile must gate the exec-block on the real seccomp check, not on the seccomp
// every development host has. The pure decision above proves the gating; this proves
// compile consults the check at all, which a host WITH seccomp cannot otherwise
// exercise: a compile that hardcoded seccomp support would encode a none-strict
// launch the launcher then cannot deliver.
func TestCompileReadsTheRealSeccompCheck(t *testing.T) {
	sb := testSandbox("/work/run.py")
	p := &policy.Policy{Entrypoint: "/work/run.py", Exec: policy.ExecNoneStrict}

	// A positive control: with seccomp present this host must encode the strict
	// block, or the fallback below would not be caused by losing the capability.
	args, _, err := compile(p, enforce.Process{}, sb)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFlagValue(args, "--exec", "none-strict") {
		t.Skipf("this host does not encode a none-strict launch to begin with: %v", args)
	}

	swap(t, &seccompSupported, false)
	args, _, err = compile(p, enforce.Process{}, sb)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFlagValue(args, "--exec", "all") {
		t.Errorf("without seccomp compile still encodes a blocking exec mode: %v - it is not reading the check", args)
	}
}

// hasFlagValue reports whether args carries flag immediately followed by value.
func hasFlagValue(args []string, flag, value string) bool {
	for i, a := range args {
		if a == flag && i+1 < len(args) && args[i+1] == value {
			return true
		}
	}
	return false
}

// A grant of a pseudo-filesystem baseFlags mounts fresh (/proc, /dev, /tmp) must be
// refused: bound whole it would overmount the sandbox's hardened version with the
// host's. A specific path inside one still binds.
func TestManagedMountGrantRefused(t *testing.T) {
	for _, managed := range []string{"/proc", "/dev", "/dev/shm", "/dev/pts", "/tmp"} {
		for _, p := range []*policy.Policy{
			{Entrypoint: "/work/run.py", Read: []string{managed}},
			{Entrypoint: "/work/run.py", Write: []string{managed}},
		} {
			if _, _, err := compile(p, enforce.Process{}, testSandbox()); err == nil {
				t.Errorf("grant of %s should be refused, not overmount the sandbox's own", managed)
			}
		}
	}

	p := &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/proc/cpuinfo"}}
	if _, _, err := compile(p, enforce.Process{}, testSandbox()); err != nil {
		t.Errorf("a specific path inside /proc should still bind: %v", err)
	}
}

// A grant inside an always-shielded directory cannot be honored, so it must be a
// hard error rather than silently vanishing behind the shield.
func TestGrantInsideShieldedPathIsRejected(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/home/u/.ssh/pubkeys"}}
	_, _, err := compile(p, enforce.Process{}, testSandbox())
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
	if _, _, err := compile(p, enforce.Process{}, testSandbox()); err != nil {
		t.Fatalf("reading $HOME (with ~/.ssh shielded inside) should be allowed: %v", err)
	}
}

// A WRITE grant that contains a credential shield is refused: it binds the
// shield's parent read-write, so a run could create the shield on the host or
// replace a symlinked one, bypassing it.
func TestWriteGrantContainingShieldedPathIsRejected(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/home/u"}}
	_, _, err := compile(p, enforce.Process{}, testSandbox())
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
	_, _, err := compile(p, enforce.Process{}, sb)
	if err == nil {
		t.Fatal("a write grant above a symlinked ~/.ssh should be rejected (the symlink is deletable in the writable parent)")
	}
	if !strings.Contains(err.Error(), "always-shielded") {
		t.Errorf("error = %v, want it to explain the shield conflict", err)
	}
}

func TestEnvIsClearedAndAllowlistApplied(t *testing.T) {
	proc := enforce.Process{Env: map[string]string{"LANG": "C", "TOKEN": "abc"}}
	args, _, err := compile(&policy.Policy{Entrypoint: "/work/run.py"}, proc, testSandbox())
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

// A write grant covering the interpreter's directory (write: ~/bin over a
// ~/bin/python3 wrapper) would overmount the interpreter's read-only bind with a
// read-write one - letting the target rewrite the binary it is running, host
// persistence. The interpreter must be re-bound read-only after the write grant, so
// the shield wins by argv order, just as the entrypoint is.
// The interpreter sits in a project virtualenv rather than ~/bin: ~/bin is itself a
// write-shielded $PATH directory, so a write grant naming it is refused outright and
// never reaches the ordering this test is about. A venv is the case where the grant is
// legitimate and the re-bind is the only thing protecting the binary.
func TestWriteGrantDoesNotLeaveInterpreterWritable(t *testing.T) {
	sb := testSandbox("/work", "/work/venv/bin", "/work/venv/bin/python3")
	sb.interpreter = "/work/venv/bin/python3"
	args := compileOrFail(t, &policy.Policy{Write: []string{"/work/venv/bin"}}, sb)

	rw := pairIndex(args, "--bind-try", "/work/venv/bin")
	ro := lastPairIndex(args, "--ro-bind", "/work/venv/bin/python3")
	if rw < 0 {
		t.Fatalf("the write grant should bind /work/venv/bin read-write; got %v", args)
	}
	if ro < 0 {
		t.Fatalf("the interpreter must be re-bound read-only; got %v", args)
	}
	if ro < rw {
		t.Errorf("the interpreter re-bind (at %d) must come after the write grant (at %d) so it wins", ro, rw)
	}
}

// The $PATH shields have no opt-in: a write grant naming one is refused at compile,
// not silently overmounted by the shield and left to fail EROFS at run time. ~/bin and
// ~/.local/bin are the distro-default $PATH entries, and ~/.cargo/bin the toolchain
// case (`cargo install`), so each is what an author would most plausibly try to grant.
func TestWriteGrantUnderPathShieldIsRefused(t *testing.T) {
	sb := testSandbox("/home/u", "/home/u/bin", "/home/u/.local/bin", "/home/u/.cargo/bin", "/work")
	for _, w := range []string{
		"/home/u/bin",
		"/home/u/.local/bin",
		"/home/u/.cargo/bin",
		"/home/u/.cargo/bin/nested", // strictly inside, not just the shield itself
	} {
		_, _, err := compile(&policy.Policy{Entrypoint: "/work/run.py", Write: []string{w}}, enforce.Process{}, sb)
		if err == nil {
			t.Errorf("write: %q must be refused - the shield would silently win and every write fail EROFS", w)
			continue
		}
		if !strings.Contains(err.Error(), "no opt-in") {
			t.Errorf("write: %q refused, but the message must say there is no opt-in (unlike a credential shield); got %v", w, err)
		}
	}
	// A read of the same path stays honored: a DenyWrite shield leaves its content
	// readable, so refusing the read would remove access the shield never took.
	if _, _, err := compile(&policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/home/u/.cargo/bin"}}, enforce.Process{}, sb); err != nil {
		t.Errorf("a READ of a write-shielded path must still be honored: %v", err)
	}
	// A write ABOVE the shield is not this refusal's business - the shield covers the
	// interior and still lands on top. (~/.cargo would be the natural case but is
	// refused by checkWriteNotAboveShield for the DenyAll credentials.toml inside it,
	// which is a different check; coursier's tree holds no credential store.)
	sb2 := testSandbox("/home/u", "/home/u/.local/share/coursier", "/home/u/.local/share/coursier/bin", "/work")
	if _, _, err := compile(&policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/home/u/.local/share/coursier"}}, enforce.Process{}, sb2); err != nil {
		t.Errorf("a write grant containing a write-shielded path must not be refused by it: %v", err)
	}
}

// The re-bind protects the interpreter binary for a version-managed runtime too,
// where the whole install prefix is bound and a write grant over it (write: ~/.pyenv)
// would otherwise make the binary itself writable.
func TestWriteGrantDoesNotLeavePyenvInterpreterWritable(t *testing.T) {
	interp := "/home/u/.pyenv/versions/3.12/bin/python3"
	sb := testSandbox("/home/u/.pyenv", "/home/u/.pyenv/versions/3.12", interp, "/work")
	sb.interpreter = interp
	args := compileOrFail(t, &policy.Policy{Write: []string{"/home/u/.pyenv"}}, sb)

	rw := pairIndex(args, "--bind-try", "/home/u/.pyenv")
	ro := lastPairIndex(args, "--ro-bind", interp)
	if rw < 0 || ro < 0 {
		t.Fatalf("want both a write bind of the prefix and a read-only re-bind of the interpreter; got %v", args)
	}
	if ro < rw {
		t.Errorf("the interpreter re-bind (at %d) must come after the write grant (at %d)", ro, rw)
	}
}

// On a host where the home directory is reached through a symlink (/home ->
// var/home on Silverblue, or a relocated home) the interpreter resolves to the real
// tree while os.UserHomeDir still reports the linked name. The floor must compare
// the two on the same footing, or it misses and binds the whole home tree.
func TestInterpreterUnderSymlinkedHomeBindsOnlyItself(t *testing.T) {
	sb := testSandbox("/var/home/u", "/var/home/u/bin", "/var/home/u/bin/python3", "/work")
	sb.homes = []string{"/home/u"}
	sb.interpreter = "/var/home/u/bin/python3"
	sb.resolve = func(p string) string {
		if p == "/home/u" || policy.CoversResolved("/home/u", p) {
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

// A grant naming the runtime directory itself cannot be honored - the shield wins -
// so it is refused rather than silently emptied, per the same rule that refuses a
// grant inside ~/.ssh.
func TestGrantOfRuntimeDirIsRefused(t *testing.T) {
	sb := testSandbox("/run", "/run/docker.sock")
	_, _, err := compile(&policy.Policy{Read: []string{"/run/docker.sock"}}, enforce.Process{}, sb)
	if err == nil {
		t.Fatalf("a grant of /run/docker.sock must be refused, not silently shielded")
	}
	if !strings.Contains(err.Error(), "always-shielded") {
		t.Errorf("the error should say the grant is inside an always-shielded path; got %v", err)
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

// A write grant that names a symlink into a credential store must be refused, and the
// refusal has to hold on a host where the two paths differ only after resolution. This
// is the case a fake filesystem could not express while grants resolved against the real
// host and shields resolved through sb.resolve: the fake's shield resolved to
// /home/u/.ssh while the grant stayed /home/u/link, so nothing matched and the test
// passed for the wrong reason. Both now go through the same seam.
func TestCheckGrantsResolvesGrantsThroughTheSandboxSeam(t *testing.T) {
	sb := testSandbox("/home/u/.ssh/id_rsa")
	sb.resolve = func(p string) string {
		if p == "/home/u/link" {
			return "/home/u/.ssh"
		}
		return p
	}
	p := &policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/home/u/link"}}
	reads, writes, err := resolveGrants(sb, p)
	if err != nil {
		t.Fatalf("resolveGrants: %v", err)
	}
	if len(writes) != 1 || writes[0] != "/home/u/.ssh" {
		t.Fatalf("writes = %v, want the grant resolved through the seam to /home/u/.ssh", writes)
	}
	if err := checkGrants(sb, p, reads, writes); err == nil {
		t.Error("a write grant symlinked into ~/.ssh must be refused")
	}
}

// The interpreter can come from the target script's shebang, so its install prefix is
// adversary-influenced. A prefix that covers a top-level host directory or another
// user's home must narrow the run to the interpreter file rather than exposing the
// tree - nothing under /srv, /opt, or an alien home is covered by any deny-list rule,
// which is anchored on the running user's home.
func TestInterpreterReadPathRefusesABroadPrefix(t *testing.T) {
	cases := []struct {
		name string
		// broad is the tree the unfloored prefix would have exposed. It is present in
		// the fake filesystem, so a missing floor binds it rather than failing the
		// exists check for an unrelated reason.
		interp, broad, want string
	}{
		{"top-level dir", "/srv/bin/python3", "/srv", "/srv/bin/python3"},
		{"root itself", "/python3", "/", "/python3"},
		{"another user's home", "/home/other/bin/python3", "/home/other", "/home/other/bin/python3"},
		{"alien home on another base", "/var/home/other/bin/python3", "/var/home/other", "/var/home/other/bin/python3"},
		{"own home", "/home/u/bin/python3", "/home/u", "/home/u/bin/python3"},
		{"a genuine install root", "/opt/toolchains/py/3.12/bin/python3", "", "/opt/toolchains/py/3.12"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sb := testSandbox(tc.interp, tc.want, tc.broad)
			sb.interpreter = tc.interp
			if got := interpreterReadPath(sb); got != tc.want {
				t.Errorf("interpreterReadPath(%q) = %q, want %q", tc.interp, got, tc.want)
			}
		})
	}

	// As root the home is /root, so a floor that only compared against the running
	// user's home base would never fire for anything under /home - the case where an
	// alien home's credentials are least protected, since the deny-list is anchored on
	// /root and shields nothing under /home/other.
	t.Run("alien home while running as root", func(t *testing.T) {
		sb := testSandbox("/home/other/bin/python3", "/home/other")
		sb.homes = []string{"/root"}
		sb.interpreter = "/home/other/bin/python3"
		if got := interpreterReadPath(sb); got != "/home/other/bin/python3" {
			t.Errorf("interpreterReadPath = %q, want the interpreter file alone, not another user's home", got)
		}
	})

	// With no home there is no deny-list anchor either, so nothing shields whatever a
	// prefix contains. The ratchet has to close, not open, at that point.
	t.Run("no home at all", func(t *testing.T) {
		sb := testSandbox("/srv/rt/py/bin/python3", "/srv/rt/py")
		sb.homes = nil
		sb.interpreter = "/srv/rt/py/bin/python3"
		if got := interpreterReadPath(sb); got != "/srv/rt/py/bin/python3" {
			t.Errorf("interpreterReadPath = %q, want the interpreter file alone when there is no home to anchor shields on", got)
		}
	})
}

// The interpreter's own options go before the entrypoint, which is the only place the
// interpreter reads them: after it they would be the script's argv, and `python3 -u`
// would become `python3 script -u`.
func TestCommandPutsInterpreterArgsBeforeTheEntrypoint(t *testing.T) {
	sb := testSandbox()
	sb.interpreter = "/bin/sh"
	p := &policy.Policy{Entrypoint: "/work/run.py", InterpreterArgs: []string{"-eu"}, Args: []string{"--flag"}}
	args := compileOrFail(t, p, sb)

	// The last separator, as its neighbour above does: bwrap's own "--" comes first
	// and the launcher's is the one the target's argv follows.
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
		}
	}
	if sep < 0 {
		t.Fatal("argv must contain the -- separator")
	}
	if got := strings.Join(args[sep+1:], " "); got != "/bin/sh -eu /work/run.py --flag" {
		t.Errorf("command = %q", got)
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
