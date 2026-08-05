//go:build linux

package linux

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/policy"
	"github.com/whiskeyjimbo/bento/profile"
)

// buildExtraDeny turns caller paths into DenyAll shields: an existing regular file
// is shielded as a file, an existing directory and a not-yet-existing path as a
// directory (so a first-run store dir never leaves a host file artifact). Relative
// paths and a path resolving to the root are refused.
func TestBuildExtraDeny(t *testing.T) {
	sb := testSandbox("/home/u/store", "/home/u/store/perms.json", "/home/u/afile")

	rules, err := buildExtraDeny([]string{"/home/u/store", "/home/u/afile", "/home/u/absent"}, sb)
	if err != nil {
		t.Fatalf("buildExtraDeny: %v", err)
	}
	wantDir := map[string]bool{
		"/home/u/store":  true,  // existing directory
		"/home/u/afile":  false, // existing regular file
		"/home/u/absent": true,  // nonexistent -> directory default
	}
	if len(rules) != len(wantDir) {
		t.Fatalf("got %d rules, want %d", len(rules), len(wantDir))
	}
	for _, r := range rules {
		if r.Deny != denylist.DenyAll {
			t.Errorf("%s: Deny=%v, want DenyAll", r.Path, r.Deny)
		}
		if want, ok := wantDir[r.Path]; !ok {
			t.Errorf("unexpected rule for %q", r.Path)
		} else if r.Dir != want {
			t.Errorf("%s: Dir=%v, want %v", r.Path, r.Dir, want)
		}
	}

	if _, err := buildExtraDeny([]string{"relative/path"}, sb); err == nil {
		t.Error("a relative deny path must be refused")
	}
	if _, err := buildExtraDeny([]string{"/"}, sb); err == nil {
		t.Error("a deny path resolving to the root must be refused")
	}
	// denyArgs drops a rule that would take the whole grant surface, so accepting one
	// here would mean a caller's deny was honored in the API and never mounted.
	sb.homes = []string{"/home/u"}
	if _, err := buildExtraDeny([]string{"/home/u"}, sb); err == nil {
		t.Error("a deny path resolving to a home must be refused, not silently dropped later")
	}
}

// A dangling symlink deny path (Lstat sees the link, its target is absent) must be
// a DIRECTORY shield, classified by the resolved target - not a file shield, which
// would bind an empty file at the absent target and leave an uncleanable host
// artifact. Uses a hand-built sandbox because testSandbox has no symlinks.
func TestBuildExtraDenyDanglingSymlink(t *testing.T) {
	sb := sandbox{
		resolve: func(p string) string {
			if p == "/home/u/cfg/store" {
				return "/home/u/proj/data" // the (absent) symlink target
			}
			return p
		},
		exists: func(p string) bool { return p == "/home/u/cfg/store" }, // link exists, target absent
		isDir:  func(string) bool { return false },
	}
	rules, err := buildExtraDeny([]string{"/home/u/cfg/store"}, sb)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || !rules[0].Dir {
		t.Errorf("a dangling-symlink deny path must be a directory shield; got %+v", rules)
	}
}

// A write grant that contains a caller deny path must be refused loudly (its parent
// would be writable, letting the run tamper with the shield), the same as for a
// built-in shield.
func TestExtraDenyWriteAboveShieldRefused(t *testing.T) {
	sb := testSandbox()
	sb.extraDeny = []denylist.Rule{{Path: "/home/u/cfg/store", Deny: denylist.DenyAll, Dir: true}}

	if err := checkWriteNotAboveShield(sb, []string{"/home/u/cfg"}); err == nil {
		t.Error("a write grant containing an extra-deny path must be refused")
	}
	if err := checkWriteNotAboveShield(sb, []string{"/home/u/other"}); err != nil {
		t.Errorf("an unrelated write grant must be allowed: %v", err)
	}
}

// An absent caller-deny directory under a write grant is created by bwrap as a
// mount point, so it must be reported for cleanup or it leaves a host artifact.
func TestExtraDenyCreatedShieldDirCleaned(t *testing.T) {
	sb := testSandbox() // empty fake fs: the deny dir does not exist yet
	sb.extraDeny = []denylist.Rule{{Path: "/home/u/proj/store", Deny: denylist.DenyAll, Dir: true}}

	dirs, _ := createdShields(sb, []string{"/home/u/proj"}, []string{"/home/u/proj"}, nil)
	found := false
	for _, d := range dirs {
		if d == "/home/u/proj/store" {
			found = true
		}
	}
	if !found {
		t.Errorf("an absent extra-deny dir under a write grant must be in createdShields for cleanup; got %v", dirs)
	}
}

// A DenyAll store nested inside a DenyWrite readable tree (fish_history under the
// readable ~/.local/share/fish, kept readable so fish loads its functions and
// completions) must not be reachable by a write grant to a subdir - the grant that fires
// the parent's read-only bind, binding the whole subtree readable.
//
// That exposure is now closed one step earlier than it used to be: the write grant is
// refused outright, because a DenyWrite shield has no opt-in. The refusal is the stronger
// guarantee (nothing runs at all), so this asserts it rather than the leak. denyArgs'
// carve still orders the child's shield after the parent bind for the case where some
// future rule shape makes the parent reachable again - pinned by
// TestDenyAllChildEmittedAfterExposedDenyWriteParent, which drives denyArgs directly.
func TestNestedDenyAllUnderExposedParentIsRefused(t *testing.T) {
	requireSandbox(t)

	home := t.TempDir()
	t.Setenv("HOME", home)
	fish := filepath.Join(home, ".local/share/fish")
	if err := os.MkdirAll(fish, 0o700); err != nil {
		t.Fatal(err)
	}
	history := filepath.Join(fish, "fish_history")
	if err := os.WriteFile(history, []byte("FISH-HISTORY-SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(fish, "functions")
	populateWorkspaceTargets(t, sub)

	err := runScriptExpectingRefusal(t, &policy.Policy{Write: []string{sub}}, "cat "+history+" 2>&1 || true\n")
	if err == nil {
		t.Fatal("a write grant under the DenyWrite fish tree must be refused, not run")
	}
	if !strings.Contains(err.Error(), "no opt-in") {
		t.Errorf("the refusal must name the missing opt-in so the author knows it is not addable; got %v", err)
	}
}

// The same refusal reached through an env relocation rather than a built-in rule:
// GIT_CONFIG_GLOBAL pointed at ~/.local makes a DenyWrite rule whose real target is that
// whole directory, so a write anywhere under ~/.local is refused on this host and would
// be honored on one without the variable set. That environment-dependence is the point
// worth pinning - it is how the refusal reaches furthest beyond the built-in shields.
func TestRelocatedDenyWriteRefusesWriteUnderIt(t *testing.T) {
	requireSandbox(t)

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(home, ".local"))
	gh := filepath.Join(home, ".local", "share", "gh")
	if err := os.MkdirAll(gh, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gh, "hosts.yml"), []byte("GH-OAUTH-TOKEN-SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(home, ".local", "foo")
	populateWorkspaceTargets(t, sub)

	script := "cat " + filepath.Join(gh, "hosts.yml") + " 2>&1 || true\n"
	err := runScriptExpectingRefusal(t, &policy.Policy{Write: []string{sub}}, script)
	if err == nil {
		t.Fatal("a write under the relocated DenyWrite tree must be refused, not run")
	}
	if !strings.Contains(err.Error(), filepath.Join(home, ".local")) {
		t.Errorf("the refusal must name the relocated shield, or the author cannot tell why an ordinary path is refused; got %v", err)
	}
}

// populateWorkspaceTargets pre-creates every workspace shield target under a
// write-granted dir, so each becomes a ro-bind of an existing path rather than a tmpfs
// that would need mkdir inside a read-only parent bind (which aborts the run, masking the
// exposure under test).
func populateWorkspaceTargets(t *testing.T, dir string) {
	t.Helper()
	for _, d := range []string{filepath.Join(dir, ".git", "hooks"), filepath.Join(dir, ".vscode"), filepath.Join(dir, ".idea")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(dir, ".git", "config"), filepath.Join(dir, ".git", "config.worktree")} {
		if err := os.WriteFile(f, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// A profiling trial grants Read:["/"], so without a deny path the target reads a
// caller's own file; passing that file's directory as a DenyPath shields its
// contents (a tmpfs overmount), so the trial can no longer read it. The store
// lives under $HOME, not /tmp, because the sandbox always overmounts /tmp with its
// own tmpfs.
func TestProfileDenyPathsShieldsCallerStore(t *testing.T) {
	requireSandbox(t)

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	storeDir, err := os.MkdirTemp(home, "bento-denytest-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(storeDir)
	const secret = "TOPSECRET-STORE-CONTENTS"
	if err := os.WriteFile(filepath.Join(storeDir, "perms.json"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(script, []byte("cat "+filepath.Join(storeDir, "perms.json")+" 2>&1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{"/"}, Exec: policy.ExecAll}

	run := func(deny []string) (profile.Observation, string) {
		var out bytes.Buffer
		obs, err := sandboxEnforcer(t).Profile(context.Background(), p,
			enforce.Process{Stdout: &out, Stderr: &out}, false, deny, nil)
		if err != nil {
			t.Fatalf("Profile: %v", err)
		}
		return obs, out.String()
	}

	if _, base := run(nil); !strings.Contains(base, secret) {
		t.Fatalf("baseline: the trial should read the store with no deny path; got %q", base)
	}

	obs, shielded := run([]string{storeDir})
	if strings.Contains(shielded, secret) {
		t.Errorf("the deny path did not shield the store contents; leaked %q", shielded)
	}
	// The shield hides contents, not the access: the attempted open is still observed
	// (which is why the wrapper must still refuse a grant that would cover the store).
	observed := false
	for _, r := range obs.Reads {
		if strings.Contains(r, "perms.json") {
			observed = true
		}
	}
	if !observed {
		t.Errorf("the shielded store access should still appear in obs.Reads; got %v", obs.Reads)
	}
}

// The enforced run honors caller deny paths the same way the profiling run does: a
// read grant covering the store no longer reaches its contents, and the shield is
// reported so an audit shows the boundary engaged rather than assuming it.
func TestRunDenyPathsShieldsCallerStore(t *testing.T) {
	requireSandbox(t)

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	storeDir, err := os.MkdirTemp(home, "bento-denytest-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(storeDir)
	const secret = "TOPSECRET-ENFORCED-STORE"
	if err := os.WriteFile(filepath.Join(storeDir, "perms.json"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(script, []byte("cat "+filepath.Join(storeDir, "perms.json")+" 2>&1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{home}, Exec: policy.ExecAll}

	run := func(deny []string) (enforce.Result, string) {
		var out bytes.Buffer
		res, err := sandboxEnforcer(t).Run(context.Background(), p,
			enforce.Process{Stdout: &out, Stderr: &out}, enforce.RunOptions{DenyPaths: deny})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return res, out.String()
	}

	// Without the deny the home read grant reaches the store, which is the exposure
	// this option exists to close - if it did not, the shielded case below would pass
	// for the wrong reason.
	if _, base := run(nil); !strings.Contains(base, secret) {
		t.Fatalf("baseline: the home read grant should reach the store with no deny path; got %q", base)
	}

	res, shielded := run([]string{storeDir})
	if strings.Contains(shielded, secret) {
		t.Errorf("the deny path did not shield the store on the enforced run; leaked %q", shielded)
	}
	reported := false
	for _, s := range res.Shields {
		if s.Path == storeDir {
			reported = true
			if s.Kind != "hidden" {
				t.Errorf("Shields[%q].Kind = %q, want hidden", s.Path, s.Kind)
			}
		}
	}
	if !reported {
		t.Errorf("the caller deny is missing from Result.Shields; got %v", res.Shields)
	}
}

// The degraded tier applies no shields at all, so a caller deny it cannot honor is
// refused rather than silently dropped - the same call the tier already makes for a
// network gate it has no proxy for. Admitting the run and reporting the gap afterwards
// would hand back a target that had already read the caller's control state.
func TestRunDegradedRefusesDenyPaths(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/bin/true", Exec: policy.ExecAll}
	_, err := New().Run(context.Background(), p, enforce.Process{},
		enforce.RunOptions{Degraded: true, DenyPaths: []string{"/home/u/store"}})
	if err == nil {
		t.Fatal("a degraded run with caller deny paths must be refused")
	}
	if !strings.Contains(err.Error(), "deny path") {
		t.Errorf("error = %v, want it to name the caller deny paths as the reason", err)
	}
}

// denylist.Shieldable is lexical, so a relocation whose target only reaches a home
// through a symlink passes it and arrives here as a rule on the whole home - a tmpfs
// over the grant surface, with the run failing for no stated reason. The same test on
// the resolved paths is what catches it.
func TestSymlinkedRelocationOntoAHomeIsNotShielded(t *testing.T) {
	sb := testSandbox("/export/home/u", "/export/home/u/work")
	sb.homes = []string{"/export/home/u"}
	// The passwd entry is /export/home/u and /home is a symlink to /export/home.
	sb.resolve = func(p string) string {
		if after, ok := strings.CutPrefix(p, "/home/"); ok {
			return "/export/home/" + after
		}
		return p
	}
	// What GNUPGHOME=/home/u produces: Shieldable saw no lexical relation to the anchor.
	sb.extraDeny = []denylist.Rule{{Path: "/home/u", Deny: denylist.DenyAll, Dir: true}}

	args, _ := denyArgs(sb, []string{"/export/home/u"}, nil, nil)
	if has(args, "--tmpfs", "/export/home/u") {
		t.Errorf("a shield resolving onto the home must be dropped, not mounted over it: %v", args)
	}
}

// ...and the drop must stay narrow. denylist exempts its base store rules from the same
// guard on purpose: where a caller's $HOME is itself a credential store, beside a passwd
// home that contains it, the store's own rule equals a home anchor. Dropping that rule
// unshields the credentials it exists to hide - the opposite of what the guard is for.
func TestAStoreThatIsAlsoAHomeAnchorStaysShielded(t *testing.T) {
	sb := testSandbox("/home/u/.aws", "/home/u/.aws/credentials")
	sb.homes = []string{"/home/u/.aws", "/home/u"}

	args, _ := denyArgs(sb, []string{"/home/u"}, nil, nil)
	if !has(args, "--tmpfs", "/home/u/.aws") {
		t.Errorf("a credential store that coincides with a home anchor must still be shielded: %v", args)
	}
}

// Rule carries fields that only describe a shield to a reader - which store it holds, and
// (once the diagnostic lands) which env var relocated it. Two rules differing in nothing
// else bind identically, so the dedup must collapse them: keying it on the whole rule
// would emit the same bind twice and let a report-only field change what is enforced.
func TestRulesDifferingOnlyInDescriptionBindOnce(t *testing.T) {
	sb := testSandbox("/home/u", "/home/u/store")
	sb.homes = []string{"/home/u"}
	sb.extraDeny = []denylist.Rule{
		{Path: "/home/u/store", Deny: denylist.DenyAll, Dir: true, Holds: denylist.HoldsCredentials},
		{Path: "/home/u/store", Deny: denylist.DenyAll, Dir: true, Holds: denylist.HoldsHistory},
	}

	args, _ := denyArgs(sb, []string{"/home/u"}, nil, nil)
	n := 0
	for _, a := range args {
		if a == "/home/u/store" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("one shielded path must bind once; got %d binds in %v", n, args)
	}
}

// A deny-list dotfile whose host symlink resolves to the root must not refuse every
// grant on the host. denyArgs drops such a rule rather than shielding the whole root,
// so refusing here would blame an unrelated dotfile for a shield that was never
// applied - and CoversResolved("/", g) is true for every absolute grant, so it would
// refuse every run in both tiers.
func TestShieldResolvingToRootDoesNotRefuseGrants(t *testing.T) {
	sb := testSandbox()
	sb.resolve = func(p string) string {
		if p == "/home/u/.gnupg" {
			return "/"
		}
		return p
	}

	if err := checkReadNotShielded(sb, []string{"/work"}, nil); err != nil {
		t.Errorf("a shield resolving to the root must not refuse an unrelated grant: %v", err)
	}
	// The other shields still bite: this must not have disarmed the check itself.
	if err := checkReadNotShielded(sb, []string{"/home/u/.ssh"}, nil); err == nil {
		t.Error("a grant inside a shield that resolves normally must still be refused")
	}
}
