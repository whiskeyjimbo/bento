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

	dirs := createdShieldDirs(sb, []string{"/home/u/proj"}, []string{"/home/u/proj"}, nil)
	found := false
	for _, d := range dirs {
		if d == "/home/u/proj/store" {
			found = true
		}
	}
	if !found {
		t.Errorf("an absent extra-deny dir under a write grant must be in createdShieldDirs for cleanup; got %v", dirs)
	}
}

// A DenyAll store nested inside a DenyWrite readable tree (fish_history under the
// readable ~/.local/share/fish, kept readable so fish loads its functions and
// completions) must stay hidden even when a grant fires the parent's read-only bind. A
// write grant to a subdir - the kind of grant the readable tree exists to permit - makes
// the parent's ro-bind fire, which binds the whole subtree readable and would otherwise
// re-expose the hidden store.
//
// The write-granted subdir is pre-populated with every workspace shield target
// (.git/hooks, .vscode, ...) so each becomes a ro-bind of an existing path rather than
// a tmpfs that would need mkdir inside the now-readonly parent (which aborts the run):
// this is the shape that reaches the exposure instead of failing closed by accident.
// With no read grant, the DenyAll child is not independently reachable, so the shield
// is emitted only because a DenyWrite ancestor's bind would otherwise expose it.
func TestNestedDenyAllHiddenUnderExposedParent(t *testing.T) {
	requireSandbox(t)

	home := t.TempDir()
	t.Setenv("HOME", home)
	fish := filepath.Join(home, ".local/share/fish")
	if err := os.MkdirAll(fish, 0o700); err != nil {
		t.Fatal(err)
	}
	const secret = "FISH-HISTORY-SECRET"
	history := filepath.Join(fish, "fish_history")
	if err := os.WriteFile(history, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(fish, "functions")
	populateWorkspaceTargets(t, sub)

	_, out := runScript(t, &policy.Policy{Write: []string{sub}}, "cat "+history+" 2>&1 || true\n")
	if strings.Contains(out, secret) {
		t.Errorf("the fish history store leaked through the parent bind: %q", out)
	}
}

// A DenyWrite rule whose real target is a directory (an env relocation like
// GIT_CONFIG_GLOBAL pointed at ~/.local) ro-binds that whole tree read-only, so a
// DenyAll store nested inside it (the gh OAuth token dir at ~/.local/share/gh) must stay
// hidden. The carve keys on the real filesystem kind, not the declared Rule.Dir, so this
// file-declared rule is treated as the directory bind it actually is.
func TestFileRuleOverDirDoesNotExposeNestedStore(t *testing.T) {
	requireSandbox(t)

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(home, ".local"))
	gh := filepath.Join(home, ".local", "share", "gh")
	if err := os.MkdirAll(gh, 0o700); err != nil {
		t.Fatal(err)
	}
	const secret = "GH-OAUTH-TOKEN-SECRET"
	if err := os.WriteFile(filepath.Join(gh, "hosts.yml"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(home, ".local", "foo")
	populateWorkspaceTargets(t, sub)

	_, out := runScript(t, &policy.Policy{Write: []string{sub}}, "cat "+filepath.Join(gh, "hosts.yml")+" 2>&1 || true\n")
	if strings.Contains(out, secret) {
		t.Errorf("the gh token store leaked through the relocated-config parent bind: %q", out)
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
			enforce.Process{Stdout: &out, Stderr: &out}, false, deny)
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
