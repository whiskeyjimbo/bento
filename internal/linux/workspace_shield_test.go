//go:build linux

package linux

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/policy"
)

// A write grant whose per-workspace shield is redirected by a symlinked directory
// component must be refused: the shield would bind at the resolved path while the
// tooling opens the literal name, and the symlink - inside the writable grant - lets
// the target plant a real hook/task that runs on the host. Both an escape
// out of the grant and a redirect within it leave the literal name unshielded.
func TestWorkspaceShieldRedirectRefused(t *testing.T) {
	for name, target := range map[string]string{
		"escapes the grant":      "/outside/.git",
		"redirects within grant": "/work/realgit",
	} {
		t.Run(name, func(t *testing.T) {
			sb := testSandbox("/work/.git/hooks") // an entry under /work makes it a workspace dir
			base := sb.resolve
			sb.resolve = func(p string) string {
				if p == "/work/.git" {
					return target
				}
				if strings.HasPrefix(p, "/work/.git/") {
					return target + strings.TrimPrefix(p, "/work/.git")
				}
				return base(p)
			}
			p := &policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/work"}}
			if _, _, err := compile(p, enforce.Process{}, sb); err == nil {
				t.Fatalf("a write grant whose .git shield is redirected (%s) must be refused", name)
			}
		})
	}
}

// The redirect check must run against the real pathresolve.Existing, which is identity on
// a symlink-free path - so a normal project checkout is NOT over-refused (the trap:
// a check that fired on every clean grant would pass the identity-double tests while
// breaking production). And a real symlinked .git that escapes the grant IS refused.
func TestWorkspaceShieldRealFilesystem(t *testing.T) {
	realSB := func(entrypoint string) sandbox {
		return sandbox{
			homes:      []string{"/home/does-not-exist"},
			emptyFile:  "/dev/null",
			bentoPath:  "/dev/null",
			entrypoint: entrypoint,
			exists:     hostExists,
			isDir:      hostIsDir,
			listDir:    hostListDir,
			resolve:    hostResolve,
			rootDirs:   func() ([]string, error) { return nil, nil },
		}
	}

	t.Run("symlink-free project is not over-refused", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, ".git", "hooks"), 0o755); err != nil {
			t.Fatal(err)
		}
		entry := filepath.Join(root, "run.py")
		if err := os.WriteFile(entry, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		p := &policy.Policy{Entrypoint: entry, Write: []string{root}}
		if _, _, err := compile(p, enforce.Process{}, realSB(entry)); err != nil {
			t.Fatalf("a real symlink-free project write grant must not be refused: %v", err)
		}
	})

	t.Run("real symlinked .git escaping the grant is refused", func(t *testing.T) {
		root := t.TempDir()
		outside := t.TempDir()
		if err := os.MkdirAll(filepath.Join(outside, "hooks"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(root, ".git")); err != nil {
			t.Fatal(err)
		}
		entry := filepath.Join(root, "run.py")
		if err := os.WriteFile(entry, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		p := &policy.Policy{Entrypoint: entry, Write: []string{root}}
		if _, _, err := compile(p, enforce.Process{}, realSB(entry)); err == nil {
			t.Fatal("a write grant whose real .git is a symlink escaping the grant must be refused")
		}
	})
}

// A dotfile farm (stow, chezmoi, yadm) keeps ~/.ssh as a real directory whose entries
// are symlinks into ~/dotfiles. The shield binds over ~/.ssh, so the link dangles inside
// the sandbox - but the target it names is covered by no rule and is read in full under
// a grant of the home. A whole store symlinked at its own path (~/.netrc) was always
// chased; this is the same store one level down.
func TestSymlinkedCredentialInsideADirectoryShieldIsShielded(t *testing.T) {
	home := t.TempDir()
	canon, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(canon, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(canon, "dotfiles", "ssh"), 0o755); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(canon, "dotfiles", "ssh", "id_rsa")
	if err := os.WriteFile(key, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(key, filepath.Join(canon, ".ssh", "id_rsa")); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(canon, "run.py")
	if err := os.WriteFile(entry, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	sb := sandbox{
		homes:      []string{canon},
		emptyFile:  "/dev/null",
		bentoPath:  "/dev/null",
		entrypoint: entry,
		exists:     hostExists,
		isDir:      hostIsDir,
		listDir:    hostListDir,
		resolve:    hostResolve,
		rootDirs:   func() ([]string, error) { return nil, nil },
	}
	args, _, err := compile(&policy.Policy{Entrypoint: entry, Read: []string{canon}}, enforce.Process{}, sb)
	if err != nil {
		t.Fatalf("a read grant over a home with a symlinked credential must not be refused: %v", err)
	}
	// The pair, not just the path: a --ro-bind of the key onto itself would also put the
	// string in the argv while leaving the real key readable.
	if i := slices.Index(args, key); i < 3 || args[i-2] != "--ro-bind" || args[i-1] != sb.emptyFile {
		t.Errorf("the argv does not blank %q with the empty file: %v", key, args)
	}

	// The shield must stay opt-in-able by the path it is mounted at. A rule the opt-in
	// machinery cannot see refuses the grant that names it and then offers that same
	// grant as the remedy - which is why the rule names the target and not the link.
	p := &policy.Policy{Entrypoint: entry, Read: []string{canon, key}}
	optedIn, applied, err := compile(p, enforce.Process{}, sb)
	if err != nil {
		t.Fatalf("a read grant naming the shielded target must opt in, not be refused: %v", err)
	}
	if i := slices.Index(optedIn, key); i < 1 || i+1 >= len(optedIn) || optedIn[i-1] != "--ro-bind-try" || optedIn[i+1] != key {
		t.Errorf("the opted-in key is not bound as itself: %v", optedIn)
	}
	// The store around it stays shielded: opting into one file is not opting into ~/.ssh.
	if len(applied) != 1 || applied[0].Path != filepath.Join(canon, ".ssh") {
		t.Errorf("applied shields = %v, want only the store itself", applied)
	}
}

// farmHome builds the ordinary dotfile-farm shape: ~/.ssh a real directory whose id_rsa
// links into ~/dotfiles, plus n unrelated entries in the store so the walk has real work.
// It returns the canonical home and the key's target path.
func farmHome(tb testing.TB, n int) (home, key string) {
	root := tb.TempDir()
	canon, err := filepath.EvalSymlinks(root)
	if err != nil {
		tb.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(canon, "dotfiles", "ssh"), 0o755); err != nil {
		tb.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(canon, ".ssh"), 0o700); err != nil {
		tb.Fatal(err)
	}
	key = filepath.Join(canon, "dotfiles", "ssh", "id_rsa")
	if err := os.WriteFile(key, []byte("k"), 0o600); err != nil {
		tb.Fatal(err)
	}
	if err := os.Symlink(key, filepath.Join(canon, ".ssh", "id_rsa")); err != nil {
		tb.Fatal(err)
	}
	for i := range n {
		if err := os.WriteFile(filepath.Join(canon, ".ssh", fmt.Sprintf("known_hosts.%d", i)), []byte("h"), 0o600); err != nil {
			tb.Fatal(err)
		}
	}
	return canon, key
}

// The memo's whole claim is that it changes nothing a caller can see. Unlike the
// workspace one it has no key, so the check that matters is that repeated calls keep
// answering what the uncached walk answers.
func TestCredentialLinkCacheIsTransparent(t *testing.T) {
	canon, _ := farmHome(t, 4)
	sb := sandbox{
		homes:     []string{canon},
		emptyFile: "/dev/null",
		exists:    hostExists,
		isDir:     hostIsDir,
		listDir:   hostListDir,
		resolve:   hostResolve,
	}
	cached := sb
	cached.credentialLinkCache = &credentialLinkMemo{}
	for range 3 {
		want, got := alwaysShields(sb), alwaysShields(cached)
		if !slices.Equal(want, got) {
			t.Fatalf("cached shields differ from the uncached walk\n got %v\nwant %v", got, want)
		}
	}

	// The memo is unkeyed, so what would break it is a second consumer whose input is
	// not the built-in set: it would get the built-in answer back with nothing to say
	// so. The opt-in machinery is that second consumer - a derived shield it cannot see
	// is one a policy can only be refused over - so it has to reach the same rules the
	// shields do, on a warm memo as much as a cold one.
	derived := credentialLinkShields(cached)
	if len(derived) == 0 {
		t.Fatal("the farm produced no derived shield, so the rest of this proves nothing")
	}
	for _, r := range derived {
		if !slices.ContainsFunc(explicitShieldOptIns(cached, []string{r.Path}), func(o shieldOptIn) bool { return o.path == r.Path }) {
			t.Errorf("the derived shield at %q cannot be opted into, so a read grant naming it is only refusable", r.Path)
		}
	}

	// A caller deny is not part of the expansion's input and must not be swallowed by a
	// warm memo either.
	withDeny := cached
	withDeny.extraDeny = []denylist.Rule{{Path: "/srv/state", Deny: denylist.DenyAll, Dir: true}}
	if !slices.ContainsFunc(alwaysShields(withDeny), func(r denylist.Rule) bool { return r.Path == "/srv/state" }) {
		t.Error("a caller deny is missing from the shields once the memo is warm")
	}
}

// The derived link-target rules are DenyAll FILE rules, so credentialFiles picks them up
// as alias-scan roots alongside the deny-list's own hidden files. That is what the scan is
// for - the farm copy IS the credential, and a second readable name for it defeats the
// shield exactly as one for ~/.ssh/id_rsa would - but it fell out of where the expansion
// was hoisted to rather than being chosen, so it is pinned here.
func TestSymlinkedCredentialTargetIsAnAliasScanRoot(t *testing.T) {
	canon, key := farmHome(t, 0)
	sb := sandbox{
		homes:     []string{canon},
		emptyFile: "/dev/null",
		exists:    hostExists,
		isDir:     hostIsDir,
		listDir:   hostListDir,
		resolve:   hostResolve,
		fileIDs:   hostFileIDs,
	}
	// A second readable name for the farm copy, outside every store.
	alias := filepath.Join(canon, "copy_of_key")
	if err := os.Link(key, alias); err != nil {
		t.Skipf("hard link unsupported here: %v", err)
	}
	files, _, err := credentialFiles(sb, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(files, func(f identifiedFile) bool { return f.path == key }) {
		t.Errorf("the symlinked credential's target %q is not an alias-scan root: %v", key, files)
	}
}

// BenchmarkCredentialLinkWalk measures one compile's worth of alwaysShields calls over a
// home with a populated credential store. The walk is isDir/listDir/resolve per entry and
// the call count is fixed by the callers, so the memo is the whole difference.
func BenchmarkCredentialLinkWalk(b *testing.B) {
	canon, _ := farmHome(b, 64)
	sb := sandbox{
		homes:     []string{canon},
		emptyFile: "/dev/null",
		exists:    hostExists,
		isDir:     hostIsDir,
		listDir:   hostListDir,
		resolve:   hostResolve,
	}
	run := func(b *testing.B, memo bool) {
		for b.Loop() {
			sb := sb
			if memo {
				// Fresh per iteration: the memo is a one-run cache, so carrying it across
				// iterations would measure a hit rate no run ever sees.
				sb.credentialLinkCache = &credentialLinkMemo{}
			}
			for range 10 {
				alwaysShields(sb)
			}
		}
	}
	b.Run("nomemo", func(b *testing.B) { run(b, false) })
	b.Run("memo", func(b *testing.B) { run(b, true) })
}
