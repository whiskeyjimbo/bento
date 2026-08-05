//go:build linux

package linux

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// A write grant whose per-workspace shield is redirected by a symlinked directory
// component must be refused: the shield would bind at the resolved path while the
// tooling opens the literal name, and the symlink - inside the writable grant - lets
// the target plant a real hook/task that runs on the host (bv2-1z8). Both an escape
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
