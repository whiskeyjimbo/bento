//go:build linux

package linux

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/policy"
)

// The grant checks: which grants a run refuses and in whose words, plus the resolution
// every one of them compares against. What a run SHIELDS rather than refuses is in
// shields_test.go.

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
