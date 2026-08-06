//go:build linux

package linux

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/policy"
)

// Red-team regression corpus: each test is a named escape attempt the boundary must
// defeat, kept together so a documented bypass class cannot regress silently. Most
// escape classes are already asserted where their defense lives - symlink relocation
// and grant-inside-shield in sandbox_test.go (TestGrantOnSymlinkedShieldTargetIsRejected,
// TestSymlinkedGrantDoesNotAliasPastShield), /proc grants (TestProcessPathGrantIsRefused),
// inherited-fd forgery (TestInheritedFdContentUnreadable, TestSupervisorFdPathNotDisclosed),
// read:/ exposure (TestReadRootDoesNotExposeHostRuntime plus the shield_fuzz oracle),
// and the /run socket shield (denylist TestRuntimeShieldsHostSockets). This file holds
// the classes that had no coverage, including the default-deny inversion's keystone at
// enforce time: a narrow grant must not expose an ungranted sibling, directly or via a
// path-traversal trick (TestGrantDoesNotExposeUngrantedSibling,
// TestTraversalCannotEscapeGrantToSibling), each with a positive control.

// Default-deny's keystone at enforce time: granting one path under home must not drag
// in an ungranted sibling. The inversion rests on a forgotten path failing
// closed - absent - rather than leaking, so a narrow grant beside a secret must leave
// the secret unreachable. The positive control grants the whole home and reads the
// same secret, proving it is real and reachable and that the narrow grant - not a
// broken read - is what isolates it (.mytoken is not a deny-list shield, so a home
// grant does expose it; the shield classes are covered separately).
func TestGrantDoesNotExposeUngrantedSibling(t *testing.T) {
	requireSandbox(t)

	home := t.TempDir()
	t.Setenv("HOME", home)
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(home, ".mytoken") // ungranted, non-shielded sibling of the grant
	if err := os.WriteFile(secret, []byte("SIBLING-SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, out := runScript(t, &policy.Policy{Read: []string{proj}}, "cat "+secret+" 2>&1 || true\n"); strings.Contains(out, "SIBLING-SECRET") {
		t.Fatalf("a narrow grant of %q exposed the ungranted sibling %q: %q", proj, secret, out)
	}

	if _, ctrl := runScript(t, &policy.Policy{Read: []string{home}}, "cat "+secret+" 2>&1 || true\n"); !strings.Contains(ctrl, "SIBLING-SECRET") {
		t.Fatalf("positive control: a home grant should expose the non-shielded sibling, but did not: %q", ctrl)
	}
}

// The same isolation must hold against path tricks, not just a direct read: from
// inside a granted tree, parent traversal, /proc/self/root re-rooting, and a symlink
// planted in the granted dir that points back out at the sibling must all resolve to
// nothing. The positive control reads the sibling through /proc/self/root under a home
// grant, so a green result is a real boundary and not a probe that never reached it.
func TestTraversalCannotEscapeGrantToSibling(t *testing.T) {
	requireSandbox(t)

	home := t.TempDir()
	t.Setenv("HOME", home)
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(home, ".mytoken")
	if err := os.WriteFile(secret, []byte("SIBLING-SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A write grant so the target can plant the escaping symlink itself, the way an
	// attacker-controlled script would.
	link := filepath.Join(proj, "link")
	body := "cat " + filepath.Join(proj, "..", ".mytoken") + " 2>&1 || true\n" +
		"cat /proc/self/root" + secret + " 2>&1 || true\n" +
		"ln -s " + secret + " " + link + " 2>/dev/null; cat " + link + " 2>&1 || true\n"
	if _, out := runScript(t, &policy.Policy{Write: []string{proj}}, body); strings.Contains(out, "SIBLING-SECRET") {
		t.Fatalf("a path-traversal trick escaped the grant to the ungranted sibling: %q", out)
	}

	if _, ctrl := runScript(t, &policy.Policy{Read: []string{home}}, "cat /proc/self/root"+secret+" 2>&1 || true\n"); !strings.Contains(ctrl, "SIBLING-SECRET") {
		t.Fatalf("positive control: a /proc/self/root read under a home grant should expose the sibling: %q", ctrl)
	}
}

// A sandboxed program must not be able to un-shield a credential by hardlinking its
// path: the credential store is tmpfs'd (DenyAll dir) or overmounted with an empty
// file, so the real inode is never present inside the sandbox for `ln` to reach.
// This is the adversary-reachable half of the hardlink class; the host-created-alias
// half is a known residual (see TestHardlinkAliasInGrantedTreeLeaks_KnownResidual).
func TestInSandboxHardlinkCannotUnshieldCredential(t *testing.T) {
	requireSandbox(t)

	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".aws"), 0o700); err != nil {
		t.Fatal(err)
	}
	creds := filepath.Join(home, ".aws", "credentials")
	if err := os.WriteFile(creds, []byte("SECRETKEY"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Try every way a script might alias the shielded path back to a readable one.
	_, out := runScript(t, &policy.Policy{Read: []string{home}},
		"ln "+creds+" /tmp/hard 2>&1; cp -l "+creds+" /tmp/hard2 2>&1; "+
			"cat /tmp/hard /tmp/hard2 "+creds+" 2>&1; echo done\n")

	if strings.Contains(out, "SECRETKEY") {
		t.Fatalf("credential recovered through an in-sandbox hardlink: %q", out)
	}
}

// KNOWN RESIDUAL, tracked separately: a bind-mount shield protects a PATH, not the
// inode, so a host-created hardlink (or bind alias, or reflink) to a credential that
// sits inside a granted tree exposes the content, silently. The sandboxed program
// cannot create the alias itself (the test above shows the real inode is never
// visible to it), so this requires a host-created link - but it is unwarned, which is
// what makes it worth tracking. Skipped rather than asserted: a green test that
// confirmed the leak persists would bake the vulnerability in. It flips to a defense
// assertion the day inode-aware shielding (or an nlink>1 warning) lands.
func TestHardlinkAliasInGrantedTreeLeaks_KnownResidual(t *testing.T) {
	t.Skip("known residual: path-based shields miss inode aliases; see the hardlink/alias shield bead")

	requireSandbox(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	_ = os.MkdirAll(filepath.Join(home, ".aws"), 0o700)
	creds := filepath.Join(home, ".aws", "credentials")
	_ = os.WriteFile(creds, []byte("SECRETKEY"), 0o600)
	proj := filepath.Join(home, "proj")
	_ = os.MkdirAll(proj, 0o755)
	if err := os.Link(creds, filepath.Join(proj, "innocent.txt")); err != nil {
		t.Fatal(err)
	}

	_, out := runScript(t, &policy.Policy{Read: []string{home}},
		"cat "+filepath.Join(proj, "innocent.txt")+" 2>&1\n")
	if strings.Contains(out, "SECRETKEY") {
		t.Fatal("hardlink alias exposed the credential (expected once this residual is fixed)")
	}
}
