package linux

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/policy"
)

// Red-team regression corpus: each test is a named escape attempt the boundary must
// defeat, kept together so a documented bypass class cannot regress silently. Most
// escape classes are already asserted where their defense lives - symlink relocation
// and grant-inside-shield in sandbox_test.go (TestGrantOnSymlinkedShieldTargetIsRejected,
// TestSymlinkedGrantDoesNotAliasPastShield), /proc grants (TestProcessPathGrantIsRefused),
// inherited-fd forgery (TestInheritedFdContentUnreadable, TestSupervisorFdPathNotDisclosed),
// read:/ exposure (TestReadRootDoesNotExposeHostRuntime plus the shield_fuzz oracle),
// and the /run socket shield (denylist TestRuntimeShieldsHostSockets). This file holds
// the classes that had no coverage.

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
