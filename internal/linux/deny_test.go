package linux

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/enforce"
	"github.com/whiskeyjimbo/bento-v2/internal/denylist"
	"github.com/whiskeyjimbo/bento-v2/policy"
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

	run := func(deny []string) string {
		var out bytes.Buffer
		if _, err := sandboxEnforcer(t).Profile(context.Background(), p,
			enforce.Process{Stdout: &out, Stderr: &out}, false, deny); err != nil {
			t.Fatalf("Profile: %v", err)
		}
		return out.String()
	}

	if base := run(nil); !strings.Contains(base, secret) {
		t.Fatalf("baseline: the trial should read the store with no deny path; got %q", base)
	}
	if shielded := run([]string{storeDir}); strings.Contains(shielded, secret) {
		t.Errorf("the deny path did not shield the store; leaked %q", shielded)
	}
}
