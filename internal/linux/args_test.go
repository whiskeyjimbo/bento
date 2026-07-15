package linux

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/internal/enforce"
	"github.com/whiskeyjimbo/bento-v2/internal/policy"
)

// testSandbox compiles argv against a hypothetical filesystem, so the
// security-critical argv decisions can be asserted without launching anything.
func testSandbox(existing ...string) sandbox {
	set := make(map[string]bool, len(existing))
	for _, p := range existing {
		set[p] = true
	}
	return sandbox{
		home:       "/home/u",
		emptyFile:  "/tmp/shield",
		entrypoint: "/work/run.py",
		exists:     func(p string) bool { return set[p] },
		// A path is a directory if the fake filesystem has an entry strictly under
		// it; a leaf entry is a file. This lets a write grant that is a project
		// directory get its workspace shields while a plain-file grant does not.
		isDir: func(p string) bool {
			for e := range set {
				if e != p && under(e, p) {
					return true
				}
			}
			return false
		},
		rootDirs: func() []string { return []string{"/usr", "/home", "/etc"} },
	}
}

func compileOrFail(t *testing.T, p *policy.Policy, sb sandbox) []string {
	t.Helper()
	args, err := compile(p, enforce.Process{}, sb)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
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
	p := &policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/home/u"}}
	args := compileOrFail(t, p, testSandbox())

	grant := pairIndex(args, "--bind-try", "/home/u")
	shield := pairIndex(args, "--tmpfs", "/home/u/.ssh")
	if grant < 0 || shield < 0 {
		t.Fatalf("expected both a $HOME grant and a ~/.ssh shield; grant=%d shield=%d", grant, shield)
	}
	if shield < grant {
		t.Error("deny-list is applied before the grant, so the grant would win and re-expose ~/.ssh")
	}
}

// A broad grant must shield credential directories even when they do not exist
// on the host: otherwise a script can create ~/.ssh and plant a key. This is the
// v1 hole.
func TestUnbornCredentialDirIsShielded(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/home/u"}}
	// Note: ~/.ssh is deliberately absent from the fake filesystem.
	args := compileOrFail(t, p, testSandbox())

	if !has(args, "--tmpfs", "/home/u/.ssh") {
		t.Error("a credential directory that does not exist yet must still be shielded")
	}
}

// Likewise an unborn shell profile: a script must not be able to create ~/.bashrc
// and gain persistence.
func TestUnbornShellProfileIsShielded(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/home/u"}}
	args := compileOrFail(t, p, testSandbox())

	if !has(args, "--ro-bind", "/tmp/shield") {
		t.Error("an unborn write-denied file must be shielded by an empty read-only file")
	}
	i := pairIndex(args, "--ro-bind", "/tmp/shield")
	if i < 0 || args[i+2] != "/home/u/.bashrc" {
		// Find the specific .bashrc shield.
		found := false
		for j := 0; j+2 < len(args); j++ {
			if args[j] == "--ro-bind" && args[j+1] == "/tmp/shield" && args[j+2] == "/home/u/.bashrc" {
				found = true
			}
		}
		if !found {
			t.Error("~/.bashrc was not shielded against creation")
		}
	}
}

// A write-denied file that DOES exist stays readable. v1 shadowed these with
// /dev/null, which also destroyed reads and left git seeing an empty config.
func TestExistingWriteDeniedFileStaysReadable(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/home/u"}}
	sb := testSandbox("/home/u/.gitconfig")
	args := compileOrFail(t, p, sb)

	found := false
	for j := 0; j+2 < len(args); j++ {
		if args[j] == "--ro-bind" && args[j+1] == "/home/u/.gitconfig" && args[j+2] == "/home/u/.gitconfig" {
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

// Write grants are directory-granular: binding a file makes it a mount point,
// which breaks save-via-rename. A grant naming an existing file is refused,
// pointing the user at the directory.
func TestFileWriteGrantIsRejected(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/work/out.txt"}}
	sb := testSandbox("/work/out.txt") // exists as a file (no children)
	_, err := compile(p, enforce.Process{}, sb)
	if err == nil {
		t.Fatal("a write grant naming an existing file should be rejected")
	}
	if !strings.Contains(err.Error(), "parent directory") {
		t.Errorf("error = %v, want it to point at the parent directory", err)
	}
}

// A read-only grant already makes a write-denied path unwritable, so no shield
// mount is needed — and adding one over a read-only parent would abort bwrap.
func TestReadOnlyDenyWritePathIsNotShielded(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/home/u"}}
	sb := testSandbox("/home/u/.gitconfig")
	args := compileOrFail(t, p, sb)

	if has(args, "--ro-bind", "/home/u/.gitconfig") {
		t.Error("a write-denied file reached only by a read grant needs no shield: the read-only bind already blocks writes")
	}
}

// A "/" read grant must bind the root's children individually, never the host
// root onto the sandbox root — and never the mounts baseFlags manages, or the
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

// A grant inside an always-shielded directory cannot be honored, so it must be a
// hard error rather than silently vanishing behind the shield.
func TestGrantInsideShieldedPathIsRejected(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/home/u/.ssh/pubkeys"}}
	_, err := compile(p, enforce.Process{}, testSandbox())
	if err == nil {
		t.Fatal("a grant inside ~/.ssh should be rejected, not silently dropped")
	}
	if !strings.Contains(err.Error(), "always-shielded") {
		t.Errorf("error = %v, want it to explain the shield conflict", err)
	}
}

// A grant that merely contains a shielded path is the normal case and must be
// allowed: the shield is applied inside it.
func TestGrantContainingShieldedPathIsAllowed(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/home/u"}}
	if _, err := compile(p, enforce.Process{}, testSandbox()); err != nil {
		t.Fatalf("granting $HOME (with ~/.ssh shielded inside) should be allowed: %v", err)
	}
}

func TestEnvIsClearedAndAllowlistApplied(t *testing.T) {
	proc := enforce.Process{Env: map[string]string{"LANG": "C", "TOKEN": "abc"}}
	args, err := compile(&policy.Policy{Entrypoint: "/work/run.py"}, proc, testSandbox())
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

func TestUnderPathContainment(t *testing.T) {
	cases := []struct {
		child, parent string
		want          bool
	}{
		{"/home/u/.ssh", "/home/u", true},
		{"/home/u", "/home/u", true},
		{"/home/user2", "/home/u", false}, // prefix-string trap: must not match
		{"/tmp", "/home/u", false},
	}
	for _, tc := range cases {
		if got := under(tc.child, tc.parent); got != tc.want {
			t.Errorf("under(%q, %q) = %v, want %v", tc.child, tc.parent, got, tc.want)
		}
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
