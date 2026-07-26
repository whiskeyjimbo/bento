package linux

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// Every filesystem defense rests on one assumption that nothing in bento enforces:
// that a program inside the sandbox cannot clear the read-only flag on a mount. The
// credential shields and the read-only root are plain read-only binds, and bento's own
// layers do not stop a mount(2) - the exec filter blocks only execve/execveat, Landlock
// has no mount hook, and the cross-process block is degraded-tier only. What stops it is
// the target having no CAP_SYS_ADMIN plus the kernel's lock on a read-only bind. That was
// asserted in a comment and checked on one kernel; here it is exercised on whatever
// kernel actually runs the suite, because if it is ever false every shield is writable
// while the run still reports the filesystem layer enforced.
//
// buildMountProbe compiles a CGO-free helper that attempts the remount on each target it
// is given and then reports whether the path is writable afterwards. The write is what
// the assertions turn on: a refused mount(2) is only interesting if the path also stayed
// unwritable, and a path that ends up writable is a breach however the mount call went.
func buildMountProbe(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		skipMissingDep(t, "go toolchain not available to build the probe")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "probe.go")
	const prog = `package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func main() {
	for _, target := range os.Args[1:] {
		mount := "MOUNT_REFUSED"
		if err := syscall.Mount("", target, "", syscall.MS_REMOUNT|syscall.MS_BIND, ""); err == nil {
			mount = "MOUNT_CLEARED"
		}
		write := "UNWRITABLE"
		probe := filepath.Join(target, "bento-remount-probe")
		if f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			f.Close()
			os.Remove(probe)
			write = "WRITABLE"
		}
		fmt.Printf("%s %s %s\n", target, mount, write)
	}
}
`
	if err := os.WriteFile(src, []byte(prog), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "mountprobe")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", bin, src)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=", "HOME="+toolchainHome)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building mount probe: %v\n%s", err, out)
	}
	return bin
}

// The claim bites hardest on a DenyWrite shield, so that is what this targets. A DenyAll
// shield hides its path behind an empty stand-in, and a write there lands in the stand-in
// and never reaches the credential - clearing its read-only flag wins the attacker
// nothing. A DenyWrite shield is the opposite: a read-only bind over the real host
// directory, kept readable on purpose, where the only thing between the target and
// planting a file the host later runs is that read-only flag. ~/.vim is one of those
// (its plugin and autoload trees are sourced on the next vim start).
//
// The granted write directory is the control: the same probe reports it WRITABLE, proving
// the probe can tell the difference and that the sandbox is not simply read-only
// everywhere. Without it, UNWRITABLE on the shield would be unremarkable.
func TestShieldsSurviveRemountFromInsideSandbox(t *testing.T) {
	requireSandbox(t)

	t.Setenv("HOME", t.TempDir())
	// A write grant over a repository is the case that makes this sharp: the working
	// tree really is writable, and the only thing standing between the target and a
	// git hook the host runs on the next commit is the shield's read-only bind. If a
	// remount could clear that flag, the write grant the user did give would hand over
	// the one path inside it they were promised was protected.
	granted := t.TempDir()
	shield := filepath.Join(granted, ".git", "hooks")
	if err := os.MkdirAll(shield, 0o700); err != nil {
		t.Fatal(err)
	}

	bin := buildMountProbe(t)
	p := &policy.Policy{
		Entrypoint: bin,
		Args:       []string{shield, "/", granted},
		Read:       []string{filepath.Dir(bin)},
		Write:      []string{granted},
		Exec:       policy.ExecAll,
	}

	var out strings.Builder
	if _, err := sandboxEnforcer(t).Run(context.Background(), p,
		enforce.Process{Stdout: &out, Stderr: &out}, enforce.RunOptions{}); err != nil {
		t.Fatalf("Run: %v (output: %s)", err, out.String())
	}
	got := out.String()

	for _, target := range []string{shield, "/"} {
		if !strings.Contains(got, target+" MOUNT_REFUSED UNWRITABLE") {
			t.Errorf("%q must refuse the remount and stay unwritable; output:\n%s", target, got)
		}
	}
	if !strings.Contains(got, granted+" MOUNT_REFUSED WRITABLE") {
		t.Errorf("control: the granted write directory should stay writable (proving the probe detects writability at all); output:\n%s", got)
	}

	// Belt and suspenders. The UNWRITABLE token above is the real guard - the probe
	// removes its own file, so a breach would leave this directory empty anyway - but a
	// probe that somehow wrote without reporting it would still be caught here.
	entries, err := os.ReadDir(shield)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("the run planted %d entry/entries in the host's %s; the read-only bind did not hold", len(entries), shield)
	}
}
