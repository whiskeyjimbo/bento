package landlock_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/landlock"
)

func TestAvailableOnLinux(t *testing.T) {
	if !landlock.Available() {
		t.Skip("Landlock not present on this kernel")
	}
}

// The regression: Available() must report true on a Landlock-capable kernel even
// when /sys/kernel/security is unavailable - the container case. The old
// implementation parsed /sys/kernel/security/lsm and returned false there, wrongly
// reporting "no backstop" while the syscalls worked. This masks that path with a
// tmpfs under bwrap and asserts Available() still says true.
func TestAvailableWithoutSecurityfs(t *testing.T) {
	if !landlock.Available() {
		t.Skip("Landlock not present on this kernel")
	}
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		t.Skip("bwrap not available to mask /sys/kernel/security")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available to build the probe")
	}

	bin := filepath.Join(t.TempDir(), "probe")
	build := exec.Command("go", "build", "-o", bin, "github.com/whiskeyjimbo/bento/internal/landlock/internal/probe")
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building probe: %v\n%s", err, out)
	}

	// --tmpfs over /sys/kernel/security makes the lsm file unreadable, exactly as a
	// restricted-/sys container does, while the Landlock syscalls stay available.
	out, err := exec.Command(
		bwrap,
		"--dev-bind", "/", "/",
		"--tmpfs", "/sys/kernel/security",
		bin, "available",
	).CombinedOutput()
	if err != nil {
		t.Skipf("bwrap could not run the probe here (%v): %s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "available=true" {
		t.Errorf("Available() under a masked /sys/kernel/security = %q, want available=true", got)
	}
}

// Landlock must actually confine filesystem access on this host - that it loads
// without error is not the same as that it denies. The probe confines itself to
// one directory in a fresh process; a path inside must stay readable and a path
// outside must be denied.
func TestRestrictConfinesReads(t *testing.T) {
	if !landlock.Available() {
		t.Skip("Landlock not present on this kernel")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available to build the probe")
	}

	bin := filepath.Join(t.TempDir(), "probe")
	build := exec.Command("go", "build", "-o", bin, "github.com/whiskeyjimbo/bento/internal/landlock/internal/probe")
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building probe: %v\n%s", err, out)
	}

	allowed := t.TempDir()
	inside := filepath.Join(allowed, "in.txt")
	if err := os.WriteFile(inside, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	// An outside path the process can read without Landlock, so a denial proves
	// Landlock - not permissions - is what confines.
	outside := filepath.Join(t.TempDir(), "out.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command(bin, allowed, inside, outside).CombinedOutput()
	if err != nil {
		t.Fatalf("probe: %v\n%s", err, out)
	}
	got := strings.TrimSpace(string(out))
	if !strings.Contains(got, "inside=OK") {
		t.Errorf("a path inside the allowed dir should stay readable: %q", got)
	}
	if !strings.Contains(got, "outside=DENIED") {
		t.Errorf("a path outside the allowed dir must be denied by Landlock: %q", got)
	}

	// A regular file in the writable set must get a file rule. Routed to RWDirs it
	// returns EINVAL, and RestrictPaths applies the ruleset as a whole - so the process
	// would run with NO rules at all and outside=OK. Only the real kernel shows this:
	// the rule kinds are indistinguishable until the ruleset is submitted, which is why
	// this goes through the probe rather than asserting on the rules bento builds.
	t.Run("a file in the writable set does not discard the ruleset", func(t *testing.T) {
		out, err := exec.Command(bin, allowed, inside, outside, inside).CombinedOutput()
		if err != nil {
			t.Fatalf("probe with a file write path: %v\n%s", err, out)
		}
		got := strings.TrimSpace(string(out))
		if !strings.Contains(got, "outside=DENIED") {
			t.Errorf("a file in the writable set left the process unconfined: %q", got)
		}
		if !strings.Contains(got, "inside=OK") {
			t.Errorf("the granted tree stopped being readable: %q", got)
		}
	})
}
