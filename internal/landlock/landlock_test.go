package landlock_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/internal/landlock"
)

func TestAvailableOnLinux(t *testing.T) {
	if !landlock.Available() {
		t.Skip("Landlock not present on this kernel")
	}
}

// Landlock must actually confine filesystem access on this host — that it loads
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
	build := exec.Command("go", "build", "-o", bin, "github.com/whiskeyjimbo/bento-v2/internal/landlock/internal/probe")
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
	// Landlock — not permissions — is what confines.
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
}
