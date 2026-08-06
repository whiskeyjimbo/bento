//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Ctrl-C must leave nothing behind. bwrap creates a shield mount point on the host when
// the shielded path does not exist yet and a write grant makes its parent writable - an
// unborn .git/hooks under a granted project is the reachable case - and every removal of
// those is deferred. Before this, SIGINT default-terminated bento, no defer ran, and the
// empty directory (plus a /tmp/bento-run-*) was left in the user's own tree, one set per
// aborted run.
func TestInterruptedRunLeavesNoShieldArtifacts(t *testing.T) {
	requireSandbox(t)
	if _, err := exec.LookPath("go"); err != nil {
		skipMissingDep(t, "go toolchain not available")
	}

	dir := t.TempDir()
	bin := filepath.Join(dir, "bento")
	build := exec.Command("go", "build", "-o", bin, "github.com/whiskeyjimbo/bento/cmd/bento")
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building bento: %v\n%s", err, out)
	}

	project := filepath.Join(dir, "project")
	if err := os.MkdirAll(filepath.Join(project, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(project, "wait.sh")
	if err := os.WriteFile(script, []byte("sleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(project, "bento.yaml")
	if err := os.WriteFile(manifest, []byte("entrypoint: ./wait.sh\ninterpreter: sh\nwrite: [.]\nexec: all\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin, "run", "--allow-unapproved", manifest)
	cmd.Dir = project
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// The sandbox has to be up before the signal means anything: too early and the
	// shield mount point does not exist yet, so the test would pass without exercising
	// the cleanup at all.
	hooks := filepath.Join(project, ".git", "hooks")
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(hooks); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Skip("bwrap never created the .git/hooks shield mount point on this host")
		}
		time.Sleep(50 * time.Millisecond)
	}

	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Error("an interrupted run exited 0; the abort must not read as a clean run")
	}
	if _, err := os.Stat(hooks); err == nil {
		t.Errorf("SIGINT left the bwrap-created shield mount point behind: %s", hooks)
	}
}
