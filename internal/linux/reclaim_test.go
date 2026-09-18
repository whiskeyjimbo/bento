//go:build linux

package linux

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// removeCreatedShields is best effort by design - every skip in it is the safe direction
// - but a caller that cannot tell a partial reclaim from a complete one cannot say a
// mount point survived inside the user's checkout. One arm per route by which it declines
// to remove something, each asserting the path comes back named rather than swallowed.
func TestRemoveCreatedShieldsNamesWhatItDidNotReclaim(t *testing.T) {
	t.Run("a reclaim that fully succeeds names nothing", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "empty")
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		d := filepath.Join(dir, "mountpoint")
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if left := removeCreatedShields([]string{d}, []string{f}); len(left) != 0 {
			t.Errorf("a clean reclaim must name nothing; got %v", left)
		}
		for _, p := range []string{f, d} {
			if _, err := os.Lstat(p); !os.IsNotExist(err) {
				t.Errorf("%s survived a reclaim that reported success", p)
			}
		}
	})

	// A setup failure before the launch leaves this shape: bwrap never ran, so none of
	// the mount points exist. Reporting them would name paths bento did not create.
	t.Run("paths that were never created name nothing", func(t *testing.T) {
		dir := t.TempDir()
		if left := removeCreatedShields([]string{filepath.Join(dir, "d")}, []string{filepath.Join(dir, "f")}); len(left) != 0 {
			t.Errorf("an absent path was never created and is not residue; got %v", left)
		}
	})

	// The bound's error, discarded before the fix. On an expiry the closure is abandoned
	// rather than cancelled, so how far it got is unknowable and every input path is the
	// honest answer.
	t.Run("an expired bound names every path", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "empty")
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		d := filepath.Join(dir, "mountpoint")
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		// The bound must expire before the walk finishes, not race it: hold the first
		// Lstat open past the deadline.
		setWalkTimeout(t, 50*time.Millisecond)
		old := shieldLstat
		shieldLstat = func(name string) (os.FileInfo, error) {
			time.Sleep(time.Second)
			return old(name)
		}
		t.Cleanup(func() { shieldLstat = old })

		left := removeCreatedShields([]string{d}, []string{f})
		if !slices.Contains(left, f) || !slices.Contains(left, d) {
			t.Errorf("an expired reclaim must name every path it cannot account for; got %v, want %v and %v", left, f, d)
		}
	})

	// The non-regular / non-empty continue. A file the host wrote to during the run is
	// correctly left alone - and must be said so.
	t.Run("a file left alone is named", func(t *testing.T) {
		dir := t.TempDir()
		nonEmpty := filepath.Join(dir, "written")
		if err := os.WriteFile(nonEmpty, []byte("host content"), 0o600); err != nil {
			t.Fatal(err)
		}
		symlink := filepath.Join(dir, "link")
		if err := os.Symlink(nonEmpty, symlink); err != nil {
			t.Fatal(err)
		}

		left := removeCreatedShields(nil, []string{nonEmpty, symlink})
		for _, want := range []string{nonEmpty, symlink} {
			if !slices.Contains(left, want) {
				t.Errorf("a shield file the reclaim skipped must be named; got %v, want %v", left, want)
			}
			if _, err := os.Lstat(want); err != nil {
				t.Errorf("%s must be left alone, not removed: %v", want, err)
			}
		}
	})

	// The discarded syscall.Rmdir. A mount point the target filled is correctly kept -
	// and it is inside the user's checkout, which is exactly the case the invariant
	// forbids leaving unsaid.
	t.Run("a non-empty mount point is named", func(t *testing.T) {
		dir := t.TempDir()
		d := filepath.Join(dir, "hooks")
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "pre-commit"), []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatal(err)
		}

		left := removeCreatedShields([]string{d}, nil)
		if !slices.Contains(left, d) {
			t.Errorf("a mount point rmdir refused must be named; got %v, want %v", left, d)
		}
		if _, err := os.Stat(d); err != nil {
			t.Errorf("%s must be left alone, not removed: %v", d, err)
		}
	})
}

// Five steps between prepareWriteDirs and the launch can fail, each returning a bare
// error with the write-grant directory already on the host. The directory stays - the
// manifest named it - but the run must say it is there. checkLauncher is the last of the
// five and the one with a seam.
func TestSetupFailureNamesTheWriteDirItCreated(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	script := filepath.Join(dir, "s.sh")
	if err := os.WriteFile(script, []byte("true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Absent, so prepareWriteDirs is what brings it into existence.
	out := filepath.Join(dir, "build", "out")

	old := launchGuard
	launchGuard = func(string) error { return errors.New("refused for the test") }
	t.Cleanup(func() { launchGuard = old })

	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir}, Write: []string{out}}
	var stderr bytes.Buffer
	if _, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{Stderr: &stderr}, enforce.RunOptions{}); err == nil {
		t.Fatal("the launch guard must fail the run")
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("the premise of the test is that the directory is created and kept: %v", err)
	}
	// The exact line, not a substring of stderr: every shield mount point under the
	// grant has this path as its prefix, so a loose match would pass on their names.
	if !strings.Contains(stderr.String(), "\n  "+out+"\n") {
		t.Errorf("a setup failure must name the host directory it left behind; stderr was %q, want a line naming %s", stderr.String(), out)
	}
	// Nothing ran, so bwrap created no mount point and the reclaim has nothing to report.
	if strings.Contains(stderr.String(), "could not reclaim") {
		t.Errorf("a run that never launched must not report unreclaimed shield mount points; stderr was %q", stderr.String())
	}
}

// A cancel that lands before the wrapper starts is the other half of the same cell: the
// directory is on the host, no target ever used it, and the run returns an error. The
// runCmd seam is how the suite produces that arm - it is the only way to get a return
// with cmd.ProcessState nil, which is what the cancel arm reads as "never started".
func TestCancelBeforeLaunchNamesTheWriteDirItCreated(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	script := filepath.Join(dir, "s.sh")
	if err := os.WriteFile(script, []byte("true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "build", "out")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	orig := runCmd
	runCmd = func(*exec.Cmd, func(int)) error { return context.Canceled }
	t.Cleanup(func() { runCmd = orig })

	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir}, Write: []string{out}}
	var stderr bytes.Buffer
	if _, err := sandboxEnforcer(t).Run(ctx, p, enforce.Process{Stderr: &stderr}, enforce.RunOptions{}); err == nil {
		t.Fatal("a cancelled context must fail the run")
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("the premise of the test is that the directory is created and kept: %v", err)
	}
	if !strings.Contains(stderr.String(), "\n  "+out+"\n") {
		t.Errorf("a run cancelled before the wrapper started must name the host directory it left behind; stderr was %q, want a line naming %s", stderr.String(), out)
	}
}

// prepareWriteDirs creates one grant at a time, so a refusal on a later grant returns
// with an earlier grant's directory already on the host - before any of the five later
// steps the sibling test covers, and on preflightGrants' own error path.
func TestPreflightFailureNamesTheWriteDirItAlreadyCreated(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	script := filepath.Join(dir, "s.sh")
	if err := os.WriteFile(script, []byte("true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	made := filepath.Join(dir, "a-created")
	// A regular file where a write grant names a directory: prepareWriteDirs refuses it.
	refused := filepath.Join(dir, "b-refused")
	if err := os.WriteFile(refused, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir}, Write: []string{made, refused}}
	var stderr bytes.Buffer
	if _, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{Stderr: &stderr}, enforce.RunOptions{}); err == nil {
		t.Fatal("a write grant naming a regular file must fail the run")
	}
	if _, err := os.Stat(made); err != nil {
		t.Skipf("the refusal landed before the first grant was created, so there is no residue to report: %v", err)
	}
	if !strings.Contains(stderr.String(), "\n  "+made+"\n") {
		t.Errorf("a preflight refusal must name the directory it already created; stderr was %q, want a line naming %s", stderr.String(), made)
	}
}

// The degraded tier calls prepareWriteDirs through the same function the bwrap tier
// does, and has failable steps of its own between it and the launch - checkLauncher is
// one. The directory stays, as it does on the full tier, but the run must say so.
func TestDegradedSetupFailureNamesTheWriteDirItCreated(t *testing.T) {
	requireDegraded(t)

	dir := t.TempDir()
	script := filepath.Join(dir, "s.sh")
	if err := os.WriteFile(script, []byte("true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "build", "out")

	old := launchGuard
	launchGuard = func(string) error { return errors.New("refused for the test") }
	t.Cleanup(func() { launchGuard = old })

	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir}, Write: []string{out}}
	var stderr bytes.Buffer
	if _, err := enforcerUsing(testBento(t)).runDegraded(context.Background(), p, enforce.Process{Stderr: &stderr}, enforce.RunOptions{}); err == nil {
		t.Fatal("the launch guard must fail the run")
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("the premise of the test is that the directory is created and kept: %v", err)
	}
	if !strings.Contains(stderr.String(), "\n  "+out+"\n") {
		t.Errorf("a degraded setup failure must name the host directory it left behind; stderr was %q, want a line naming %s", stderr.String(), out)
	}
}

// Profiling is the third entry path through prepareWriteDirs, and the one whose whole
// job is to run a target nobody has vetted yet. The runCmd seam produces the arm where
// the wrapper never started, which is what leaves the directory with no target having
// used it.
func TestProfileSetupFailureNamesTheWriteDirItCreated(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	script := filepath.Join(dir, "s.sh")
	if err := os.WriteFile(script, []byte("true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "build", "out")

	orig := runCmd
	runCmd = func(*exec.Cmd, func(int)) error { return errors.New("the wrapper never started") }
	t.Cleanup(func() { runCmd = orig })

	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir}, Write: []string{out}}
	var stderr bytes.Buffer
	if _, err := sandboxEnforcer(t).Profile(context.Background(), p, enforce.Process{Stderr: &stderr}, false, nil, nil); err == nil {
		t.Fatal("a wrapper that never starts must fail the profiling run")
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("the premise of the test is that the directory is created and kept: %v", err)
	}
	if !strings.Contains(stderr.String(), "\n  "+out+"\n") {
		t.Errorf("a profiling setup failure must name the host directory it left behind; stderr was %q, want a line naming %s", stderr.String(), out)
	}
}

// removeCreatedShields reports what it could not reclaim; Profile is the other bwrap
// entry path and must hand that to the operator as Run does. The seam forces the reclaim
// to fail on every file, which is what a mount point standing inside the checkout looks
// like from here.
func TestProfileNamesShieldMountPointsItCouldNotReclaim(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	script := filepath.Join(dir, "s.sh")
	if err := os.WriteFile(script, []byte("true\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	old := shieldLstat
	shieldLstat = func(string) (os.FileInfo, error) { return nil, errors.New("the host will not answer for it") }
	t.Cleanup(func() { shieldLstat = old })

	// A write grant on a plain directory is what makes bwrap carve the workspace
	// shields (.cargo/config and friends) as host mount points inside it.
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir}, Write: []string{dir}}
	var stderr bytes.Buffer
	if _, err := sandboxEnforcer(t).Profile(context.Background(), p, enforce.Process{Stderr: &stderr}, false, nil, nil); err != nil {
		t.Fatalf("profiling: %v", err)
	}
	if !strings.Contains(stderr.String(), "could not reclaim") {
		t.Errorf("a profiling run that left a shield mount point standing must name it; stderr was %q", stderr.String())
	}
}
