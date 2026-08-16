//go:build linux

package launcher

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// boundSelf is where the test binary is bound inside the child's sandbox. It is bound in
// AFTER /tmp is replaced, so it survives that replacement - `go test` builds the binary
// under /tmp/go-build*, which a fresh tmpfs would otherwise hide. The report descriptor
// travels as an inherited fd rather than as a path, so nothing else the child needs lives
// under /tmp.
const boundSelf = "/tmp/bento-launcher.test"

// inSandbox re-points a test child at a real bwrap sandbox. Run verifies from the inside
// that the sandbox it is in is the one the host asked bwrap for, so a child that has to
// reach past those checks needs a real one. It cannot be built with a bare clone: on a
// host that restricts unprivileged user namespaces (the Ubuntu default since 24.04) the
// new namespace carries no capability to mount, so the tmpfs and the fresh procfs are
// refused. bwrap is permitted there, and bento requires it for a run anyway.
//
// weaken names the ONE guarantee to take away, which is how each verification's refusal is
// exercised: a sandbox weakened in exactly one place is the shimmed bwrap the checks exist
// to catch, and every other check still passes, so the refusal under test is the one that
// fires. "" builds the whole sandbox.
//
// There is no arm for the capability bounding set: unprivileged bwrap empties it whether
// or not --cap-drop ALL is passed, so dropping that flag builds the same sandbox. Only a
// setuid bwrap produces the state verifyEmptyCapBound refuses, and a test cannot make one.
func inSandbox(t *testing.T, cmd *exec.Cmd, weaken string) {
	t.Helper()
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		skipMissingDep(t, "bwrap is not installed, so there is no sandbox to run the stage in: %v", err)
	}
	args := []string{bwrap, "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev"}
	// The host's own /tmp in place of the fresh one, which is what a shim filtering
	// --tmpfs out of argv leaves behind - and it keeps /tmp writable, so the binary bind
	// below still has somewhere to land.
	if weaken == "tmp" {
		args = append(args, "--bind", "/tmp", "/tmp")
	} else {
		args = append(args, "--tmpfs", "/tmp")
	}
	args = append(args, "--ro-bind", os.Args[0], boundSelf,
		"--unshare-net", "--unshare-user", "--unshare-ipc", "--unshare-uts")
	if weaken != "pid" {
		args = append(args, "--unshare-pid")
	}
	args = append(args, "--cap-drop", "ALL")
	args = append(args, "--die-with-parent", boundSelf)

	cmd.Args = append(args, cmd.Args[1:]...)
	cmd.Path = bwrap
}

// skipMissingDep skips for a missing host dependency, or fails when
// BENTO_REQUIRE_TEST_DEPS is set. Everything inSandbox guards is a behavioral check on
// Run's refusal of a weakened sandbox, so a self-skip reports a clean pass having asserted
// nothing about it; the variable is how a host that is supposed to have bwrap - CI, and
// `make test` - says so. A fifth copy of a four-line helper rather than a shared test
// package, matching cmd/bento, cmd/denylist-audit, internal/observe and
// internal/denylist/audit.
func skipMissingDep(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("BENTO_REQUIRE_TEST_DEPS") != "" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

const sentinelNoBwrap = "BENTO_TEST_NO_BWRAP"

// A host without bwrap must not report a pass over the sandbox tests: they are the only
// proof that Run's verifications are wired into Run at all. In children because the two
// outcomes under test are a fail and a skip of the calling test itself, which no assertion
// in that test can survive to make. PATH is emptied rather than bwrap removed, which is
// what inSandbox's own lookup sees on a host that never installed it.
func TestInSandboxHonorsRequireTestDeps(t *testing.T) {
	if os.Getenv(sentinelNoBwrap) != "" {
		inSandbox(t, exec.Command("/bin/true"), "")
		return
	}
	for _, tc := range []struct {
		name     string
		require  string
		wantFail bool
	}{
		{"required", "1", true},
		{"not required", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run", "^TestInSandboxHonorsRequireTestDeps$", "-test.v")
			cmd.Env = append(os.Environ(), sentinelNoBwrap+"=1", "PATH=",
				"BENTO_REQUIRE_TEST_DEPS="+tc.require)
			out, err := cmd.CombinedOutput()
			if (err != nil) != tc.wantFail {
				t.Fatalf("child exited with %v, want failure=%v:\n%s", err, tc.wantFail, out)
			}
			if !strings.Contains(string(out), "bwrap is not installed") {
				t.Errorf("child did not report the missing dependency: %s", out)
			}
			if !tc.wantFail && !strings.Contains(string(out), "SKIP") {
				t.Errorf("child neither skipped nor failed without bwrap: %s", out)
			}
		})
	}
}
