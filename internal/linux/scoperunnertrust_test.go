//go:build linux

package linux

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/policy"
)

// plantScopeRunner puts an executable named systemd-run in a directory this user owns and
// points PATH at it - the shape a sandboxed target with a write grant on a bin directory
// the user's PATH carries can produce for the NEXT run.
func plantScopeRunner(t *testing.T) string {
	t.Helper()
	if os.Getuid() == 0 {
		t.Skip("running as root, where every path is writable and the question is vacuous")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "systemd-run"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	return dir
}

// Under limits the scope runner, not bwrap, is the outer process the host execs, and it
// inherits the applied-report descriptor and the bridge liveness pipe. A systemd-run this
// user can replace therefore decides both what runs - it need never exec bwrap or the
// launcher at all - and what the report the user reads afterwards says was enforced. That
// is the same thing resolveBwrap refuses one path over, so it is refused the same way.
func TestResolveScopeRunnerRefusesAUserWritableRunner(t *testing.T) {
	dir := plantScopeRunner(t)

	path, notInstalled, err := resolveScopeRunner()
	if err == nil {
		t.Fatalf("resolveScopeRunner accepted a systemd-run planted in a directory this user can write (%s)", path)
	}
	if notInstalled {
		t.Error("a hijackable scope runner was reported as one that is not installed, which is the benign verdict")
	}
	if !strings.Contains(err.Error(), dir) {
		t.Errorf("refusal = %q, want it to name the writable directory so the user can act on it", err)
	}
}

// The decision above is worth nothing unless the launch path consults it, and that is what
// was actually broken: trustLauncherPath already worked, limits.go never called it.
// preflightLimits is the one gate every wrapped launch reaches - the bwrap tier, the
// degraded tier, and profiling, which consults no scope verdict of its own - so the refusal
// lands there, ahead of the probe, and needs no working systemd user manager to fire.
func TestPreflightLimitsRefusesAUserWritableScopeRunner(t *testing.T) {
	dir := plantScopeRunner(t)

	err := preflightLimits(context.Background(), policy.Limits{Memory: "64M"}, nil)
	if err == nil {
		t.Fatal("preflightLimits admitted a run wrapped in a systemd-run this user can replace")
	}
	if !strings.Contains(err.Error(), "writable by this user") {
		t.Errorf("preflight error = %q, want the launcher-provenance refusal", err)
	}
	if !strings.Contains(err.Error(), dir) {
		t.Errorf("preflight error = %q, want it to name the writable directory", err)
	}
}

// The positive control, and the reason the check is a per-component write test rather than
// a list of blessed directories: a false refusal here refuses every limited run on a
// working machine, which is worse than the hole it closes.
func TestResolveScopeRunnerAcceptsTheHostsOwnSystemdRun(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root, where every path is writable and the question is vacuous")
	}
	path, notInstalled, err := resolveScopeRunner()
	if notInstalled {
		skipMissingDep(t, "systemd-run not installed")
	}
	if err != nil {
		t.Fatalf("resolveScopeRunner refused this host's own systemd-run, which would refuse every limited run here: %v", err)
	}
	if path == "" {
		t.Error("resolveScopeRunner returned no path for an accepted runner")
	}
}
