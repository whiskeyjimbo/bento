//go:build linux

package linux

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// A run id is only worth anything if it reaches the scope wrapper, and the argv-level
// tests beside wrapWithLimits cannot see that: a tier that dropped opts.RunID and passed
// "" would leave every one of them passing. So these observe the host's user manager
// while a real run is alive and assert the unit the SUPERVISOR would have computed is the
// one that came up - the whole contract, end to end, on both tiers.
//
// The target cannot answer this itself. bwrap unshares the cgroup namespace, so a
// sandboxed program reading /proc/self/cgroup sees "0::/" and learns nothing about the
// scope it sits in; the observation has to come from outside.

// sleepPolicy is a target that stays alive long enough to be observed, under limits so
// the run is wrapped in a scope at all. /bin/sleep is its own interpreter, so it needs no
// exec grant.
func sleepPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary to hold a run open")
	}
	return &policy.Policy{
		Entrypoint: sleep,
		Args:       []string{"10"},
		Exec:       policy.ExecNone,
		Limits:     policy.Limits{Memory: "128M"},
	}
}

// awaitScope waits for the named unit to go active and returns its cgroup path. It polls
// because the scope comes up while the run is starting, which is the same race a real
// supervisor is allowed to have: it may hold the name before the unit exists.
func awaitScope(t *testing.T, unit string) string {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		out, err := exec.Command("systemctl", "--user", "show", "-p", "ControlGroup", "--value", unit).Output()
		if path := strings.TrimSpace(string(out)); err == nil && path != "" {
			return path
		}
		time.Sleep(100 * time.Millisecond)
	}
	return ""
}

func TestRunIDNamesTheScopeOnTheFullTier(t *testing.T) {
	if ok, reason := canCreateScope(); !ok {
		t.Skip("no usable systemd user scope: " + reason)
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("no bwrap on this host; the full tier cannot run")
	}
	p := sleepPolicy(t)

	const id = "fulltier_probe"
	unit := scopeUnitName(id)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// The run's outcome is not the subject: the test cancels it as soon as it has
		// observed the scope, so it ends however a cancelled run ends.
		_, _ = enforcerUsing(testBento(t)).Run(ctx, p, enforce.Process{}, enforce.RunOptions{RunID: id})
	}()

	path := awaitScope(t, unit)
	cancel()
	<-done
	if path == "" {
		t.Fatalf("no scope named %s came up; the run id did not reach the scope wrapper", unit)
	}
	// The path is what `systemctl show -p ControlGroup` reports, which is the route the
	// RunID contract tells a supervisor to use rather than synthesizing one.
	if filepath.Base(path) != unit {
		t.Errorf("scope cgroup is %q, want one ending in %s", path, unit)
	}
}

func TestRunIDNamesTheScopeOnTheDegradedTier(t *testing.T) {
	requireDegraded(t)
	if ok, reason := canCreateScope(); !ok {
		t.Skip("no usable systemd user scope: " + reason)
	}
	p := sleepPolicy(t)

	const id = "degraded_probe"
	unit := scopeUnitName(id)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = enforcerUsing(testBento(t)).runDegraded(ctx, p, enforce.Process{}, id)
	}()

	path := awaitScope(t, unit)
	cancel()
	<-done
	if path == "" {
		t.Fatalf("no scope named %s came up; the run id did not reach the degraded tier's scope wrapper", unit)
	}
	if filepath.Base(path) != unit {
		t.Errorf("scope cgroup is %q, want one ending in %s", path, unit)
	}
}

// Run is exported, so an embedder reaches it without enforce.Run's admission ahead of
// it. Both halves of the run-id contract have to hold here too: the spelling, because an
// id that reaches --unit unscreened is a unit name the supervisor did not spell, and the
// promise of a scope, because a run id on a manifest with no limits is never wrapped at
// all - the supervisor's kill then does nothing to a target still running, with no error
// anywhere and the run reporting success.
func TestRunScreensTheRunIDAtTheBackendEntryPoint(t *testing.T) {
	e := New()
	limited := &policy.Policy{Entrypoint: "/bin/true", Exec: policy.ExecNone, Limits: policy.Limits{Memory: "128M"}}
	for _, id := range []string{"job.17", "job-17", "a/b", strings.Repeat("a", 65)} {
		if err := e.screenRunID(limited, id); err == nil {
			t.Errorf("run id %q reached the unit name unscreened", id)
		}
	}
	if err := e.screenRunID(limited, "job_17"); err != nil && !strings.Contains(err.Error(), "cannot create one") {
		t.Errorf("a well-spelled id on a limited manifest must pass: %v", err)
	}

	unlimited := &policy.Policy{Entrypoint: "/bin/true", Exec: policy.ExecNone}
	if err := e.screenRunID(unlimited, "job_17"); err == nil || !strings.Contains(err.Error(), "sets no resource limits") {
		t.Errorf("a run id on a manifest with no limits must be refused, not silently unscoped; got %v", err)
	}
	if err := e.screenRunID(unlimited, ""); err != nil {
		t.Errorf("no run id must stay unaffected: %v", err)
	}
}
