//go:build linux

package linux

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/whiskeyjimbo/bento/policy"
)

// Killing systemd-run on the probe deadline bounds nothing on its own: both probes read
// the command's output, and that read waits for the output PIPE to close, not for the
// process to die. A scope whose own command outlives the deadline still holds the
// inherited descriptor, so the probe blocks for as long as that command lives - which on
// the launch path (preflightLimits) is admission hanging with no output and no exit.
// Only cmd.WaitDelay makes exec close the pipe itself shortly after the kill.
//
// The shim reproduces exactly that shape with no systemd and no attacker: it backgrounds
// a holder of stdout and exits 0, which is what a real killed `systemd-run --user --scope`
// leaves behind.
func TestScopeProbesAreBoundedWhenSomethingHoldsTheirOutput(t *testing.T) {
	shimPATH(t, "systemd-run", "#!/bin/sh\nsleep 20 &\nexit 0\n")

	// Comfortably past the 5s bound plus the 1s WaitDelay, and comfortably short of the
	// 20s the holder lives: whichever side of that window the probe lands on is the
	// verdict, and neither is a flake.
	const bound = 12 * time.Second

	t.Run("runScopeProbe", func(t *testing.T) {
		err, ok := within(t, bound, func() error {
			return runScopeProbe(context.Background(), policy.Limits{Memory: "64M"}, nil)
		})
		if !ok {
			t.Fatalf("runScopeProbe was still blocked after %s while its documented bound is %s; the deadline killed systemd-run but the backgrounded holder of stdout keeps the output read waiting", bound, scopeProbeTimeout)
		}
		// The probe proved nothing about this host, so it must not report that the limits
		// will bind: a nil here is the fail-open direction, where the target then runs
		// unbounded under a report saying the cap holds.
		if err == nil {
			t.Error("runScopeProbe returned success from a probe whose scope never answered")
		}
	})

	t.Run("measureDelegatedControllers", func(t *testing.T) {
		known, ok := within(t, bound, func() bool {
			_, known := measureDelegatedControllers(context.Background())
			return known
		})
		if !ok {
			t.Fatalf("measureDelegatedControllers was still blocked after %s while its documented bound is %s", bound, scopeProbeTimeout)
		}
		if known {
			t.Error("measureDelegatedControllers answered known=true from a probe whose scope never answered")
		}
	})
}

// within runs f and reports its result, or ok=false if it has not returned within d. f is
// abandoned rather than waited on, which is the point: the failure under test is a call
// that never returns, and a test that waited for it would report a binary timeout panic
// instead of an assertion.
func within[T any](t *testing.T, d time.Duration, f func() T) (T, bool) {
	t.Helper()
	done := make(chan T, 1)
	go func() { done <- f() }()
	select {
	case v := <-done:
		return v, true
	case <-time.After(d):
		var zero T
		return zero, false
	}
}

// shimPATH puts a script named name ahead of the real PATH, so a probe that resolves the
// binary by name gets the shim. The rest of PATH is kept: these probes also resolve `true`
// and `sh`, and a bare shim directory would fail them for the wrong reason.
func shimPATH(t *testing.T, name, script string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir
}
