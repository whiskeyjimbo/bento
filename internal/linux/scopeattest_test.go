//go:build linux

package linux

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// The three limits layers were the only gatable layers whose final state was never
// reconciled against what the run applied - everything downstream read the pre-run probe's
// verdict, memoized for the process lifetime. These cover the reconcile itself: a scope the
// kernel shows carrying no cap must not leave the report claiming the limit held.
func TestScopeLimitsReconcileAgainstTheScopeTheRunGot(t *testing.T) {
	limits := policy.Limits{Memory: "64M", PIDs: 64, CPU: "50%"}

	enforced := func() enforce.Report {
		var r enforce.Report
		r.Add(enforce.LayerLimitsMemory, enforce.Enforced, "")
		r.Add(enforce.LayerLimitsPIDs, enforce.Enforced, "")
		r.Add(enforce.LayerLimitsCPU, enforce.Enforced, "")
		return r
	}

	// A scope carrying every cap: nothing to worsen. The positive control for the two
	// below, and the shape a delegated host produces.
	t.Run("a scope carrying the caps", func(t *testing.T) {
		dir := fakeScope(t, map[string]string{"memory.max": "67108864\n", "pids.max": "64\n", "cpu.max": "50000 100000\n"})

		r := enforced()
		noteScopeLimits(&r, limits, scopeLimits{dir: dir})
		for _, l := range []enforce.Layer{enforce.LayerLimitsMemory, enforce.LayerLimitsPIDs, enforce.LayerLimitsCPU} {
			if got := r.StateOf(l); got != enforce.Enforced {
				t.Errorf("%v = %v over a scope that carries its cap, want enforced", l, got)
			}
		}
	})

	// The bead's failure, made observable: systemd-run accepts a property for an
	// undelegated controller and exits 0, and the controller's file is then simply absent
	// from the scope. The pre-run probe said Enforced; the kernel says nothing bound.
	t.Run("a scope missing a controller", func(t *testing.T) {
		dir := fakeScope(t, map[string]string{"pids.max": "64\n", "cpu.max": "50000 100000\n"})

		r := enforced()
		noteScopeLimits(&r, limits, scopeLimits{dir: dir})
		if got := r.StateOf(enforce.LayerLimitsMemory); got != enforce.Unavailable {
			t.Errorf("memory = %v over a scope with no memory.max, want unavailable - the target ran unbounded", got)
		}
		if reason := reasonOf(r, enforce.LayerLimitsMemory); !strings.Contains(reason, "carries no memory cap") {
			t.Errorf("reason = %q, want it to name what the scope did not carry", reason)
		}
		if got := r.StateOf(enforce.LayerLimitsPIDs); got != enforce.Enforced {
			t.Errorf("pids = %v, want enforced: only the layer the scope lacks is worsened", got)
		}
	})

	// cgroup-v2 words "no limit" as "max", and it is cpu.max's first field too.
	t.Run("a controller present with no cap", func(t *testing.T) {
		dir := fakeScope(t, map[string]string{"memory.max": "max\n", "pids.max": "max\n", "cpu.max": "max 100000\n"})

		r := enforced()
		noteScopeLimits(&r, limits, scopeLimits{dir: dir})
		for _, l := range []enforce.Layer{enforce.LayerLimitsMemory, enforce.LayerLimitsPIDs, enforce.LayerLimitsCPU} {
			if got := r.StateOf(l); got != enforce.Unavailable {
				t.Errorf("%v = %v over an uncapped controller, want unavailable", l, got)
			}
		}
	})

	// A target that finishes before the sample lands leaves no scope to read, and that is
	// not a finding: faulting a completed run for being fast would refuse correct runs,
	// which is worse than the gap it closes.
	t.Run("no scope found", func(t *testing.T) {
		r := enforced()
		noteScopeLimits(&r, limits, scopeLimits{})
		if got := r.StateOf(enforce.LayerLimitsMemory); got != enforce.Enforced {
			t.Errorf("memory = %v with nothing sampled, want the probe's verdict left alone", got)
		}
	})
}

// The reading has to find the scope's cgroup from the wrapper's pid alone, which is the
// half no fake covers: a reading that landed on bento's own cgroup instead would attest the
// session scope and find every cap absent, faulting every limited run. This drives it
// against a real transient scope, and asserts both halves - a cgroup that is not this
// process's, carrying the cap that was requested.
func TestAttestScopeLimitsFindsTheTransientScope(t *testing.T) {
	if _, err := exec.LookPath("systemd-run"); err != nil {
		skipMissingDep(t, "systemd-run is not installed")
	}
	if ok, reason := canCreateScope(t.Context()); !ok {
		skipMissingDep(t, "this host cannot create a transient scope: %s", reason)
	}

	exe, args := wrapWithLimits(trueBinary(), nil, policy.Limits{Memory: "64M"}, "")
	cmd := exec.Command(exe, append(args[:len(args)-1], shBinary(), "-c", "sleep 5")...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	a := attestScopeLimits(cmd.Process.Pid)
	if a.dir == "" {
		t.Fatal("the scope's cgroup was not found from the wrapper's pid")
	}
	own, _ := cgroupPathOf(strconv.Itoa(os.Getpid()))
	if a.dir == filepath.Join("/sys/fs/cgroup", own) {
		t.Fatalf("the reading found this process's own cgroup (%s), not the scope the wrapper was placed in", a.dir)
	}
	if bound, known := controllerBound(filepath.Join(a.dir, "memory.max")); !known || !bound {
		t.Errorf("memory.max of the scope reads unbound (known=%v bound=%v); the requested 64M did not land", known, bound)
	}
}

func fakeScope(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// The wiring, which neither test above reaches: the reconcile has to be called from the run
// path with the scope the run actually got, and a call site that dropped it would leave
// every test above passing. The reading is forced to a scope carrying no memory cap - the
// host this exists for, which cannot be constructed here - and the run's own returned report
// must carry the worsened layer, since that is what postRunShortfall and
// unenforcedRequestedLimits read.
func TestRunReconcilesTheLimitsLayersItGot(t *testing.T) {
	requireHostSafetyLimits(t)

	orig := attestScopeLimits
	attestScopeLimits = func(int) scopeLimits {
		return scopeLimits{dir: fakeScope(t, map[string]string{"pids.max": "64\n"})}
	}
	t.Cleanup(func() { attestScopeLimits = orig })

	p := &policy.Policy{
		Entrypoint: buildEnvDumpProbe(t),
		Exec:       policy.ExecNone,
		Limits:     policy.Limits{Memory: "64M"},
	}
	res, err := sandboxEnforcer(t).Run(t.Context(), p, enforce.Process{}, enforce.RunOptions{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := res.Report.StateOf(enforce.LayerLimitsMemory); got != enforce.Unavailable {
		t.Errorf("LayerLimitsMemory = %v in the run's own report, want unavailable: the scope it got carried no memory cap", got)
	}
}
