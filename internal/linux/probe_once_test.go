//go:build linux

package linux

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// A manifest without limits never reads the limits layers, and measuring them is a
// throwaway scope and a controllers read through the systemd user manager: seven execs,
// two round trips, and on a busy manager a wait of up to scopeProbeTimeout. ProbeFor
// skips that where the run requires no limits layer, and only there - Probe itself is
// doctor's, and a limits manifest has to be measured.
func TestAProbeForARunWithoutLimitsLeavesSystemdAlone(t *testing.T) {
	var scopes int
	saved := scopeProbe
	t.Cleanup(func() { scopeProbe = saved })
	scopeProbe = func(context.Context) (scopeVerdict, bool) {
		scopes++
		return scopeVerdict{ok: false, reason: "fake scope"}, true
	}

	e := New()
	e.ProbeFor(context.Background(), []enforce.Layer{enforce.LayerFilesystem, enforce.LayerExec})
	if scopes != 0 {
		t.Errorf("a run requiring no limits layer asked for a scope %d times", scopes)
	}
	e.ProbeFor(context.Background(), []enforce.Layer{enforce.LayerFilesystem, enforce.LayerLimitsPIDs})
	if scopes != 1 {
		t.Errorf("a run requiring a limits layer asked for a scope %d times, want 1", scopes)
	}
	e.Probe(context.Background())
	if scopes != 2 {
		t.Errorf("doctor's Probe must measure the limits layers whatever a manifest asks; scope asked %d times, want 2", scopes)
	}
}

// enforce.Run hands the backend the probe its admission judged, and the backend has to
// report from that reading rather than take a second one - which cost every launch a
// namespace canary, twelve Landlock probes and, on a limits manifest, a systemd round
// trip. The handed report carries a reason no host probe writes, so a run that probed
// again comes back without it. Both tiers, since each takes its reading at its own site.
func TestRunReportsFromTheProbeItWasHanded(t *testing.T) {
	const sentinel = "the reading enforce.Run took for admission"
	handed := New().Probe(context.Background())
	handed.SetStatus(enforce.LayerStatus{Layer: enforce.LayerAutoExecReport, State: enforce.Degraded, Reason: sentinel})

	dir := t.TempDir()
	script := filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(script, []byte("exit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{dir}}

	t.Run("full", func(t *testing.T) {
		requireSandbox(t)
		var out strings.Builder
		res, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out}, enforce.RunOptions{Probed: &handed})
		if err != nil {
			t.Fatalf("Run: %v (output: %s)", err, out.String())
		}
		if got := reasonOf(res.Report, enforce.LayerAutoExecReport); got != sentinel {
			t.Errorf("the run's report was not built on the probe it was handed; auto-exec reason %q", got)
		}
	})
	t.Run("degraded", func(t *testing.T) {
		requireDegraded(t)
		var out strings.Builder
		res, err := enforcerUsing(testBento(t)).runDegraded(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out}, enforce.RunOptions{Probed: &handed})
		if err != nil {
			t.Fatalf("runDegraded: %v (output: %s)", err, out.String())
		}
		if got := reasonOf(res.Report, enforce.LayerAutoExecReport); got != sentinel {
			t.Errorf("the degraded run's report was not built on the probe it was handed; auto-exec reason %q", got)
		}
	})
}
