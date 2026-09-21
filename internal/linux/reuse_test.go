//go:build linux

package linux

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// The Enforcer holds no per-run state, which is what lets an embedder keep one for the
// life of its process and run targets through it concurrently. Documented on
// enforce.Enforcer, so it is pinned here: a future field on the receiver that a Run
// mutated would make every embedder that took the doc at its word race.
//
// Half the runs are gated and carry a network rule, so each has its own proxy, egress
// collector and gate verdicts in flight, and the gate parks every gated run until all of
// them are inside it: the per-run egress state of every run exists at once. Each run then
// must report only the destinations its own target asked for.
func TestEnforcerReuseIsConcurrencySafe(t *testing.T) {
	requireSandbox(t)
	if _, err := exec.LookPath("curl"); err != nil {
		skipMissingDep(t, "curl not available")
	}

	e := sandboxEnforcer(t)
	const runs = 8
	gated := func(i int) bool { return i%2 == 0 }
	admit := func(i int) string { return fmt.Sprintf("admit%d.invalid", i) }
	refuse := func(i int) string { return fmt.Sprintf("refuse%d.invalid", i) }
	// Link-local, so the guard refuses it whatever rule names it and whatever the host's
	// network: a GuardBlocked entry with no dependence on DNS or a route.
	declared := func(i int) string { return fmt.Sprintf("169.254.254.%d", i+1) }

	// Distinct entrypoints and no write grants, so the runs share no host artifact and a
	// failure here is the Enforcer itself rather than two runs colliding on a path.
	scripts := make([]string, runs)
	for i := range scripts {
		script := fmt.Sprintf("exit %d\n", i%3)
		if gated(i) {
			curl := "curl -sS --proxytunnel -o /dev/null --max-time 5 "
			script = fmt.Sprintf("%shttp://%s:443/ >/dev/null 2>&1\n%shttp://%s:443/ >/dev/null 2>&1\n%shttp://%s:1/ >/dev/null 2>&1\n%s",
				curl, admit(i), curl, refuse(i), curl, declared(i), script)
		}
		scripts[i] = filepath.Join(t.TempDir(), "run.sh")
		if err := os.WriteFile(scripts[i], []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// The barrier: a gated run's first gate call waits until every gated run has made
	// one, so no run finishes and tears its egress state down while another's is live.
	var arrived sync.WaitGroup
	arrived.Add(runs / 2)
	allIn := make(chan struct{})
	go func() { arrived.Wait(); close(allIn) }()
	gateFor := func(i int) enforce.NetworkGate {
		var once sync.Once
		return func(_ context.Context, host, _ string) bool {
			once.Do(func() {
				arrived.Done()
				select {
				case <-allIn:
				case <-time.After(30 * time.Second):
					t.Errorf("run %d: the other gated runs never reached their gate", i)
				}
			})
			return host == admit(i)
		}
	}

	var wg sync.WaitGroup
	results := make([]enforce.Result, runs)
	errs := make([]error, runs)
	for i, script := range scripts {
		wg.Go(func() {
			p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Exec: policy.ExecAll}
			var opts enforce.RunOptions
			if gated(i) {
				p.Network = []policy.NetworkRule{{Host: declared(i), Port: "1"}}
				opts.Gate = gateFor(i)
			}
			results[i], errs[i] = e.Run(context.Background(), p, enforce.Process{}, opts)
		})
	}
	wg.Wait()

	for i, res := range results {
		if errs[i] != nil {
			t.Errorf("concurrent run %d: %v", i, errs[i])
			continue
		}
		// Each run must report ITS OWN target's exit code and egress: a verdict landing on
		// another run is the failure mode shared receiver state would produce.
		if want := i % 3; res.ExitCode != want {
			t.Errorf("concurrent run %d exit code = %d, want %d", i, res.ExitCode, want)
		}
		var wantAdmitted, wantRefused, wantBlocked []enforce.HostPort
		if gated(i) {
			wantAdmitted = []enforce.HostPort{{Host: admit(i), Port: "443"}}
			wantRefused = []enforce.HostPort{{Host: refuse(i), Port: "443"}}
			wantBlocked = []enforce.HostPort{{Host: declared(i), Port: "1"}}
		}
		for _, set := range []struct {
			name      string
			got, want []enforce.HostPort
		}{
			{"GateAdmitted", res.GateAdmitted, wantAdmitted},
			{"GateDenied", res.GateDenied, wantRefused},
			{"GuardBlocked", res.GuardBlocked, wantBlocked},
		} {
			if !slices.Equal(set.got, set.want) {
				t.Errorf("concurrent run %d %s = %v, want %v", i, set.name, set.got, set.want)
			}
		}
	}
}
