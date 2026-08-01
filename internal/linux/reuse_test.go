//go:build linux

package linux

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// The Enforcer holds no per-run state, which is what lets an embedder keep one for the
// life of its process and run targets through it concurrently. Documented on
// enforce.Enforcer, so it is pinned here: a future field on the receiver that a Run
// mutated would make every embedder that took the doc at its word race.
func TestEnforcerReuseIsConcurrencySafe(t *testing.T) {
	requireSandbox(t)

	e := sandboxEnforcer(t)
	// Distinct entrypoints and no write grants, so the runs share no host artifact and a
	// failure here is the Enforcer itself rather than two runs colliding on a path.
	scripts := make([]string, 8)
	for i := range scripts {
		scripts[i] = filepath.Join(t.TempDir(), "noop.sh")
		if err := os.WriteFile(scripts[i], []byte(fmt.Sprintf("exit %d\n", i%3)), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	var wg sync.WaitGroup
	codes := make([]int, len(scripts))
	errs := make([]error, len(scripts))
	for i, script := range scripts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Exec: policy.ExecAll}
			res, err := e.Run(context.Background(), p, enforce.Process{}, enforce.RunOptions{})
			codes[i], errs[i] = res.ExitCode, err
		}()
	}
	wg.Wait()

	for i := range scripts {
		if errs[i] != nil {
			t.Errorf("concurrent run %d: %v", i, errs[i])
			continue
		}
		// Each run must report ITS OWN target's exit code: a verdict landing on another
		// run is the failure mode shared receiver state would produce.
		if want := i % 3; codes[i] != want {
			t.Errorf("concurrent run %d exit code = %d, want %d", i, codes[i], want)
		}
	}
}
