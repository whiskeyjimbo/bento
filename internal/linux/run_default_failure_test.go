//go:build linux

package linux

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// The post-run default arm is reached only by a cmd.Run error that is neither nil nor
// an *exec.ExitError - the wrapper vanishing mid-run, a fork failure, an I/O error on
// the pipes. The runCmd seam is the only way to produce one: it lets the wrapper run to
// completion, so the launcher writes its applied report exactly as on a real run, and
// then fails the wait the way those failures do. That is the arm's own premise - the
// target may already have run - so the record it asked for is on disk and must come out.
func TestRunFailingOnANonExitErrorStillReportsTheExecRecord(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	script := filepath.Join(dir, "p.sh")
	if err := os.WriteFile(script, []byte("/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{
		Entrypoint:  script,
		Interpreter: "sh",
		Read:        []string{dir, "/bin", "/usr"},
		Exec:        policy.ExecAll,
	}

	boom := errors.New("waiting on the wrapper: input/output error")
	orig := runCmd
	runCmd = func(c *exec.Cmd, started func(int)) error {
		_ = c.Run()
		return boom
	}
	t.Cleanup(func() { runCmd = orig })

	res, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{}, enforce.RunOptions{RecordExec: true})
	if err == nil || !strings.Contains(err.Error(), boom.Error()) {
		t.Fatalf("Run = %v, want the wrapper's non-exit failure carried out", err)
	}
	if res.ExecRecord == nil {
		t.Fatal("ExecRecord is nil though the run asked for one: nil reads as 'never asked', not 'nothing recorded'")
	}
	if !res.ExecRecord.Watched {
		t.Errorf("ExecRecord.Watched = false (%q): the launcher did install the recorder on this run", res.ExecRecord.Reason)
	}
}

// The same arm, with the wrapper never dispatched: nothing wrote an applied report, so
// no in-sandbox stage installed the layers the probe says this host CAN enforce. A
// report handed back claiming them attests a confinement that was never built - the
// one-sided invariant reconcile exists to hold, and the only return arm in either tier
// that used to skip it.
func TestRunFailingBeforeTheStageReportsClaimsNoLayer(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	script := filepath.Join(dir, "p.sh")
	if err := os.WriteFile(script, []byte("/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{
		Entrypoint:  script,
		Interpreter: "sh",
		Read:        []string{dir, "/bin", "/usr"},
		Exec:        policy.ExecAll,
	}

	boom := errors.New("waiting on the wrapper: input/output error")
	orig := runCmd
	runCmd = func(*exec.Cmd, func(int)) error { return boom }
	t.Cleanup(func() { runCmd = orig })

	res, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{}, enforce.RunOptions{})
	if err == nil || !strings.Contains(err.Error(), boom.Error()) {
		t.Fatalf("Run = %v, want the wrapper's non-exit failure carried out", err)
	}
	if res.Setup != enforce.SetupSilent {
		t.Errorf("Setup = %v, want SetupSilent: no stage reported what it applied", res.Setup)
	}
	for _, l := range []enforce.Layer{enforce.LayerFilesystem, enforce.LayerExec, enforce.LayerExecStrict} {
		if got := res.Report.StateOf(l); got != enforce.Unavailable {
			t.Errorf("%s = %v, want Unavailable: no stage reported installing it", l, got)
		}
	}
}
