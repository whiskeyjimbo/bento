//go:build linux

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/manifest"
	"github.com/whiskeyjimbo/bento/policy"
)

// writeRunnableManifest writes a manifest whose entrypoint is a real script beside it,
// stamped as approved over the policy AS WRITTEN. The grants are deliberately relative:
// that is what makes the ordering assertion below sharp, since resolving them changes
// the fingerprint the stamp was taken over.
func writeRunnableManifest(t *testing.T, script string, p *policy.Policy) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "run.sh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := manifest.Marshal(p, manifest.Provenance{Approves: p.Fingerprint()})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "bento.yaml")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// runCmd drives the real run command through cobra, so the whole of RunE's admission
// sequence runs in the order the command actually uses - which is the part unit tests of
// the individual predicates cannot cover.
func runCmd(t *testing.T, args ...string) error {
	t.Helper()
	cmd := newRunCmd()
	cmd.SetArgs(args)
	// Buffered rather than passed through, so a refused run's usage/error text does not
	// interleave with the test output that reports it.
	var out strings.Builder
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	return cmd.Execute()
}

// THE ORDERING INVARIANT: requireApproval reads the manifest as written, and
// manifest.Resolve rewrites its relative grants to absolute paths - so resolving before
// checking approval would change the fingerprint out from under the stamp and refuse
// every approved manifest that uses a relative grant. Nothing else in the tree runs an
// approved manifest through `run` at all, so this is what fails if the two ever swap.
func TestRunHonorsApprovalBeforeResolvingGrants(t *testing.T) {
	requireSandbox(t)

	dataDir := "./data"
	m := writeRunnableManifest(t, "exit 0\n", &policy.Policy{
		Entrypoint:  "./run.sh",
		Interpreter: "sh",
		Read:        []string{dataDir},
	})
	if err := os.Mkdir(filepath.Join(filepath.Dir(m), "data"), 0o755); err != nil {
		t.Fatal(err)
	}

	// A completed run returns the target's own code as an exitError, so 0 is success
	// here and any refusal on the way in is a different error entirely.
	if got := asExitError(t, runCmd(t, m)).code; got != 0 {
		t.Fatalf("an approved manifest with a relative grant must run; exit = %d", got)
	}
}

// The other half of the same order: the stamp is checked against the manifest's own
// bytes, so an edit after approval is still caught here - a run that only ever saw
// resolved grants could not tell the two apart.
func TestRunRefusesAManifestEditedAfterApproval(t *testing.T) {
	m := writeRunnableManifest(t, "exit 0\n", &policy.Policy{
		Entrypoint:  "./run.sh",
		Interpreter: "sh",
		Read:        []string{"./data"},
	})
	edited, err := manifest.Marshal(
		&policy.Policy{Entrypoint: "./run.sh", Interpreter: "sh", Read: []string{"./data", "/etc"}},
		manifest.Provenance{Approves: "sha256:stale"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m, edited, 0o644); err != nil {
		t.Fatal(err)
	}

	err = runCmd(t, m)
	if err == nil {
		t.Fatal("a manifest edited after approval must be refused")
	}
	if !strings.Contains(err.Error(), "changed since it was approved") {
		t.Errorf("refusal = %v, want the drift refusal", err)
	}
}

// --env is screened twice on the way in: parseEnvFlags takes the spelling, ResolveEnv
// takes the name against the manifest's allowlist. Both refusals are raised before the
// sandbox exists, so neither needs one.
func TestRunRefusesBadEnvFlags(t *testing.T) {
	m := writeRunnableManifest(t, "exit 0\n", &policy.Policy{
		Entrypoint:  "./run.sh",
		Interpreter: "sh",
		Env:         []string{"ALLOWED"},
	})

	for name, tc := range map[string]struct{ flag, want string }{
		"no equals":  {"NOTAPAIR", "want NAME=VALUE"},
		"empty name": {"=value", "want NAME=VALUE"},
		"undeclared": {"OTHER=v", "not in the manifest's env allowlist"},
	} {
		t.Run(name, func(t *testing.T) {
			err := runCmd(t, "--env", tc.flag, m)
			if err == nil {
				t.Fatalf("--env %q must be refused", tc.flag)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refusal = %v, want it to name %q", err, tc.want)
			}
		})
	}
}

// runCmdCapturingStderr is runCmd with the process's own stderr redirected, which is where
// writeRunResult renders: run.go hands it os.Stderr rather than cobra's writer, so cobra's
// buffers see nothing of the verdict.
func runCmdCapturingStderr(t *testing.T, args ...string) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	// Drained while the command runs: a verdict can outgrow a pipe buffer, and reading
	// afterwards would deadlock the run.
	out := readAll(r)
	runErr := func() error {
		saved := os.Stderr
		defer func() {
			os.Stderr = saved
			w.Close()
		}()
		os.Stderr = w
		return runCmd(t, args...)
	}()
	return <-out, runErr
}

// run.go:163 is the only call site of writeRunResult, and the ~20 run rows in
// output_parity_test.go render their human half by calling it directly - so without this
// a run that returned the exit code and rendered nothing would stay green everywhere.
// The exit code alone does not cover it: it comes back from the same call, but a return
// built by hand from res.ExitCode satisfies every other assertion in this file.
func TestACompletedRunRendersItsVerdict(t *testing.T) {
	requireSandbox(t)

	m := writeRunnableManifest(t, "exit 0\n", &policy.Policy{
		Entrypoint:  "./run.sh",
		Interpreter: "sh",
	})
	stderr, err := runCmdCapturingStderr(t, m)
	if got := asExitError(t, err).code; got != 0 {
		t.Fatalf("exit = %d, want the target's own 0:\n%s", got, stderr)
	}
	if want := "a denial is the script's own error to report"; !strings.Contains(stderr, want) {
		t.Errorf("a completed run must render its verdict (%q):\n%s", want, stderr)
	}
}

// The stamp-at-risk note is computed in run's own RunE (run.go), not by the writer that
// renders it, so a round-trip of a hand-built runNotesJSON through writeRunResult stays
// green while run builds the slice wrong or stops assigning it. This is the only test
// that drives the real command over a real manifest whose directory anyone can write and
// reads the key back off stdout.
func TestRunJSONCarriesStampAtRisk(t *testing.T) {
	requireSandbox(t)

	m := writeRunnableManifest(t, "exit 0\n", &policy.Policy{Entrypoint: "./run.sh", Interpreter: "sh"})
	// The flaw itself: a stamp in a directory anyone can write attests only what whoever
	// can write it leaves there.
	if err := os.Chmod(filepath.Dir(m), 0o777); err != nil {
		t.Fatal(err)
	}

	out, _ := runCapturingStdout(t, newRunCmd(), "--json", m)
	var carried []flawJSON
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var obj struct {
			Event       string     `json:"event"`
			StampAtRisk []flawJSON `json:"stamp_at_risk"`
		}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("run --json emitted a line that is not JSON (%v): %s", err, line)
		}
		if obj.Event == "verdict" {
			carried = obj.StampAtRisk
		}
	}
	if len(carried) == 0 {
		t.Fatalf("run --json must carry the stamp's flaws on the verdict object; got:\n%s", out)
	}
	// The hint is what tells the reader what to do about it, and it is the half a
	// consumer reading only the reason would lose.
	for _, f := range carried {
		if f.Reason == "" || f.Hint == "" {
			t.Errorf("each stamp_at_risk entry must carry both the reason and its hint; got %+v", f)
		}
	}
}

// Arguments after -- are refused unless the manifest opts in: the stamp's reviewer read
// one command line, and a one-shot manifest must not be repurposable into a runner for
// whatever a caller sends.
func TestRunRefusesExtraArgsWithoutTheOptIn(t *testing.T) {
	m := writeRunnableManifest(t, "exit 0\n", &policy.Policy{Entrypoint: "./run.sh", Interpreter: "sh"})
	err := runCmd(t, m, "--", "surprise")
	if err == nil || !strings.Contains(err.Error(), "extra_args") {
		t.Fatalf("run appended arguments the manifest never allowed; want a refusal naming extra_args, got %v", err)
	}
	// A stray positional before -- is a usage mistake as it always was, opt-in or not.
	if err := runCmd(t, m, "stray", "--", "x"); err == nil {
		t.Fatal("a second positional before -- was accepted")
	}
}

// With the opt-in, extra arguments land after the manifest's fixed ones, in order and
// unsplit, and the run says what it appended - they are not in the stamp, so the report
// is the only place a reader sees them.
func TestRunAppendsExtraArgsAfterTheFixedOnes(t *testing.T) {
	requireSandbox(t)

	m := writeRunnableManifest(t, `[ "$#|$1|$2|$3" = "3|fixed|a|b c" ] || exit 9`+"\n", &policy.Policy{
		Entrypoint:  "./run.sh",
		Interpreter: "sh",
		Args:        []string{"fixed"},
		ExtraArgs:   true,
	})
	stderr, err := runCmdCapturingStderr(t, m, "--", "a", "b c")
	if got := asExitError(t, err).code; got != 0 {
		t.Fatalf("exit = %d, want 0 (9 means the target saw the wrong argv):\n%s", got, stderr)
	}
	if want := `extra args: "a" "b c"`; !strings.Contains(stderr, want) {
		t.Errorf("the run must disclose the arguments it appended (%q):\n%s", want, stderr)
	}
}

// Approval is the stamp inside the manifest, so a run that can write its own manifest can
// widen it and re-stamp it (`bento approve --yes` needs nothing the sandbox withholds),
// and the next run executes a policy no human read. The manifest is read-only to its own
// run for that reason, including under a write grant that covers it.
func TestRunCannotRewriteItsOwnManifest(t *testing.T) {
	requireSandbox(t)

	m := writeRunnableManifest(t, `echo "write: [/]" >> bento.yaml && exit 0; exit 7`+"\n", &policy.Policy{
		Entrypoint:  "./run.sh",
		Interpreter: "sh",
		Workdir:     ".",
		Read:        []string{"."},
		Write:       []string{"."},
	})
	before, err := os.ReadFile(m)
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := runCmdCapturingStderr(t, m)
	if got := asExitError(t, err).code; got != 7 {
		t.Errorf("exit = %d, want the target's 7 from a refused write:\n%s", got, stderr)
	}
	if after, _ := os.ReadFile(m); string(after) != string(before) {
		t.Errorf("the run rewrote its own manifest:\n%s", after)
	}
}
