//go:build linux

package main

import (
	"encoding/json"
	"os"
	"os/exec"
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
	// A multi-line script is the ordinary shape of an agent's command (heredocs, several
	// statements). The appended args are not the approved policy, so the screen that keeps
	// a newline out of fingerprinted fields has nothing to protect here.
	m = writeRunnableManifest(t, `[ "$2" = "$(printf 'one\ntwo')" ] || exit 9`+"\n", &policy.Policy{
		Entrypoint:  "./run.sh",
		Interpreter: "sh",
		Args:        []string{"fixed"},
		ExtraArgs:   true,
	})
	stderr, err = runCmdCapturingStderr(t, m, "--", "one\ntwo")
	if got := asExitError(t, err).code; got != 0 {
		t.Fatalf("exit = %d, want 0 (9 means the target saw the wrong argv):\n%s", got, stderr)
	}
	if want := `extra args: "one\ntwo"`; !strings.Contains(stderr, want) {
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

// The bind over the manifest holds only its own name, so a write grant wider than the
// manifest's directory could rename that directory away and put a new manifest in its
// place. run refuses that shape. Both halves run for real: the refusal, and, with the
// write grant rooted at the manifest's directory, every way of moving the manifest
// failing inside the sandbox.
func TestRunKeepsTheManifestPutUnderAWiderWriteGrant(t *testing.T) {
	requireSandbox(t)

	script := `d=$(basename "$PWD")
rm -f bento.yaml 2>/dev/null && exit 3
mv bento.yaml x.yaml 2>/dev/null && exit 4
cd .. && mv "$d" moved 2>/dev/null && exit 5
exit 0
`
	wide := &policy.Policy{Entrypoint: "./run.sh", Interpreter: "sh", Workdir: ".", Write: []string{".."}, Exec: policy.ExecAll}
	m := writeRunnableManifest(t, script, wide)
	if err := runCmd(t, m); err == nil || !strings.Contains(err.Error(), "renamed") {
		t.Fatalf("a manifest whose directory a write grant could rename was run; want a refusal, got %v", err)
	}

	rooted := &policy.Policy{Entrypoint: "./run.sh", Interpreter: "sh", Workdir: ".", Write: []string{"."}, Exec: policy.ExecAll}
	m = writeRunnableManifest(t, script, rooted)
	stderr, err := runCmdCapturingStderr(t, m)
	if got := asExitError(t, err).code; got != 0 {
		t.Fatalf("exit = %d (3 unlinked, 4 renamed the manifest, 5 renamed its directory):\n%s", got, stderr)
	}
	if _, err := os.Stat(m); err != nil {
		t.Errorf("the manifest is gone from where it was approved: %v", err)
	}
}

// A shield is a bind over one path, and the kernel refuses to rename a mount point but
// not a directory above one: renaming .git carried the .git/hooks bind away with it, and
// a fresh .git/hooks/pre-commit landed on the host to run at the developer's next commit.
// Every directory between a write grant and a shield has to hold still for the shield
// to mean anything - including one the shield itself had to create, like an absent .cargo.
func TestRenamingAShieldsParentDoesNotReachTheHost(t *testing.T) {
	requireSandbox(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("needs git")
	}

	script := `touch .git/objects/written || exit 6
mv .git .git.old 2>/dev/null && mkdir -p .git/hooks && echo planted > .git/hooks/pre-commit
mv .cargo .cargo.old 2>/dev/null; mkdir -p .cargo && echo planted > .cargo/config.toml
exit 0
`
	m := writeRunnableManifest(t, script, &policy.Policy{
		Entrypoint: "./run.sh", Interpreter: "sh", Workdir: ".", Write: []string{"."}, Exec: policy.ExecAll,
	})
	dir := filepath.Dir(m)
	if out, err := exec.Command("git", "init", "-q", dir).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	stderr, err := runCmdCapturingStderr(t, m)
	if got := asExitError(t, err).code; got != 0 {
		t.Fatalf("exit = %d (6: the pin left .git unwritable, which the grant made writable):\n%s", got, stderr)
	}
	// .cargo did not exist before the run; the pin had to create it, and the run's
	// shield cleanup must take it away again.
	if _, err := os.Lstat(filepath.Join(dir, ".cargo")); err == nil {
		t.Error("the run left a .cargo directory on the host that it created to pin")
	}
	for _, p := range []string{".git/hooks/pre-commit", ".cargo/config.toml"} {
		if b, _ := os.ReadFile(filepath.Join(dir, p)); strings.Contains(string(b), "planted") {
			t.Errorf("%s was planted on the host by renaming the directory above its shield", p)
		}
	}
}

// Workspace shields anchored only at the checkout enclosing each write grant, so a git
// repository further down - a vendored repo, a monorepo's sub-checkout - kept a writable
// .git/hooks, and a hook planted there ran on the host at the next commit in it.
func TestANestedCheckoutsHooksAreShielded(t *testing.T) {
	requireSandbox(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("needs git")
	}

	m := writeRunnableManifest(t, "echo planted > vendor/lib/.git/hooks/pre-commit; echo planted > vendor/lib/.git/config; echo planted > wt/.git; exit 0\n", &policy.Policy{
		Entrypoint: "./run.sh", Interpreter: "sh", Workdir: ".", Write: []string{"."},
	})
	nested := filepath.Join(filepath.Dir(m), "vendor", "lib")
	if out, err := exec.Command("git", "init", "-q", nested).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	// A linked worktree's .git is a pointer file; repointing it at a gitdir the run
	// fabricates runs that gitdir's hooks at the next git command in the worktree.
	wt := filepath.Join(filepath.Dir(m), "wt")
	if err := os.MkdirAll(wt, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: /elsewhere\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stderr, err := runCmdCapturingStderr(t, m)
	if got := asExitError(t, err).code; got != 0 {
		t.Fatalf("exit = %d:\n%s", got, stderr)
	}
	for _, p := range []string{"vendor/lib/.git/hooks/pre-commit", "vendor/lib/.git/config", "wt/.git"} {
		if b, _ := os.ReadFile(filepath.Join(filepath.Dir(m), p)); strings.Contains(string(b), "planted") {
			t.Errorf("%s was planted on the host through the write grant above it", p)
		}
	}
}

// The approval does not cover appended arguments, so a gate reading --json alone has to
// be able to see them - the stderr line is not part of that stream.
func TestRunJSONCarriesExtraArgs(t *testing.T) {
	requireSandbox(t)

	m := writeRunnableManifest(t, "exit 0\n", &policy.Policy{Entrypoint: "./run.sh", Interpreter: "sh", ExtraArgs: true})
	out, err := runCapturingStdout(t, newRunCmd(), "--json", m, "--", "appended")
	if asExitError(t, err).code != 0 {
		t.Fatalf("run failed:\n%s", out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if !strings.Contains(lines[len(lines)-1], `"extra_args":["appended"]`) {
		t.Errorf("the verdict object does not carry the appended args:\n%s", lines[len(lines)-1])
	}
}

// Claude Code keeps worktrees at .claude/worktrees/<n>, inside the read-only .claude
// shield. A checkout found there is already out of the run's reach for writes, and giving
// it shields of its own made bwrap try to create their mount points inside a read-only
// mount - which killed every run on such a checkout.
func TestANestedCheckoutInsideAShieldDoesNotBreakTheRun(t *testing.T) {
	requireSandbox(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("needs git")
	}
	m := writeRunnableManifest(t, "exit 0\n", &policy.Policy{Entrypoint: "./run.sh", Interpreter: "sh", Workdir: ".", Write: []string{"."}})
	dir := filepath.Dir(m)
	for _, args := range [][]string{
		{"init", "-q", dir},
		{"-C", dir, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "x"},
		{"-C", dir, "worktree", "add", "-q", filepath.Join(dir, ".claude", "worktrees", "wt1")},
	} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	stderr, err := runCmdCapturingStderr(t, m)
	if got := asExitError(t, err).code; got != 0 {
		t.Fatalf("exit = %d, want 0:\n%s", got, stderr)
	}
}

// A write grant inside a nested checkout's shield is refused the way one inside the
// enclosing checkout's is. Admitted, it was silently neutered: the shield's mount took
// every write and the host file never appeared.
func TestAWriteGrantInsideANestedCheckoutsShieldIsRefused(t *testing.T) {
	requireSandbox(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("needs git")
	}
	m := writeRunnableManifest(t, "exit 0\n", &policy.Policy{Entrypoint: "./run.sh", Interpreter: "sh", Workdir: ".", Write: []string{".", "vendor/lib/.vscode"}})
	if out, err := exec.Command("git", "init", "-q", filepath.Join(filepath.Dir(m), "vendor", "lib")).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	if err := runCmd(t, m); err == nil || !strings.Contains(err.Error(), ".vscode") {
		t.Fatalf("a write grant inside a nested checkout's .vscode shield was not refused naming it; got %v", err)
	}
}

// Agent config in a project directory with no .git below the grant root had no shield:
// the workspace shields anchor at git checkouts. An existing .claude/settings.json there
// declares hooks Claude Code runs on the host when the project is opened.
func TestAgentConfigInANonGitProjectIsShielded(t *testing.T) {
	requireSandbox(t)

	m := writeRunnableManifest(t, "echo planted > notes/.claude/settings.json; echo planted > notes/.mcp.json; exit 0\n", &policy.Policy{
		Entrypoint: "./run.sh", Interpreter: "sh", Workdir: ".", Write: []string{"."},
	})
	notes := filepath.Join(filepath.Dir(m), "notes")
	if err := os.MkdirAll(filepath.Join(notes, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{".claude/settings.json", ".mcp.json"} {
		if err := os.WriteFile(filepath.Join(notes, f), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stderr, err := runCmdCapturingStderr(t, m)
	if got := asExitError(t, err).code; got != 0 {
		t.Fatalf("exit = %d:\n%s", got, stderr)
	}
	for _, f := range []string{".claude/settings.json", ".mcp.json"} {
		if b, _ := os.ReadFile(filepath.Join(notes, f)); strings.Contains(string(b), "planted") {
			t.Errorf("notes/%s was planted on the host through the write grant above it", f)
		}
	}

	// A grant inside it is refused, not admitted and silently neutered by the shield.
	m = writeRunnableManifest(t, "exit 0\n", &policy.Policy{
		Entrypoint: "./run.sh", Interpreter: "sh", Workdir: ".", Write: []string{".", "notes/.claude"},
	})
	if err := os.MkdirAll(filepath.Join(filepath.Dir(m), "notes", ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := runCmd(t, m); err == nil || !strings.Contains(err.Error(), ".claude") {
		t.Errorf("a write grant inside a non-git project's .claude was not refused naming it; got %v", err)
	}
}

// A git worktree kept under a project's .claude that is not the grant root: the .claude is
// shielded now, and a checkout inside it must be left alone like one under the root's.
func TestAWorktreeUnderADeepClaudeDoesNotBreakTheRun(t *testing.T) {
	requireSandbox(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("needs git")
	}
	m := writeRunnableManifest(t, "exit 0\n", &policy.Policy{Entrypoint: "./run.sh", Interpreter: "sh", Workdir: ".", Write: []string{"."}})
	proj := filepath.Join(filepath.Dir(m), "proj")
	for _, args := range [][]string{
		{"init", "-q", proj},
		{"-C", proj, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "x"},
		{"-C", proj, "worktree", "add", "-q", filepath.Join(filepath.Dir(m), "notes", ".claude", "worktrees", "wt1")},
	} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	stderr, err := runCmdCapturingStderr(t, m)
	if got := asExitError(t, err).code; got != 0 {
		t.Fatalf("exit = %d, want 0:\n%s", got, stderr)
	}
}
