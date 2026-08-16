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
	"time"
)

// hookResolveTimeout bounds one `git rev-parse --git-path hooks`, so a grant whose
// object store sits on an unresponsive network mount cannot hang the preflight before
// the sandbox is built. Expiring is an error like any other: it leaves the grant
// unresolved and the report says so.
var hookResolveTimeout = 5 * time.Second

// The auto-executing files a write grant legitimately contains. Each runs on the host
// without anyone reading it first - the criterion the shields are built on - but each is
// also a checked-in project file an agent doing ordinary work must be able to edit, so
// denying them turns routine work into refusals. They are reported instead: a reviewer
// who knows which of these a run touched looks there first.
//
// The names are the ones that execute with no lifecycle script and no approval record in
// between. Notably not the same set as "files a build reads": a Makefile or a Dockerfile
// runs only because someone typed the command, which is the review the shields exist to
// preserve.
var autoExecNames = []string{
	"package.json",            // scripts.{pre,post}install run on the next npm/yarn/pnpm install
	".npmrc",                  // registry= routes the install through a dependency's install script
	".yarnrc",                 // yarn-path names a binary yarn execs on ANY invocation
	".yarnrc.yml",             // yarnPath, the berry spelling of the same
	".pnpmfile.cjs",           // pnpm executes it on every install; ignore-scripts does not disable it
	".pnpmfile.js",            // the legacy filename pnpm still reads
	".pre-commit-config.yaml", // an installed hook reads it at commit time, so a `repo: local` entry runs without the run touching .git
	"eslint.config.js",        // flat config is executed as a module, and it resolves plugins out of node_modules
	"eslint.config.mjs",       // the ESM spelling of the same
	"conftest.py",             // imported on pytest collection
	"setup.py",                // executed by pip install and by setuptools
	"build.rs",                // compiled and run by cargo build
	"mvnw",                    // the maven wrapper script itself
	"gradlew",                 // the gradle wrapper script itself
	".mvn/extensions.xml",     // loaded into the maven JVM on the next ./mvnw
	".mvn/jvm.config",         // JVM flags the wrapper passes, including agent paths
	"gradle/wrapper/gradle-wrapper.properties", // distributionUrl decides which gradle the wrapper downloads and runs
}

// The directories under a write grant whose every entry auto-executes, so no fixed name
// reaches them. Each is listed one level deep, and a subdirectory that holds more of the
// same is named in its own right rather than walked - a recursive walk of a grant is what
// this deliberately is not.
//
// The .husky names stay even though hookRunnerDir resolves core.hooksPath: husky's
// directory is committed, and a clone whose `npm install` has not run yet has the hooks
// on disk with core.hooksPath still unset.
//
// Residual: .github/actions/<name>/action.yml is a local composite action a workflow
// runs, and the name in the middle is chosen per repo, so no concrete path reaches it.
var autoExecDirs = []string{
	".github/workflows", // runs on the CI host at the next push
	".husky",            // husky's default core.hooksPath
	".husky/_",          // husky v9 keeps the wrapper the hooks source in here
}

// hookRunnerDir names the directory git runs this checkout's hooks out of. Everything in
// it executes on the host at the next commit with nobody reading it first, which is the
// criterion autoExecDirs is built on - but unlike those, its location is configuration
// rather than a fixed name. core.hooksPath is commonly something other than .husky:
// tooling that installs its own hooks (beads, and any other non-husky installer) points
// it at an in-tree directory of its own, whose contents are then ordinary project files
// under a write grant that the report never named.
//
// The value that matters is the one git itself computes - relative to the checkout,
// overridden per linked worktree, or absolute and pointing at another repo entirely -
// so this asks git rather than parsing .git/config, which gets the worktree and relative
// cases wrong. It is a fixed cost, not a tree walk: one resolution per grant.
//
// Running git against the grant is not a way in for the run. Only the BASELINE resolves
// it, and the after-snapshot walks that answer - see autoExecBaseline, which is where the
// value is actually fixed for the run. The shields do most of it: gitDirShields DenyWrites
// .git/config and every config.worktree, the workspace denylist covers ~/.gitconfig and
// ~/.config/git/config, and /etc/gitconfig is under no write grant. What they do not cover
// is a write grant with no enclosing checkout, where there is no .git to shield and the
// target can git init one of its own; resolving once is what answers that case too.
// GIT_* is dropped below for the same reason
// from the other direction - notably GIT_CONFIG_GLOBAL, which would name a global config
// no shield covers - and `rev-parse --git-path` only reads config, so none of git's
// config-driven exec knobs (aliases, pager, fsmonitor, textconv) fire for it.
//
// Answers outside every write grant are dropped: an absolute hooksPath into a checkout
// the run cannot write is not a file the run can plant. The default .git/hooks is inside
// the grant and stays in, at the cost of a ReadDir - it is DenyWrite-shielded, so it
// cannot change and never reaches the report.
//
// Containment is tested on symlink-resolved paths, both sides. core.hooksPath is fixed
// for the run but the directory it names is an ordinary project path the run may replace
// with a symlink, and comparing the names alone would then have the after-snapshot walk
// wherever that link points - turning the report into a list of host files outside every
// grant. Resolving also keeps the other direction honest, where an absolute hooksPath
// spells a real grant through a different alias and the hint would be dropped. A path
// that cannot be resolved at all is compared as written, whatever the reason: EvalSymlinks
// needs the same traversal the stamping ReadDir needs, so a name it cannot walk is one
// nothing walks either.
//
// The resolution and the ReadDir that follows it are two separate lookups, which a
// process racing between them could point at different directories. Neither snapshot
// runs while the target does - the baseline precedes it and the compare follows it - so
// the racer has to be something that outlived the target, which the bwrap tier's pid
// namespace reaps. It is a residual of the degraded tier and the cancelled run, and it
// costs the report a stray filename rather than anything a read of names can reach.
//
// Where the grant is not a repo at all, git discovers upward, so an enclosing checkout's
// hooks directory can be the answer. It is reported only if it too is under a write
// grant, which is the same question asked of any other answer.
//
// An error is returned rather than folded into the empty answer: a git that does not
// answer does not mean the grant has no hook directory, it means this run cannot see the
// one it has, and an empty report from such a host would otherwise read exactly like an
// empty report from a clean one.
func hookRunnerDir(grant string, writes []string) (string, error) {
	// The deadline is this call's own rather than the run's: changed() asks again after
	// the target, on the cancelled path too, and a cancelled run's context would fail
	// every resolution there and report the answer unseeable when it was merely late to
	// be asked. What this bounds is a grant whose object store sits on a dead mount,
	// where cmd.Output() otherwise blocks for as long as git does.
	ctx, cancel := context.WithTimeout(context.Background(), hookResolveTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "--git-path", "hooks")
	cmd.Dir = grant
	// GIT_* out of the environment, or the answer is not this grant's. GIT_DIR and
	// GIT_WORK_TREE override cmd.Dir outright (measured), and GIT_CONFIG_COUNT with
	// GIT_CONFIG_KEY_0=core.hooksPath sets the value directly - all three are set
	// whenever bento is itself run from a hook or a `git rebase --exec`, which is an
	// ordinary way to reach it.
	cmd.Env = slices.DeleteFunc(os.Environ(), func(kv string) bool {
		return strings.HasPrefix(kv, "GIT_")
	})
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse --git-path hooks in %s: %w", grant, err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		return "", nil
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(grant, dir)
	}
	dir = resolved(dir)
	for _, w := range writes {
		rel, err := filepath.Rel(resolved(w), dir)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
			return dir, nil
		}
	}
	return "", nil
}

// resolved is EvalSymlinks with the path itself as the answer when it cannot be walked.
func resolved(path string) string {
	if p, err := filepath.EvalSymlinks(path); err == nil {
		return p
	}
	return path
}

// autoExecState is one snapshot of those files: absolute path to a size-and-mtime stamp,
// with a missing file simply absent. Comparing two of them names what a run created,
// modified or removed.
type autoExecState map[string]string

// autoExecBaseline is the preflight snapshot together with the hook directories that
// resolved to, and the pairing is the point. core.hooksPath is only as fixed for the run
// as the files it comes from, and a write grant with NO enclosing checkout has none of
// them: nothing above it is a repo, so nothing is shielded, and the target can git init
// inside the grant and set core.hooksPath to any other write-granted directory. Asking
// again afterwards would walk wherever the run just pointed it and report every file
// there as newly created - noise in a hint the operator is told to read, which is how a
// hint stops being read. So the answer is taken once, before the target runs, and the
// after-snapshot walks that.
type autoExecBaseline struct {
	state      autoExecState
	hooks      []string
	unresolved []string
}

// changed re-stamps the same paths the baseline stamped and names what the run altered,
// and separately any hook directory the run itself put in play. The second question is
// asked here rather than left to the frozen walk because freezing answers the noise and
// not the silence: see redirectedHooks. The two answers stay apart because they are
// different claims - one is a file this run wrote, the other a directory it may never have
// touched - and a caller with one flat list can only word them alike.
func (b autoExecBaseline) changed(writes []string) (changed, redirected, unresolved []string) {
	changed = changedAutoExec(b.state, snapshotAutoExec(writes, b.hooks))
	slices.Sort(changed)
	after, afterUnresolved := hookRunnerDirs(writes)
	redirected = redirectedHooks(b.hooks, after)
	slices.Sort(redirected)
	// Either side's failure makes the redirect answer short: a grant unresolvable before
	// the run has no baseline to compare against, and one unresolvable after has nothing
	// to compare.
	unresolved = append(slices.Clone(b.unresolved), afterUnresolved...)
	slices.Sort(unresolved)
	return slices.Compact(changed), slices.Compact(redirected), slices.Compact(unresolved)
}

// snapshotAutoExec stats the auto-executing files under each write grant. Errors are
// dropped rather than surfaced: a path that cannot be stat'd is one this run also could
// not have changed in a way the comparison would see, and a report is a hint - failing a
// run over it would trade a fence's cost for a hint's benefit.
//
// hooks are the hook directories to stamp, which only the baseline discovers; every later
// snapshot is handed the baseline's answer.
func snapshotAutoExec(writes, hooks []string) autoExecState {
	state := autoExecState{}
	stamp := func(p string) {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			state[p] = fmt.Sprintf("%d:%d", fi.Size(), fi.ModTime().UnixNano())
		}
	}
	stampDir := func(dir string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			stamp(filepath.Join(dir, e.Name()))
		}
	}
	for _, w := range writes {
		for _, n := range autoExecNames {
			stamp(filepath.Join(w, n))
		}
		for _, d := range autoExecDirs {
			stampDir(filepath.Join(w, d))
		}
	}
	for _, h := range hooks {
		stampDir(h)
	}
	return state
}

// baselineAutoExec is the preflight snapshot: the one that resolves core.hooksPath, per
// grant, and keeps the answer for every snapshot after it.
func baselineAutoExec(writes []string) autoExecBaseline {
	hooks, unresolved := hookRunnerDirs(writes)
	return autoExecBaseline{state: snapshotAutoExec(writes, hooks), hooks: hooks, unresolved: unresolved}
}

// hookRunnerDirs is every hook directory the write grants resolve to, deduplicated. The
// order follows the grants, so two snapshots of one run list them alike.
// unresolved names the grants git could not answer for, so the caller can say the report
// is short rather than let a host where git failed read like a clean one.
func hookRunnerDirs(writes []string) (hooks, unresolved []string) {
	for _, w := range writes {
		h, err := hookRunnerDir(w, writes)
		if err != nil {
			unresolved = append(unresolved, w)
			continue
		}
		if h != "" && !slices.Contains(hooks, h) {
			hooks = append(hooks, h)
		}
	}
	return hooks, unresolved
}

// redirectedHooks names a hook directory the run itself put in play - the answer git gives
// after the target ran that it did not give before.
//
// The DIRECTORY is what gets named, not the files inside it, and that is the whole design.
// The baseline never stamped it, so every file there would read as newly created and the
// report would fill with a directory's existing contents; but saying nothing is worse,
// because two real shapes reach here. A write grant with no enclosing checkout has no
// .git for the shields to hold down, so the target can git init one and point hooks
// wherever it likes. And the degraded tier applies no shields at all, so even an existing
// checkout's .git/config is writable mid-run there. Either way the operator needs to know
// the run chose where the host's next commit executes from, which is a fact about the
// redirection rather than about any file - and it is true whether or not anything was
// planted yet.
func redirectedHooks(before, after []string) []string {
	var out []string
	for _, h := range after {
		if !slices.Contains(before, h) {
			out = append(out, h)
		}
	}
	return out
}

// changedAutoExec names the files whose stamp the run changed, in either direction: a
// path in one snapshot and not the other was created or removed, a path in both with a
// different stamp was modified. Sorted, so the report reads the same on every run.
func changedAutoExec(before, after autoExecState) []string {
	var changed []string
	for p, b := range before {
		if a, ok := after[p]; !ok || a != b {
			changed = append(changed, p)
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			changed = append(changed, p)
		}
	}
	slices.Sort(changed)
	return changed
}
