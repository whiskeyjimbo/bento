//go:build linux

package linux

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

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
// Running git against the grant is not a way in for the run. gitDirShields DenyWrites
// .git/config and every config.worktree, the workspace denylist covers ~/.gitconfig and
// ~/.config/git/config, and /etc/gitconfig is under no write grant - so every file the
// value could come from is fixed for the run. GIT_* is dropped below for the same reason
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
func hookRunnerDir(grant string, writes []string) string {
	cmd := exec.Command("git", "rev-parse", "--git-path", "hooks")
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
		return ""
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		return ""
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(grant, dir)
	}
	dir = resolved(dir)
	for _, w := range writes {
		rel, err := filepath.Rel(resolved(w), dir)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
			return dir
		}
	}
	return ""
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

// snapshotAutoExec stats the auto-executing files under each write grant. Errors are
// dropped rather than surfaced: a path that cannot be stat'd is one this run also could
// not have changed in a way the comparison would see, and a report is a hint - failing a
// run over it would trade a fence's cost for a hint's benefit.
func snapshotAutoExec(writes []string) autoExecState {
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
		if hooks := hookRunnerDir(w, writes); hooks != "" {
			stampDir(hooks)
		}
	}
	return state
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
