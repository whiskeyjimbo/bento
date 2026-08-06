//go:build linux

package linux

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
// Residual: .github/actions/<name>/action.yml is a local composite action a workflow
// runs, and the name in the middle is chosen per repo, so no concrete path reaches it.
var autoExecDirs = []string{
	".github/workflows", // runs on the CI host at the next push
	".husky",            // an in-tree hook runner core.hooksPath points at
	".husky/_",          // husky v9 keeps the wrapper the hooks source in here
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
	for _, w := range writes {
		for _, n := range autoExecNames {
			stamp(filepath.Join(w, n))
		}
		for _, d := range autoExecDirs {
			dir := filepath.Join(w, d)
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				stamp(filepath.Join(dir, e.Name()))
			}
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
