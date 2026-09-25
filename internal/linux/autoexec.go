//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
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
// this deliberately is not. The one walk the report does make is the one the shields
// already make, for the git checkouts nested below a grant: each is a root of its own here,
// with its own names, directories and hook directory - see nestedCheckoutRoots.
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
// cases wrong. It is a fixed cost, not a tree walk: one resolution per checkout the grants
// sit in, which hookRunnerDirs shares among them.
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
// no shield covers - and the commands asked, `rev-parse --git-path`, outside a work tree
// `config --get core.hooksPath`, and includeTargets' `config --get-regexp`, only read
// config, so none of git's config-driven exec knobs (aliases, pager, fsmonitor, textconv)
// fire for them.
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
//
// resolvedWrites are the write grants already resolved, once per pass by the caller: this
// runs once per grant, so resolving them here would cost a pass grants squared symlink
// walks. grant is resolved too: git's relative answer is relative to the physical
// directory it ran in, and joined onto a name spelled through a symlink its ".." steps
// would climb out of the link's parent instead.
func hookRunnerDir(grant string, resolvedWrites []string) (string, error) {
	a, err := askGitHooks(grant)
	if err != nil {
		return "", err
	}
	dir := a.hooks
	// Outside a work tree git has no prefix to make a relative core.hooksPath relative to,
	// so it hands the value back as configured, and that is relative to where hooks run -
	// the git directory of a bare repository, the work tree of any other - not to the grant.
	// Joining it onto the grant would also make the answer depend on which grant under one
	// git directory asked first, which hookRunnerDirs' sharing relies on it not doing. The
	// default hooks directory is spelled relative to the grant there as everywhere, so
	// which of the two a relative answer is takes a second ask.
	if !filepath.IsAbs(dir) {
		configured := false
		if !a.insideWorkTree && !a.bare {
			if configured, err = hooksPathConfigured(grant); err != nil {
				return "", err
			}
		}
		switch {
		case a.insideWorkTree || !a.bare && !configured:
			dir = filepath.Join(grant, dir)
		case a.bare:
			dir = filepath.Join(a.gitDir, dir)
		// A directory named .git is normally its parent's, so git is asked again from there,
		// and its answer is taken only if that parent is the work tree: one set elsewhere by
		// core.worktree is where hooks run, and git does not name it from here.
		case filepath.Base(a.gitDir) == ".git":
			top := filepath.Dir(a.gitDir)
			b, err := askGitHooks(top)
			if err != nil {
				return "", err
			}
			if !b.insideWorkTree {
				return "", fmt.Errorf("grant %s: git directory %s has no work tree at %s, so a relative core.hooksPath %q has no directory to be relative to", grant, a.gitDir, top, dir)
			}
			dir = b.hooks
			if !filepath.IsAbs(dir) {
				dir = filepath.Join(top, dir)
			}
		// A linked worktree's or a submodule's git directory, whose work tree is recorded
		// somewhere git does not report from here. Unresolved rather than guessed.
		default:
			return "", fmt.Errorf("grant %s is outside the work tree of git directory %s, which git cannot name from there, so a relative core.hooksPath %q has no directory to be relative to", grant, a.gitDir, dir)
		}
	}
	dir = resolved(dir)
	if underAny(dir, resolvedWrites) {
		return dir, nil
	}
	return "", nil
}

// underAny says whether the resolved path p is at or below one of the resolved grants.
func underAny(p string, resolvedWrites []string) bool {
	for _, w := range resolvedWrites {
		rel, err := filepath.Rel(w, p)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
			return true
		}
	}
	return false
}

// gitHooksAnswer is what git reports from one directory: its hooks path as git spells it
// there, and where that directory sits relative to the repository.
type gitHooksAnswer struct {
	hooks          string
	insideWorkTree bool
	bare           bool
	gitDir         string
}

// askGitHooks runs the one rev-parse hookRunnerDir reads, in dir.
func askGitHooks(dir string) (gitHooksAnswer, error) {
	out, err := runGit(dir, "rev-parse", "--is-inside-work-tree", "--is-bare-repository", "--absolute-git-dir", "--git-path", "hooks")
	if err != nil {
		return gitHooksAnswer{}, err
	}
	// A git older than --absolute-git-dir (2.13) echoes the flag it does not know as a line
	// of its own, so the count alone would pass; the git directory has to be a path.
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 || !filepath.IsAbs(lines[2]) {
		return gitHooksAnswer{}, fmt.Errorf("git rev-parse in %s: want four lines naming an absolute git directory, got %q", dir, out)
	}
	return gitHooksAnswer{
		insideWorkTree: lines[0] == "true",
		bare:           lines[1] == "true",
		gitDir:         lines[2],
		hooks:          lines[3],
	}, nil
}

// hooksPathConfigured says whether core.hooksPath is set for the repository git finds from
// dir. `git config --get` exits 1 for a key that is not set, which is an answer here and
// not a failure.
func hooksPathConfigured(dir string) (bool, error) {
	_, err := runGit(dir, "config", "--get", "core.hooksPath")
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return false, nil
	}
	return err == nil, err
}

// runGit runs git in dir and returns its standard output.
func runGit(dir string, args ...string) (string, error) {
	// The deadline is this call's own rather than the run's: changed() asks again after
	// the target, on the cancelled path too, and a cancelled run's context would fail
	// every resolution there and report the answer unseeable when it was merely late to
	// be asked. What this bounds is a grant whose object store sits on a dead mount,
	// where cmd.Output() otherwise blocks for as long as git does.
	ctx, cancel := context.WithTimeout(context.Background(), hookResolveTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	// Without this the deadline above bounds nothing, for probeWaitDelay's reason: Output
	// waits for the pipe, and a git wedged on the dead mount this bound exists for ignores
	// the kill in uninterruptible sleep while still holding it.
	cmd.WaitDelay = probeWaitDelay
	// GIT_* out of the environment, or the answer is not this grant's. GIT_DIR and
	// GIT_WORK_TREE override cmd.Dir outright (measured), and GIT_CONFIG_COUNT with
	// GIT_CONFIG_KEY_0=core.hooksPath sets the value directly - all three are set
	// whenever bento is itself run from a hook or a `git rebase --exec`, which is an
	// ordinary way to reach it.
	cmd.Env = slices.DeleteFunc(os.Environ(), func(kv string) bool {
		return strings.HasPrefix(kv, "GIT_")
	})
	out, err := cmd.Output()
	// The deadline is this call's own (see above), so there is no caller to have given up
	// first: the parent is Background and noteProbeDeadline's live-parent test is free.
	noteProbeDeadline(context.Background(), ctx)
	if err != nil {
		return "", fmt.Errorf("git %s in %s: %w", strings.Join(args, " "), dir, err)
	}
	return string(out), nil
}

// resolved is EvalSymlinks with the path itself as the answer when it cannot be walked.
//
// Under the walks' bound, because EvalSymlinks lstats every component and a hook
// directory on a mount that stopped answering blocks it for as long as the mount hangs -
// after the bounded git call has already returned, and on the after-run path too. An
// expiry lands on the fallback the function already has for a path it cannot walk.
func resolved(path string) string {
	p, err := bounded("the symlink resolution of "+path, func() (string, error) {
		return evalSymlinks(path)
	})
	if err != nil {
		return path
	}
	return p
}

// evalSymlinks is behind a var for autoExecStat's reason: the mount its bound exists for
// cannot be stood up in a test otherwise.
var evalSymlinks = filepath.EvalSymlinks

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
//
// nested and includes are fixed the same way, for the same reason: a run that could add a
// checkout or an include directive would otherwise choose what the after-snapshot stamps.
type autoExecBaseline struct {
	state      autoExecState
	hooks      []string
	nested     []string
	includes   []string
	unresolved []string
}

// changed re-stamps the same paths the baseline stamped and names what the run altered,
// and separately any hook directory the run itself put in play. The second question is
// asked here rather than left to the frozen walk because freezing answers the noise and
// not the silence: see redirectedHooks. The two answers stay apart because they are
// different claims - one is a file this run wrote, the other a directory it may never have
// touched - and a caller with one flat list can only word them alike.
func (b autoExecBaseline) changed(writes []string) (changed, redirected, unresolved []string) {
	roots := append(slices.Clone(writes), b.nested...)
	after, afterUnresolved := hookRunnerDirs(roots)
	redirected = redirectedHooks(b.hooks, after)
	slices.Sort(redirected)
	// Either side's failure makes the redirect answer short: a grant unresolvable before
	// the run has no baseline to compare against, and one unresolvable after has nothing
	// to compare.
	unresolved = append(slices.Clone(b.unresolved), afterUnresolved...)

	// The whole snapshot under one bound, not each stat: the names are seventeen per grant
	// plus the directories, so a bound per call would still block for hours. This runs
	// AFTER the target has exited, with the sandbox torn down and nothing left to print,
	// so a grant whose mount died during the run otherwise hangs Run forever with no
	// output - the same total failure the baseline is wrapped against on both tiers.
	state, err := bounded("the auto-exec snapshot of the write grants", func() (autoExecState, error) {
		return snapshotAutoExec(roots, b.hooks, b.includes), nil
	})
	if err != nil {
		// An expired snapshot is empty, and comparing an empty one against the baseline
		// names every file it stamped as removed - a report invented out of a mount that
		// stopped answering, which is worse than the silence. The grants go into
		// unresolved instead, which already says the report is short.
		unresolved = append(unresolved, writes...)
	} else {
		changed = changedAutoExec(b.state, state)
	}
	slices.Sort(changed)
	slices.Sort(unresolved)
	return slices.Compact(changed), slices.Compact(redirected), slices.Compact(unresolved)
}

// autoExecStat is the snapshot's stat behind a var, for probe.go's reason: it is a raw
// host call with no seam, so the mount this snapshot is bounded against cannot be stood
// up in a test at all and the bound could be deleted with everything still green.
var autoExecStat = os.Stat

// snapshotAutoExec stats the auto-executing files under each write grant. Errors are
// dropped rather than surfaced: a path that cannot be stat'd is one this run also could
// not have changed in a way the comparison would see, and a report is a hint - failing a
// run over it would trade a fence's cost for a hint's benefit.
//
// hooks are the hook directories to stamp and includes the config files git reads through
// include directives, which only the baseline discovers; every later snapshot is handed the
// baseline's answer.
func snapshotAutoExec(writes, hooks, includes []string) autoExecState {
	state := autoExecState{}
	stamp := func(p string) {
		if fi, err := autoExecStat(p); err == nil && fi.Mode().IsRegular() {
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
	for _, p := range includes {
		stamp(p)
	}
	return state
}

// baselineAutoExec is the preflight snapshot: the one that resolves core.hooksPath, per
// grant, and keeps the answer for every snapshot after it.
func baselineAutoExec(writes []string) autoExecBaseline {
	nested, unresolved := nestedCheckoutRoots(writes)
	hooks, hooksUnresolved := hookRunnerDirs(append(slices.Clone(writes), nested...))
	includes, includesUnresolved := includeTargets(append(slices.Clone(writes), nested...))
	unresolved = append(append(unresolved, hooksUnresolved...), includesUnresolved...)
	return autoExecBaseline{
		state:      snapshotAutoExec(append(slices.Clone(writes), nested...), hooks, includes),
		hooks:      hooks,
		nested:     nested,
		includes:   includes,
		unresolved: unresolved,
	}
}

// nestedCheckoutRoots is every git checkout below a write grant. A nested checkout is a
// project of its own, with its own package.json, .husky and core.hooksPath, so each is
// treated as a root the way a grant is. The list is the one the shields walk for, bounded
// the same way by maxNestedCheckouts.
//
// A grant whose walk fails or expires is unresolved rather than refused: this is a report,
// and the shields' own walk is what refuses a grant it cannot bound.
//
// ponytail: on the shielded tier this repeats the walk that fills sb.nestedCheckouts;
// hand that list in if the second walk ever shows in a launch's cost.
func nestedCheckoutRoots(writes []string) (nested, unresolved []string) {
	for _, w := range writes {
		found, err := bounded("the search of "+w+" for nested git checkouts", func() ([]string, error) {
			c, _, err := findWorkspaceEntries(resolved(w))
			return c, err
		})
		if err != nil {
			unresolved = append(unresolved, w)
			continue
		}
		for _, c := range found {
			if !slices.Contains(nested, c) {
				nested = append(nested, c)
			}
		}
	}
	return nested, unresolved
}

// includeTargets is every file the checkouts' own config pulls in through include.path or
// includeIf.*.path, when it sits under a write grant. The shields hold .git/config down, but
// a file it includes is config by another name: core.fsmonitor, core.sshCommand or an alias
// set there runs on the host at the next git command, and nothing else stamps it. Every
// directive is taken whatever its condition, since a condition that does not match here
// may match in the next shell.
//
// git names the file it reads config from, which for a linked worktree is the common git
// directory's, and follows the includes itself, so a chain of them is reported as far as
// git reads it - past a matching condition, not past one that does not match here.
//
// A linked worktree's config.worktree is asked too, whether or not extensions.worktreeConfig
// is on here: turning it on is itself one config write away.
// Missing targets are kept: creating one is the write that matters.
func includeTargets(roots []string) (includes, unresolved []string) {
	resolvedWrites := make([]string, 0, len(roots))
	for _, r := range roots {
		resolvedWrites = append(resolvedWrites, resolved(r))
	}
	asked := map[string]bool{}
	for i, r := range roots {
		stop := gitDiscoveryStop(resolvedWrites[i])
		if stop != "" && asked[stop] {
			continue
		}
		asked[stop] = true
		found, err := includesOf(resolvedWrites[i])
		if err != nil {
			unresolved = append(unresolved, r)
			continue
		}
		for _, p := range found {
			if p = resolved(p); underAny(p, resolvedWrites) && !slices.Contains(includes, p) {
				includes = append(includes, p)
			}
		}
	}
	return includes, unresolved
}

// includesOf asks git, in dir, for the include targets of the repository config and the
// worktree's config.worktree.
func includesOf(dir string) ([]string, error) {
	var targets []string
	for _, name := range []string{"config", "config.worktree"} {
		config, err := runGit(dir, "rev-parse", "--git-path", name)
		if err != nil {
			return nil, err
		}
		if config = strings.TrimSpace(config); !filepath.IsAbs(config) {
			config = filepath.Join(dir, config)
		}
		// --show-origin names each directive's file as given, so an absolute --file makes the
		// origin absolute, and a relative value is relative to that file's directory. A file
		// that is not there answers like one with no match.
		out, err := runGit(dir, "config", "--file", config, "--includes", "--show-origin", "--type=path", "-z", "--get-regexp", `^include(if\..*)?\.path$`)
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 {
			continue
		}
		if err != nil {
			return nil, err
		}
		fields := strings.Split(strings.TrimSuffix(out, "\x00"), "\x00")
		if len(fields)%2 != 0 {
			return nil, fmt.Errorf("git config in %s: want origin and entry pairs, got %q", dir, out)
		}
		for i := 0; i < len(fields); i += 2 {
			origin, ok := strings.CutPrefix(fields[i], "file:")
			_, value, entry := strings.Cut(fields[i+1], "\n")
			if !ok || !entry || value == "" {
				return nil, fmt.Errorf("git config in %s: unexpected entry %q from %q", dir, fields[i+1], fields[i])
			}
			if !filepath.IsAbs(value) {
				value = filepath.Join(filepath.Dir(origin), value)
			}
			targets = append(targets, value)
		}
	}
	return targets, nil
}

// hookRunnerDirs is every hook directory the write grants resolve to, deduplicated. The
// order follows the grants, so two snapshots of one run list them alike.
// unresolved names the grants git could not answer for, so the caller can say the report
// is short rather than let a host where git failed read like a clean one.
//
// git is asked once per gitDiscoveryStop rather than once per grant: many grants in one
// checkout are one answer, and each ask is an exec. The answer shared is the finished one,
// absolute and already tested for containment against every grant, so no part of it
// depends on which grant asked.
func hookRunnerDirs(writes []string) (hooks, unresolved []string) {
	resolvedWrites := make([]string, 0, len(writes))
	for _, w := range writes {
		resolvedWrites = append(resolvedWrites, resolved(w))
	}
	type answer struct {
		dir string
		err error
	}
	asked := map[string]answer{}
	for i, w := range writes {
		stop := gitDiscoveryStop(resolvedWrites[i])
		a, ok := asked[stop]
		if stop == "" || !ok {
			a.dir, a.err = hookRunnerDir(resolvedWrites[i], resolvedWrites)
			if stop != "" {
				asked[stop] = a
			}
		}
		if a.err != nil {
			unresolved = append(unresolved, w)
			continue
		}
		if a.dir != "" && !slices.Contains(hooks, a.dir) {
			hooks = append(hooks, a.dir)
		}
	}
	return hooks, unresolved
}

// gitDiscoveryStop is the first directory at or above dir where git's own discovery could
// stop, or "" where this cannot say. Two grants with the same one reach it through
// directories git passes over, and from it upward their walks are the same walk, so git
// answers both from the same repository and the same configuration.
//
// What stops git on the way up is a .git entry of any kind (a directory, a worktree's or
// submodule's gitfile, one git will reject), a directory it takes for a bare repository,
// which needs a HEAD, and a change of filesystem. Any entry of either name is a stop here,
// valid or not, which only ever costs an extra ask; a filesystem change, or anything the
// walk cannot stat, gives up and leaves the grant to be asked on its own. GIT_DIR and
// GIT_CEILING_DIRECTORIES would move discovery too, and hookRunnerDir drops every GIT_*.
//
// Under the walks' bound, for resolved's reason: a mount that stopped answering blocks
// the lstat, and an expiry lands on the grant being asked on its own, which is bounded.
func gitDiscoveryStop(dir string) string {
	stop, err := bounded("the git discovery walk from "+dir, func() (string, error) {
		fi, err := os.Stat(dir)
		if err != nil {
			return "", err
		}
		dev := fi.Sys().(*syscall.Stat_t).Dev
		for {
			for _, marker := range []string{".git", "HEAD"} {
				if _, err := os.Lstat(filepath.Join(dir, marker)); err == nil {
					return dir, nil
				} else if !errors.Is(err, fs.ErrNotExist) {
					return "", err
				}
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				return dir, nil
			}
			fi, err := os.Stat(parent)
			if err != nil || fi.Sys().(*syscall.Stat_t).Dev != dev {
				return "", err
			}
			dir = parent
		}
	})
	if err != nil {
		return ""
	}
	return stop
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
