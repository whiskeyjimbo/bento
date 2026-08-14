//go:build linux

package linux

import (
	"cmp"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/grantrefusal"
	"github.com/whiskeyjimbo/bento/internal/shield"
	"github.com/whiskeyjimbo/bento/policy"
)

// shieldsApplied converts the deny-list rules a run engaged into the operator-facing
// audit record: one entry per shielded path, sorted, with the kind of shield. A
// DenyAll rule (credential stores, ~/.ssh) reports hidden; a DenyWrite rule (shell rc
// files, git hooks, editor config trees) reports read-only.
//
// The kind is read off what shieldMount really emits, not off the rule alone, which is
// why the host is consulted here. A DenyWrite on a directory that does not exist yet gets
// a tmpfs rather than a read-only bind, and a tmpfs is writable: the target can create
// files in it for the whole run and they simply never reach the host. That is the common
// case, not an exotic one - a write grant on a plain directory shields a .git/hooks that
// is not there - and calling it read-only would name a protection other than the one
// applied. It reports discarded instead.
func shieldsApplied(sb sandbox, rules []denylist.Rule) []enforce.ShieldApplied {
	if len(rules) == 0 {
		return nil
	}
	out := make([]enforce.ShieldApplied, 0, len(rules))
	for _, r := range rules {
		kind := "hidden"
		if r.Deny == denylist.DenyWrite {
			kind = "read-only"
			if r.Dir && !sb.exists(r.Path) {
				kind = "discarded"
			}
		}
		out = append(out, enforce.ShieldApplied{Path: r.Path, Kind: kind, Source: r.Source})
	}
	slices.SortFunc(out, func(a, b enforce.ShieldApplied) int { return cmp.Compare(a.Path, b.Path) })
	return out
}

// exposedShields reports the always-on shields a bwrap run would have engaged among the
// paths visible to this run, for the degraded tier to record as exposed rather than
// applied. It runs the same deny-list match denyArgs does - naming exactly what would have
// been hidden or made read-only - and discards the argv, since the degraded tier has no
// mount namespace to apply it in. visible is the set this tier actually exposes host
// content at (its Landlock read/write set), NOT the full tier's exposedPaths: the degraded
// tier never binds an out-of-FHS interpreter's whole prefix, so a credential under it is
// not exposed here and must not be reported as if it were. Opt-ins are dropped by denyArgs.
func exposedShields(sb sandbox, visible, writes, optIns []string) []enforce.ShieldApplied {
	_, applied := denyArgs(sb, visible, writes, optIns)
	return shieldsApplied(sb, applied)
}

// shields is the run's assembled shield set: the built-in credential and runtime rules,
// the caller's own denies, the symlinked-credential expansion, and the drops - all of it
// from internal/shield, which is where the validate gate and the profiler clamp get the
// same answer. Everything that enforces or checks a shield derives from this, so a caller
// deny can never reach one place and miss another.
//
// The sandbox's seams are handed over as the shield package's own FS, not as the sandbox
// itself: that is what keeps the compiler's fake-filesystem tests working against shared
// code, and what keeps a backend type out of a package cmd/bento has to import.
func shields(sb sandbox) shield.Set {
	if m := sb.shieldCache; m != nil && m.done {
		return m.set
	}
	set := shield.Assemble(shield.FS{
		IsDir:   sb.isDir,
		Resolve: sb.resolve,
		ListDir: sb.listDir,
		// Built from the alias scan's identity seam rather than a second one: both ask
		// whether two names reach one file, and a fake that disagrees with itself between
		// them would let the scan and the shield check tell different stories about the
		// same host.
		SameFile: func(a, b string) bool {
			ida, ok := sb.statID(a)
			if !ok {
				return false
			}
			idb, ok := sb.statID(b)
			return ok && ida == idb
		},
	}, sb.homes, sb.runtimeDir, sb.extraDeny)
	if m := sb.shieldCache; m != nil {
		m.done, m.set = true, set
	}
	return set
}

// shieldRules is the full deny-list for a run: the mandatory Home shields plus,
// for each write-granted checkout, the static Workspace shields and the git
// directories discovered under it (see gitDirShields). Building it in one place
// keeps denyArgs and createdShields enforcing and cleaning up the exact same
// set - a divergence would either leak a host artifact or leave a path unshielded.
func shieldRules(sb sandbox, writes []string) []denylist.Rule {
	rules := shields(sb).Rules()
	seen := map[string]bool{}
	for _, w := range writes {
		// Workspace shields (git hooks, editor tasks) only make sense for a project
		// directory. A write grant that is a plain file - or a path that does not
		// exist yet - is not a checkout, and shielding a ".git/hooks" under it would
		// force bwrap to create that path inside a file, or pre-create the target as
		// a directory the script then cannot write as a file.
		if !sb.isDir(w) {
			continue
		}
		// One checkout derives one set of shields however many grants land in it, and
		// that is settled here rather than in each consumer: denyArgs collapses repeats
		// on its resolved-shield key and createdShields has no such key, so a duplicate
		// admitted here reaches only one of the two - and they are meant to select the
		// same rules.
		// The root is asked for BEFORE the shields, so a repeat costs a walk up the parent
		// chain rather than a second gitDirShields descent through .git/modules - which is
		// what a sandbox carrying no workspaceShieldCache would pay otherwise.
		root := checkoutRoot(sb, w)
		if seen[root] {
			continue
		}
		seen[root] = true
		ws, _ := workspaceShields(sb, w)
		rules = append(rules, ws...)
	}
	return rules
}

// workspaceShields is the code-execution surface of the checkout a write grant lands
// in: the static Workspace rules plus the git directories discovered under it.
//
// The anchor is the enclosing CHECKOUT, not the grant. Anchoring at the grant made the
// shields relative to whatever the policy happened to spell, so a grant one directory
// deeper walked out from under every one of them: "write: <repo>/.git" put them at
// <repo>/.git/.git/hooks and left the real hooks dir under a writable bind with no rule
// at all, and a planted pre-commit then ran on the host at the developer's next commit -
// the exact persistence these rules exist to stop, reachable by spelling the grant
// deeper. Anchoring at the checkout also brings "write: <repo>/.vscode" back under a
// rule, where checkWriteNotUnderReadOnlyShield refuses it.
//
// A grant outside any checkout anchors on itself, and shields above a grant are
// unreachable, so shieldNeeded skips them and the argv is unchanged for the ordinary
// "write: <repo>" and "write: <repo>/build" shapes.
// The checkout it anchored on comes back with the rules, so a caller collapsing grants
// that share one does not have to walk to it a second time.
func workspaceShields(sb sandbox, dir string) ([]denylist.Rule, string) {
	root := checkoutRoot(sb, dir)
	if rules, ok := sb.workspaceShieldCache[root]; ok {
		return rules, root
	}
	// A gitfile checkout has no directory to walk, so gitDirShields is skipped with the
	// .git children it would extend. Same test as the gitdir identification below: a
	// regular file, never a directory that happens to be named .git.
	var rules []denylist.Rule
	if gitfile := filepath.Join(root, ".git"); sb.exists(gitfile) && !sb.isDir(gitfile) {
		rules = slices.Clip(denylist.WorkspaceGitfile(root))
	} else {
		rules = slices.Clip(append(denylist.Workspace(root), gitDirShields(sb, root)...))
	}
	if sb.workspaceShieldCache != nil {
		sb.workspaceShieldCache[root] = rules
	}
	return rules, root
}

// checkoutRoot walks up from dir to the nearest directory holding a .git, or returns
// dir where there is none. The walk is by name only - it never reads .git's content -
// so a decoy planted under a write grant only moves where the shields anchor, never what
// they can reach. A decoy above the grant anchors higher and adds rules; one at the grant
// dir stops the walk there and drops the rules above it, which were unreachable anyway -
// shieldNeeded skips a shield over a path outside every write grant, so the real
// checkout's .git was never being shielded from this run to begin with.
func checkoutRoot(sb sandbox, dir string) string {
	for d := dir; ; {
		if sb.exists(filepath.Join(d, ".git")) {
			return d
		}
		parent := filepath.Dir(d)
		if parent == d {
			return dir
		}
		d = parent
	}
}

// gitDirShields discovers, under a write-granted checkout dir, the git directories
// that sit at deterministic locations and returns DenyWrite shields for their
// code-execution surfaces. The top-level .git/hooks and .git/config shields cover
// the main repo, but a repo with submodules or linked worktrees keeps additional
// live hooks/config the main shields miss:
//
//   - submodule gitdirs at dir/.git/modules/<name>/ (recursively, so a nested
//     submodule at .git/modules/<a>/modules/<b>/ is covered too), each with its own
//     hooks/ and config that run when the developer uses that submodule on the host;
//   - linked-worktree config at dir/.git/worktrees/<name>/config.worktree.
//
// hooks and config.worktree are shielded whether or not they exist yet, matching the
// top-level shields denylist.Workspace emits: an absent one under a real gitdir is
// still plantable, so it is tmpfs'd and reclaimed by createdShields. An absent
// config.worktree is NOT inert on the reasoning that the run cannot enable
// extensions.worktreeConfig - a repo that already has it on honors a config.worktree
// planted where none existed, and core.hooksPath there redirects the next commit in
// that worktree.
//
// Not covered, because a concrete-path deny-list cannot express them (a documented
// residual): independent nested repos created anywhere under the grant,
// repos created during the run, in-tree hook runners (husky, core.hooksPath
// pointing at a tracked directory) whose hooks are ordinary project files, and the
// gitfile of a linked worktree or submodule that sits INSIDE the granted checkout.
//
// That last one is the mirror of what WorkspaceGitfile shields. Where the grant IS the
// worktree, its .git is the checkout root and takes a shield; where the worktree sits
// under a granted main checkout, dir/.git is a real directory, so the walk takes this
// branch and dir/<wt>/.git stays writable - a run can repoint it at a gitdir it
// fabricates elsewhere under the grant, and the developer's next git command in that
// worktree runs those hooks. Finding the worktrees to shield means reading
// .git/worktrees/<n>/gitdir for a path, which is content, and checkoutRoot's whole
// safety rests on never reading content. The shape is the nested-repo residual above.
func gitDirShields(sb sandbox, dir string) []denylist.Rule {
	gitDir := filepath.Join(dir, ".git")
	var rules []denylist.Rule

	// worktreeConfigs shields the config.worktree of every linked worktree of a
	// gitdir. Linked worktrees share the gitdir's hooks (already shielded), but each
	// keeps its own config.worktree, which can carry core.hooksPath.
	worktreeConfigs := func(gd string) {
		wt := filepath.Join(gd, "worktrees")
		rules = append(rules, redirectedPath(sb, wt)...)
		names, links, ok := sb.listDir(wt)
		if !ok {
			// Unreadable but traversable-by-name: fail closed like the module walk.
			if sb.isDir(wt) {
				rules = append(rules, denylist.Rule{Path: wt, Deny: denylist.DenyWrite, Dir: true})
			}
			return
		}
		for _, name := range names {
			rules = append(rules, denylist.Rule{Path: filepath.Join(wt, name, "config.worktree"), Deny: denylist.DenyWrite})
		}
		rules = append(rules, redirectedEntries(wt, links)...)
	}

	// Traversal is UNCONDITIONAL over real directories; identification gates only
	// whether shields are emitted, never whether recursion continues. .git/modules
	// is writable and unshielded across runs, so any predicate that decided *where to
	// walk* from attacker-writable content could be spoofed: a planted decoy config
	// file, or a fabricated gitdir-shaped container, could redirect or truncate the
	// walk and hide a real submodule's hooks. Walking every real subdirectory removes
	// that lever - a decoy can only add a harmless extra ro-bind. The cost is walking
	// git's store dirs (objects/refs/...), which hold no config file so emit nothing
	// and are bounded and setup-time. Recursion is over sb.listDir's real subdirectories
	// only, never its symlinked entries (those get a rule instead, see
	// redirectedEntries), so a planted symlink cannot escape the tree or loop; depth
	// bounds a deeply-nested planted tree as a backstop.
	var walk func(d string, depth int)
	walk = func(d string, depth int) {
		if depth > maxGitdirDepth {
			// Past the bound this scan stops seeing, which is the same condition as the
			// unreadable directory below and takes the same answer: fail closed, so a tree
			// planted deep enough to truncate the walk is shielded whole rather than
			// dropped. Returning nothing here would make depth the lever the paragraph
			// above says attacker-writable content must not have.
			if sb.isDir(d) {
				rules = append(rules, denylist.Rule{Path: d, Deny: denylist.DenyWrite, Dir: true})
			}
			return
		}
		// A gitdir is identified by a regular config FILE (not a directory named
		// "config", which is how a submodule literally named "config" nests its own
		// gitdir at .git/modules/config/).
		if cfg := filepath.Join(d, "config"); sb.exists(cfg) && !sb.isDir(cfg) {
			rules = append(
				rules,
				denylist.Rule{Path: cfg, Deny: denylist.DenyWrite},
				denylist.Rule{Path: filepath.Join(d, "hooks"), Deny: denylist.DenyWrite, Dir: true},
				denylist.Rule{Path: filepath.Join(d, "config.worktree"), Deny: denylist.DenyWrite},
			)
			worktreeConfigs(d)
		}
		names, links, ok := sb.listDir(d)
		if !ok {
			// d could not be enumerated. If it is a real directory (traversable by
			// name, so host git still reaches gitdirs inside it) that we cannot read -
			// a prior run can chmod it 0111 to blind this scan - fail closed: shield the
			// whole subtree read-only so nothing new can be planted under it.
			if sb.isDir(d) {
				rules = append(rules, denylist.Rule{Path: d, Deny: denylist.DenyWrite, Dir: true})
			}
			return
		}
		rules = append(rules, redirectedEntries(d, links)...)
		for _, name := range names {
			walk(filepath.Join(d, name), depth+1)
		}
	}
	modules := filepath.Join(gitDir, "modules")
	rules = append(rules, redirectedPath(sb, modules)...)
	walk(modules, 0)
	worktreeConfigs(gitDir)
	return rules
}

// redirectedEntries covers the symlinked children the gitdir walk refuses to descend
// into. Skipping them is right - following one could leave the tree or loop - but a
// name the scan drops is a name no rule covers, and checkWorkspaceShieldNotRedirected,
// which exists to refuse exactly a shield a symlink redirects, only inspects the rules
// gitDirShields returned. .git/modules is writable and unshielded by design, so a run
// can plant .git/modules/<name> as a symlink to a tree it controls, populated with config
// and hooks/, which host git follows on the next `git submodule update --init`. A rule on
// the link itself gives the redirect check something to refuse.
func redirectedEntries(dir string, links []string) []denylist.Rule {
	rules := make([]denylist.Rule, 0, len(links))
	for _, name := range links {
		rules = append(rules, denylist.Rule{Path: filepath.Join(dir, name), Deny: denylist.DenyWrite, Dir: true})
	}
	return rules
}

// redirectedPath covers a walk ROOT that is itself a symlink. Its children are covered
// by redirectedEntries, but listDir follows a link at the path it is handed, so a root
// replaced by a link to an empty directory the run controls enumerates clean and emits
// nothing at all: the same plant with the link moved one level up, and the one spelling
// where a populated target would have given itself away by producing redirected rules.
func redirectedPath(sb sandbox, path string) []denylist.Rule {
	if !sb.exists(path) || sb.resolve(path) == path {
		return nil
	}
	return []denylist.Rule{{Path: path, Deny: denylist.DenyWrite, Dir: true}}
}

// maxGitdirDepth bounds how deep the .git/modules recursion descends into real
// subdirectories. It bounds the walk, not any chain of links: a symlinked entry gets a
// rule instead of being descended (see redirectedEntries), so no link ever costs depth and
// no planted loop can drive this recursion. What it bounds is a deeply-nested real tree a
// prior run could plant to spin setup, and reaching it is not a reason to stop shielding -
// the cutoff fails closed on the subtree. Real submodule nesting is a handful deep. Kept
// identical to internal/shield's maxWalkDepth, which walks the same host trees.
const maxGitdirDepth = 64

// denyArgs shields every deny-list rule that a grant could otherwise expose.
//
// A rule whose path no grant reaches is skipped: it is already invisible under
// deny-by-default, and binding over it would force bwrap to create a mount point
// it has no parent for.
func denyArgs(sb sandbox, grants, writes, optIns []string) ([]string, []denylist.Rule) {
	rules := shieldRules(sb, writes)

	// Resolve and dedup first, so ancestry and ordering below compare real paths. A
	// symlinked deny path, or a symlinked /home component, would otherwise slip past
	// reachability, and the shield must mount where bwrap can create the mount point
	// (never at a symlink, which aborts the run). Two rules that resolve to the same
	// real path (/var/run and /run on a merged host) collapse to one; only the
	// identical rule is dropped, so a path shielded two different ways keeps both.
	// Mount carries the drops, shared with the grant checks so neither side can refuse
	// over a shield the other never applied.
	// Keyed on what the shield actually does and not on the whole rule: two rules can
	// name one resolved path and differ only in fields that describe it to a reader
	// (which store it holds, which env var put it there). Those produce byte-identical
	// bwrap arguments, so keying on the rule would emit the same bind twice and let a
	// field that exists for the report change what is enforced.
	type shieldKey struct {
		path string
		deny denylist.Deny
		dir  bool
	}
	seen := map[shieldKey]int{}
	resolved := make([]denylist.Rule, 0, len(rules))
	for _, a := range shields(sb).Mount(rules) {
		r := a.Rule
		r.Path = a.Resolved
		k := shieldKey{r.Path, r.Deny, r.Dir}
		if i, ok := seen[k]; ok {
			// One path can be both a default store under one anchor and a relocation
			// target under another, and which arrives first is just anchor order. A
			// shield bento would have applied anyway must not be reported as something
			// an environment variable caused, so the default claim wins the merge.
			if r.Source == "" {
				resolved[i].Source = ""
			}
			continue
		}
		seen[k] = len(resolved)
		resolved = append(resolved, r)
	}

	// A DenyWrite directory shield binds its real subtree read-only, which re-exposes
	// any DenyAll path nested inside it: the readable parent bind wins over a hidden
	// child that landed earlier, or was never emitted because no grant reached it
	// directly. Collect the DenyWrite rules whose shield actually ro-binds a real
	// directory subtree, so a DenyAll descendant of one is shielded even when only the
	// parent is granted. The test is the real kind, not the declared r.Dir: shieldMount()
	// binds by what is on disk, so a file-declared rule pointed at a directory (an env
	// relocation like GIT_CONFIG_GLOBAL) still ro-binds the whole tree. An absent path
	// becomes an empty tmpfs and a real file has no subtree, so both expose nothing.
	var exposed []string
	for _, r := range resolved {
		if r.Deny == denylist.DenyWrite && sb.exists(r.Path) && sb.isDir(r.Path) && shieldNeeded(r, sb, grants, writes, optIns) {
			exposed = append(exposed, r.Path)
		}
	}
	underExposed := func(p string) bool {
		for _, d := range exposed {
			if policy.CoversResolved(d, p) {
				return true
			}
		}
		return false
	}

	// Emit DenyWrite shields before DenyAll shields. bwrap mounts are last-wins, so the
	// stricter DenyAll (hide) must land after any DenyWrite (readable) bind that covers
	// the same subtree, or the readable parent re-exposes a hidden child. A forced child
	// must pre-exist: mounting over an existing path inside a read-only parent is a
	// namespace op, but creating a new mount point there is EROFS and aborts the run
	// (which is also why an absent DenyAll under an exposed parent needs no shield -
	// there is nothing to hide).
	//
	// No policy that survives checkGrants can currently reach the forced-child branch:
	// firing an exposed DenyWrite parent needs a write grant at, under, or above it, and
	// for a parent with a DenyAll child all three are refused - under by
	// checkWriteNotUnderReadOnlyShield, at and above by checkWriteNotAboveShield
	// (measured: instrumenting the branch panics under the full suite only with the
	// former check removed). It is kept because the ordering property is what makes the
	// refusals safe to relax: whichever of them a later rule shape loosens, the hidden
	// child must still land after the readable parent. Pinned directly against denyArgs
	// by the carve tests, which can no longer reach it through compile.
	var args []string
	var applied []denylist.Rule
	emit := func(want denylist.Deny) {
		for _, r := range resolved {
			if r.Deny != want {
				continue
			}
			needed := shieldNeeded(r, sb, grants, writes, optIns)
			if !needed && r.Deny == denylist.DenyAll && sb.exists(r.Path) &&
				!slices.Contains(optIns, r.Path) && underExposed(r.Path) {
				needed = true
			}
			if !needed {
				continue
			}
			args = append(args, shieldMount(r, sb)...)
			applied = append(applied, r)
		}
	}
	emit(denylist.DenyWrite)
	emit(denylist.DenyAll)
	return args, applied
}

// createdShields returns the host paths bwrap will create for this run's shield mount
// points, because the shielded path does not exist yet and a write grant makes its
// parent writable (a nonexistent path is only shielded when a write grant reaches it,
// so its parent is a read-write host bind). dirs also carries the intermediate
// directories bwrap has to make to hold one (the .git/ above an unborn .git/hooks),
// deepest first, so the caller can reclaim the whole artifact. The caller removes
// these after the run so the sandbox leaves no artifact.
//
// EXISTENCE IS READ HERE, before the run, and that is the whole safety argument: a
// path already on the host - including an intermediate directory the user already had
// - is never in the list, so cleanup can only remove something bento itself caused to
// appear. Deciding an ancestor was "obviously bwrap's" at cleanup time instead would
// reclaim a user's own empty directory that a shield merely landed inside.
//
// This selects the same shieldNeeded rules denyArgs emits, minus the DenyAll children
// denyArgs force-emits under an exposed DenyWrite ancestor: those are gated on the path
// already existing, and this returns only nonexistent paths, so bwrap never creates a
// mount point for them and there is nothing to clean up.
func createdShields(sb sandbox, grants, writes, optIns []string) (dirs, files []string) {
	seen := map[string]bool{}
	for _, a := range shields(sb).Mount(shieldRules(sb, writes)) {
		r := a.Rule
		r.Path = a.Resolved
		if !shieldNeeded(r, sb, grants, writes, optIns) || sb.exists(r.Path) {
			continue
		}
		if r.Dir {
			dirs = append(dirs, r.Path)
		} else {
			files = append(files, r.Path)
		}
		// The parents bwrap must create to reach the mount point. The walk stops at
		// the first one that already exists (nothing above it is bwrap's either) and
		// at a write grant, whose directory is the user's own - prepareWriteDirs has
		// already created a granted directory that was missing, so a grant is never
		// mistaken for an artifact here.
		for d := filepath.Dir(r.Path); insideAWriteGrant(d, writes) && !sb.exists(d); d = filepath.Dir(d) {
			if !seen[d] {
				seen[d] = true
				dirs = append(dirs, d)
			}
		}
	}
	// Deepest first, so a parent is only attempted once the mount points inside it are
	// gone. Sorting by length is enough: a parent is a strict prefix of its children.
	slices.SortStableFunc(dirs, func(a, b string) int { return len(b) - len(a) })
	return dirs, files
}

// checkShieldsCarvable refuses a write grant whose tree bwrap cannot carve this run's
// shield mount points into. A grant on a directory this uid cannot create entries in (a
// system tree such as /etc or /opt, drwxr-xr-x root root) makes bwrap die during setup
// with "Can't mkdir parents for /etc/.git/hooks", and the launcher then reports nothing:
// the run comes back as an unattested silent stage, whose sentence offers the embedder's
// DispatchReexec placement as the cause. A manifest author has no relationship with that
// API, so the one thing they can act on - their own write: line - has to be named here,
// before the launch, while the grant behind the mount point is still known.
//
// Writability, not ownership: /var/tmp is root-owned and world-writable, and a grant on
// it carves its shields fine.
func checkShieldsCarvable(sb sandbox, grants, writes, optIns []string) error {
	dirs, files := createdShields(sb, grants, writes, optIns)
	for _, mount := range slices.Concat(dirs, files) {
		// bwrap makes the whole missing chain, so the directory that has to accept the
		// mkdir is the deepest ancestor that is already there. The walk terminates at "/",
		// which exists on every host.
		parent := filepath.Dir(mount)
		for !sb.exists(parent) {
			parent = filepath.Dir(parent)
		}
		if sb.writable(parent) {
			continue
		}
		for _, w := range writes {
			if policy.CoversResolved(w, mount) {
				return grantrefusal.ShieldNotCarvable(w, mount, parent)
			}
		}
	}
	return nil
}

// insideAWriteGrant reports whether path is STRICTLY inside a write grant and is not
// itself one, so neither the createdShields walk nor the cleanup can reach a granted
// directory - the user's own - or anything above it. A grant nested inside another
// grant is still a grant, which is why equality is checked against every write.
func insideAWriteGrant(path string, writes []string) bool {
	inside := false
	for _, w := range writes {
		if path == w {
			return false
		}
		if policy.CoversResolved(w, path) {
			inside = true
		}
	}
	return inside
}

// removeCreatedShields removes the host paths bento caused bwrap to create (see
// createdShields) after the run - a write grant on a plain directory otherwise left an
// empty .git/ with two empty files in it, host clutter no run asked for.
//
// Removal cannot destroy host content. Every path here is one that did not exist when
// the run started. A directory goes only by rmdir, which refuses a non-empty one -
// and rmdir, not os.Remove, precisely so that a path which is no longer a directory
// is left alone rather than unlinked. A file goes only while it is still zero bytes,
// which holds nothing, so a host-side atomic save (write-temp then rename) leaves a
// non-empty file that is skipped.
//
// Two residuals, both requiring a host process to touch one of these paths during the
// window the run occupied. A process that CREATED one and still holds the descriptor
// loses its later writes to an unlinked inode. And the zero-length check is not atomic
// with the unlink: a write landing between the two is removed with the file.
//
// Best effort throughout: a kill before this runs leaves the artifact, as before.
func removeCreatedShields(dirs, files []string) {
	for _, f := range files {
		if fi, err := os.Lstat(f); err != nil || !fi.Mode().IsRegular() || fi.Size() != 0 {
			continue
		}
		os.Remove(f)
	}
	// dirs is deepest first, so the mount points inside an intermediate directory are
	// gone by the time it is tried.
	for _, d := range dirs {
		_ = syscall.Rmdir(d)
	}
}

// shieldNeeded decides whether a deny rule needs a shield mount, given what the
// grants expose. Beyond protecting the path, this avoids asking bwrap to bind a
// shield over a path whose parent is read-only - which it cannot do - for paths
// that are not actually a threat there.
func shieldNeeded(r denylist.Rule, sb sandbox, grants, writes, optIns []string) bool {
	// An exact opt-in grant wins over the shield: skip it so the grant binds
	// the real content instead of being overmounted. r.Path is already resolved by the
	// caller, matching the resolved paths in optIns. Only DenyAll shields are opt-in-able:
	// the opt-in is a READ escape, and a DenyWrite shield's content is readable already,
	// so there is nothing for it to grant but the write it exists to refuse. A write grant
	// under one is rejected by checkWriteNotUnderReadOnlyShield rather than reaching here.
	if r.Deny == denylist.DenyAll && slices.Contains(optIns, r.Path) {
		return false
	}
	if !reachable(r.Path, grants) {
		return false // not exposed by any grant; already invisible
	}
	writable := reachable(r.Path, writes)
	if r.Deny == denylist.DenyAll {
		// Hide existing contents from reads; prevent creation only where a write
		// grant could create it (a read-only parent cannot).
		return sb.exists(r.Path) || writable
	}
	// DenyWrite: a read-only grant already prevents writes, so a shield is only
	// needed where the path is actually writable.
	return writable
}

// shieldMount returns the bwrap arguments that enforce one deny rule.
//
// Both branches cover paths that do not exist yet, which is what closes the
// "plant a new credential file or shell profile under a broad write grant" hole:
// bwrap creates the mount point, and the shield - not the host - receives the
// write.
// shield's rule path is already symlink-resolved by denyArgs, so it binds where
// bwrap can create the mount point (never at a symlink, which aborts the run). A
// symlinked dotfile (~/.bashrc under home-manager) is thereby shielded via its
// real target: reads follow the symlink to it, and the bind makes it read-only.
// (Replacing the symlink itself under a broad home write grant is not preventable
// this way, but that grant is discouraged and the profiler no longer proposes it.)
func shieldMount(r denylist.Rule, sb sandbox) []string {
	switch {
	case r.Deny == denylist.DenyAll:
		// A tmpfs hides a directory's contents and absorbs new files; a file cannot take
		// a tmpfs, so an empty read-only bind hides it (contents unreadable, writes
		// rejected). Pick from the real kind when the path exists rather than the declared
		// r.Dir - ~/.cert is a directory on one host, a file on another - so bwrap is never
		// handed a tmpfs-over-file or file-over-dir mount that aborts the run. When absent,
		// synthesize per the declared kind.
		dir := r.Dir
		if sb.exists(r.Path) {
			dir = sb.isDir(r.Path)
		}
		if dir {
			return []string{"--tmpfs", r.Path}
		}
		return []string{"--ro-bind", sb.emptyFile, r.Path}
	case r.Dir:
		// DenyWrite on a directory. Rebinding it read-only keeps existing contents
		// readable while rejecting new files (a planted git hook). If it does not
		// exist, a tmpfs both keeps it empty and absorbs writes.
		if sb.exists(r.Path) {
			return []string{"--ro-bind", r.Path, r.Path}
		}
		return []string{"--tmpfs", r.Path}
	default:
		// DenyWrite on a file. Rebinding the real file read-only keeps it readable
		// - git must still read ~/.gitconfig - while rejecting writes. Shadowing it
		// with /dev/null, as v1 did, would have blinded those legitimate reads.
		if sb.exists(r.Path) {
			return []string{"--ro-bind", r.Path, r.Path}
		}
		return []string{"--ro-bind", sb.emptyFile, r.Path}
	}
}

// explicitShieldOptIns finds the built-in DenyAll shields the policy opts into by
// READING them - the caveat-emptor escape (a program that legitimately reads
// ~/.ssh, exposed read-only with a warning). Deliberate scope:
//
//   - Read grants only. A WRITE grant to a credential store is the key-planting threat
//     the deny-list exists to stop, so it is never an opt-in and stays refused; passing
//     literalReads (not writes) is what enforces that.
//   - A shield is opted in only when a read names its LITERAL deny-list path (~/.ssh); a
//     read that merely resolves to the same place (a symlink's target) is a side-step the
//     shield still refuses, so the match is on the unresolved grant string. The names
//     that count are the ones the deny-list built, and those are built from the run's
//     homes - so where $HOME reaches the real home through a symlink, the grant that opts
//     in is spelled with the link and the store exposed is the link's target. That is not
//     closable from here: the same shape is a caller aliasing the home and a host whose
//     home is legitimately a symlink, and refusing it would break the second. The
//     frontend names the resolved store in its warning so the exposure is not read as
//     the literal path alone.
//   - Built-in Home/Runtime shields only, never sb.extraDeny: a caller-supplied deny (a
//     supervising embedder shielding its own control store from an untrusted target) is a
//     different trust domain the profiled policy must not be able to lift. Building the
//     set from the built-ins is not enough on its own, because both consumers match a
//     bare resolved path: where a caller deny lands on the same host path as a built-in
//     (it names ~/.aws defensively, or its own store is a symlink there), an opt-in of
//     the built-in would carry the caller's shield away with it. So a built-in whose
//     store a caller deny also covers is not opt-in-able at all, and the read grant
//     stays refused.
//
// literalReads are the policy's own absolute, un-symlink-resolved read paths. Sorted by
// literal path, which is the order the reported opt-ins keep.
func explicitShieldOptIns(sb sandbox, literalReads []string) []shield.OptIn {
	return shields(sb).OptIns(literalReads)
}

func optInPaths(optIns []shield.OptIn) []string {
	out := make([]string, 0, len(optIns))
	for _, o := range optIns {
		out = append(out, o.Path)
	}
	return out
}

// reportedOptIns renders the opt-ins for the Result. OnHost is filled only where the
// grant reached somewhere other than its own name; the resolution is the compile-time one
// the binds themselves use, so the report names what was exposed rather than what the
// path points at once the target has exited.
func reportedOptIns(optIns []shield.OptIn) []enforce.ShieldedGrant {
	var out []enforce.ShieldedGrant
	for _, o := range optIns {
		g := enforce.ShieldedGrant{Path: o.Path, Holds: o.Holds.Code()}
		if o.OnHost != o.Path {
			g.OnHost = o.OnHost
		}
		out = append(out, g)
	}
	return out
}
