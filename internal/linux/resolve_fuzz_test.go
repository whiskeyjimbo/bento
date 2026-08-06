//go:build linux

package linux

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Fuzz resolve()/pathresolve.Existing against a REAL symlink tree built under a temp dir.
// Both functions hit the kernel (filepath.EvalSymlinks + os.Readlink), NOT the fake-FS
// testSandbox seam, so the fuzzer builds a real tree of dirs, files, symlink chains,
// dangling leaves, "..-after-symlink" targets, and loops.
//
// The oracle is LOOP-AWARE, and it has to be: under a symlink loop pathresolve.Existing
// deliberately bails at pathresolve.MaxDepth and returns a still-symlink path (a shield bound
// there fails closed), so the naive "the resolved leaf is never a symlink" and
// fixed-point invariants are false BY DESIGN on a loop and would flake. So the oracle
// splits on whether the result still holds an unresolved symlink in ANY component (not
// just its leaf: a loop reached through a dangling leaf fails closed at a path like
// n2/leaf where the symlink is the parent n2 and the missing leaf is not a link):
//
//   - result still has a symlink component => the depth-cutoff/loop branch. A loop has no
//     valid resolution, so the only guarantee is that resolve terminated and returned an
//     absolute path to fail closed on; assert nothing stronger.
//   - result is fully symlink-free => a resolved path, which must be a FIXED POINT and,
//     crucially, must be where the kernel itself lands once the tree is populated: the
//     oracle creates the missing components a write through start would create (each as a
//     directory, following symlinks before a later "..") and requires the kernel to then
//     resolve start to exactly that path. That is a real check on the dangling walk (which
//     runs precisely when EvalSymlinks(start) fails, so comparing against EvalSymlinks
//     directly would test nothing), catching any resolution that lands on the wrong path.
//
// This is breadth over the hand-written TestResolveFollows* cases (relative dangling leaf
// through a symlinked parent, multi-hop dangling chain, ".." after a symlink); the teeth
// are pinned by TestResolveOracleLoopAndChainControls below, so no branch depends on a
// lucky fuzz run reaching it.
//
// The generated trees are NESTED and the start paths carry the shapes a real grant can be
// spelled in - a multi-level dangling remainder, a ".." that has to apply to wherever a
// symlink landed, a trailing slash, a relative path - because a flat tree of siblings with
// an absolute one-leaf start reaches neither the cross-depth ".." this resolver exists for
// nor the Getwd branch at all. Start paths are CONCATENATED rather than joined for the
// same reason: filepath.Join cleans a ".." away lexically and would hand resolve the very
// answer it is being checked for.

const maxResolveNodes = 6

// buildSymlinkTree materializes up to maxResolveNodes named nodes under root from the
// fuzzer bytes and returns where each landed: each node is a directory, a regular file, or
// a symlink, and each sits either directly under root or inside an EARLIER node, so a
// symlink target can route through another symlink's subdirectory. Dirs and files are
// created first and symlinks second, so a symlink may dangle, point at a never-created
// node, or point at another symlink to form a chain or a loop. Errors are tolerated (a
// node whose parent turned out to be a file is simply never created): the oracle validates
// whatever tree actually lands on disk, not the fuzzer's intent.
//
// The nesting is what makes the ".."-after-a-symlink targets below bite. Flat siblings can
// only produce a ".." that lexical cleaning happens to get right; a link that crosses
// depth is the case where raw joining and lexical cleaning disagree, which is the whole
// reason resolve does not simply Clean.
func buildSymlinkTree(root string, data []byte) (paths []string) {
	byteAt := func(i int) byte {
		if i < len(data) {
			return data[i]
		}
		return 0
	}

	kinds := make([]byte, maxResolveNodes)
	targets := make([]string, maxResolveNodes)
	paths = make([]string, maxResolveNodes)
	for i := range maxResolveNodes {
		kinds[i] = byteAt(3*i) % 3
		// The parent is an earlier node or root, so a directory is always created before
		// anything nests inside it.
		dir := root
		if p := int(byteAt(3*i+2)) % (i + 1); p < i {
			dir = paths[p]
		}
		paths[i] = filepath.Join(dir, fmt.Sprintf("n%d", i))
	}
	name := func(i int) string { return paths[i] }

	for i := range maxResolveNodes {
		a := byteAt(3*i + 1)
		// A target node index in [0, maxResolveNodes]; the extra value names a node that
		// is never created, so the symlink dangles.
		tgt := int(a) % (maxResolveNodes + 1)
		if tgt == maxResolveNodes {
			targets[i] = filepath.Join(root, "never")
			continue
		}
		// Relative to the LINK'S OWN directory, which is what the kernel resolves a relative
		// target against. Prefixing ".." to an absolute path instead yields "..//abs/path",
		// a relative target naming a literal component under the link's grandparent, which
		// dangles for every tree this builds - so the ".." forms would generate nothing but
		// broken links and the cross-depth class would never be reached.
		rel, relErr := filepath.Rel(filepath.Dir(paths[i]), name(tgt))
		switch {
		case a/64%4 == 0 || relErr != nil:
			targets[i] = name(tgt) // absolute
		case a/64%4 == 1:
			targets[i] = fmt.Sprintf("n%d", tgt) // a sibling name, which often does not exist
		case a/64%4 == 2:
			// The relative route to the target, which carries a ".." for every level the link
			// sits below their common parent: a nested link reaches across depth here rather
			// than around its own siblings.
			targets[i] = rel
		default:
			// ".." AFTER ANOTHER NODE that may itself be a symlink: this is the class the
			// raw-join logic exists for - if n<lead> is a symlink to a dir elsewhere, the ".."
			// must apply to THAT dir, not be cleaned away lexically back to the link's own
			// directory and on to the target.
			lead := (tgt + 1) % maxResolveNodes
			targets[i] = fmt.Sprintf("n%d/../%s", lead, rel)
		}
	}

	for i := range maxResolveNodes {
		switch kinds[i] {
		case 0:
			_ = os.Mkdir(paths[i], 0o755)
		case 2:
			_ = os.WriteFile(paths[i], nil, 0o644)
		}
	}
	for i := range maxResolveNodes {
		if kinds[i] == 1 {
			_ = os.Symlink(targets[i], paths[i])
		}
	}
	return paths
}

// startSuffixes are the shapes appended to a chosen node to make the fuzzed input a path
// UNDER it. The bare node and a single missing leaf are the ordinary cases; the rest are
// the ones resolve has to get right and the flat one-leaf generator never produced - a
// multi-level dangling remainder, a ".." that must apply to wherever the node's symlink
// landed rather than to its lexical parent, and a trailing slash (which the kernel treats
// as "must be a directory" and Clean silently drops).
var startSuffixes = []string{"", "/leaf", "/leaf/deeper", "/leaf/../other", "/..", "/leaf/"}

// resolveBranch names which of the oracle's assertions actually ran for one start path.
// Reported rather than kept internal because breadth in the generator is worthless if the
// inputs it produces all land somewhere that asserts nothing: the controls below pin one
// hand-built case per shape to branchKernelConfirmed, which is the only branch that checks
// WHERE resolve landed rather than merely that it terminated.
type resolveBranch int

const (
	// branchFailClosed is the depth-cutoff/loop result: still holds a symlink component, so
	// only "terminated, absolute" is guaranteed.
	branchFailClosed resolveBranch = iota
	// branchUnconfirmable is a symlink-free result the kernel cannot be asked about - start
	// routes through a real file (ENOTDIR, which resolve handles lexically and the kernel
	// cannot), or populating did not converge. The fixed point is checked; the landing is not.
	branchUnconfirmable
	// branchKernelConfirmed is the strong case: the kernel, once the dangling components are
	// created, resolves start to exactly where resolve said a write would land.
	branchKernelConfirmed
)

// checkResolveInvariants builds a tree from data, picks a start path (a node plus one of
// startSuffixes, spelled absolute or relative to the working directory), and runs the
// loop-aware oracle. Shared by the fuzz and its seed corpus.
func checkResolveInvariants(t *testing.T, data []byte) {
	root := canonTempDir(t)
	paths := buildSymlinkTree(root, data)

	startIdx, suffix, rel := 0, "", false
	if n := len(data); n > 0 {
		startIdx = int(data[n-1]) % maxResolveNodes
		if n > 1 {
			suffix = startSuffixes[int(data[n-2])%len(startSuffixes)]
		}
		rel = n > 2 && data[n-3]%2 == 0
	}
	start := paths[startIdx] + suffix
	if rel {
		// resolve's own Getwd branch, which nothing else here reaches: every other start is
		// absolute, so the code that turns a relative grant into one was never fuzzed at all.
		// Chdir after canonTempDir so the cleanups unwind cwd before removing the tree.
		t.Chdir(root)
		start = "." + strings.TrimPrefix(start, root)
	}
	assertResolveOracle(t, start)
}

// assertResolveOracle runs the loop-aware invariants for one start path in an already-
// built tree and reports which branch it took, so a positive-control test can prove each
// is reachable.
func assertResolveOracle(t *testing.T, start string) resolveBranch {
	t.Helper()
	r1, err := resolve(start)
	if err != nil {
		t.Fatalf("resolve(%q): %v", start, err)
	}
	if !filepath.IsAbs(r1) {
		t.Fatalf("resolve(%q) = %q, want an absolute path", start, r1)
	}
	if hasSymlinkComponent(r1) {
		// Depth-cutoff/loop branch: resolve bailed and returned a path that still holds a
		// symlink component, to fail closed. Fixed point and EvalSymlinks agreement are
		// false by design here.
		return branchFailClosed
	}
	r2, err := resolve(r1)
	if err != nil {
		t.Fatalf("resolve(resolve(%q)): %v", start, err)
	}
	if r2 != r1 {
		t.Fatalf("resolve is not a fixed point: resolve(%q) = %q, resolve(%q) = %q", start, r1, r1, r2)
	}

	// The real oracle for the dangling walk: pathresolve.Existing promises r1 is "the target a
	// write through start would actually reach", following each symlink (even a dangling
	// one) before a later "..". filepath.EvalSymlinks cannot validate that directly - it
	// errors on the first missing component, and where start fully exists pathresolve.Existing
	// just returns EvalSymlinks verbatim, so agreeing there proves nothing about the walk.
	// So confirm the prediction the way a real write would: populate the missing pieces and
	// see where the kernel lands. This catches any bug that resolves start to the wrong path
	// on the generated trees - a dropped path remainder, a mis-followed chain, a bad
	// dangling leaf - since the kernel follows the true chain regardless of resolve's output.
	kernelR, ok := kernelResolveByPopulating(start)
	if !ok {
		return branchUnconfirmable
	}
	if kernelR != r1 {
		t.Fatalf("resolve(%q) = %q, but once its dangling components are populated the kernel resolves start to %q", start, r1, kernelR)
	}
	return branchKernelConfirmed
}

// kernelResolveByPopulating confirms resolve's write-target prediction the way the kernel
// would once the tree is populated: it repeatedly asks filepath.EvalSymlinks(start) and,
// each time the kernel reports a missing component, creates that component as a directory -
// exactly the chain a write through start would create, following each (now-real) symlink
// before a later "..". It returns where the kernel finally resolves start, or ok=false when
// start routes through a real file (ENOTDIR, which pathresolve.Existing handles lexically but the
// kernel cannot) so there is no kernel resolution to compare against. Bounded so a
// pathological input cannot spin; start is symlink-free-resolved here, so it holds no loop.
func kernelResolveByPopulating(start string) (string, bool) {
	for range 4*maxResolveNodes + 16 {
		eval, err := filepath.EvalSymlinks(start)
		if err == nil {
			// Absolutized because EvalSymlinks answers a relative start relatively while
			// resolve always answers absolutely; comparing the two spellings would fail every
			// relative input on a difference that is not a resolution difference.
			abs, absErr := filepath.Abs(eval)
			return abs, absErr == nil
		}
		var pe *os.PathError
		if !errors.As(err, &pe) || !errors.Is(err, syscall.ENOENT) {
			return "", false // ENOTDIR (routes through a file) or unexpected: not confirmable
		}
		if os.MkdirAll(pe.Path, 0o755) != nil {
			return "", false // an ancestor is a real file; cannot populate
		}
	}
	return "", false // did not converge within the bound
}

func FuzzResolveSymlinkTree(f *testing.F) {
	// Three bytes per node (kind, target, parent) and up to three trailing bytes choosing
	// the start node, its suffix and whether it is spelled relative. The seeds are shapes
	// rather than exact trees - the generator reads the same bytes for several fields, so
	// pinning what each one builds would be comment drift waiting to happen.
	f.Add([]byte{})
	f.Add([]byte{1, 0, 0, 1, 1, 0, 2, 0, 0})    // links among top-level nodes, one file
	f.Add([]byte{0, 0, 0, 1, 65, 0, 1, 194, 1}) // a nested node, relative and "..-after" targets
	f.Add([]byte{1, 1, 0, 1, 0, 0})             // a two-hop loop
	f.Add([]byte{0, 0, 0, 1, 6, 1, 2, 0, 0})    // real dir, a dangling symlink inside it, a file
	f.Fuzz(checkResolveInvariants)
}

// TestResolveOracleLoopAndChainControls pins the oracle's teeth against hand-built trees,
// so each branch is proven reachable without depending on a fuzz run finding it. Two kinds
// of vacuity are guarded here: a fuzzer that never hits a loop would leave the fail-closed
// branch untested, and one whose inputs all route through a real file would reach only
// branchUnconfirmable, where nothing checks WHERE resolve landed. The shapes below are one
// per generator feature, so a change that stops producing any of them fails here.
func TestResolveOracleLoopAndChainControls(t *testing.T) {
	// A two-hop symlink loop: pathresolve.Existing must bail at pathresolve.MaxDepth and return a
	// still-symlink path, taking the fail-closed branch.
	loop := canonTempDir(t)
	mustLink(t, filepath.Join(loop, "b"), filepath.Join(loop, "a"))
	mustLink(t, filepath.Join(loop, "a"), filepath.Join(loop, "b"))
	if got := assertResolveOracle(t, filepath.Join(loop, "a")); got != branchFailClosed {
		t.Errorf("a symlink loop must take the fail-closed branch; got %d", got)
	}

	// A dangling chain a -> b -> c(missing): resolve follows it to c, a non-symlink
	// fixed point, so the resolved branch and its fixed-point check bite.
	chain := canonTempDir(t)
	c := filepath.Join(chain, "c")
	mustLink(t, c, filepath.Join(chain, "b"))
	mustLink(t, filepath.Join(chain, "b"), filepath.Join(chain, "a"))
	if got := assertResolveOracle(t, filepath.Join(chain, "a")); got != branchKernelConfirmed {
		t.Errorf("a terminating chain must reach the kernel-confirmed branch; got %d", got)
	}
	if got, err := resolve(filepath.Join(chain, "a")); err != nil || got != c {
		t.Errorf("resolve(a) = %q, %v; want %q", got, err, c)
	}

	// A path routing through a real file: the kernel cannot be asked where a write would
	// land (ENOTDIR), so this is the branch that checks only the fixed point. Named here so
	// the difference between it and the confirmed branch is visible rather than silent.
	viaFile := canonTempDir(t)
	if err := os.WriteFile(filepath.Join(viaFile, "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := assertResolveOracle(t, filepath.Join(viaFile, "f", "under")); got != branchUnconfirmable {
		t.Errorf("a path through a real file cannot be kernel-confirmed; got %d", got)
	}

	// Cross-depth ".." after a symlink, the case flat sibling trees cannot build: deep/link
	// points at a directory elsewhere, so ".." after it must apply to THAT directory and not
	// be cleaned away to deep's own parent.
	cross := canonTempDir(t)
	deep := filepath.Join(cross, "a", "b")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	elsewhere := filepath.Join(cross, "x", "y")
	if err := os.MkdirAll(elsewhere, 0o755); err != nil {
		t.Fatal(err)
	}
	mustLink(t, elsewhere, filepath.Join(deep, "link"))
	// Concatenated rather than joined: filepath.Join would clean the ".." away lexically and
	// hand resolve the very path this is checking it does not produce.
	start := filepath.Join(deep, "link") + "/../leaf"
	if got, err := resolve(start); err != nil || got != filepath.Join(cross, "x", "leaf") {
		t.Errorf("resolve through a cross-depth link then \"..\" = %q, %v; want %q", got, err, filepath.Join(cross, "x", "leaf"))
	}
	if got := assertResolveOracle(t, start); got != branchKernelConfirmed {
		t.Errorf("a cross-depth \"..\" start must be kernel-confirmed; got %d", got)
	}

	// A relative start, which reaches resolve's Getwd branch - the one the fuzzer's
	// absolute-only starts never entered.
	relRoot := canonTempDir(t)
	mustLink(t, filepath.Join(relRoot, "target"), filepath.Join(relRoot, "link"))
	t.Chdir(relRoot)
	if got := assertResolveOracle(t, "link/leaf"); got != branchKernelConfirmed {
		t.Errorf("a relative start must be kernel-confirmed; got %d", got)
	}
}

// canonTempDir returns a canonicalized temp dir, so filepath.EvalSymlinks agreement in
// the oracle is exact even where the system temp root is itself reached through a symlink.
func canonTempDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func mustLink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// hasSymlinkComponent reports whether any component of p is an unresolved symlink, so a
// fail-closed result whose symlink sits in a parent (a loop reached through a dangling
// leaf) is recognized, not only one whose leaf is a link. A missing component is not a
// symlink. p is absolute, and its prefix above the tree is a canonical temp dir with no
// links, so the walk only ever flags symlinks the fuzzer planted.
func hasSymlinkComponent(p string) bool {
	cur := "/"
	for c := range strings.SplitSeq(strings.Trim(p, "/"), "/") {
		if c == "" {
			continue
		}
		cur = filepath.Join(cur, c)
		if fi, err := os.Lstat(cur); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			return true
		}
	}
	return false
}
