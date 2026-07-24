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

// Fuzz resolve()/resolveExisting against a REAL symlink tree built under a temp dir.
// Both functions hit the kernel (filepath.EvalSymlinks + os.Readlink), NOT the fake-FS
// testSandbox seam, so the fuzzer builds a real tree of dirs, files, symlink chains,
// dangling leaves, "..-after-symlink" targets, and loops.
//
// The oracle is LOOP-AWARE, and it has to be: under a symlink loop resolveExisting
// deliberately bails at maxSymlinkDepth and returns a still-symlink path (a shield bound
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
// through a symlinked parent, multi-hop dangling chain, ".." after a symlink), so it is
// lower priority; the teeth are pinned by TestResolveOracleLoopAndChainControls below so
// they do not depend on a lucky fuzz run reaching a loop.

const maxResolveNodes = 6

// buildSymlinkTree materializes up to maxResolveNodes named nodes under root from the
// fuzzer bytes: each node is a directory, a regular file, or a symlink. Dirs and files
// are created first and symlinks second, so a symlink may dangle, point at a never-
// created node, or point at another symlink to form a chain or a loop. Errors are
// tolerated (a node a prior one already occupies simply keeps its first kind): the oracle
// validates whatever tree actually lands on disk, not the fuzzer's intent.
func buildSymlinkTree(root string, data []byte) {
	name := func(i int) string { return filepath.Join(root, fmt.Sprintf("n%d", i)) }
	byteAt := func(i int) byte {
		if i < len(data) {
			return data[i]
		}
		return 0
	}

	kinds := make([]byte, maxResolveNodes)
	targets := make([]string, maxResolveNodes)
	for i := 0; i < maxResolveNodes; i++ {
		kinds[i] = byteAt(2*i) % 3
		a := byteAt(2*i + 1)
		// A target node index in [0, maxResolveNodes]; the extra value names a node that
		// is never created, so the symlink dangles.
		tgt := int(a) % (maxResolveNodes + 1)
		switch a / 64 % 4 {
		case 0:
			targets[i] = name(tgt) // absolute
		case 1:
			targets[i] = fmt.Sprintf("n%d", tgt) // relative, same directory
		case 2:
			// ".." after a real parent: walks up out of root and back in.
			targets[i] = fmt.Sprintf("../%s/n%d", filepath.Base(root), tgt)
		default:
			// ".." AFTER ANOTHER NODE that may itself be a symlink: this is the class the
			// raw-join logic exists for - if n<lead> is a symlink to a dir elsewhere, the ".."
			// must apply to THAT dir, not be cleaned away lexically to name(tgt)'s sibling.
			lead := (tgt + 1) % maxResolveNodes
			targets[i] = fmt.Sprintf("n%d/../n%d", lead, tgt)
		}
	}

	for i := 0; i < maxResolveNodes; i++ {
		switch kinds[i] {
		case 0:
			os.Mkdir(name(i), 0o755)
		case 2:
			os.WriteFile(name(i), nil, 0o644)
		}
	}
	for i := 0; i < maxResolveNodes; i++ {
		if kinds[i] == 1 {
			os.Symlink(targets[i], name(i))
		}
	}
}

// checkResolveInvariants builds a tree from data, picks a start path (a node, optionally
// with a trailing component so the input is a path UNDER a possibly-symlinked node), and
// runs the loop-aware oracle. Shared by the fuzz and its seed corpus.
func checkResolveInvariants(t *testing.T, data []byte) {
	root := canonTempDir(t)
	buildSymlinkTree(root, data)

	startIdx, extra := 0, false
	if n := len(data); n > 0 {
		startIdx = int(data[n-1]) % maxResolveNodes
		extra = n > 1 && data[n-2]%2 == 0
	}
	start := filepath.Join(root, fmt.Sprintf("n%d", startIdx))
	if extra {
		start = filepath.Join(start, "leaf")
	}
	assertResolveOracle(t, start)
}

// assertResolveOracle runs the loop-aware invariants for one start path in an already-
// built tree and reports whether it took the fail-closed (still-symlink) branch, so a
// positive-control test can prove both branches are reachable.
func assertResolveOracle(t *testing.T, start string) (looped bool) {
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
		return true
	}
	r2, err := resolve(r1)
	if err != nil {
		t.Fatalf("resolve(resolve(%q)): %v", start, err)
	}
	if r2 != r1 {
		t.Fatalf("resolve is not a fixed point: resolve(%q) = %q, resolve(%q) = %q", start, r1, r1, r2)
	}

	// The real oracle for the dangling walk: resolveExisting promises r1 is "the target a
	// write through start would actually reach", following each symlink (even a dangling
	// one) before a later "..". filepath.EvalSymlinks cannot validate that directly - it
	// errors on the first missing component, and where start fully exists resolveExisting
	// just returns EvalSymlinks verbatim, so agreeing there proves nothing about the walk.
	// So confirm the prediction the way a real write would: populate the missing pieces and
	// see where the kernel lands. This catches any bug that resolves start to the wrong path
	// on the generated trees - a dropped path remainder, a mis-followed chain, a bad
	// dangling leaf - since the kernel follows the true chain regardless of resolve's output.
	// (The specific raw-vs-lexical ".." divergence needs a CROSS-DEPTH symlink these flat
	// trees do not build; that case is pinned by TestResolveFollowsSymlinkBeforeDotDotInDanglingTarget.)
	kernelR, ok := kernelResolveByPopulating(start)
	if !ok {
		return false // start routes through a real file (or did not converge); nothing to confirm
	}
	if kernelR != r1 {
		t.Fatalf("resolve(%q) = %q, but once its dangling components are populated the kernel resolves start to %q", start, r1, kernelR)
	}
	return false
}

// kernelResolveByPopulating confirms resolve's write-target prediction the way the kernel
// would once the tree is populated: it repeatedly asks filepath.EvalSymlinks(start) and,
// each time the kernel reports a missing component, creates that component as a directory -
// exactly the chain a write through start would create, following each (now-real) symlink
// before a later "..". It returns where the kernel finally resolves start, or ok=false when
// start routes through a real file (ENOTDIR, which resolveExisting handles lexically but the
// kernel cannot) so there is no kernel resolution to compare against. Bounded so a
// pathological input cannot spin; start is symlink-free-resolved here, so it holds no loop.
func kernelResolveByPopulating(start string) (string, bool) {
	for i := 0; i < 4*maxResolveNodes+16; i++ {
		eval, err := filepath.EvalSymlinks(start)
		if err == nil {
			return eval, true
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
	f.Add([]byte{})
	f.Add([]byte{1, 0, 1, 1, 2, 2})   // n0->n0, n1->n1, n2 a file
	f.Add([]byte{1, 65, 1, 66, 0, 0}) // relative + "..-after" symlink targets into dirs
	f.Add([]byte{1, 1, 1, 0})         // n0->n1, n1->n0: a two-hop loop
	f.Add([]byte{0, 0, 1, 7, 2, 0})   // real dir, a dangling symlink, a file
	f.Fuzz(checkResolveInvariants)
}

// TestResolveOracleLoopAndChainControls pins the oracle's teeth against hand-built trees,
// so the loop-aware and fixed-point branches are proven reachable without depending on a
// fuzz run finding them (a fuzzer that never hits a loop would leave that branch vacuous).
func TestResolveOracleLoopAndChainControls(t *testing.T) {
	// A two-hop symlink loop: resolveExisting must bail at maxSymlinkDepth and return a
	// still-symlink path, taking the fail-closed branch.
	loop := canonTempDir(t)
	mustLink(t, filepath.Join(loop, "b"), filepath.Join(loop, "a"))
	mustLink(t, filepath.Join(loop, "a"), filepath.Join(loop, "b"))
	if !assertResolveOracle(t, filepath.Join(loop, "a")) {
		t.Error("a symlink loop must take the fail-closed (still-symlink) branch")
	}

	// A dangling chain a -> b -> c(missing): resolve follows it to c, a non-symlink
	// fixed point, so the resolved branch and its fixed-point check bite.
	chain := canonTempDir(t)
	c := filepath.Join(chain, "c")
	mustLink(t, c, filepath.Join(chain, "b"))
	mustLink(t, filepath.Join(chain, "b"), filepath.Join(chain, "a"))
	if assertResolveOracle(t, filepath.Join(chain, "a")) {
		t.Error("a terminating chain must take the resolved (fixed-point) branch")
	}
	if got, err := resolve(filepath.Join(chain, "a")); err != nil || got != c {
		t.Errorf("resolve(a) = %q, %v; want %q", got, err, c)
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
	for _, c := range strings.Split(strings.Trim(p, "/"), "/") {
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
