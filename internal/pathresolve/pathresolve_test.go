package pathresolve

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// canonDir returns a temp dir with its own symlinks resolved, so an assertion compares
// against the path the kernel reports rather than the /var -> /private/var shape a
// TempDir can carry.
func canonDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func link(t *testing.T, target, name string) {
	t.Helper()
	if err := os.Symlink(target, name); err != nil {
		t.Fatal(err)
	}
}

// A path that fully exists is EvalSymlinks verbatim, and a symlink-free one is identity.
// This is the case every ordinary grant takes, so a resolver that mangled it would break
// production while passing the interesting cases below.
func TestExistingResolvesWhatExists(t *testing.T) {
	d := canonDir(t)
	real := filepath.Join(d, "real")
	if err := os.MkdirAll(filepath.Join(real, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	link(t, real, filepath.Join(d, "alias"))

	if got := Existing(real); got != real {
		t.Errorf("Existing(%q) = %q, want identity on a symlink-free path", real, got)
	}
	want := filepath.Join(real, "sub")
	if got := Existing(filepath.Join(d, "alias", "sub")); got != want {
		t.Errorf("Existing through a parent symlink = %q, want %q", got, want)
	}
}

// The reason the package exists: a write through a path that does not exist yet lands
// where the links point, not where the lexical spelling suggests. A dangling leaf is
// followed rather than treated as the destination.
func TestExistingFollowsDanglingComponents(t *testing.T) {
	d := canonDir(t)
	store := filepath.Join(d, "store")
	if err := os.Mkdir(store, 0o755); err != nil {
		t.Fatal(err)
	}
	// ~/link -> store/unborn, which nothing has created: a write through link/file lands
	// under store, and a resolver stopping at the link would shield the wrong tree.
	link(t, filepath.Join(store, "unborn"), filepath.Join(d, "link"))

	want := filepath.Join(store, "unborn", "file")
	if got := Existing(filepath.Join(d, "link", "file")); got != want {
		t.Errorf("Existing through a dangling leaf = %q, want %q", got, want)
	}
}

// A ".." inside a symlink's own target resolves from where the kernel reads the link,
// not from the path's lexical spelling - the divergence filepath.Join would produce.
func TestExistingFollowsSymlinkBeforeDotDot(t *testing.T) {
	d := canonDir(t)
	for _, sub := range []string{"real", "b"} {
		if err := os.Mkdir(filepath.Join(d, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// d/link -> d/real, and d/real/hop -> ../b. The ".." is read in d/real, where the
	// kernel reads the link, so it lands on d/b - while lexically cleaning it against
	// the path as spelled would answer d/link/b, a directory that does not exist.
	link(t, filepath.Join(d, "real"), filepath.Join(d, "link"))
	link(t, "../b", filepath.Join(d, "real", "hop"))

	want := filepath.Join(d, "b", "target")
	if got := Existing(filepath.Join(d, "link", "hop", "target")); got != want {
		t.Errorf("Existing over a ..-bearing target = %q, want %q", got, want)
	}
}

// The documented fail-closed contract: past the budget the caller gets the path it
// asked about, not an interior hop of the chain. A shield bound on a rewritten mid-chain
// path protects neither the input nor the target, which is the whole failure this pins.
func TestExistingReturnsInputAtDepthCutoff(t *testing.T) {
	d := canonDir(t)
	if err := os.Mkdir(filepath.Join(d, "l0"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A chain longer than the budget. The kernel ELOOPs on it too, so there is no
	// resolution to return and the only honest answer is the input.
	for i := 1; i <= MaxDepth+9; i++ {
		link(t, filepath.Join(d, "l"+strconv.Itoa(i-1)), filepath.Join(d, "l"+strconv.Itoa(i)))
	}

	over := filepath.Join(d, "l"+strconv.Itoa(MaxDepth+9), "missing")
	if got := Existing(over); got != over {
		t.Errorf("Existing(%q) = %q past the budget, want the input back", over, got)
	}
	// Under the budget the same shape still resolves, so the cutoff is not swallowing
	// chains it can walk.
	under := filepath.Join(d, "l"+strconv.Itoa(MaxDepth-10), "missing")
	if want := filepath.Join(d, "l0", "missing"); Existing(under) != want {
		t.Errorf("Existing(%q) = %q under the budget, want %q", under, Existing(under), want)
	}
}

// A self-referential link has no resolution at all; it must terminate and hand back the
// input for the caller (checkGrantNotLooped) to refuse by name.
// A three-hop cycle, not two: MaxDepth is even, so a two-hop cycle walks back onto its
// own head at the budget and would pass even for a resolver returning the interior path
// it had rebuilt. An odd cycle length makes the two answers differ.
func TestExistingReturnsInputOnLoop(t *testing.T) {
	d := canonDir(t)
	a, b, c := filepath.Join(d, "a"), filepath.Join(d, "b"), filepath.Join(d, "c")
	link(t, b, a)
	link(t, c, b)
	link(t, a, c)

	if got := Existing(a); got != a {
		t.Errorf("Existing(%q) on a loop = %q, want the input back", a, got)
	}
	// And it is a fixed point, so a caller that resolves twice gets the same answer.
	if got := Existing(Existing(a)); got != a {
		t.Errorf("Existing is not a fixed point on a loop: %q", got)
	}
}

// The gate calls this with the grant as the manifest spells it, and the backend calls it
// with the same grant after prepending the working directory. A relative grant must land
// on the same path through both, or the gate judges /foo/bar while the run binds
// $PWD/foo/bar - and the empty grant, which reaches here too, must not answer for the
// whole filesystem.
func TestExistingAbsolutizesAgainstTheWorkingDirectory(t *testing.T) {
	d := canonDir(t)
	if err := os.MkdirAll(filepath.Join(d, "work", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(filepath.Join(d, "work"))

	if got, want := Existing("sub"), filepath.Join(d, "work", "sub"); got != want {
		t.Errorf("Existing(%q) = %q, want %q (a relative grant must not be re-rooted at /)", "sub", got, want)
	}
	if got, want := Existing("absent/leaf"), filepath.Join(d, "work", "absent", "leaf"); got != want {
		t.Errorf("Existing(%q) = %q, want %q", "absent/leaf", got, want)
	}
	if got, want := Existing(""), filepath.Join(d, "work"); got != want {
		t.Errorf("Existing(%q) = %q, want %q (the empty grant must not resolve to the root)", "", got, want)
	}
}

// A component that cannot be READ is not a component that is not a symlink. Taking it as
// a real directory would leave a symlink in the resolved prefix, which the lexical ".."
// below it then pops off - landing somewhere the kernel would not.
func TestUnreadableComponentResolvesToNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root traverses a 0000 directory, so there is no EACCES to raise")
	}
	root := t.TempDir()
	closed := filepath.Join(root, "closed")
	if err := os.Mkdir(closed, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(closed, 0o700) })

	// Built raw: filepath.Join would clean the ".." away lexically, which is precisely
	// the pop this checks does not happen against an unread component.
	path := closed + "/link/../secret"
	if got := Existing(path); got != path {
		t.Errorf("Existing(%q) = %q, want the path unresolved - whether %q is a symlink could not be read", path, got, filepath.Join(closed, "link"))
	}
}
