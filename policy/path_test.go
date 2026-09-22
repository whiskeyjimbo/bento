package policy

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The predicate every consumer of a grant now shares, so its edges are pinned once.
// The prefix-string trap is the one that matters: a grant of /home/u must not reach
// /home/user2, which is exactly what a HasPrefix spelling of this gets wrong.
func TestCoversResolved(t *testing.T) {
	cases := []struct {
		grant, path string
		want        bool
	}{
		{"/home/u", "/home/u/.ssh", true},
		{"/home/u", "/home/u", true},
		{"/home/u", "/home/user2", false},
		{"/home/u", "/tmp", false},
		{"/a", "/ab", false},
		{"/", "/anything", true},
		{"/home/u/.ssh", "/home/u", false},
		// Cleaned before comparing, so a traversal cannot spell its way out of a grant
		// and back in - or, here, out of one it never re-enters.
		{"/home/u", "/home/u/../user2", false},
		{"/home/u", "/home/u/proj/../.ssh", true},
		// A relative path cannot be under an absolute grant, or the reverse. Refusing is
		// the safe direction: a caller that skipped the absolute-path precondition is
		// told the grant does not cover, never that it does.
		{"/home/u", "relative/path", false},
		{"relative", "/home/u", false},
		// The root branch must not answer for a path that is not absolute at all.
		{"/", "relative", false},
		// Outside the precondition a relative grant still compares lexically.
		{"rel", "rel/x", true},
		{"rel", "relx", false},
		{"/", "/", true},
		// A trailing separator on the grant is the other spelling Clean has to settle:
		// naive prefix-building would produce "//" and match nothing.
		{"/home/u/", "/home/u/.ssh", true},
		{"/home/u/", "/home/u", true},
		// A leading ".." in a real filename is not a traversal segment.
		{"/home/u", "/home/u/..bashrc", true},
		// Empty and "." segments anywhere, including INSIDE the grant's own span, where
		// they shift the byte offsets a prefix comparison depends on.
		{"/home/u", "/home/u//./.ssh", true},
		{"/home/u/.ssh", "/home/u//.ssh//id_rsa", true},
		{"/home/u/.ssh", "/home/u/./.ssh/id_rsa", true},
		{"/home/u/.gnupg", "/home/u/./.gnupg", true},
		{"/home/u/.ssh", "/home/u//.sshx/id_rsa", false},
	}
	for _, tc := range cases {
		if got := CoversResolved(tc.grant, tc.path); got != tc.want {
			t.Errorf("CoversResolved(%q, %q) = %v, want %v", tc.grant, tc.path, got, tc.want)
		}
	}
}

// CoversResolved sits under every coverage question bento asks, including one per
// ancestor for every file of a whole-home credential walk, so its cost and its
// allocations both matter. The two obvious spellings - filepath.Rel, or
// HasPrefix(path, grant+sep) - each allocate on every call; this one allocates only
// when an input is not already clean, which the preconditions say it should be.
//
// The paths are long on purpose: Go keeps a concatenation of up to 32 bytes on the stack,
// so the allocating spelling is free on a short fixture and the test would pass with it.
func TestCoversResolvedDoesNotAllocateOnCleanPaths(t *testing.T) {
	const grant = "/home/someone-with-a-long-name/.config/some-tool"
	for _, path := range []string{
		grant + "/credentials/deeper/file.json",
		"/home/someone-with-a-long-name/projects/checkout/src/main.go",
	} {
		if n := testing.AllocsPerRun(100, func() { sink = CoversResolved(grant, path) }); n != 0 {
			t.Errorf("CoversResolved(%q, %q) allocated %v times", grant, path, n)
		}
	}
}

// BenchmarkCoversResolved reports the cost; TestCoversResolvedDoesNotAllocateOnCleanPaths
// asserts the allocations.
func BenchmarkCoversResolved(b *testing.B) {
	for _, tc := range []struct {
		name, grant, path string
	}{
		{"miss", "/home/u/.ssh", "/home/u/proj/src/deep/file.go"},
		{"hit", "/home/u", "/home/u/proj/src/deep/file.go"},
		{"needs cleaning", "/home/u", "/home/u/proj/../src/file.go"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				sink = CoversResolved(tc.grant, tc.path)
			}
		})
	}
}

var sink bool

// FuzzCoversResolvedMatchesComponents holds CoversResolved to its doc restated over path
// components rather than byte offsets: a grant covers a path when the grant's cleaned
// components are a prefix of the path's. The index comparison it actually runs is where a
// one-off lets /a reach /ab, and three consumers answer a security question with it.
func FuzzCoversResolvedMatchesComponents(f *testing.F) {
	f.Add("/home/u", "/home/u/.ssh")
	f.Add("/home/u", "/home/user2")
	f.Add("/a", "/ab")
	f.Add("/", "/anything")
	f.Add("/", "rel")
	f.Add("rel", "rel/x")
	f.Add("..", "../x")
	f.Add("/home/u/", "/home/u//.ssh//id_rsa")
	f.Add("/home/u", "/home/u/../u2")

	f.Fuzz(func(t *testing.T, grant, path string) {
		got := CoversResolved(grant, path)
		if want := referenceCoversResolved(grant, path); got != want {
			t.Fatalf("CoversResolved(%q, %q) = %v; the component restatement says %v", grant, path, got, want)
		}
		// Empty and "." segments are spelling, not reach, on either side.
		if filepath.IsAbs(grant) && filepath.IsAbs(path) {
			noisy := func(s string) string { return strings.ReplaceAll(s, "/", "//./") }
			if again := CoversResolved(noisy(grant), noisy(path)); again != got {
				t.Fatalf("CoversResolved(%q, %q) = %v but %v once the same paths are spelled with // and /./", grant, path, got, again)
			}
		}
	})
}

// referenceCoversResolved: the path is the grant itself, or a path of the same kind
// (absolute or relative) whose components extend the grant's.
func referenceCoversResolved(grant, path string) bool {
	grant, path = filepath.Clean(grant), filepath.Clean(path)
	if grant == path {
		return true
	}
	if filepath.IsAbs(grant) != filepath.IsAbs(path) {
		return false
	}
	split := func(s string) []string {
		return slices.DeleteFunc(strings.Split(s, "/"), func(c string) bool { return c == "" })
	}
	g, p := split(grant), split(path)
	return len(g) < len(p) && slices.Equal(g, p[:len(g)])
}
