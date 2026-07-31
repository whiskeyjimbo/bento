package policy

import "testing"

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
// Reported, not asserted: a benchmark cannot fail on an allocation.
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
			for i := 0; i < b.N; i++ {
				sink = CoversResolved(tc.grant, tc.path)
			}
		})
	}
}

var sink bool
