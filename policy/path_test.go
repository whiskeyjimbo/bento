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
		// Rel cannot relate an absolute path to a relative one. Refusing is the safe
		// direction: a caller that skipped the absolute-path precondition is told the
		// grant does not cover, never that it does.
		{"/home/u", "relative/path", false},
		{"relative", "/home/u", false},
	}
	for _, tc := range cases {
		if got := CoversResolved(tc.grant, tc.path); got != tc.want {
			t.Errorf("CoversResolved(%q, %q) = %v, want %v", tc.grant, tc.path, got, tc.want)
		}
	}
}
