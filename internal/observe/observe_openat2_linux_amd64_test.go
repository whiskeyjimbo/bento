package observe

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// openat2 with RESOLVE_IN_ROOT treats the dirfd as the root, so an absolute path is
// re-rooted there and a ".." climbing above it is clamped - recording the bare path
// would name a host file the run never opened (bv2-2yi). RESOLVE_BENEATH instead
// rejects an absolute path outright (EXDEV), so it must not be anchored as if it
// resolved. The earlier TrimPrefix collapsed neither the extra leading slash nor the
// "..", leaking the real host path.
func TestOpenat2Path(t *testing.T) {
	for _, tc := range []struct {
		name     string
		resolve  uint64
		path     string
		anchored string
		record   bool
	}{
		{"in_root absolute", unix.RESOLVE_IN_ROOT, "/etc/hosts", "etc/hosts", true},
		{"in_root double slash", unix.RESOLVE_IN_ROOT, "//etc/shadow", "etc/shadow", true},
		{"in_root climbing dotdot", unix.RESOLVE_IN_ROOT, "/../../etc/hosts", "etc/hosts", true},
		{"in_root relative", unix.RESOLVE_IN_ROOT, "sub/x", "sub/x", true},
		{"in_root relative dotdot", unix.RESOLVE_IN_ROOT, "a/../b", "b", true},
		{"beneath absolute rejected", unix.RESOLVE_BENEATH, "/etc/hosts", "", false},
		{"beneath relative", unix.RESOLVE_BENEATH, "sub/x", "sub/x", true},
		{"no rooting flag absolute", 0, "/etc/hosts", "/etc/hosts", true},
		{"no rooting flag relative", 0, "sub/x", "sub/x", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			anchored, record := openat2Path(tc.resolve, tc.path)
			if anchored != tc.anchored || record != tc.record {
				t.Errorf("openat2Path(%#x, %q) = (%q, %v); want (%q, %v)",
					tc.resolve, tc.path, anchored, record, tc.anchored, tc.record)
			}
		})
	}
}

// An openat2 whose open_how cannot be read is a dropped observation, not a guess. The
// resolve flags decide whether the pathname is re-rooted at the dirfd, clamped, or
// rejected outright, so an unreadable how leaves no path that can honestly be recorded.
// The old fallback assumed RESOLVE_IN_ROOT and anchored the path at the dirfd, which
// fabricated an access - <cwd>/etc/passwd - out of a call the kernel refused with EFAULT.
//
// Both halves are asserted: nothing recorded for the path the tracee named, and the loss
// counted, so the run reports its manifest as short rather than silently inventing a file.
func TestOpenat2WithUnreadableHowIsDroppedNotFabricated(t *testing.T) {
	dir := t.TempDir()
	res := traceHelper(t, "badhow", dir, 1)
	for _, a := range res.Accesses {
		if strings.Contains(a.Path, badHowName) {
			t.Errorf("recorded %q from an openat2 the kernel refused with EFAULT", a.Path)
		}
	}
	if res.Dropped < 1 {
		t.Errorf("Dropped = %d, want at least 1 - an openat2 whose open_how could not be read is an observation the profiler lost", res.Dropped)
	}
}
