package observe

import (
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

// When the open_how read fails (ok=false) the real RESOLVE_* flags are unknown. Falling
// back to the zero value would let an absolute path be recorded as a real-root host path
// the run may never have opened (bv2-3lh); RESOLVE_IN_ROOT instead anchors it at the
// dirfd. A successful read is passed through untouched.
func TestOpenat2ResolveFailSafe(t *testing.T) {
	if got := openat2Resolve(0, false); got != unix.RESOLVE_IN_ROOT {
		t.Errorf("openat2Resolve(0, false) = %#x; want RESOLVE_IN_ROOT (%#x)", got, unix.RESOLVE_IN_ROOT)
	}
	if got := openat2Resolve(unix.RESOLVE_BENEATH, true); got != unix.RESOLVE_BENEATH {
		t.Errorf("openat2Resolve passes a good read through: got %#x; want %#x", got, unix.RESOLVE_BENEATH)
	}
	// The fail-safe resolve must anchor an absolute path at the dirfd, not at real root.
	if anchored, rec := openat2Path(openat2Resolve(0, false), "/etc/hosts"); !rec || anchored != "etc/hosts" {
		t.Errorf("fail-safe openat2 of /etc/hosts = (%q, %v); want (%q, true)", anchored, rec, "etc/hosts")
	}
}
