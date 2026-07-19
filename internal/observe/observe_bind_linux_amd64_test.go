package observe

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

// bind(2) on an AF_UNIX pathname socket creates a socket file, a directory write the
// manifest must grant or enforcement fails the run closed (bv2-5u3). Only pathname
// sockets make a filesystem entry: abstract sockets, unnamed/autobind addresses, and
// other families create nothing and must not be recorded.
func TestUnixSockaddrPath(t *testing.T) {
	sa := func(family uint16, path string) []byte {
		b := make([]byte, 2+len(path))
		binary.LittleEndian.PutUint16(b, family)
		copy(b[2:], path)
		return b
	}
	for _, tc := range []struct {
		name string
		buf  []byte
		want string
	}{
		{"pathname socket", sa(unix.AF_UNIX, "/run/app.sock"), "/run/app.sock"},
		{"nul terminated with trailing", sa(unix.AF_UNIX, "/tmp/x\x00\x00\x00"), "/tmp/x"},
		{"relative pathname", sa(unix.AF_UNIX, "app.sock"), "app.sock"},
		{"abstract socket", sa(unix.AF_UNIX, "\x00hidden"), ""},
		{"non-unix family", sa(unix.AF_INET, "/run/app.sock"), ""},
		{"unnamed autobind", sa(unix.AF_UNIX, ""), ""},
		{"empty", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := unixSockaddrPath(tc.buf); got != tc.want {
				t.Errorf("unixSockaddrPath(%v) = %q; want %q", tc.buf, got, tc.want)
			}
		})
	}
}
