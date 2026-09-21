//go:build linux

package linux

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
)

// A container that lifted only one of docker's two profiles fails in a shape that names
// neither: with only apparmor=unconfined the refusal reads the host's AppArmor sysctl
// through /proc, and with only seccomp=unconfined bwrap stops at "Failed to make / slave".
// Both must still tell the reader that each flag is needed on its own.
func TestDockerRemedyNamesBothFlagsForEitherHalf(t *testing.T) {
	for _, tc := range []struct {
		name, out string
		sysctls   map[string]string
		want      namespaceProbe
	}{
		{
			name:    "apparmor lifted, seccomp still filtering",
			out:     "bwrap: No permissions to create new namespace, likely because the kernel does not allow non-privileged user namespaces.",
			sysctls: map[string]string{"/proc/sys/kernel/apparmor_restrict_unprivileged_userns": "1\n"},
			want:    namespacesBlocked,
		},
		{
			name: "seccomp lifted, apparmor still confining",
			out:  "bwrap: Failed to make / slave: Permission denied",
			want: namespacesUnknown,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			orig := readSysctl
			t.Cleanup(func() { readSysctl = orig })
			readSysctl = func(p string) ([]byte, error) {
				if v, ok := tc.sysctls[p]; ok {
					return []byte(v), nil
				}
				return nil, fs.ErrNotExist
			}
			ns, reason := classifyUnshare(&usernsError{output: tc.out, err: errors.New("exit status 1")})
			if ns != tc.want {
				t.Fatalf("ns = %v, want %v: %q", ns, tc.want, reason)
			}
			for _, flag := range []string{"seccomp=unconfined", "apparmor=unconfined", "both needed"} {
				if !strings.Contains(reason, flag) {
					t.Errorf("reason does not carry %q: %q", flag, reason)
				}
			}
		})
	}
}
