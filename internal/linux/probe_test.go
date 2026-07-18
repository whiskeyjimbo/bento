package linux

import (
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/enforce"
)

// filesystemLayer is the three-state decision at the heart of the degraded tier:
// bwrap when userns works, Landlock-only Degraded when it does not but the kernel
// has Landlock, and Unavailable only when neither confines the filesystem. It is a
// pure function so every branch is testable without a userns-blocked host.
func TestFilesystemLayerThreeStates(t *testing.T) {
	const nsReason = "userns blocked here"
	cases := []struct {
		name          string
		nsOK          bool
		landlockAvail bool
		want          enforce.State
		reasonHas     string
	}{
		{"userns ok, landlock present", true, true, enforce.Enforced, "backstop"},
		{"userns ok, no landlock", true, false, enforce.Enforced, "bwrap alone"},
		{"userns blocked, landlock present", false, true, enforce.Degraded, "Landlock path rules"},
		{"userns blocked, no landlock", false, false, enforce.Unavailable, "no filesystem confinement"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state, reason := filesystemLayer(tc.nsOK, nsReason, tc.landlockAvail)
			if state != tc.want {
				t.Errorf("state = %v, want %v", state, tc.want)
			}
			if !strings.Contains(reason, tc.reasonHas) {
				t.Errorf("reason %q does not mention %q", reason, tc.reasonHas)
			}
		})
	}
}

// The degraded and unavailable reasons must carry the underlying namespace reason,
// so a user sees why bwrap could not run (and its remediation), not just that the
// filesystem tier changed.
func TestFilesystemLayerCarriesNamespaceReason(t *testing.T) {
	const nsReason = "AppArmor restricts unprivileged user namespaces"
	for _, landlock := range []bool{true, false} {
		state, reason := filesystemLayer(false, nsReason, landlock)
		if !strings.Contains(reason, nsReason) {
			t.Errorf("landlock=%v: %v reason %q dropped the namespace reason", landlock, state, reason)
		}
	}
}
