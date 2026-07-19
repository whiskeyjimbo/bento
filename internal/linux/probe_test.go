package linux

import (
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/enforce"
)

// filesystemLayer is the decision at the heart of the degraded tier: bwrap when
// userns works, Landlock-only Degraded when it does not but the kernel has Landlock
// and the reduced tier's seccomp fences are available, and Unavailable when the
// filesystem cannot be confined or those fences cannot stand in for the missing
// namespaces. It is a pure function so every branch is testable without a
// userns-blocked host.
func TestFilesystemLayerThreeStates(t *testing.T) {
	const nsReason = "userns blocked here"
	cases := []struct {
		name             string
		nsOK             bool
		landlockAvail    bool
		degradedFencesOK bool
		want             enforce.State
		reasonHas        string
	}{
		{"userns ok, landlock present", true, true, true, enforce.Enforced, "backstop"},
		{"userns ok, no landlock", true, false, true, enforce.Enforced, "bwrap alone"},
		{"userns blocked, landlock present, fences ok", false, true, true, enforce.Degraded, "Landlock path rules"},
		{"userns blocked, landlock present, no seccomp fences", false, true, false, enforce.Unavailable, "reduced-confinement fallback needs a seccomp"},
		{"userns blocked, no landlock", false, false, true, enforce.Unavailable, "no filesystem confinement"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state, reason := filesystemLayer(tc.nsOK, nsReason, tc.landlockAvail, tc.degradedFencesOK)
			if state != tc.want {
				t.Errorf("state = %v, want %v", state, tc.want)
			}
			if !strings.Contains(reason, tc.reasonHas) {
				t.Errorf("reason %q does not mention %q", reason, tc.reasonHas)
			}
		})
	}
}

// The degraded tier runs the target directly and applies no resource limit, so a
// limit-bearing manifest on that tier must never see LayerLimits=Enforced (which
// would report a memory/pids/cpu cap that does not actually hold - the fail-open).
func TestLimitsLayersDegradedTierNeverEnforced(t *testing.T) {
	// nsOK=false is the degraded tier; even with a creatable scope and delegated cpu,
	// limits are not applied there.
	got := limitsLayers(false, true, "", enforce.Enforced, "")
	if len(got) != 1 || got[0].Layer != enforce.LayerLimits || got[0].State != enforce.Unavailable {
		t.Fatalf("degraded tier: got %+v, want a single LayerLimits=Unavailable", got)
	}

	// bwrap tier with a scope: limits enforced, cpu sub-layer carried through.
	ok := limitsLayers(true, true, "", enforce.Degraded, "cpu controller not delegated")
	if len(ok) != 2 || ok[0].State != enforce.Enforced || ok[1].Layer != enforce.LayerLimitsCPU || ok[1].State != enforce.Degraded {
		t.Fatalf("bwrap+scope: got %+v, want LayerLimits=Enforced + LayerLimitsCPU=Degraded", ok)
	}

	// bwrap tier without a scope: limits unavailable.
	no := limitsLayers(true, false, "no scope here", enforce.Enforced, "")
	if len(no) != 1 || no[0].State != enforce.Unavailable || no[0].Reason != "no scope here" {
		t.Fatalf("bwrap+noscope: got %+v, want LayerLimits=Unavailable carrying the scope reason", no)
	}
}

// The degraded and unavailable reasons must carry the underlying namespace reason,
// so a user sees why bwrap could not run (and its remediation), not just that the
// filesystem tier changed.
func TestFilesystemLayerCarriesNamespaceReason(t *testing.T) {
	const nsReason = "AppArmor restricts unprivileged user namespaces"
	for _, landlock := range []bool{true, false} {
		state, reason := filesystemLayer(false, nsReason, landlock, true)
		if !strings.Contains(reason, nsReason) {
			t.Errorf("landlock=%v: %v reason %q dropped the namespace reason", landlock, state, reason)
		}
	}
}
