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
		name               string
		nsOK               bool
		landlockAvail      bool
		truncateRestricted bool
		degradedFencesOK   bool
		want               enforce.State
		reasonHas          string
	}{
		{"userns ok, landlock present", true, true, true, true, enforce.Enforced, "backstop"},
		{"userns ok, no landlock", true, false, true, true, enforce.Enforced, "bwrap alone"},
		{"userns blocked, landlock present, fences ok", false, true, true, true, enforce.Degraded, "Landlock path rules"},
		{"userns blocked, landlock present, truncate unrestricted", false, true, false, true, enforce.Degraded, "cannot restrict truncate"},
		{"userns blocked, landlock present, no seccomp fences", false, true, true, false, enforce.Unavailable, "reduced-confinement fallback needs a seccomp"},
		{"userns blocked, no landlock", false, false, true, true, enforce.Unavailable, "no filesystem confinement"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state, reason := filesystemLayer(tc.nsOK, nsReason, tc.landlockAvail, tc.truncateRestricted, tc.degradedFencesOK)
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

// exec-strict is the stricter of the two claims and needs the architecture filter on
// top of seccomp, so a host with seccomp but no strict filter must report exec
// Enforced and exec-strict Unavailable rather than letting the coarser layer's
// success speak for both.
func TestExecLayers(t *testing.T) {
	cases := []struct {
		name            string
		seccompOK       bool
		strictOK        bool
		wantExec        enforce.State
		wantStrict      enforce.State
		strictReasonHas string
	}{
		{"seccomp and strict filter", true, true, enforce.Enforced, enforce.Enforced, ""},
		{"seccomp, no strict filter", true, false, enforce.Enforced, enforce.Unavailable, "not implemented for this architecture"},
		{"no seccomp", false, true, enforce.Unavailable, enforce.Unavailable, "does not support seccomp BPF"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := execLayers(tc.seccompOK, tc.strictOK)
			if len(got) != 2 || got[0].Layer != enforce.LayerExec || got[1].Layer != enforce.LayerExecStrict {
				t.Fatalf("got %+v, want LayerExec then LayerExecStrict", got)
			}
			if got[0].State != tc.wantExec {
				t.Errorf("exec = %v, want %v", got[0].State, tc.wantExec)
			}
			if got[1].State != tc.wantStrict {
				t.Errorf("exec-strict = %v, want %v", got[1].State, tc.wantStrict)
			}
			if !strings.Contains(got[1].Reason, tc.strictReasonHas) {
				t.Errorf("exec-strict reason %q does not mention %q", got[1].Reason, tc.strictReasonHas)
			}
		})
	}
}

// Probe must read the real capability checks, not assume the capabilities it was
// developed on. The decision functions above prove the decisions; this proves the
// wiring, which no host that HAS every capability can otherwise exercise: a Probe
// that hardcoded a layer Enforced would satisfy every test above and still report a
// guarantee this kernel cannot deliver.
func TestProbeReadsTheRealCapabilityChecks(t *testing.T) {
	cases := []struct {
		name string
		lose func(*testing.T)

		layer enforce.Layer
		// wantState after the loss. The filesystem layer stays Enforced without
		// Landlock on a userns-capable host - bwrap is the guarantee there and
		// Landlock only the backstop - so what must change is the disclosure, not
		// the verdict.
		wantState     enforce.State
		wantReasonHas string
	}{
		{"no landlock", func(t *testing.T) { swap(t, &landlockAvailable, false) },
			enforce.LayerFilesystem, enforce.Enforced, "bwrap alone"},
		{"no seccomp", func(t *testing.T) { swap(t, &seccompSupported, false) },
			enforce.LayerExec, enforce.Unavailable, "does not support seccomp BPF"},
		{"no strict exec filter", func(t *testing.T) { swap(t, &seccompStrictExecSupported, false) },
			enforce.LayerExecStrict, enforce.Unavailable, "not implemented for this architecture"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A positive control: this host must report the layer Enforced and NOT
			// already say what the loss should make it say, or the assertion below
			// would hold for a Probe that ignores the check entirely.
			before := layerStatus(t, tc.layer)
			if before.State != enforce.Enforced || strings.Contains(before.Reason, tc.wantReasonHas) {
				t.Skipf("this host already reports %v as %v (%q), so losing the capability proves nothing",
					tc.layer, before.State, before.Reason)
			}
			tc.lose(t)
			after := layerStatus(t, tc.layer)
			if after.State != tc.wantState || !strings.Contains(after.Reason, tc.wantReasonHas) {
				t.Errorf("with the capability absent %v = %v (%q), want %v mentioning %q - Probe is not reading the check",
					tc.layer, after.State, after.Reason, tc.wantState, tc.wantReasonHas)
			}
		})
	}
}

// The egress check reaches the filesystem layer only indirectly, through the
// degradedFencesOK term: the reduced tier stands in for the missing namespaces with
// a seccomp egress block, so without one there is no tier left to offer. Dropping
// that term from Probe would offer --allow-degraded on a host where the launcher can
// only refuse, which is the fail-open this layer exists to prevent.
//
// Emptying PATH is what makes the branch reachable: usableNamespaces looks bwrap up
// on PATH, so this drives Probe down the userns-blocked path on a host where userns
// works.
func TestProbeReadsTheEgressCheckForTheDegradedTier(t *testing.T) {
	t.Setenv("PATH", "")

	// A positive control: with the fences intact this host must still offer the
	// degraded tier, or the Unavailable below would just be the absent bwrap talking.
	if before := layerStatus(t, enforce.LayerFilesystem); before.State != enforce.Degraded {
		t.Skipf("without bwrap this host reports filesystem %v (%q), not the degraded tier, so losing the egress fence proves nothing",
			before.State, before.Reason)
	}

	swap(t, &seccompEgressSupported, false)
	after := layerStatus(t, enforce.LayerFilesystem)
	// The state check carries the teeth here: the Degraded reason this must NOT be
	// also mentions the seccomp egress block, so a reason-only assertion passes even
	// when Probe ignores the check entirely.
	if after.State != enforce.Unavailable || !strings.Contains(after.Reason, "seccomp") {
		t.Errorf("with the egress fence absent filesystem = %v (%q), want unavailable blaming the seccomp fences - Probe is not reading the check",
			after.State, after.Reason)
	}
}

func swap(t *testing.T, fn *func() bool, v bool) {
	t.Helper()
	orig := *fn
	t.Cleanup(func() { *fn = orig })
	*fn = func() bool { return v }
}

func layerStatus(t *testing.T, layer enforce.Layer) enforce.LayerStatus {
	t.Helper()
	for _, ls := range New().Probe(t.Context()).Layers {
		if ls.Layer == layer {
			return ls
		}
	}
	t.Fatalf("Probe reported no %v layer", layer)
	return enforce.LayerStatus{}
}

// The degraded and unavailable reasons must carry the underlying namespace reason,
// so a user sees why bwrap could not run (and its remediation), not just that the
// filesystem tier changed.
func TestFilesystemLayerCarriesNamespaceReason(t *testing.T) {
	const nsReason = "AppArmor restricts unprivileged user namespaces"
	for _, landlock := range []bool{true, false} {
		state, reason := filesystemLayer(false, nsReason, landlock, true, true)
		if !strings.Contains(reason, nsReason) {
			t.Errorf("landlock=%v: %v reason %q dropped the namespace reason", landlock, state, reason)
		}
	}
}
