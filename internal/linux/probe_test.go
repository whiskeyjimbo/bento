package linux

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
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
		ioctlDevRestricted bool
		degradedFencesOK   bool
		want               enforce.State
		reasonHas          string
	}{
		{"userns ok, landlock present", true, true, true, true, true, enforce.Enforced, "backstop"},
		{"userns ok, no landlock", true, false, true, true, true, enforce.Enforced, "bwrap alone"},
		{"userns blocked, landlock present, fences ok", false, true, true, true, true, enforce.Degraded, "Landlock path rules"},
		{"userns blocked, landlock present, truncate unrestricted", false, true, false, true, true, enforce.Degraded, "cannot restrict truncate"},
		{"userns blocked, landlock present, ioctl_dev unrestricted", false, true, true, false, true, enforce.Degraded, "cannot restrict ioctl on device files"},
		{"userns blocked, landlock present, no seccomp fences", false, true, true, true, false, enforce.Unavailable, "reduced-confinement fallback needs a seccomp"},
		{"userns blocked, no landlock", false, false, true, true, true, enforce.Unavailable, "no filesystem confinement"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state, reason := filesystemLayer(tc.nsOK, nsReason, tc.landlockAvail, tc.truncateRestricted, tc.ioctlDevRestricted, tc.degradedFencesOK)
			if state != tc.want {
				t.Errorf("state = %v, want %v", state, tc.want)
			}
			if !strings.Contains(reason, tc.reasonHas) {
				t.Errorf("reason %q does not mention %q", reason, tc.reasonHas)
			}
		})
	}
}

// A limit is enforced by the systemd scope both tiers wrap their command in, so the
// report must hang on scope creation alone - and must never claim Enforced without a
// creatable scope, which would report a memory/pids/cpu cap that does not hold.
func TestLimitsLayersTrackScopeCreation(t *testing.T) {
	ok := limitsLayers(true, "", enforce.Degraded, "cpu controller not delegated")
	if len(ok) != 2 || ok[0].State != enforce.Enforced || ok[1].Layer != enforce.LayerLimitsCPU || ok[1].State != enforce.Degraded {
		t.Fatalf("scope: got %+v, want LayerLimits=Enforced + LayerLimitsCPU=Degraded", ok)
	}

	no := limitsLayers(false, "no scope here", enforce.Enforced, "")
	if len(no) != 1 || no[0].State != enforce.Unavailable || no[0].Reason != "no scope here" {
		t.Fatalf("no scope: got %+v, want LayerLimits=Unavailable carrying the scope reason", no)
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
		{
			"no landlock", func(t *testing.T) { swap(t, &landlockAvailable, false) },
			enforce.LayerFilesystem, enforce.Enforced, "bwrap alone",
		},
		{
			"no seccomp", func(t *testing.T) { swap(t, &seccompSupported, false) },
			enforce.LayerExec, enforce.Unavailable, "does not support seccomp BPF",
		},
		{
			"no strict exec filter", func(t *testing.T) { swap(t, &seccompStrictExecSupported, false) },
			enforce.LayerExecStrict, enforce.Unavailable, "not implemented for this architecture",
		},
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
		state, reason := filesystemLayer(false, nsReason, landlock, true, true, true)
		if !strings.Contains(reason, nsReason) {
			t.Errorf("landlock=%v: %v reason %q dropped the namespace reason", landlock, state, reason)
		}
	}
}

// The namespace probe's canary must be resolved on $PATH, not hardcoded to
// /bin/true. bwrap creates the namespaces first and execs last, so on a host with no
// /bin/true only the exec fails - and the probe would report userns blocked, refuse
// every network manifest, and silently downgrade the run to the Landlock-only tier.
// A host missing /bin/true cannot be constructed here, so this drives the property
// from the other side: with $PATH naming a `true` that exits non-zero, the probe must
// fail, which it can only do if the canary it ran was the resolved one.
func TestCanUnshareRunsTheResolvedCanary(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	canary := filepath.Join(dir, "true")
	if err := os.WriteFile(canary, []byte("#!/bin/sh\nexit 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if err := canUnshare(context.Background(), "bwrap"); err == nil {
		t.Error("canUnshare passed while its canary exited 3; it ran a hardcoded /bin/true, not the resolved one")
	}
}

// The degraded tier's own system paths are raw literals, and several are commonly
// symlinks (/dev/urandom, the FHS lib dirs on a usrmerge host, /nix). go-landlock
// opens a path without O_NOFOLLOW, so the rule it installs lands on the resolved
// target either way - but bento's record of the read set feeds the exposure scan,
// which must name the paths that were actually granted, not the names they were
// granted under.
func TestDegradedSystemPathsResolveThroughTheSeam(t *testing.T) {
	sb := testSandbox()
	sb.resolve = func(p string) string {
		if p == "/dev/urandom" {
			return "/dev/hwrng"
		}
		return p
	}
	reads, writes := degradedSystemPaths(sb)
	if !slices.Contains(reads, "/dev/hwrng") {
		t.Errorf("reads = %v, want the symlinked /dev/urandom resolved to /dev/hwrng", reads)
	}
	if slices.Contains(reads, "/dev/urandom") {
		t.Errorf("reads = %v, want only the resolved name, not the symlink", reads)
	}
	if !slices.Contains(writes, "/dev/null") {
		t.Errorf("writes = %v, want /dev/null", writes)
	}
}
