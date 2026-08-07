package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
)

// onPlatform makes platformName answer for a host the tests cannot be run on, so the
// unverified branch - the reason doctor names the platform at all - can be watched. On a
// test host the value is the build's own and never varies.
func onPlatform(t *testing.T, name string) {
	t.Helper()
	saved := platformName
	platformName = func() string { return name }
	t.Cleanup(func() { platformName = saved })
}

// pureLookup pins which passwd resolver this build is said to carry. Without it a test
// asserts whatever the runner's C toolchain decided, which is the one thing the caveat
// exists to distinguish.
func pureLookup(t *testing.T, pure bool) {
	t.Helper()
	saved := pureUserLookup
	pureUserLookup = pure
	t.Cleanup(func() { pureUserLookup = saved })
}

// An arm64 Linux build probes a real kernel and fills the table in exactly as a verified
// host's does, so the only thing separating "this is what bento enforces" from "this is
// what this kernel answered" is doctor naming the platform and saying which one it has.
func TestDoctorNamesAnUnverifiedPlatform(t *testing.T) {
	onPlatform(t, "linux/arm64")
	var out bytes.Buffer
	writePlatform(&out)
	got := out.String()
	if !strings.Contains(got, "Platform: linux/arm64") {
		t.Errorf("doctor must name the platform it reports on; got %q", got)
	}
	if !strings.Contains(got, "planned, not verified") {
		t.Errorf("an unverified platform must say so, as README says of arm64; got %q", got)
	}
}

// The verified platform gets the name and nothing else: a caveat on every amd64 run is
// noise that would train a reader to skip the line where it matters.
func TestDoctorNamesTheVerifiedPlatformWithoutACaveat(t *testing.T) {
	onPlatform(t, verifiedPlatform)
	var out bytes.Buffer
	writePlatform(&out)
	got := out.String()
	if !strings.Contains(got, "Platform: "+verifiedPlatform) {
		t.Errorf("doctor must name the platform on every host; got %q", got)
	}
	if strings.Contains(got, "not verified") {
		t.Errorf("the verified platform must carry no caveat; got %q", got)
	}
}

// platform_verified is not readiness. An unverified host can probe every layer as
// enforced - that is precisely the case a reader needs told apart - so the field must not
// be folded into Ready or the exit code, which stay a statement about this kernel.
func TestDoctorJSONCarriesPlatformIndependentOfReady(t *testing.T) {
	var clean enforce.Report
	clean.Add(enforce.LayerFilesystem, enforce.Enforced, "")

	onPlatform(t, "linux/arm64")
	dj := toDoctorJSON(clean)
	if dj.Platform != "linux/arm64" || dj.PlatformVerified {
		t.Errorf("platform must be named and marked unverified; got %q verified=%v", dj.Platform, dj.PlatformVerified)
	}
	if !dj.Ready {
		t.Error("an unverified platform whose layers all hold is still ready - the caveat is not a shortfall")
	}

	onPlatform(t, verifiedPlatform)
	if dj := toDoctorJSON(clean); !dj.PlatformVerified {
		t.Errorf("%s must be reported verified; got %+v", verifiedPlatform, dj)
	}
}

// doctor's anchor block is where a reviewer goes to learn what the shields rest on, so
// an NSS build has to say so there and not only in `bento version`. The branch where the
// anchors cannot be resolved at all says it too - a passwd lookup an LD_PRELOAD made to
// fail is how an NSS build loses its anchor - but that needs a uid with no passwd entry,
// which a test on a normal host cannot arrange.
func TestShieldAnchorsCarryTheNSSCaveat(t *testing.T) {
	pureLookup(t, false)
	t.Setenv("HOME", t.TempDir())
	var caveat bytes.Buffer
	writeShieldAnchors(&caveat)
	if !strings.Contains(caveat.String(), "libc NSS") {
		t.Errorf("the anchor block must name an NSS build; got:\n%s", caveat.String())
	}

	pureLookup(t, true)
	var b bytes.Buffer
	writeShieldAnchors(&b)
	if strings.Contains(b.String(), "libc NSS") {
		t.Errorf("the supported build must carry no caveat; got:\n%s", b.String())
	}
}

// The summary sits three lines under a table that reports each layer's real state, so a
// clause about a layer this host enforces is read as a warning about this host. It has to
// name what actually fell short and nothing else.
func TestDegradedSummaryNamesOnlyTheLayersThatFellShort(t *testing.T) {
	var limitsOnly enforce.Report
	limitsOnly.Add(enforce.LayerLimits, enforce.Unavailable, "systemd-run is not installed")

	var b strings.Builder
	writeDegradedSummary(&b, limitsOnly.Degradations())
	// The summary is wrapped to the report width, so assert against it unwrapped.
	got := strings.Join(strings.Fields(b.String()), " ")
	if !strings.Contains(got, "One layer below falls short (limits)") {
		t.Errorf("a lone shortfall must be counted and named; got %q", got)
	}
	if strings.Contains(got, "network") || strings.Contains(got, "Egress") {
		t.Errorf("a layer this host enforces must not appear; got %q", got)
	}
	if !strings.Contains(got, "needs limits is refused by default") {
		t.Errorf("a requested limit this host cannot enforce refuses; got %q", got)
	}
	if strings.Contains(got, "runs with the gap reported") {
		t.Errorf("nothing here runs with a gap, so that clause has no referent; got %q", got)
	}

	// A hardening gap that is not a limit is the other half: the run proceeds.
	var mixed enforce.Report
	mixed.Add(enforce.LayerNetwork, enforce.Unavailable, "no egress stack")
	mixed.Add(enforce.LayerExec, enforce.Degraded, "seccomp is filtered")

	b.Reset()
	writeDegradedSummary(&b, mixed.Degradations())
	got = strings.Join(strings.Fields(b.String()), " ")
	if !strings.Contains(got, "2 layers below fall short (network, exec-block)") {
		t.Errorf("both shortfalls must be counted and named; got %q", got)
	}
	if !strings.Contains(got, "needs network is refused by default") {
		t.Errorf("a core layer refuses the manifests that need it; got %q", got)
	}
	if !strings.Contains(got, "needs exec-block runs with the gap reported") {
		t.Errorf("a non-limit hardening gap runs; got %q", got)
	}
}

// doctor gates its exit code only on core guarantees every manifest needs. Network
// egress control is core but conditionally required (only a manifest that declares
// egress needs it), so a host that cannot fence egress still runs every no-network
// manifest and must not fail the doctor gate - it is reported, not gated. Filesystem
// confinement is unconditional, so its shortfall does gate.
func TestGatedShortfallExcludesConditionalNetwork(t *testing.T) {
	// Only network falls short: reported, but the gate stays clear (exit 0).
	var netOnly enforce.Report
	netOnly.Add(enforce.LayerFilesystem, enforce.Enforced, "")
	netOnly.Add(enforce.LayerNetwork, enforce.Unavailable, "no egress stack on this host")
	if got := gatedShortfall(netOnly); len(got) != 0 {
		t.Errorf("a network-only shortfall must not gate the exit code; got %+v", got)
	}

	// Filesystem falls short: it is unconditionally required, so it gates.
	var fsShort enforce.Report
	fsShort.Add(enforce.LayerFilesystem, enforce.Degraded, "userns blocked; Landlock-only")
	fsShort.Add(enforce.LayerNetwork, enforce.Unavailable, "no egress stack")
	got := gatedShortfall(fsShort)
	if len(got) != 1 || got[0].Layer != enforce.LayerFilesystem {
		t.Errorf("a filesystem shortfall must gate; got %+v", got)
	}

	// A hardening-only gap never gates (it is not core tier).
	var hardening enforce.Report
	hardening.Add(enforce.LayerFilesystem, enforce.Enforced, "")
	hardening.Add(enforce.LayerExec, enforce.Unavailable, "no seccomp")
	if got := gatedShortfall(hardening); len(got) != 0 {
		t.Errorf("a hardening gap must not gate; got %+v", got)
	}
}

// doctor's JSON readiness field mirrors the exit gate, not fully_enforced: a host
// short only on a conditionally-required layer (network) is ready (exit 0) even though
// not every layer is enforced. A baseline (filesystem) shortfall is not ready.
func TestDoctorJSONReadyMirrorsGate(t *testing.T) {
	var netOnly enforce.Report
	netOnly.Add(enforce.LayerFilesystem, enforce.Enforced, "")
	netOnly.Add(enforce.LayerNetwork, enforce.Unavailable, "no egress stack")
	dj := toDoctorJSON(netOnly)
	if !dj.Ready {
		t.Error("a network-only shortfall must still be ready (exit 0)")
	}
	if dj.FullyEnforced {
		t.Error("fully_enforced must be false when any layer fell short")
	}

	var fsShort enforce.Report
	fsShort.Add(enforce.LayerFilesystem, enforce.Degraded, "landlock-only")
	if toDoctorJSON(fsShort).Ready {
		t.Error("a filesystem shortfall must not be ready")
	}
}
