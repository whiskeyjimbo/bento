package main

import (
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
)

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
