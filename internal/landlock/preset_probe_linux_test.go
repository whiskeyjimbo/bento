//go:build linux && bentoprobe

package landlock

import (
	"errors"
	"testing"
)

// A tier preset swaps only the handled sets: Available and RestrictDegraded's ABI floor
// both keep answering for the real kernel, so under any preset they cannot disagree
// about it. A preset that lowered effectiveABI would change what "Landlock is available"
// and "the floor refused this run" mean, which is the hybrid SetTierPreset documents
// rather than a faithful old kernel.
func TestTierPresetLeavesTheABIEverythingReadsAlone(t *testing.T) {
	fs, deg, tcp, ipc := handledFS, degradedFS, netTCP, scopedIPC
	t.Cleanup(func() { handledFS, degradedFS, netTCP, scopedIPC = fs, deg, tcp, ipc })
	kernel := detectedABI()
	for _, name := range []string{"V2", "V3", "V4", "V5", "V6", "V7", "V8", "V9"} {
		if err := SetTierPreset(name); err != nil {
			t.Fatal(err)
		}
		if err := SetScopedIPCPreset(name); err != nil {
			t.Fatal(err)
		}
		if got := effectiveABI(); got != kernel {
			t.Errorf("preset %s: effectiveABI = %d, want the kernel's %d", name, got, kernel)
		}
		if Available() != (kernel >= 1) {
			t.Errorf("preset %s: Available() = %v on a kernel at ABI %d", name, Available(), kernel)
		}
	}
}

// The other half of the agreement, driven where it is safe to drive: on an ABI-0 host
// under a preset, Available says no and the floor refuses, before any ruleset is applied.
func TestTierPresetFloorAgreesWithAvailableOnNoLandlock(t *testing.T) {
	fs, deg, tcp, abi := handledFS, degradedFS, netTCP, effectiveABI
	t.Cleanup(func() { handledFS, degradedFS, netTCP, effectiveABI = fs, deg, tcp, abi })
	effectiveABI = func() int { return 0 }
	if err := SetTierPreset("V4"); err != nil {
		t.Fatal(err)
	}
	if Available() {
		t.Error("Available() = true on an ABI-0 host")
	}
	if err := RestrictDegraded(nil, nil, nil); !errors.Is(err, errUnavailableABI) {
		t.Errorf("RestrictDegraded = %v, want the ABI floor's refusal", err)
	}
}
