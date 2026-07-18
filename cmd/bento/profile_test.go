package main

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/policy"
	"github.com/whiskeyjimbo/bento-v2/profile"
)

// bv2-2wy regression: the clamp order is load-bearing - DropCovered must run LAST,
// after the broad-write clamp, so a read under a write that gets dropped as too broad
// is NOT swallowed by that write but surfaces as its own read grant. This fails if
// DropCovered is reordered ahead of clampBroadWrites (the shape of the original bug).
func TestClampProposalDedupsReadsOnlyAfterDroppingBroadWrites(t *testing.T) {
	p := &policy.Policy{
		Read:  []string{"/srv/app/config", "/etc/thing/data"},
		Write: []string{"/srv/app", "/etc"}, // /srv/app is narrow (kept); /etc is top-level (dropped)
	}
	_, broad := clampProposal(p)

	if !slices.Contains(broad, "/etc") {
		t.Fatalf("the top-level /etc write must be surfaced as too broad, got %v", broad)
	}
	// The read under the KEPT narrow write is deduped away...
	if slices.Contains(p.Read, "/srv/app/config") {
		t.Errorf("a read under the surviving narrow write /srv/app must be deduped, got Read=%v", p.Read)
	}
	// ...but the read under the DROPPED broad /etc write survives (DropCovered ran
	// after the broad clamp, so /etc no longer covers it). If DropCovered ran first,
	// /etc would have swallowed it and it would be silently gone - the bug.
	if !slices.Contains(p.Read, "/etc/thing/data") {
		t.Errorf("a read under a dropped broad write must survive as its own grant, got Read=%v", p.Read)
	}
}

func TestClampBroadWrites(t *testing.T) {
	home, _ := os.UserHomeDir()

	deep := "/srv/app/data" // a specific directory, safe to grant
	writes := []string{deep, "/", "/etc", "/usr"}
	if home != "" {
		writes = append(writes, home)
	}

	kept, dropped := clampBroadWrites(writes)

	if !slices.Equal(kept, []string{deep}) {
		t.Fatalf("kept = %v, want just the specific directory %q", kept, deep)
	}
	for _, broad := range []string{"/", "/etc", "/usr"} {
		if !slices.Contains(dropped, broad) {
			t.Errorf("%q should be dropped as too broad to grant automatically", broad)
		}
	}
	if home != "" && !slices.Contains(dropped, home) {
		t.Errorf("the home directory %q should be dropped as too broad", home)
	}
}

func TestPartialRunWarning(t *testing.T) {
	if w := partialRunWarning(profile.Observation{ExitCode: 0}); w != "" {
		t.Errorf("clean run should not warn, got %q", w)
	}
	if w := partialRunWarning(profile.Observation{ExitCode: 7}); !strings.Contains(w, "exited with code 7") {
		t.Errorf("nonzero exit warning = %q, want it to name code 7", w)
	}
	// Signaled takes priority over the (implied nonzero) exit code.
	w := partialRunWarning(profile.Observation{Signaled: true, Signal: 9, ExitCode: 137})
	if !strings.Contains(w, "signal 9") || strings.Contains(w, "exited with code") {
		t.Errorf("signaled warning = %q, want it to name signal 9 and not the exit code", w)
	}
}

func TestClampShieldedGrants(t *testing.T) {
	home, _ := os.UserHomeDir()
	if home == "" {
		t.Skip("no home directory on this host")
	}
	ssh := home + "/.ssh/id_rsa"   // a file inside a DenyAll shield directory
	sshDir := home + "/.ssh"       // the shield directory itself
	netrc := home + "/.netrc"      // a DenyAll shield that is itself a FILE
	ordinary := "/srv/app/config"  // no shield involved
	underHome := home + "/project" // under home but not a shield

	reads := []string{ssh, sshDir, netrc, home, ordinary, underHome}
	writes := []string{home + "/.gnupg/x", ordinary}

	keptR, keptW, dropped := clampShieldedGrants(reads, writes)

	// A grant AT or INSIDE a shield is dropped, whether the shield is a directory
	// (~/.ssh) or a file (~/.netrc); the run refuses all of them.
	for _, d := range []string{ssh, sshDir, netrc, home + "/.gnupg/x"} {
		if !slices.Contains(dropped, d) {
			t.Errorf("%q is at/inside a DenyAll shield and must be dropped; dropped=%v", d, dropped)
		}
	}
	// The load-bearing property: a read that only CONTAINS a shield (read: ~) is
	// legitimate and kept - the run allows it, so dropping it would strip a valid grant.
	if !slices.Contains(keptR, home) {
		t.Errorf("read of the home directory %q must be KEPT (it merely contains shields); keptReads=%v", home, keptR)
	}
	if !slices.Contains(keptR, ordinary) || !slices.Contains(keptR, underHome) {
		t.Errorf("ordinary reads must be kept; keptReads=%v", keptR)
	}
	if !slices.Contains(keptW, ordinary) {
		t.Errorf("ordinary write must be kept; keptWrites=%v", keptW)
	}
}
