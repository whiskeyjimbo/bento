package main

import (
	"strings"
	"testing"
)

// seedStore writes an app and a global deny into a store rooted at an XDG dir the
// test controls, so perms() (which loads via storeDir) hits the same location.
func seedStore(t *testing.T) (dir, appKey string) {
	t.Helper()
	dir = t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	s, err := loadStore()
	if err != nil {
		t.Fatal(err)
	}
	appKey = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	a := s.app(appKey)
	a.Entrypoint = "/home/u/proj/agent.sh"
	a.Interpreter = "sh"
	s.rememberPath(appKey, "read", "/home/u/vault/data.csv", allow)
	s.rememberNetwork(appKey, "example.com", "443", allow, false)
	s.rememberNetwork(appKey, "ads.tracker.example", "443", deny, true) // global deny
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	return dir, appKey
}

// forget must survive save()'s concurrent-merge fold, which re-reads the store off
// disk. A pure in-memory delete would be silently resurrected; only a reload from
// disk proves the deletion stuck.
func TestForgetAppSurvivesReload(t *testing.T) {
	_, appKey := seedStore(t)
	var out strings.Builder
	if rc := perms([]string{"forget", "app", shortKey(appKey)}, strings.NewReader(""), &out); rc != 0 {
		t.Fatalf("forget app rc=%d, out=%q", rc, out.String())
	}
	reloaded, err := loadStore()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reloaded.Apps[appKey]; ok {
		t.Error("the app was resurrected by save()'s merge after forget")
	}
	// The global deny is a separate layer and must be untouched by an app forget.
	if reloaded.Global.Network["ads.tracker.example:443"] != deny {
		t.Error("forgetting an app must not touch global rules")
	}
}

// The escape hatch for the deny-wins footgun: clearing a global deny that would
// silently block a host for every app.
func TestForgetGlobalRule(t *testing.T) {
	seedStore(t)
	var out strings.Builder
	if rc := perms([]string{"forget", "global", "ads.tracker.example:443"}, strings.NewReader(""), &out); rc != 0 {
		t.Fatalf("forget global rc=%d, out=%q", rc, out.String())
	}
	reloaded, err := loadStore()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reloaded.Global.Network["ads.tracker.example:443"]; ok {
		t.Error("the global deny survived forget global")
	}
}

// reset wipes everything, but only on an explicit yes.
func TestResetConfirmsBeforeWiping(t *testing.T) {
	seedStore(t)

	// A "no" leaves the store intact.
	var out strings.Builder
	perms([]string{"reset"}, strings.NewReader("n\n"), &out)
	if s, _ := loadStore(); len(s.Apps) == 0 {
		t.Fatal("reset wiped the store despite a 'no' answer")
	}

	// A "yes" clears it, and the emptied store persists across a reload.
	perms([]string{"reset"}, strings.NewReader("y\n"), &strings.Builder{})
	s, err := loadStore()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Apps) != 0 || len(s.Global.Network) != 0 {
		t.Errorf("reset did not clear the store: %d apps, %d global", len(s.Apps), len(s.Global.Network))
	}
}

// An ambiguous app prefix must refuse rather than delete the wrong record.
func TestForgetAppAmbiguousPrefixRefuses(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	s, _ := loadStore()
	s.app("sha256:abcd0000000000000000000000000000000000000000000000000000000000000000").Entrypoint = "/a"
	s.app("sha256:abcd1111111111111111111111111111111111111111111111111111111111111111").Entrypoint = "/b"
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if rc := perms([]string{"forget", "app", "abcd"}, strings.NewReader(""), &out); rc == 0 {
		t.Error("an ambiguous prefix must not succeed")
	}
	if !strings.Contains(out.String(), "ambiguous") {
		t.Errorf("expected an ambiguity error, got %q", out.String())
	}
	if s2, _ := loadStore(); len(s2.Apps) != 2 {
		t.Error("an ambiguous forget must delete nothing")
	}
}

// list must show the EFFECTIVE decision, not the raw per-app one: an app that
// allowed a host still shows deny when a global rule denies it, marked (global) so
// the operator knows which layer to clear.
func TestListShowsEffectiveDecision(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	s, _ := loadStore()
	s.rememberNetwork("sha256:abcd", "tracker.example", "443", allow, false) // app allows
	s.rememberNetwork("sha256:abcd", "tracker.example", "443", deny, true)   // global denies
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	perms([]string{"list"}, strings.NewReader(""), &out)
	got := out.String()
	// The app's host line (4-space indent) must read the effective deny plus the
	// (global) marker, even though the app itself allowed the host.
	found := false
	for line := range strings.SplitSeq(got, "\n") {
		if strings.HasPrefix(line, "    reach") && strings.Contains(line, "tracker.example") {
			found = true
			if !strings.Contains(line, "deny") || !strings.Contains(line, "(global)") {
				t.Errorf("app host line must show effective deny with (global): %q", line)
			}
		}
	}
	if !found {
		t.Fatalf("no app host line in list output: %q", got)
	}
}

// list quotes attacker-influenced store keys (a host or path the sandboxed target
// chose), so a crafted key cannot carry a terminal escape onto the operator's
// screen.
func TestListQuotesAttackerStrings(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	s, _ := loadStore()
	s.rememberNetwork("sha256:2222", "evil\x1b[2Khost", "443", deny, true)
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	perms([]string{"list"}, strings.NewReader(""), &out)
	if strings.ContainsRune(out.String(), '\x1b') {
		t.Errorf("list leaked a raw escape byte: %q", out.String())
	}
}
