package bento

import (
	"path/filepath"
	"testing"
)

func TestSynthesizeSuggested(t *testing.T) {
	original := &Manifest{
		Interpreter: "python3",
		Script:      "/tmp/s.py",
		Read:        []string{"/etc/hostname"},
	}
	obs := []NetworkObservation{
		{Host: "api.example.com", Port: 443, Count: 5},
		{Host: "auth.example.com", Port: 443, Count: 2},
	}
	out := synthesizeSuggested(original, obs, nil, nil, nil)
	if out.Interpreter != "python3" {
		t.Errorf("interpreter lost in synthesis: %q", out.Interpreter)
	}
	if out.Network == nil || len(out.Network.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %v", out.Network)
	}
	if out.Network.Rules[0].Host != "api.example.com" || out.Network.Rules[0].Port != "443" {
		t.Errorf("rule 0: got %+v", out.Network.Rules[0])
	}
}

func TestObservationsOrdering(t *testing.T) {
	o := &observations{counts: map[obsKey]int{
		{host: "z", port: 443}:  1,
		{host: "a", port: 80}:   2,
		{host: "a", port: 443}:  3,
		{host: "a", port: 8080}: 1,
	}}
	list := o.list()
	if len(list) != 4 {
		t.Fatalf("expected 4 obs, got %d", len(list))
	}
	// Sorted by host, then port: a:80, a:443, a:8080, z:443
	if list[0].Host != "a" || list[0].Port != 80 {
		t.Errorf("first: got %v", list[0])
	}
	if list[3].Host != "z" {
		t.Errorf("last: got %v", list[3])
	}
}

func TestPartitionFSObservations_BlockedReads(t *testing.T) {
	m := &Manifest{Interpreter: "bash", Script: "/work/deploy.sh"}
	opens := []FSOpen{
		{Path: "/work/deploy.sh", OK: true},        // the script itself — skip
		{Path: "/etc/shells", OK: false},           // legit blocked read — keep
		{Path: "/usr/lib/foo.so", OK: false},       // interpreter dep noise — skip
		{Path: "/home/u/.cargo/bin/bwrap", OK: false}, // PATH probe pair — skip
		{Path: "/home/u/.local/bin/bwrap", OK: false}, // PATH probe pair — skip
		{Path: "/usr/bin/bwrap", OK: false},        // bento tooling probe — skip
	}
	_, _, _, _, blocked := partitionFSObservations(opens, m)
	if len(blocked) != 1 || blocked[0] != "/etc/shells" {
		t.Errorf("blocked = %v; want [/etc/shells]", blocked)
	}
}

func TestPartitionFSObservations_BlockedReadsMergedIntoSuggestedRead(t *testing.T) {
	m := &Manifest{Interpreter: "bash", Script: "/work/deploy.sh"}
	opens := []FSOpen{
		{Path: "/work/data.json", OK: true},
		{Path: "/etc/shells", OK: false},
	}
	read, _, _, _, blocked := partitionFSObservations(opens, m)
	out := synthesizeSuggested(m, nil, read, nil, blocked)
	got := map[string]bool{}
	for _, p := range out.Read {
		got[p] = true
	}
	if !got["/etc/shells"] || !got["/work/data.json"] {
		t.Errorf("Read = %v; want both /etc/shells and /work/data.json", out.Read)
	}
}

func TestDropPathSearchNoise(t *testing.T) {
	in := []string{
		"/etc/shells",
		"/home/u/.cargo/bin/foo",
		"/home/u/.local/bin/foo",
		"/usr/bin/foo",
		"/home/u/.local/bin/onlyhere", // single bin hit — keep
	}
	out := dropPathSearchNoise(in)
	hasFoo := false
	hasOnly := false
	for _, p := range out {
		if filepath.Base(p) == "foo" {
			hasFoo = true
		}
		if filepath.Base(p) == "onlyhere" {
			hasOnly = true
		}
	}
	if hasFoo {
		t.Errorf("expected `foo` PATH probes dropped, got %v", out)
	}
	if !hasOnly {
		t.Errorf("expected `onlyhere` kept (single bin/ hit), got %v", out)
	}
}

func TestObservationsRecordCount(t *testing.T) {
	o := &observations{counts: make(map[obsKey]int)}
	o.record("h", 1)
	o.record("h", 1)
	o.record("h", 1)
	list := o.list()
	if list[0].Count != 3 {
		t.Errorf("expected count 3, got %d", list[0].Count)
	}
}
