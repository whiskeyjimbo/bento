package bento

import (
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
	out := synthesizeSuggested(original, obs, nil)
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
