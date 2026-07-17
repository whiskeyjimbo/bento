package policy

import "testing"

func TestFingerprintStableAcrossReordering(t *testing.T) {
	a := &Policy{
		Entrypoint: "./x",
		Env:        []string{"A", "B"},
		Read:       []string{"/one", "/two"},
		Network:    []NetworkRule{{Host: "a.com", Port: "443"}, {Host: "b.com", Port: "80"}},
	}
	b := &Policy{
		Entrypoint: "./x",
		Env:        []string{"B", "A"},                                                       // reordered
		Read:       []string{"/two", "/one"},                                                 // reordered
		Network:    []NetworkRule{{Host: "b.com", Port: "80"}, {Host: "a.com", Port: "443"}}, // reordered
	}
	if a.Fingerprint() != b.Fingerprint() {
		t.Error("reordering set-like fields must not change the fingerprint")
	}
}

func TestFingerprintChangesWithPermissions(t *testing.T) {
	base := &Policy{Entrypoint: "./x", Read: []string{"/data"}}
	fp := base.Fingerprint()

	cases := map[string]func(*Policy){
		"added read":    func(p *Policy) { p.Read = append(p.Read, "/more") },
		"added network": func(p *Policy) { p.Network = []NetworkRule{{Host: "a.com", Port: "443"}} },
		"changed exec":  func(p *Policy) { p.Exec = ExecAll },
		"added write":   func(p *Policy) { p.Write = []string{"/out"} },
		"added limit":   func(p *Policy) { p.Limits = Limits{Memory: "1M"} },
		"changed entry": func(p *Policy) { p.Entrypoint = "./y" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			p := &Policy{Entrypoint: "./x", Read: []string{"/data"}}
			mut(p)
			if p.Fingerprint() == fp {
				t.Error("a permission change must change the fingerprint")
			}
		})
	}
}

// Arg order is meaningful and must affect the fingerprint.
func TestFingerprintArgOrderMatters(t *testing.T) {
	a := &Policy{Entrypoint: "./x", Args: []string{"--a", "--b"}}
	b := &Policy{Entrypoint: "./x", Args: []string{"--b", "--a"}}
	if a.Fingerprint() == b.Fingerprint() {
		t.Error("arg order is significant and must change the fingerprint")
	}
}
