package profile

import (
	"slices"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/manifest"
)

// A target names its own files and dials its own hosts, so it can produce values the
// manifest grammar refuses: an underscore hostname, a shorthand address literal, a
// filename carrying a control byte. Proposing one is not a manifest that gets rejected
// later - manifest.Marshal validates, so it is the whole profiling run failing at its
// final write with the session's work already spent. Synthesize drops them instead, so
// whatever it proposes marshals.
func TestSynthesizeProposesOnlyWhatAManifestCanHold(t *testing.T) {
	obs := Observation{
		Reads:  []string{"/work/data.txt", "/work/re\x1b[2Kport.txt", "/work/no\u202ete"},
		Writes: []string{"/work/out.txt", "/work/o\x00ut.txt"},
		Hosts: []HostPort{
			{Host: "ok.example.com", Port: "443"},
			{Host: "a_b.com", Port: "443"},
			{Host: "127.1", Port: "80"},
			{Host: "2852039166", Port: "80"},
		},
	}
	p := mustSynthesize(t, "/work/run.py", "python3", obs)

	if _, err := manifest.Marshal(p, manifest.Provenance{}); err != nil {
		t.Fatalf("Marshal(proposal) = %v, want nil - a proposal that cannot be written loses the whole profiling run", err)
	}
	if len(p.Network) != 1 || p.Network[0].Host != "ok.example.com" {
		t.Errorf("network = %+v, want only the representable host", p.Network)
	}
	for _, got := range append(append([]string{}, p.Read...), p.Write...) {
		if strings.ContainsAny(got, "\x00\x1b\u202e") {
			t.Errorf("grant %q survived; an unrepresentable path must be dropped", got)
		}
	}
	// The representable neighbors are still proposed: this drops the bad value, not the
	// run's whole read or write set.
	if !slices.Contains(p.Read, "/work/data.txt") || !slices.Contains(p.Write, "/work") {
		t.Errorf("read = %v, write = %v, want the clean grants kept", p.Read, p.Write)
	}
}
