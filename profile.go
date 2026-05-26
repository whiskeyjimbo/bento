package bento

import (
	"context"
	"sort"
	"strconv"
	"sync"

	"github.com/whiskeyjimbo/bento/internal/spec"
)

// NetworkObservation is one host:port pair the script connected to
// during a Profile run, with the connect count.
type NetworkObservation struct {
	Host  string
	Port  int
	Count int
}

// ProfileResult is what Profile returns: the script's exit code, the
// observed network behavior, and a suggested manifest with the
// discovered rules filled in (caller can write it to disk, review,
// trim, then use with Run).
type ProfileResult struct {
	ExitCode          int
	Observations      []NetworkObservation // sorted by Host, Port
	SuggestedManifest *Manifest
}

// Profile runs the script described by m in permissive-network mode:
// every outbound host:port is allowed AND recorded. All other
// isolation (filesystem, mandatory-deny, exec block, limits) stays in
// place. On exit, returns the observed network calls and a manifest
// pre-populated with the discovered rules.
//
// The intended workflow:
//
//	result, _ := bento.Profile(ctx, m)
//	// review result.Observations; trim what you don't want
//	// write result.SuggestedManifest, then bento.Run with the trimmed version
//
// The script's filesystem and exec permissions come from m unchanged;
// only the network is overridden. If you want zero-config profiling
// (no manifest at all), build a base manifest with
// PracticalStrictManifest first.
func Profile(ctx context.Context, m *Manifest, opts ...Option) (*ProfileResult, error) {
	obs := &observations{counts: make(map[obsKey]int)}
	cb := func(req GrantRequest) GrantDecision {
		obs.record(req.Host, req.Port)
		return GrantAllow
	}

	// Override Network to be non-nil but empty so every connect goes
	// through the grant callback (which records and allows).
	profile := *m
	profile.Network = &spec.NetworkPerm{Rules: nil}

	runOpts := append([]Option{WithGrantCallback(cb)}, opts...)
	code, err := Run(ctx, &profile, runOpts...)

	result := &ProfileResult{
		ExitCode:          code,
		Observations:      obs.list(),
		SuggestedManifest: synthesizeSuggested(m, obs.list()),
	}
	return result, err
}

type obsKey struct {
	host string
	port int
}

type observations struct {
	mu     sync.Mutex
	counts map[obsKey]int
}

func (o *observations) record(host string, port int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.counts[obsKey{host, port}]++
}

func (o *observations) list() []NetworkObservation {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]NetworkObservation, 0, len(o.counts))
	for k, c := range o.counts {
		out = append(out, NetworkObservation{Host: k.host, Port: k.port, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// synthesizeSuggested copies the original manifest and populates its
// Network.Rules with the discovered host:port pairs. Other fields
// (interpreter, read, write, exec, limits) are unchanged — the user
// fills those out themselves once they observe the script's behavior.
func synthesizeSuggested(original *Manifest, obs []NetworkObservation) *Manifest {
	out := *original
	rules := make([]NetworkRule, 0, len(obs))
	for _, o := range obs {
		rules = append(rules, NetworkRule{
			Host: o.Host,
			Port: strconv.Itoa(o.Port),
		})
	}
	out.Network = &NetworkPerm{Rules: rules}
	return &out
}
