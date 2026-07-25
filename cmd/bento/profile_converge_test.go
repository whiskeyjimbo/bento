package main

import (
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/policy"
)

const (
	cfgPath  = "/home/u/.config/tool/config"
	dataPath = "/home/u/.config/tool/data"
)

// branchingRound models a content-branching target: it always attempts its config
// path, and reveals the downstream data path ONLY once the config is granted (mounted
// with real content), the way a real tool proceeds past its error branch only when it
// can finally read its config. It is the profiling seam converge() drives, standing in
// for a real bwrap round.
func branchingRound(discovery *policy.Policy) (*policy.Policy, error) {
	granted := map[string]bool{}
	for _, r := range discovery.Read {
		granted[r] = true
	}
	prop := &policy.Policy{Entrypoint: "/x", Read: []string{cfgPath}}
	if granted[cfgPath] {
		prop.Read = append(prop.Read, dataPath)
	}
	return prop, nil
}

func hasPath(paths []string, want string) bool {
	return slices.Contains(paths, want)
}

func baseDiscovery() *policy.Policy {
	return &policy.Policy{Entrypoint: "/x", Read: []string{"/scriptdir"}}
}

// noRisky is the predicate for tests whose paths never reach a foreign-home shield, so
// [a]ll behaves as the plain accept-the-rest shortcut.
func noRisky(string) bool { return false }

// Accepting the config mounts it next round, so the branching target proceeds and the
// downstream path is revealed and accepted too - convergence widens the manifest past
// the boot path, which is the whole point of the loop.
func TestConvergeAcceptRevealsDownstream(t *testing.T) {
	// One prompt per new path: config in round 1, data in round 2. Round 3 sees both
	// granted and nothing new, so it converges without prompting.
	prompt := newGrantPrompter(strings.NewReader("y\ny\n"), io.Discard)
	final, err := converge(baseDiscovery(), nil, branchingRound, prompt, noRisky, io.Discard)
	if err != nil {
		t.Fatalf("converge: %v", err)
	}
	if !hasPath(final.Read, cfgPath) || !hasPath(final.Read, dataPath) {
		t.Errorf("accepting the config must converge to both paths; got Read=%v", final.Read)
	}
}

// THE security invariant: declining the config leaves it recorded-only, never mounted,
// so the branching target never proceeds and the downstream path is never revealed. A
// path the user did not accept - a credential a profiled adversary probed - must never
// have its real content mounted, so it can never surface downstream accesses.
func TestConvergeDeclineNeverMountsOrReveals(t *testing.T) {
	// Capture the discovery policy each round actually mounts, so we test mounting
	// directly rather than inferring it from the final grant set.
	var mounted [][]string
	capturing := func(d *policy.Policy) (*policy.Policy, error) {
		mounted = append(mounted, append([]string{}, d.Read...))
		return branchingRound(d)
	}
	// "n" declines the config; the trailing "y" is a tripwire - correct converge never
	// mounts the declined config, so the branching target never reveals dataPath and the
	// "y" is never consumed. A broken converge that mounts a declined path would reveal
	// dataPath, prompt it, and the "y" would accept it, failing the assertions below.
	prompt := newGrantPrompter(strings.NewReader("n\ny\n"), io.Discard)
	final, err := converge(baseDiscovery(), nil, capturing, prompt, noRisky, io.Discard)
	if err != nil {
		t.Fatalf("converge: %v", err)
	}
	for i, reads := range mounted {
		if hasPath(reads, cfgPath) {
			t.Errorf("round %d mounted the declined config %q; discovery.Read=%v", i+1, cfgPath, reads)
		}
	}
	if hasPath(final.Read, cfgPath) {
		t.Errorf("a declined path must not be granted; got Read=%v", final.Read)
	}
	if hasPath(final.Read, dataPath) {
		t.Errorf("declining the config must never mount it, so the downstream path can never be revealed; got Read=%v", final.Read)
	}
}

// The [a]ll shortcut accepts the current path and every remaining one this session
// without further prompts, so a single keystroke converges a tool that wants many
// paths - but it still only ever grants paths the loop actually surfaced.
func TestConvergeAcceptAllStopsPrompting(t *testing.T) {
	prompts := 0
	counting := func(kind, path string) (grantChoice, error) {
		prompts++
		return grantAll, nil
	}
	final, err := converge(baseDiscovery(), nil, branchingRound, counting, noRisky, io.Discard)
	if err != nil {
		t.Fatalf("converge: %v", err)
	}
	if prompts != 1 {
		t.Errorf("[a]ll must prompt once then accept the rest silently; prompted %d times", prompts)
	}
	if !hasPath(final.Read, cfgPath) || !hasPath(final.Read, dataPath) {
		t.Errorf("[a]ll must still converge to both paths; got Read=%v", final.Read)
	}
}

// Quitting stops the loop immediately, keeping only what was accepted before the quit -
// the downstream path behind an unaccepted config is not revealed.
func TestConvergeQuitKeepsAcceptedSoFar(t *testing.T) {
	// A round-1 prompt: quit before accepting anything.
	prompt := newGrantPrompter(strings.NewReader("q\n"), io.Discard)
	final, err := converge(baseDiscovery(), nil, branchingRound, prompt, noRisky, io.Discard)
	if err != nil {
		t.Fatalf("converge: %v", err)
	}
	if len(final.Read) != 0 {
		t.Errorf("quitting before accepting anything must grant nothing; got Read=%v", final.Read)
	}
}

// A tool that wants nothing under a grant converges in one round with an empty grant
// set, and never prompts.
func TestConvergeNoAttemptsConvergesImmediately(t *testing.T) {
	empty := func(*policy.Policy) (*policy.Policy, error) {
		return &policy.Policy{Entrypoint: "/x"}, nil
	}
	fail := func(kind, path string) (grantChoice, error) {
		t.Fatalf("must not prompt when there is nothing to grant (%s %s)", kind, path)
		return grantNo, nil
	}
	final, err := converge(baseDiscovery(), nil, empty, fail, noRisky, io.Discard)
	if err != nil {
		t.Fatalf("converge: %v", err)
	}
	if len(final.Read) != 0 || len(final.Write) != 0 {
		t.Errorf("a tool wanting nothing must converge empty; got Read=%v Write=%v", final.Read, final.Write)
	}
}

// newGrantPrompter maps single-key answers, and a closed input (EOF) ends the loop
// rather than erroring or spinning.
func TestGrantPrompterParsing(t *testing.T) {
	cases := map[string]grantChoice{
		"y\n": grantYes, "yes\n": grantYes,
		"a\n": grantAll, "all\n": grantAll,
		"q\n": grantQuit, "quit\n": grantQuit,
		"n\n": grantNo, "\n": grantNo, "wat\n": grantNo,
		"": grantQuit, // EOF with no line
	}
	for in, want := range cases {
		got, err := newGrantPrompter(strings.NewReader(in), io.Discard)("read", "/p")
		if err != nil {
			t.Errorf("%q: unexpected error %v", in, err)
		}
		if got != want {
			t.Errorf("answer %q -> %v, want %v", in, got, want)
		}
	}
}

// [a]ll must NOT silently accept a foreign-home-shielded path (a credential store the
// enforced run will not re-shield): those always prompt, even after [a]ll, so a
// content-branching target cannot smuggle one in on a later round under a single earlier
// keystroke. This is the regression guard for the [a]ll bypass.
func TestConvergeAllStillPromptsRiskyPaths(t *testing.T) {
	const cred = "/home/other/.ssh/id_rsa"
	// Round 1 shows an innocuous path; once granted, round 2 reveals the foreign cred.
	round := func(d *policy.Policy) (*policy.Policy, error) {
		granted := map[string]bool{}
		for _, r := range d.Read {
			granted[r] = true
		}
		prop := &policy.Policy{Entrypoint: "/x", Read: []string{"/innocuous"}}
		if granted["/innocuous"] {
			prop.Read = append(prop.Read, cred)
		}
		return prop, nil
	}
	risky := func(p string) bool { return p == cred }

	askedCred := 0
	prompt := func(kind, path string) (grantChoice, error) {
		if path == cred {
			askedCred++
			return grantNo, nil // the reviewer declines the smuggled credential
		}
		return grantAll, nil // [a]ll on the innocuous path
	}
	final, err := converge(baseDiscovery(), nil, round, prompt, risky, io.Discard)
	if err != nil {
		t.Fatalf("converge: %v", err)
	}
	if askedCred != 1 {
		t.Errorf("a foreign-home cred must still prompt under [a]ll; prompted %d times", askedCred)
	}
	if hasPath(final.Read, cred) {
		t.Errorf("the declined foreign cred must not be granted; got Read=%v", final.Read)
	}
}

// A tool that touches a genuinely new path every round never converges; with [a]ll set
// the loop must still terminate at the round cap rather than spin forever.
func TestConvergeCapsRoundsOnNonConvergence(t *testing.T) {
	rounds := 0
	everNew := func(*policy.Policy) (*policy.Policy, error) {
		rounds++
		// A new path each round, so newGrants never empties.
		return &policy.Policy{Entrypoint: "/x", Read: []string{"/p/" + string(rune('a'+rounds%26)) + string(rune('0'+rounds))}}, nil
	}
	acceptAll := func(kind, path string) (grantChoice, error) { return grantAll, nil }
	if _, err := converge(baseDiscovery(), nil, everNew, acceptAll, noRisky, io.Discard); err != nil {
		t.Fatalf("converge: %v", err)
	}
	if rounds > maxConvergeRounds+1 {
		t.Errorf("loop must stop near the round cap; ran %d rounds", rounds)
	}
}

// A declined path is remembered so a later round does not re-ask about it, even though
// the target keeps attempting it every round.
func TestConvergeDoesNotReaskDeclined(t *testing.T) {
	// A target that attempts two paths every round regardless of grants.
	twoPaths := func(*policy.Policy) (*policy.Policy, error) {
		return &policy.Policy{Entrypoint: "/x", Read: []string{"/a", "/b"}}, nil
	}
	asked := map[string]int{}
	prompt := func(kind, path string) (grantChoice, error) {
		asked[path]++
		if path == "/a" {
			return grantYes, nil // accept /a
		}
		return grantNo, nil // decline /b
	}
	final, err := converge(baseDiscovery(), nil, twoPaths, prompt, noRisky, io.Discard)
	if err != nil {
		t.Fatalf("converge: %v", err)
	}
	// /a accepted (so not re-asked), /b declined (remembered, not re-asked): each asked
	// exactly once even though the target keeps attempting both.
	if asked["/a"] != 1 || asked["/b"] != 1 {
		t.Errorf("each path must be asked once; got %v", asked)
	}
	if !hasPath(final.Read, "/a") || hasPath(final.Read, "/b") {
		t.Errorf("final must hold /a (accepted) and not /b (declined); got Read=%v", final.Read)
	}
}

// A resumed session must not re-ask what the previous one already granted, and the
// seeded grant must be MOUNTED in round 1 - the point of resuming is that the target
// proceeds past its error branch immediately instead of re-walking the whole loop.
func TestConvergeSeedMountsGrantsWithoutReasking(t *testing.T) {
	var round1Reads []string
	recording := func(d *policy.Policy) (*policy.Policy, error) {
		if round1Reads == nil {
			round1Reads = append([]string{}, d.Read...)
		}
		return branchingRound(d)
	}
	asked := map[string]int{}
	prompt := func(kind, path string) (grantChoice, error) {
		asked[path]++
		return grantYes, nil
	}
	seed := &policy.Policy{Read: []string{cfgPath}}
	final, err := converge(baseDiscovery(), seed, recording, prompt, noRisky, io.Discard)
	if err != nil {
		t.Fatalf("converge: %v", err)
	}
	if !hasPath(round1Reads, cfgPath) {
		t.Errorf("a seeded grant must be mounted in round 1; round 1 discovery Read=%v", round1Reads)
	}
	if asked[cfgPath] != 0 {
		t.Errorf("a seeded grant must not be re-asked; %s was asked %d time(s)", cfgPath, asked[cfgPath])
	}
	if !hasPath(final.Read, cfgPath) || !hasPath(final.Read, dataPath) {
		t.Errorf("final must keep the seeded grant and the path it unlocked; got Read=%v", final.Read)
	}
}
