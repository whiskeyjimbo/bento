package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
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
	prompt := newGrantPrompter(t.Context(), ttyLines(strings.NewReader("y\ny\n")), io.Discard)
	final, _, _, err := converge(baseDiscovery(), nil, branchingRound, prompt, noRisky, io.Discard)
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
	prompt := newGrantPrompter(t.Context(), ttyLines(strings.NewReader("n\ny\n")), io.Discard)
	final, _, _, err := converge(baseDiscovery(), nil, capturing, prompt, noRisky, io.Discard)
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
	final, _, _, err := converge(baseDiscovery(), nil, branchingRound, counting, noRisky, io.Discard)
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
	prompt := newGrantPrompter(t.Context(), ttyLines(strings.NewReader("q\n")), io.Discard)
	final, _, _, err := converge(baseDiscovery(), nil, branchingRound, prompt, noRisky, io.Discard)
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
	final, _, _, err := converge(baseDiscovery(), nil, empty, fail, noRisky, io.Discard)
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
		got, err := newGrantPrompter(t.Context(), ttyLines(strings.NewReader(in)), io.Discard)("read", "/p")
		if err != nil {
			t.Errorf("%q: unexpected error %v", in, err)
		}
		if got != want {
			t.Errorf("answer %q -> %v, want %v", in, got, want)
		}
	}
}

// Ctrl-C at a prompt ends the session with the cancellation, not with the [q]uit
// answer: quit writes the proposal the session reached, and a cancelled run must leave
// no manifest behind - the same thing the non-interactive path does. A nil channel is
// the prompt parked on a terminal nobody is typing at, which is where a Ctrl-C finds it.
func TestPromptsReportCancellationRatherThanQuit(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var parked chan string

	got, err := newGrantPrompter(ctx, parked, io.Discard)("read", "/p")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled grant prompt returned (%v, %v), want a context.Canceled error", got, err)
	}
	if got == grantQuit {
		t.Error("a cancelled prompt answered quit, which writes the manifest")
	}
	if err := confirmNetworkExfil(ctx, parked, io.Discard); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled exfil confirmation returned %v, want a context.Canceled error", err)
	}
	// approve stamps nothing on a cancel either way, but its decline text tells the
	// reviewer to go edit the manifest, which is advice for a refusal and not for a
	// Ctrl-C.
	if err := readApprovalAnswer(ctx, parked, io.Discard); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled approval prompt returned %v, want a context.Canceled error", err)
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
	final, _, _, err := converge(baseDiscovery(), nil, round, prompt, risky, io.Discard)
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
	if _, _, _, err := converge(baseDiscovery(), nil, everNew, acceptAll, noRisky, io.Discard); err != nil {
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
	final, _, _, err := converge(baseDiscovery(), nil, twoPaths, prompt, noRisky, io.Discard)
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
	final, _, _, err := converge(baseDiscovery(), seed, recording, prompt, noRisky, io.Discard)
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

// A seed's approval stamp is unkeyed drift detection, not a signature, so it cannot
// stand in for consent to mount a path the enforced run will not re-shield. Those are
// asked before round 1; a declined one must never reach the discovery policy.
func TestConvergeSeedPromptsRiskyPaths(t *testing.T) {
	const cred = "/home/other/.ssh/id_rsa"
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
		return grantNo, nil
	}
	seed := &policy.Policy{Read: []string{cfgPath, cred}}
	final, _, _, err := converge(baseDiscovery(), seed, recording, prompt, func(p string) bool { return p == cred }, io.Discard)
	if err != nil {
		t.Fatalf("converge: %v", err)
	}
	if asked[cred] != 1 {
		t.Errorf("a risky seeded grant must be asked once; asked %d time(s)", asked[cred])
	}
	if asked[cfgPath] != 0 {
		t.Errorf("an ordinary seeded grant must still resume without a prompt; %s asked %d time(s)", cfgPath, asked[cfgPath])
	}
	if hasPath(round1Reads, cred) {
		t.Errorf("a declined risky seed must not be mounted in round 1; round 1 discovery Read=%v", round1Reads)
	}
	if hasPath(final.Read, cred) {
		t.Errorf("a declined risky seed must not survive into the final policy; got Read=%v", final.Read)
	}
	if !hasPath(round1Reads, cfgPath) {
		t.Errorf("an ordinary seeded grant must still be mounted in round 1; got %v", round1Reads)
	}
}

// [a]ll answered at a seed prompt covers that path only. No round has run yet, so
// carrying it forward would grant the whole session's discoveries unseen.
func TestConvergeSeedAllDoesNotCoverLaterRounds(t *testing.T) {
	const cred = "/home/other/.ssh/id_rsa"
	asked := map[string]int{}
	prompt := func(kind, path string) (grantChoice, error) {
		asked[path]++
		return grantAll, nil
	}
	seed := &policy.Policy{Read: []string{cred}}
	if _, _, _, err := converge(baseDiscovery(), seed, branchingRound, prompt, func(p string) bool { return p == cred }, io.Discard); err != nil {
		t.Fatalf("converge: %v", err)
	}
	if asked[cfgPath] != 1 {
		t.Errorf("[a]ll at a seed prompt must not pre-accept round 1's discoveries; %s asked %d time(s)", cfgPath, asked[cfgPath])
	}
}

// The merge unions in the manifest at --out whatever its approval state, so without the
// drop a declined grant would be written back out - a refusal that held for the mount
// and not the file.
func TestDropDeclinedRemovesRefusedGrants(t *testing.T) {
	const cred = "/home/other/.ssh/id_rsa"
	merged := &policy.Policy{Read: []string{cred, cfgPath, "/discovered", "/both"}, Write: []string{"/w", "/both"}}
	declined := map[string]bool{
		grantItem{"read", cred}.key():  true,
		grantItem{"write", "/w"}.key(): true,
		// The same path decided both ways: refusing the read must not take the write.
		grantItem{"read", "/both"}.key(): true,
	}

	got := dropDeclined(merged, declined)
	if hasPath(got.Read, cred) {
		t.Errorf("a declined read must not survive the merge; got Read=%v", got.Read)
	}
	if !hasPath(got.Read, cfgPath) || !hasPath(got.Read, "/discovered") {
		t.Errorf("an accepted grant and a fresh discovery must both survive; got Read=%v", got.Read)
	}
	if hasPath(got.Write, "/w") {
		t.Errorf("a declined write must not survive either; got Write=%v", got.Write)
	}
	if hasPath(got.Read, "/both") || !hasPath(got.Write, "/both") {
		t.Errorf("read and write are decided separately; got Read=%v Write=%v", got.Read, got.Write)
	}
}

// Nothing prompted means nothing declined, so the merge must widen exactly as it always
// did - the non-interactive pass, and an interactive one where every answer was yes.
func TestDropDeclinedKeepsEverythingWithoutARefusal(t *testing.T) {
	merged := &policy.Policy{Read: []string{"/a", "/b"}}
	got := dropDeclined(merged, nil)
	if !hasPath(got.Read, "/a") || !hasPath(got.Read, "/b") {
		t.Errorf("with no refusals the merge must be untouched; got Read=%v", got.Read)
	}
}

// The kept lists say what the file carries that this run did not show, so they have to
// describe the manifest actually written: computed inside mergeExisting, they name the
// pre-drop policy, and a path the session declined is then reported as kept while being
// absent from disk - to the reviewer and to a gate reading merged.kept_read.
func TestKeptListsDescribeTheWrittenManifest(t *testing.T) {
	const cred = "/home/other/.ssh/id_rsa"
	existing := &policy.Policy{Read: []string{cred, "/w/prior.txt"}}
	accepted := &policy.Policy{Read: []string{cfgPath}}
	declined := map[string]bool{grantItem{"read", cred}.key(): true}

	merged := mergePolicies(existing, accepted)
	keptRead := only(existing.Read, accepted.Read)
	merged = dropDeclined(merged, declined)
	keptRead = retained(keptRead, merged.Read)

	if hasPath(keptRead, cred) {
		t.Errorf("kept_read names %q, which the drop removed from the manifest; got %v", cred, keptRead)
	}
	if !hasPath(keptRead, "/w/prior.txt") {
		t.Errorf("a grant the file really does carry must still be reported; got %v", keptRead)
	}
}

// The hole the drop exists to close, from the session's end: an unapproved manifest at
// --out seeds nothing, so the target attempts the path under default-deny and converge
// prompts for it. Answering n has to reach the artifact, and the seed-shaped drop could
// not - it only ever looked at paths a seed carried, and there was no seed.
func TestDeclinedPathHeldAgainstAnUnapprovedManifest(t *testing.T) {
	prompt := newGrantPrompter(t.Context(), ttyLines(strings.NewReader("n\n")), io.Discard)
	final, _, declined, err := converge(baseDiscovery(), nil, branchingRound, prompt, noRisky, io.Discard)
	if err != nil {
		t.Fatalf("converge: %v", err)
	}
	if hasPath(final.Read, cfgPath) {
		t.Fatalf("the declined path must not be in the accepted set; got Read=%v", final.Read)
	}
	// What mergeExisting does with the unapproved file already at --out.
	merged := mergePolicies(&policy.Policy{Read: []string{cfgPath}}, final)
	if got := dropDeclined(merged, declined); hasPath(got.Read, cfgPath) {
		t.Errorf("the declined path came back through the union; got Read=%v", got.Read)
	}
}

// execRound models a target that shells out: it attempts one path and one subprocess.
func execRound(*policy.Policy) (*policy.Policy, error) {
	return &policy.Policy{Entrypoint: "/x", Read: []string{cfgPath}, Exec: policy.ExecAll}, nil
}

// exec: all lets the target spawn anything the rest of the policy permits, so it is a
// grant like any other and must pass through the prompt. One observed
// exec put exec: all in the stamped manifest even if the reviewer declined everything.
func TestConvergeExecNeedsConsent(t *testing.T) {
	cases := map[string]struct {
		answers string
		want    policy.ExecMode
	}{
		// exec is asked first, then the path; the second answer is the path's.
		"declined": {"n\nn\n", policy.ExecNone},
		"accepted": {"y\nn\n", policy.ExecAll},
		// [a]ll answers the paths, never exec: the exec prompt comes first, so an [a]ll
		// meant for the paths must not silently carry exec with it.
		"all after declining exec": {"n\na\n", policy.ExecNone},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			prompt := newGrantPrompter(t.Context(), ttyLines(strings.NewReader(tc.answers)), io.Discard)
			final, _, _, err := converge(baseDiscovery(), nil, execRound, prompt, noRisky, io.Discard)
			if err != nil {
				t.Fatalf("converge: %v", err)
			}
			if final.Exec != tc.want {
				t.Errorf("Exec = %q, want %q", final.Exec, tc.want)
			}
		})
	}
}

// A resumed session must not re-ask for an exec grant the approved manifest already
// carries, the same way it does not re-ask for a non-risky path.
func TestConvergeSeededExecResumesWithoutPrompt(t *testing.T) {
	seed := &policy.Policy{Read: []string{cfgPath}, Exec: policy.ExecAll}
	// An empty prompt input returns grantQuit on EOF, so any prompt at all would end
	// the loop before it converged - the tripwire that exec was not re-asked.
	prompt := newGrantPrompter(t.Context(), ttyLines(strings.NewReader("")), io.Discard)
	final, _, _, err := converge(baseDiscovery(), seed, execRound, prompt, noRisky, io.Discard)
	if err != nil {
		t.Fatalf("converge: %v", err)
	}
	if final.Exec != policy.ExecAll {
		t.Errorf("Exec = %q, want the seeded %q back without a prompt", final.Exec, policy.ExecAll)
	}
}

// mergePolicies promotes exec: all from either side, so an existing manifest at --out
// that already carries it would reinstate the grant the reviewer just declined - the
// exact hole the prompt exists to close, and one dropDeclined cannot reach because exec
// is not a path. The session's answer has to win in the
// artifact, and it must narrow only from exec: all so a hand-written none-strict is not
// widened to plain none.
func TestMergeExecRespectsTheSessionAnswer(t *testing.T) {
	cases := map[string]struct {
		existing, accepted, want policy.ExecMode
	}{
		"declined against an existing exec: all": {policy.ExecAll, policy.ExecNone, policy.ExecNone},
		"accepted":                               {policy.ExecAll, policy.ExecAll, policy.ExecAll},
		"hand-written none-strict is left alone": {policy.ExecNoneStrict, policy.ExecNone, policy.ExecNoneStrict},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			accepted := &policy.Policy{Exec: tc.accepted}
			merged := applyExecAnswer(mergePolicies(&policy.Policy{Exec: tc.existing}, accepted), accepted)
			if merged.Exec != tc.want {
				t.Errorf("Exec = %q, want %q", merged.Exec, tc.want)
			}
		})
	}
}

// converge must say why it stopped, so profile can exit nonzero over a manifest built
// from a session the user never finished rather than let `profile && approve` stamp it.
// A quit and a hit round cap are both "not converged".
func TestConvergeReportsWhyItStopped(t *testing.T) {
	prompt := newGrantPrompter(t.Context(), ttyLines(strings.NewReader("y\ny\ny\n")), io.Discard)
	if _, stop, _, err := converge(baseDiscovery(), nil, branchingRound, prompt, noRisky, io.Discard); err != nil || stop != convergeDone {
		t.Errorf("a converged session: stop = %v, err = %v; want convergeDone", stop, err)
	}

	quitting := newGrantPrompter(t.Context(), ttyLines(strings.NewReader("q\n")), io.Discard)
	if _, stop, _, err := converge(baseDiscovery(), nil, branchingRound, quitting, noRisky, io.Discard); err != nil || stop != convergeQuit {
		t.Errorf("a quit session: stop = %v, err = %v; want convergeQuit", stop, err)
	}

	// A new path every round never converges, so [a]ll runs it into the round cap.
	round := 0
	everNew := func(*policy.Policy) (*policy.Policy, error) {
		round++
		return &policy.Policy{Entrypoint: "/x", Read: []string{fmt.Sprintf("/p/%d", round)}}, nil
	}
	acceptAll := func(kind, path string) (grantChoice, error) { return grantAll, nil }
	if _, stop, _, err := converge(baseDiscovery(), nil, everNew, acceptAll, noRisky, io.Discard); err != nil || stop != convergeMaxRounds {
		t.Errorf("a capped session: stop = %v, err = %v; want convergeMaxRounds", stop, err)
	}
}

// The exit code is the honest signal, so every not-converged outcome has to reach it.
func TestIncompleteReason(t *testing.T) {
	if got := incompleteReason(roundStatus{}, convergeDone); got != "" {
		t.Errorf("a clean converged session must be vouched for; got %q", got)
	}
	for _, tc := range []struct {
		status roundStatus
		stop   convergeStop
	}{
		{roundStatus{unfinished: "did not finish"}, convergeDone},
		{roundStatus{dropped: true}, convergeDone},
		{roundStatus{}, convergeQuit},
		{roundStatus{}, convergeMaxRounds},
	} {
		if incompleteReason(tc.status, tc.stop) == "" {
			t.Errorf("status=%+v stop=%v must be reported as incomplete", tc.status, tc.stop)
		}
	}
}

// Every round has to run the invocation the proposal will record. A round that ran the
// script bare while the manifest said `sh -eu script` would propose grants from a run
// nobody watched - and for -e, from a script that ran further than the enforced one
// will. Asserted against the whole base rather than one field: the discovery policy is
// base plus this round's accepted grants, and nothing else.
func TestConvergeRunsEveryRoundUnderTheBasesInvocation(t *testing.T) {
	base := baseDiscovery()
	base.Interpreter = "/bin/sh"
	base.InterpreterArgs = []string{"-eu"}
	base.Args = []string{"--flag"}

	var ran []policy.Policy
	capturing := func(d *policy.Policy) (*policy.Policy, error) {
		ran = append(ran, *d)
		return branchingRound(d)
	}
	prompt := newGrantPrompter(t.Context(), ttyLines(strings.NewReader("y\ny\n")), io.Discard)
	if _, _, _, err := converge(base, nil, capturing, prompt, noRisky, io.Discard); err != nil {
		t.Fatalf("converge: %v", err)
	}
	if len(ran) == 0 {
		t.Fatal("converge ran no rounds")
	}
	for i, d := range ran {
		want := *base
		want.Read, want.Write = d.Read, d.Write
		if !reflect.DeepEqual(d, want) {
			t.Errorf("round %d ran a different policy than the base modulo grants:\n got %+v\nwant %+v", i+1, d, want)
		}
	}
}
