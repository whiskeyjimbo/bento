package main

import (
	"fmt"
	"io"
	"maps"
	"slices"

	"github.com/whiskeyjimbo/bento/policy"
)

// maxConvergeRounds bounds the convergence loop so a tool that touches a new path each
// run cannot spin it forever; typical tools converge in a handful of rounds.
const maxConvergeRounds = 25

// converge repeats profiling rounds, mounting the grants the user accepts so a
// content-branching target proceeds past its error branch and reveals the next layer
// of accesses, until a round surfaces nothing new. round is the profiling seam (the
// real backend-backed profileRound in production, a fake in tests): it receives the
// discovery policy carrying the accepted grants and returns the clamped proposal.
// prompt asks about one newly-attempted path; declining it (or anything but yes/all)
// leaves it recorded-only and never mounts it - the consent that keeps real content off
// a path the user did not approve. risky reports a path that would be exposed at enforce
// time (a foreign-home shield the run will not re-shield); those always prompt, never
// auto-accepted under [a]ll, and are prompted in a seed too. seed carries the grants of
// an approved manifest to accept before round 1, so a session resumed after a quit
// continues where it left off rather than re-asking every path; only its Read and Write
// are read, and nil starts fresh. It
// returns the final proposal with reads/writes narrowed to exactly the accepted set,
// and the refusals themselves - keyed by grantItem.key(), so the merge can hold them
// against a manifest that already granted what the user just said no to.
func converge(base, seed *policy.Policy, round func(*policy.Policy) (*policy.Policy, error), prompt func(kind, path string) (grantChoice, error), risky func(path string) bool, out io.Writer) (*policy.Policy, convergeStop, map[string]bool, error) {
	stop := convergeDone
	acceptedR := map[string]bool{}
	acceptedW := map[string]bool{}
	acceptedExec := false
	declined := map[string]bool{} // key() -> asked and refused, so it is not re-asked
	acceptAll := false
	accept := func(it grantItem) {
		switch it.kind {
		case "read":
			acceptedR[it.path] = true
		case "write":
			acceptedW[it.path] = true
		case "exec":
			acceptedExec = true
		}
	}

	// A seed's grants are mounted in round 1 with the approval stamp standing in for
	// this session's prompt. The stamp is unkeyed drift detection rather than a
	// signature, so for a risky path - one the enforced run will not re-shield - it is
	// not enough on its own: anyone able to write the manifest can compute a current
	// fingerprint. Those are asked here, before any content is mounted, for the same
	// reason [a]ll never covers them below. The rest resume without a prompt.
	if seed != nil {
		// exec has no path, so it cannot be risky in the foreign-home sense; the stamp
		// resumes it exactly as a non-risky read or write resumes.
		acceptedExec = seed.Exec == policy.ExecAll
		for _, it := range seedItems(seed) {
			if !risky(it.path) {
				accept(it)
				continue
			}
			c, err := prompt(it.kind, it.path)
			if err != nil {
				return nil, convergeQuit, declined, err
			}
			switch c {
			// [a]ll here accepts only this seeded path. In the loop below it answers for
			// a list the user has just been shown; at seed time no round has run, so
			// carrying it forward would grant every path the whole session goes on to
			// discover, unseen - a wider consent than the prompt asked for.
			case grantAll, grantYes:
				accept(it)
				continue
			case grantQuit:
				return nil, convergeQuit, declined, fmt.Errorf("aborted: quit before the first profiling round, so there is no proposal to write")
			case grantNo:
			}
			// grantNo, and any answer the enum does not name yet: decline, do not re-ask.
			declined[it.key()] = true
		}
	}

	var last *policy.Policy
loop:
	for r := 1; ; r++ {
		// A tool that attempts a genuinely new path every round (a timestamped or
		// pid-named file) never converges; with [a]ll set it would loop forever mounting
		// more each round. Cap the rounds and stop loudly rather than spin - the user
		// grants any remaining paths by hand.
		if r > maxConvergeRounds {
			fmt.Fprintf(out, "[bento] stopped after %d rounds without converging - the tool may touch a new path each run; review the manifest and grant any remaining paths by hand.\n", maxConvergeRounds)
			stop = convergeMaxRounds
			break
		}
		// Copied from base rather than rebuilt field by field: every round has to run the
		// invocation the proposal will record, and a literal listing the fields it knows
		// about silently drops the next one added to a Policy - which is how a round ran
		// `sh script` while the manifest it produced said `sh -eu script`. Only the grants
		// differ round to round, and they are fresh slices so the accepted paths of one
		// round do not write into base.
		discovery := *base
		discovery.Read = append(append([]string{}, base.Read...), sortedBoolKeys(acceptedR)...)
		discovery.Write = append(append([]string{}, base.Write...), sortedBoolKeys(acceptedW)...)
		proposal, err := round(&discovery)
		if err != nil {
			return nil, convergeQuit, declined, err
		}
		last = proposal
		// exec: all is broader than any single path - it lets the target spawn anything
		// the rest of the policy permits - so it gets its own prompt rather than riding
		// along with the proposal. It is never covered by [a]ll, for the same reason a
		// foreign-home shield is not: it is a decision the reviewer must make explicitly.
		if proposal.Exec == policy.ExecAll && !acceptedExec && !declined[execGrant.key()] {
			fmt.Fprintf(out, "[bento] round %d: the target spawned a subprocess.\n", r)
			c, err := prompt(execGrant.kind, execGrant.path)
			if err != nil {
				return nil, convergeQuit, declined, err
			}
			switch c {
			case grantAll, grantYes:
				accept(execGrant)
			case grantQuit:
				stop = convergeQuit
				break loop
			case grantNo:
				declined[execGrant.key()] = true
			}
		}
		items := newGrants(proposal, acceptedR, acceptedW, declined)
		if len(items) == 0 {
			fmt.Fprintf(out, "[bento] round %d: no new attempted paths - converged.\n", r)
			break
		}
		fmt.Fprintf(out, "[bento] round %d: the target attempted %d new path(s):\n", r, len(items))
		for _, it := range items {
			// [a]ll grants the rest without asking - but never silently for a path that
			// reaches a credential/persistence shield in a home the enforced run will not
			// re-shield (a foreign home, e.g. profiling under sudo). Those are exactly the
			// paths the reviewer must decide on per-path, and a content-branching target
			// chooses which round reveals them, so they always prompt even under [a]ll.
			if acceptAll && !risky(it.path) {
				accept(it)
				continue
			}
			c, err := prompt(it.kind, it.path)
			if err != nil {
				return nil, convergeQuit, declined, err
			}
			switch c {
			case grantAll:
				acceptAll = true
				accept(it)
				continue
			case grantYes:
				accept(it)
				continue
			case grantQuit:
				stop = convergeQuit
				break loop
			case grantNo:
			}
			// grantNo, and any answer the enum does not name yet: decline, do not re-ask.
			declined[it.key()] = true
		}
	}

	final := last
	final.Read = sortedBoolKeys(acceptedR)
	final.Write = sortedBoolKeys(acceptedW)
	final.Exec = policy.ExecNone
	if acceptedExec {
		final.Exec = policy.ExecAll
	}
	return final, stop, declined, nil
}

// convergeStop says why the loop ended. Anything but convergeDone means the user was
// still being asked about paths when it stopped, so the proposal is what had been
// granted so far rather than what the target needs.
type convergeStop int

const (
	convergeDone      convergeStop = iota // a round surfaced nothing new
	convergeQuit                          // the user quit mid-session
	convergeMaxRounds                     // the round cap was hit without converging
)

// foreignShielded reports whether granting path would expose a credential or
// persistence store in a home directory the enforced run will not re-shield - the
// foreign-home case clampShieldedGrants cannot drop (it clamps only the profiler's own
// home). Such a path is never auto-accepted under [a]ll; the reviewer decides it.
func foreignShielded(path string) bool {
	return len(foreignHomeShields([]string{path})) > 0
}

// dropDeclined removes from merged every grant the session asked about and the user
// refused. The refusal has to hold in the artifact and not only in the mount: mergeExisting
// unions in whatever the file at --out already granted, regardless of its approval state,
// so without this a manifest that is unapproved or stale - the ordinary profile-then-run
// inner loop state - reinstates the path the reviewer just declined. Only a path that was
// actually asked about is eligible, so an unrelated grant already in the manifest still
// merges through; nothing was prompted means nothing is dropped.
//
// Keyed by kind as well as path, because the two are decided separately: a declined
// read of a path must not take a write of it with it.
func dropDeclined(merged *policy.Policy, declined map[string]bool) *policy.Policy {
	keep := func(kind string, paths []string) []string {
		out := make([]string, 0, len(paths))
		for _, p := range paths {
			if declined[grantItem{kind, p}.key()] {
				continue
			}
			out = append(out, p)
		}
		return out
	}
	merged.Read = keep("read", merged.Read)
	merged.Write = keep("write", merged.Write)
	return merged
}

// applyExecAnswer holds the session's exec answer against the merge. mergePolicies
// promotes exec: all from EITHER side and dropDeclinedSeeds only reaches a seeded
// manifest, so without this an existing unapproved or stale manifest at --out
// reinstates the grant the reviewer just declined - the hole the prompt exists to
// close. It only ever narrows, and only from exec: all, so a hand-written none-strict
// is left alone rather than being widened to plain none.
func applyExecAnswer(merged, accepted *policy.Policy) *policy.Policy {
	if accepted.Exec != policy.ExecAll && merged.Exec == policy.ExecAll {
		merged.Exec = policy.ExecNone
	}
	return merged
}

// seedItems flattens a seed manifest's reads and writes into the same items the
// convergence loop prompts with, so a seeded path and a discovered one are decided
// through one code path.
func seedItems(seed *policy.Policy) []grantItem {
	out := make([]grantItem, 0, len(seed.Read)+len(seed.Write))
	for _, p := range seed.Read {
		out = append(out, grantItem{"read", p})
	}
	for _, p := range seed.Write {
		out = append(out, grantItem{"write", p})
	}
	return out
}

// grantItem is one access the target attempted but has not been granted yet.
type grantItem struct{ kind, path string } // kind is "read", "write", or "exec"

// execGrant is the whole-policy exec: all grant, which has no path of its own.
var execGrant = grantItem{kind: "exec"}

func (g grantItem) key() string { return g.kind + "\x00" + g.path }

// newGrants returns the reads and writes in proposal that are neither already accepted
// nor already declined - the round's delta, the paths worth asking about.
func newGrants(proposal *policy.Policy, acceptedR, acceptedW, declined map[string]bool) []grantItem {
	var out []grantItem
	for _, p := range proposal.Read {
		it := grantItem{"read", p}
		if !acceptedR[p] && !declined[it.key()] {
			out = append(out, it)
		}
	}
	for _, p := range proposal.Write {
		it := grantItem{"write", p}
		if !acceptedW[p] && !declined[it.key()] {
			out = append(out, it)
		}
	}
	return out
}

// sortedBoolKeys returns the set's keys sorted, so a manifest's grant order is stable.
func sortedBoolKeys(m map[string]bool) []string {
	return slices.Sorted(maps.Keys(m))
}
