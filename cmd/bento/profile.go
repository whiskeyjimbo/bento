package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/whiskeyjimbo/bento/backend"
	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/manifest"
	"github.com/whiskeyjimbo/bento/policy"
	"github.com/whiskeyjimbo/bento/profile"
)

func newProfileCmd() *cobra.Command {
	var (
		interpreter   string
		out           string
		allowNetwork  bool
		acceptAliases []string
	)
	cmd := &cobra.Command{
		Use:   "profile <script> [-- args...]",
		Short: "Run a script under observation and propose a manifest",
		Long: "profile runs the script under the same default-deny sandbox a real run\n" +
			"gets, recording every file it tries to open and every host it reaches, then\n" +
			"writes a proposed manifest of exactly that.\n\n" +
			"Nothing under your home directory is mounted during profiling: the script\n" +
			"runs with your real HOME so it probes the real paths (~/.ssh, ~/.aws), but\n" +
			"those paths are absent in the sandbox, so the attempt is recorded without\n" +
			"the content ever being exposed. The proposal therefore shows what the\n" +
			"script WANTS; you grant it explicitly. The only host content mounted is the\n" +
			"script's own directory, so profiling untrusted code reaches nothing else of\n" +
			"yours. Egress is recorded but not forwarded by default, so the script's\n" +
			"data stays on the host; --allow-network forwards it for a faithful run of\n" +
			"network-dependent code. Review the proposed manifest, then `bento approve`\n" +
			"it.\n\n" +
			"Because nothing sensitive is mounted, a script that reads a credential to\n" +
			"decide what to do next takes its error branch and never exercises the paths\n" +
			"beyond it, so one run can under-report. Grant what the proposal shows and\n" +
			"profile again to converge; grants are merged, not overwritten.\n\n" +
			"On a terminal, an existing manifest at --out that is currently approved for\n" +
			"this same script is resumed: its grants are listed and mounted from the first\n" +
			"round instead of being asked again, so quitting mid-session and re-running\n" +
			"picks up where you left off. An unapproved or stale manifest mounts nothing\n" +
			"and every path is asked again.\n\n" +
			"The manifest is always written, but profile exits 4 when it cannot vouch for\n" +
			"it: the profiled run did not finish, the observer dropped accesses it could\n" +
			"not name, or the granting session ended before it converged. That is what\n" +
			"keeps `profile && approve` from stamping a manifest built on a crashed run.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			script, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			// The sandbox stats the entrypoint too, but not until after the banner below
			// has announced a profiling session - so a typo would read as a session that
			// started and then fell over. Checked here, it reads as what it is.
			if _, err := os.Stat(script); err != nil {
				return fmt.Errorf("entrypoint %q: %w", args[0], err)
			}
			if interpreter == "" {
				interpreter = guessInterpreter(script)
			}
			if out == "" {
				out = args[0] + ".manifest.yaml"
			}

			// Run with the real HOME (and the config-anchor vars derived from it) so a
			// $HOME-relative probe names the real host path, which the observer records
			// even though default-deny leaves that path unmounted. The same names go
			// into the proposed manifest's env allowlist below so the enforced run
			// rebuilds the identical paths; if they diverge the grant would not match.
			// One env for every round keeps a recorded path stable pass to pass.
			env := discoveryEnv()

			cfg := profileConfig{
				ctx: cmd.Context(), script: script, interpreter: interpreter,
				args: args[1:], env: env, allowNetwork: allowNetwork,
				acceptAliases: acceptAliases,
			}
			base := discoveryPolicy(script, interpreter, args[1:])

			var proposed *policy.Policy
			var seed *policy.Policy
			// status says what the profiling rounds could not see, and stop says whether
			// the granting session itself finished. Either way the manifest below is
			// written but not vouched for - see the exit code at the end.
			var status roundStatus
			stop := convergeDone
			interactive := interactiveStdin()
			if interactive {
				// A content-branching target reads a config to decide what to do next; under
				// default-deny that read fails and it never attempts the downstream paths, so
				// one pass under-reports. Loop: mount what the user grants, re-profile so the
				// target proceeds, until nothing new is attempted. The prompt is the consent
				// gate - real content is mounted only for a path the user accepts.
				cfg.targetStdin = nil // the human answers prompts on the tty; the target gets no interactive stdin
				tty := openTTY()
				if c, ok := tty.(io.Closer); ok {
					defer c.Close()
				}
				if allowNetwork {
					if err := confirmNetworkExfil(tty, os.Stderr); err != nil {
						return err
					}
				}
				var seedErr error
				if seed, seedErr = seedGrants(out, script, os.Stderr); seedErr != nil {
					return seedErr
				}
				fmt.Fprintf(os.Stderr, "[bento] profiling %s under default-deny; grant what it needs to converge (real content is mounted only for paths you accept)...\n", args[0])
				round := func(d *policy.Policy) (*policy.Policy, error) {
					p, s, err := profileRound(cfg, d)
					// The proposal comes from the last round, so that round's completion is
					// the one that matters; a dropped access from any round is gone for good.
					status.unfinished = s.unfinished
					status.dropped = status.dropped || s.dropped
					status.blocked = union(status.blocked, s.blocked)
					return p, err
				}
				proposed, stop, err = converge(base, seed, round, newGrantPrompter(tty, os.Stderr), foreignShielded, os.Stderr)
			} else {
				// No terminal to prompt on (a pipe or CI): keep the non-interactive contract -
				// one default-deny pass and write. A content-branching target under-reports;
				// the footer says to profile again with grants to widen it.
				cfg.targetStdin = os.Stdin
				if allowNetwork {
					fmt.Fprintf(os.Stderr, "[bento] profiling %s under default-deny (egress allowed)...\n", args[0])
				} else {
					fmt.Fprintf(os.Stderr, "[bento] profiling %s under default-deny (egress recorded, not forwarded; --allow-network to permit)...\n", args[0])
				}
				proposed, status, err = profileRound(cfg, base)
			}
			if err != nil {
				return err
			}

			// Merge into an existing manifest rather than overwriting it, so a second
			// profile run widens the policy instead of replacing it.
			accepted := proposed
			var trust manifestTrust
			var carried manifest.Provenance
			proposed, carried, trust, err = mergeExisting(out, proposed)
			if err != nil {
				return err
			}
			// A manifest that does not exist yet still has a location to judge, and the first
			// run is the case nothing else looks at - seedGrants returns on a missing file,
			// and only an interactive session calls it at all.
			if trust.realPath == "" {
				if trust, err = inspectNewManifest(out); err != nil {
					return err
				}
			}
			warnUntrusted(os.Stderr, trust.locationFlaws(uint32(os.Geteuid())))
			// The merge re-reads the same file the seed came from, so a seeded grant the
			// user declined this session would come back through the union. Drop it: a
			// refusal at the prompt has to hold in the artifact, not only in the mount.
			proposed = dropDeclinedSeeds(proposed, seed, accepted)
			// Only when a session actually asked: a non-interactive pass prompts for
			// nothing, so it has no answer to hold against the merge.
			if interactive {
				proposed = applyExecAnswer(proposed, accepted)
			}

			doc := manifest.Provenance{
				GeneratedBy:  "bento profile",
				GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
				BlockedHosts: blockedHostsGranted(proposed, union(carried.BlockedHosts, status.blocked)),
			}
			data, err := manifest.Marshal(proposed, doc)
			if err != nil {
				return err
			}
			if err := writeManifestAtomically(trust, data, os.Stderr); err != nil {
				return err
			}

			fmt.Fprintf(os.Stderr, "\n[bento] wrote %s - review it, then run `bento validate %s` and `bento approve %s`.\n", out, out, out)
			fmt.Fprintf(os.Stderr, "[bento] it reflects only this run; profile again with other inputs to widen it.\n")

			// The manifest is written either way - it is where the next pass starts from -
			// but a proposal built on a partial observation, or on a session the user left
			// before it converged, is not what the target needs. Exiting 0 would let
			// `profile && approve` stamp it as though it were.
			if reason := incompleteReason(status, stop); reason != "" {
				fmt.Fprintf(os.Stderr, "[bento] the proposal is incomplete (%s), so this exits %d rather than 0 - review and widen it before approving.\n", reason, profileIncomplete)
				return &exitError{code: profileIncomplete}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&interpreter, "interpreter", "", "interpreter to run the script with (guessed from the extension if omitted)")
	cmd.Flags().StringVar(&out, "out", "", "manifest path to write (default: <script>.manifest.yaml)")
	cmd.Flags().StringArrayVar(&acceptAliases, "accept-alias", nil, "acknowledge the credential aliases under a host tree (a snapshot or deduplicated backup) instead of refusing; repeatable; same meaning as on `bento run`")
	cmd.Flags().BoolVar(&allowNetwork, "allow-network", false, "let the script's network traffic reach the host during profiling (default: record destinations but do not forward them)")
	return cmd
}

// incompleteReason names why a profiling session cannot vouch for the manifest it
// wrote, or "" when it can. The specific warnings are already on stderr; this is the
// one line that ties them to the exit code.
func incompleteReason(status roundStatus, stop convergeStop) string {
	switch {
	case status.unfinished:
		return "the profiled run did not finish"
	case status.dropped:
		return "the observer could not name every access the target made"
	case stop == convergeQuit:
		return "you quit before it converged"
	case stop == convergeMaxRounds:
		return "it hit the round cap without converging"
	default:
		return ""
	}
}

// profileConfig carries the inputs a profiling round needs that do not change between
// rounds, so the convergence loop can re-run rounds without re-threading them.
type profileConfig struct {
	ctx           context.Context
	script        string
	interpreter   string
	args          []string
	env           map[string]string
	allowNetwork  bool
	acceptAliases []string  // host trees whose credential aliases the user has acknowledged; profiling scans for them exactly as an enforced run does
	targetStdin   io.Reader // the profiled target's stdin: os.Stdin for a single pass, nil in the interactive loop where the human answers prompts instead
}

// profileRound runs one profiling pass under discovery and returns the clamped
// proposal of what the target attempted (reads, writes, exec, network), printing the
// round's shield and broad-grant warnings. It is the unit the convergence loop repeats
// with a widening grant set; discovery carries the grants accepted so far, mounted with
// real content so the target proceeds past accesses it already has.
// It also reports what the round could not see, so the command can exit nonzero over a
// proposal it cannot vouch for.
func profileRound(cfg profileConfig, discovery *policy.Policy) (*policy.Policy, roundStatus, error) {
	obs, err := backend.Profile(cfg.ctx, discovery,
		enforce.Process{Stdin: cfg.targetStdin, Stdout: os.Stderr, Stderr: os.Stderr, Env: cfg.env},
		backend.ProfileOptions{AllowNetwork: cfg.allowNetwork, AcceptAliasesUnder: cfg.acceptAliases})
	if err != nil {
		return nil, roundStatus{}, err
	}
	// Synthesize refuses the observation nothing can be proposed from (a seccomp kill).
	// It runs before the warnings below so that refusal is not preceded by advice that
	// contradicts it: a SIGSYS kill also sets Signaled and Dropped, and telling the user
	// twice to profile again, then that profiling again is pointless, is worse than the
	// refusal alone.
	proposed, err := profile.Synthesize(cfg.script, cfg.interpreter, obs)
	if err != nil {
		return nil, roundStatus{}, err
	}
	// A run that was signaled or exited nonzero may have stopped before exercising all
	// its code paths, so the observations - and the manifest synthesized from them - can
	// be silently over-tight. Warn before proposing it.
	for _, w := range profileWarnings(obs) {
		fmt.Fprintln(os.Stderr, w)
	}
	// Allowlist the discovery env so the enforced run rebuilds $HOME-relative paths to
	// the same names profiling recorded and granted.
	proposed.Env = sortedKeys(cfg.env)
	printFlooredWrites(obs.Writes)
	printScratchWrites(obs.Writes)
	printSocketAccesses(obs)
	printUnrepresentable(obs)
	printProposalWarnings(proposed)
	printTmpGrants(os.Stderr, proposed)
	return proposed, roundStatus{
		unfinished: partialRunWarning(obs) != "",
		dropped:    obs.Dropped > 0,
		blocked:    blockedHostKeys(obs.Blocked),
	}, nil
}

// blockedHostsGranted narrows the recorded guard refusals to the ones the written
// manifest grants egress to. The record exists so approve can name a rule the reader is
// about to stamp; a refusal no rule reaches has nothing to warn about, and keeping it
// would leave the manifest carrying destinations the target chose that nothing else in
// the file mentions.
//
// It keeps the DESTINATION the guard refused rather than the rule that covers it. The
// rule can be a wildcard, and rewriting `metadata.internal:80` to the `.internal:80`
// that admitted it would throw away the only fact the profiling run established, leaving
// a record that no longer says which host was refused.
func blockedHostsGranted(p *policy.Policy, blocked []string) []string {
	var out []string
	for _, key := range blocked {
		if grantsBlockedHost(p.Network, key) {
			out = append(out, key)
		}
	}
	slices.Sort(out)
	return out
}

// grantsBlockedHost reports whether any of rules permits egress to a recorded refusal.
//
// It asks policy.Allows rather than comparing the key against a rule's own text, because
// a rule need not be spelled as the destination it admits: `.internal` covers
// metadata.internal, `*` covers everything, and a host differing only in case or a
// trailing DNS root label is the same name. Comparing text lost the callout for exactly
// the rules most worth calling out - the broad ones - and, worse, made the next
// re-profile drop the record for good.
//
// A key that cannot be split is not silently treated as unmatched: it came from
// net.JoinHostPort over a validated rule, so a failure here means the manifest's record
// was hand-edited into a shape nothing can judge. It is reported as covered, so the
// reader is told to look rather than told nothing.
func grantsBlockedHost(rules []policy.NetworkRule, key string) bool {
	host, port, err := net.SplitHostPort(key)
	if err != nil {
		return true
	}
	return policy.Allows(rules, host, port)
}

// grantsAnyBlockedHost reports whether one rule covers any recorded refusal, which is
// the question approve asks per rule it is about to stamp.
func grantsAnyBlockedHost(r policy.NetworkRule, blocked []string) bool {
	for _, key := range blocked {
		if grantsBlockedHost([]policy.NetworkRule{r}, key) {
			return true
		}
	}
	return false
}

// rulesCoveringBlockedHost returns the policy's network rules that cover a recorded
// refusal, for the readers that report them as a group rather than deciding rule by
// rule (validate's summary, run's pre-flight note). unreadable holds the recorded keys
// nothing can be asked about, which those readers report on their own line.
//
// The split is the difference between those readers and approve's. grantsBlockedHost
// answers an unsplittable key with "covered", so approve's per-rule "worth a second
// look" degrades into telling the reader to look - the safe direction for a prompt. The
// grouped note is a statement of fact instead ("the profiling run reached a destination
// this rule covers"), and inheriting that answer would print it against every rule in
// the manifest, including the ones that work. So the unjudgeable key is named as what it
// is - a provenance record nothing can read - rather than turned into a false claim
// about rules it says nothing about.
func rulesCoveringBlockedHost(p *policy.Policy, blocked []string) (covering []policy.NetworkRule, unreadable []string) {
	var judgeable []string
	for _, key := range blocked {
		if _, _, err := net.SplitHostPort(key); err != nil {
			unreadable = append(unreadable, key)
			continue
		}
		judgeable = append(judgeable, key)
	}
	for _, r := range p.Network {
		if grantsAnyBlockedHost(r, judgeable) {
			covering = append(covering, r)
		}
	}
	return covering, unreadable
}

// blockedHostKeys renders the destinations the round's egress guard refused as the
// "host:port" keys the provenance block carries, dropping any the manifest grammar
// could not hold - the same screen Synthesize applies to the proposed network rules,
// so what is recorded here stays a subset of what the manifest can name.
//
// net.JoinHostPort, not a bare concatenation: an IPv6 destination is recorded with its
// own colons in it, and the reader that splits the key back apart to match it against
// the rules has to find the same separator this wrote.
func blockedHostKeys(blocked []profile.HostPort) []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range blocked {
		key := net.JoinHostPort(h.Host, h.Port)
		if seen[key] || (policy.NetworkRule{Host: h.Host, Port: h.Port}).Validate() != nil {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	slices.Sort(out)
	return out
}

// roundStatus says what a profiling round could not see. They accumulate differently
// across a convergence loop: unfinished is per-round and a later round supersedes it,
// because the early rounds of a loop routinely exit nonzero - a target failing on the
// config it has not been granted yet is the premise of the loop, not a defect. dropped
// is cumulative: an access the observer could not name in round 1 is simply absent from
// the proposal, and no later round puts it back. blocked is cumulative for the same
// reason - a host the guard refused in one round is a fact about the drafting, and a
// later round that never reached for it again does not undo it.
type roundStatus struct {
	unfinished, dropped bool
	blocked             []string
}

// The tmpfs every run mounts, and so the prefix that makes a grant target-steerable.
// profile.SandboxScratch is the authority on what is scratch under it; this is only the
// prefix test, which that package does not export.
const sandboxTmp = "/tmp"

// tmpGrants returns the proposed read and write grants that name a path under /tmp,
// which are the grants a profiled target can steer.
//
// Everything under /tmp reaches the proposal through an existence test: inside the box
// /tmp is an empty tmpfs, so every probe there fails identically, and only the names that
// exist on the HOST survive as grants (SandboxScratch). That test is what makes a real
// workspace under /tmp - a `mktemp -d`, a CI checkout - distinguishable from scratch, so
// it cannot be dropped; but it means a target that opens a list of guessed names reads
// the answer back out of the manifest it is handed, and chooses part of what the reviewer
// is asked to approve.
//
// Which is why they are named as a group rather than filtered out. Nothing here is a
// grant without a human stamping it, and a reviewer told these entries are target-chosen
// can weigh them as such; one who is not told reads them as the same discovered fact as
// every other line.
//
// Grants inside the entrypoint's own directory are excluded. Running from a `mktemp -d`
// workspace or a CI checkout under /tmp is ordinary, and there the script's own tree is
// where the user put it rather than anything the script guessed - flagging it would put
// the note on most temp-dir runs and teach the reader to skip it. A guessed name is a
// sibling of that tree, not inside it. The exclusion needs the entrypoint to be in a
// directory under /tmp rather than in /tmp itself, where it would cover everything.
//
// Lexical, but on the CLEANED spelling rather than the manifest's own text. profile
// writes these absolute and already cleaned, so on its own output the two agree; a
// hand-edited manifest is where they part, and that is the reader this serves. Both
// `//tmp/guessed` and a `/tmp/work/../guessed` written to hide inside the entrypoint's
// directory name a path the kernel binds under /tmp, and an uncleaned prefix test drops
// each from the note while the grant stands.
//
// A nil policy has no grants to disclose - approve passes one when this host could not
// resolve the manifest, and says so on its own line.
func tmpGrants(p *policy.Policy) []string {
	if p == nil {
		return nil
	}
	home := filepath.Dir(filepath.Clean(p.Entrypoint))
	if !strings.HasPrefix(home, sandboxTmp+"/") {
		home = ""
	}
	var out []string
	for _, g := range slices.Concat(p.Read, p.Write) {
		g = filepath.Clean(g)
		if g != sandboxTmp && !strings.HasPrefix(g, sandboxTmp+"/") {
			continue
		}
		if home != "" && (g == home || strings.HasPrefix(g, home+"/")) {
			continue
		}
		out = append(out, g)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// printTmpGrants tells the reviewer which of the proposal's grants the target could have
// steered. See tmpGrants for why they are disclosed rather than withheld.
func printTmpGrants(w io.Writer, p *policy.Policy) {
	grants := tmpGrants(p)
	if len(grants) == 0 {
		return
	}
	fmt.Fprintf(w, "[bento] %d proposed grant(s) name a path under /tmp: %s.\n", len(grants), strings.Join(grants, ", "))
	fmt.Fprintf(w, "[bento] Those reach the proposal because the name exists on this host, which is the only way\n")
	fmt.Fprintf(w, "[bento] a real workspace there can be told from the sandbox's own scratch - so a script that\n")
	fmt.Fprintf(w, "[bento] opens guessed names under /tmp can put them here. Treat them as the script's request\n")
	fmt.Fprintf(w, "[bento] rather than as something profiling discovered, and keep only the ones it needs.\n")
}

// printFlooredWrites names the observed writes Synthesize withheld as system trees or
// another user's home. Those are dropped inside Synthesize, before the proposal the
// clamps below report on, so without this they are the one withheld class that leaves
// no trace: the script fails EACCES at enforce time and the reviewer has nothing to
// read. It reports the collapsed directory, which is the granularity the grant would
// have had.
func printFlooredWrites(writes []string) {
	var seen map[string]bool
	for _, w := range writes {
		if !filepath.IsAbs(w) {
			continue
		}
		dir := filepath.Dir(w)
		if !profile.FlooredWrite(dir) || seen[dir] {
			continue
		}
		if seen == nil {
			seen = map[string]bool{}
		}
		seen[dir] = true
		fmt.Fprintf(os.Stderr, "[bento] not proposing write access to %q - it is a system tree or another user's home, where a writable grant is a privilege-escalation vector rather than a script's own storage. The attempt was recorded; if the script genuinely needs it, add the write: grant by hand.\n", dir)
	}
}

// printScratchWrites names the observed writes to a /tmp path that is not on the host,
// which Synthesize withholds. There is nothing to grant - inside the box that name is in
// the private tmpfs every run mounts, so the write succeeds under the manifest as it did
// here - but it does not reach the host, and a script whose real output goes there
// finishes with an exit status of 0 and nothing to show for it.
//
// The message says the name is absent from the host rather than claiming to know where
// the write landed. It cannot know: a directory the script itself created and then
// removed on the way out (the `mktemp -d` plus cleanup trap idiom) was a real host
// directory during the run and is indistinguishable from tmpfs scratch by the time this
// runs. Both want the same thing said - there is no host path left to grant - and only
// one of them wants to hear about the tmpfs.
func printScratchWrites(writes []string) {
	seen := map[string]bool{}
	for _, w := range writes {
		if !filepath.IsAbs(w) {
			continue
		}
		dir := filepath.Dir(w)
		if !profile.SandboxScratch(dir) || seen[dir] {
			continue
		}
		seen[dir] = true
		fmt.Fprintf(os.Stderr, "[bento] not proposing write access to %q - no such directory exists on the host, so inside the box that name is in the private /tmp every run mounts and there is nothing to grant. Nothing written there survives the run; if that output is meant to persist, have the script write it somewhere the manifest grants.\n", dir)
	}
}

// printSocketAccesses names the observed accesses to a unix socket, which Synthesize
// withholds whether the target read one or wrote one. Like the floored writes above they
// are dropped before the proposal the clamps report on, so without this the reviewer has
// no trace: the script fails at enforce time and there is nothing to read.
//
// The observed name is reported rather than the resolved one, because that is the name
// the reviewer would go looking for. Writes are named at the file, not at the directory
// they would have collapsed to, since the collapse is what Synthesize declined to do.
func printSocketAccesses(obs profile.Observation) {
	seen := map[string]bool{}
	for _, p := range append(append([]string{}, obs.Reads...), obs.Writes...) {
		if !filepath.IsAbs(p) || seen[p] || !profile.Socket(p) {
			continue
		}
		seen[p] = true
		fmt.Fprintf(os.Stderr, "[bento] not proposing access to %q - it is a unix socket, which is a two-way channel to whatever process is listening rather than storage of the script's own, so a grant of it confers whatever that process will do (an X11 socket is control of your session; an ssh-agent socket is use of your keys). The access was recorded; if the script genuinely needs that socket, add the grant by hand.\n", p)
	}
}

// printUnrepresentable names the observations Synthesize withheld because a manifest
// cannot hold them: a path carrying a character the policy grammar refuses in a path
// field, or a CONNECT host that is not a hostname, a canonical address, or a wildcard.
// Both are values the TARGET chose - a filename it created, a host it dialed - so a
// hostile or merely sloppy one can produce them, and proposing one would fail the
// marshal that ends the run. Like the floored writes above, they are dropped inside
// Synthesize, so without this the reviewer has no trace of the access at all.
func printUnrepresentable(obs profile.Observation) {
	// A write collapses to its parent before Synthesize screens it, so the write side is
	// judged and reported at that same granularity: a bad filename in a clean directory
	// still yields the directory grant, and warning about the file would name a grant
	// that was in fact proposed.
	names := append([]string{}, obs.Reads...)
	for _, w := range obs.Writes {
		names = append(names, filepath.Dir(w))
	}
	seen := map[string]bool{}
	for _, p := range names {
		if !profile.Unrepresentable(p) || seen[p] {
			continue
		}
		seen[p] = true
		fmt.Fprintf(os.Stderr, "[bento] not proposing access to %q - the name carries a character a manifest path cannot hold (a control, bidi, invisible, or line-separating one, or a byte that is not valid UTF-8), which is how a path is made to read as something other than what it grants. The access was recorded; if the script genuinely needs that file, rename it.\n", p)
	}
	seenHosts := map[string]bool{}
	for _, h := range obs.Hosts {
		rule := policy.NetworkRule{Host: h.Host, Port: h.Port}
		key := h.Host + ":" + h.Port
		err := rule.Validate()
		if err == nil || seenHosts[key] {
			continue
		}
		seenHosts[key] = true
		// Quoted, not %s: the host is target-chosen, and this is the one place such a
		// value is echoed to the operator's terminal. readConnect holds a CONNECT target
		// to the same screen, so nothing deceiving should reach here - but a rendering
		// that depends on a screen upstream is one refactor away from being wrong, and
		// quoting also delimits a host that is empty or carries spaces.
		fmt.Fprintf(os.Stderr, "[bento] not proposing network access to %q port %q - %v. The connection was recorded; if the script needs it, add a network: rule naming the host in that form by hand.\n", h.Host, h.Port, err)
	}
}

// printProposalWarnings clamps p in place (dropping shielded credential paths and
// over-broad grants from the auto-proposal) and prints why each was withheld, so a
// path the tool wants but bento will not auto-grant is never silently missing.
func printProposalWarnings(p *policy.Policy) {
	shielded, writeShielded, broadReads, broadWrites := clampProposal(p)
	for _, d := range shielded {
		fmt.Fprintf(os.Stderr, "[bento] not proposing access to %q - it is a shielded credential path, not granted automatically. The script's attempt was recorded; if it genuinely needs it, add a read:/write: grant for that path by hand - the run then exposes it and warns you each time.\n", d)
	}
	for _, d := range writeShielded {
		fmt.Fprintf(os.Stderr, "[bento] not proposing write access to %q - it is always write-shielded, because a file planted there is run by the host later. Unlike a credential path there is no hand-added opt-in: a write: grant for it is refused, not warned. The path stays readable; if the script must install there, run it outside bento.\n", d)
	}
	for _, d := range broadReads {
		fmt.Fprintf(os.Stderr, "[bento] not proposing read access to %q - too broad to grant automatically (it would re-expose every credential the deny-list does not enumerate); the specific paths under it the script actually read are proposed on their own, so add a narrower read: directory by hand only if it needs more.\n", d)
	}
	for _, d := range broadWrites {
		fmt.Fprintf(os.Stderr, "[bento] not proposing write access to %q - too broad to grant automatically; add a narrower write: directory by hand if the script needs it.\n", d)
	}
	for _, d := range foreignHomeShields(append(append([]string{}, p.Read...), p.Write...)) {
		fmt.Fprintf(os.Stderr, "[bento] proposing %q - it reaches shielded credential or persistence paths in a home directory profiling did not shield; the enforced run only shields the home it executes as, so these would be exposed. Confirm the script needs it before approving.\n", d)
	}
}

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
// returns the final proposal with reads/writes narrowed to exactly the accepted set.
func converge(base, seed *policy.Policy, round func(*policy.Policy) (*policy.Policy, error), prompt func(kind, path string) (grantChoice, error), risky func(path string) bool, out io.Writer) (*policy.Policy, convergeStop, error) {
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
				return nil, convergeQuit, err
			}
			switch c {
			// [a]ll here accepts only this seeded path. In the loop below it answers for
			// a list the user has just been shown; at seed time no round has run, so
			// carrying it forward would grant every path the whole session goes on to
			// discover, unseen - a wider consent than the prompt asked for.
			case grantAll, grantYes:
				accept(it)
			case grantQuit:
				return nil, convergeQuit, fmt.Errorf("aborted: quit before the first profiling round, so there is no proposal to write")
			default:
				declined[it.key()] = true
			}
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
		discovery := &policy.Policy{
			Entrypoint:  base.Entrypoint,
			Interpreter: base.Interpreter,
			Args:        base.Args,
			Network:     base.Network,
			Exec:        base.Exec,
			Read:        append(append([]string{}, base.Read...), sortedBoolKeys(acceptedR)...),
			Write:       append(append([]string{}, base.Write...), sortedBoolKeys(acceptedW)...),
		}
		proposal, err := round(discovery)
		if err != nil {
			return nil, convergeQuit, err
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
				return nil, convergeQuit, err
			}
			switch c {
			case grantAll, grantYes:
				accept(execGrant)
			case grantQuit:
				stop = convergeQuit
				break loop
			default:
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
				return nil, convergeQuit, err
			}
			switch c {
			case grantAll:
				acceptAll = true
				accept(it)
			case grantYes:
				accept(it)
			case grantQuit:
				stop = convergeQuit
				break loop
			default: // grantNo and any unrecognized answer: decline, do not re-ask
				declined[it.key()] = true
			}
		}
	}

	final := last
	final.Read = sortedBoolKeys(acceptedR)
	final.Write = sortedBoolKeys(acceptedW)
	final.Exec = policy.ExecNone
	if acceptedExec {
		final.Exec = policy.ExecAll
	}
	return final, stop, nil
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

// dropDeclinedSeeds removes from merged any seed grant missing from accepted - the
// convergence loop's final set, which holds exactly what the user said yes to. Only a
// path the seed itself carried is eligible, so an unrelated grant already in the
// manifest still merges through. A nil seed means nothing was prompted, so nothing is
// dropped.
func dropDeclinedSeeds(merged, seed, accepted *policy.Policy) *policy.Policy {
	if seed == nil {
		return merged
	}
	keep := func(all, seeded, ok []string) []string {
		out := make([]string, 0, len(all))
		for _, p := range all {
			if slices.Contains(seeded, p) && !slices.Contains(ok, p) {
				continue
			}
			out = append(out, p)
		}
		return out
	}
	merged.Read = keep(merged.Read, seed.Read, accepted.Read)
	merged.Write = keep(merged.Write, seed.Write, accepted.Write)
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

type grantChoice int

const (
	grantNo   grantChoice = iota // n / blank / unrecognized: decline, do not mount
	grantYes                     // y: mount this path next round
	grantAll                     // a: accept this and every remaining path this session
	grantQuit                    // q / EOF: stop the loop, keep what was accepted so far
)

// newGrantPrompter reads one single-line answer per call from in, mapping it to a
// grant choice. EOF returns grantQuit so a closed input ends the loop rather than
// erroring or looping forever.
func newGrantPrompter(in io.Reader, out io.Writer) func(kind, path string) (grantChoice, error) {
	r := bufio.NewReader(in)
	return func(kind, path string) (grantChoice, error) {
		// exec carries no path, so it is named by what it permits rather than left with
		// a dangling argument.
		what := kind + " " + path
		if path == "" {
			what = kind + " (let the target spawn subprocesses)"
		}
		fmt.Fprintf(out, "[bento]   grant %s? [y]es / [n]o / [a]ll / [q]uit > ", what)
		line, err := r.ReadString('\n')
		if err != nil && line == "" {
			return grantQuit, nil
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
			return grantYes, nil
		case "a", "all":
			return grantAll, nil
		case "q", "quit":
			return grantQuit, nil
		default:
			return grantNo, nil
		}
	}
}

// confirmNetworkExfil warns that --allow-network forwards egress while real granted
// content is mounted - a compromised target could exfiltrate the credentials being
// granted - and refuses the run unless the user confirms.
func confirmNetworkExfil(in io.Reader, out io.Writer) error {
	fmt.Fprintln(out, "[bento] WARNING: --allow-network forwards the target's egress WHILE the content you grant is")
	fmt.Fprintln(out, "[bento] mounted with real data. A compromised target could exfiltrate those credentials.")
	fmt.Fprint(out, "[bento] Continue with network forwarding? [y/N] > ")
	line, _ := bufio.NewReader(in).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return nil
	default:
		return fmt.Errorf("aborted: re-run without --allow-network to profile with egress recorded but not forwarded")
	}
}

// interactiveStdin reports whether stdin is a terminal, so profiling drives the
// interactive convergence loop only when there is a human to answer its prompts; a
// pipe or CI run falls back to a single non-interactive pass.
func interactiveStdin() bool {
	return isTerminal(os.Stdin)
}

// openTTY returns the controlling terminal for reading the convergence prompts, kept
// separate from the target's own stdin. It falls back to os.Stdin where /dev/tty is
// unavailable.
func openTTY() io.Reader {
	if f, err := os.OpenFile("/dev/tty", os.O_RDONLY, 0); err == nil {
		return f
	}
	return os.Stdin
}

// sortedBoolKeys returns the set's keys sorted, so a manifest's grant order is stable.
func sortedBoolKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// discoveryPolicy is the policy a profiling run executes under. It is default-deny,
// the same as a real run: nothing under $HOME is mounted, so the target probes its
// real credential paths and the observer records them without the content ever being
// exposed - the recorded attempts are the consent surface. Only the script's own
// directory is granted (read for sibling config, write for scratch output the sandbox
// does not already provide via its private /tmp); every other access is recorded as
// intent, not honored. Exec and network are left open so the run exercises its real
// code paths; egress is recorded, and forwarded only under --allow-network.
func discoveryPolicy(script, interpreter string, args []string) *policy.Policy {
	p := &policy.Policy{
		Entrypoint:  script,
		Interpreter: interpreter,
		Args:        args,
		Network:     []policy.NetworkRule{{Host: "*", Port: "*"}},
		Exec:        policy.ExecAll,
	}
	// Grant the script's own directory unless it is broad (the home directory or a
	// top-level dir): binding a broad directory during discovery would re-expose the
	// credentials that live beside the script, defeating the default-deny the run
	// relies on. A broad-dir script still runs - the entrypoint is bound regardless -
	// with its sibling reads recorded as intent, not honored.
	if dir := filepath.Dir(script); !isBroadDir(dir) {
		p.Read = []string{dir}
		p.Write = []string{dir}
	}
	return p
}

// discoveryEnvNames are the variables that anchor $HOME-relative paths. Profiling
// passes their host values to the target so it names real paths, and records the
// names in the proposed manifest so the enforced run resolves the same paths. Omitted
// deliberately: PWD (the run is chdir'd to the script's directory, so a host PWD would
// mislead) and XDG_RUNTIME_DIR (denylist.Runtime shields wherever it points, so a path
// discovered under it is one no grant can honor).
var discoveryEnvNames = []string{
	"HOME", "USER", "LOGNAME",
	"XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME",
}

// discoveryEnv reads the discovery variables that are actually set on the host. An
// unset variable is left out rather than passed empty, so the manifest's env allowlist
// names only variables the run will really see.
func discoveryEnv() map[string]string {
	env := make(map[string]string)
	for _, name := range discoveryEnvNames {
		if v, ok := os.LookupEnv(name); ok && v != "" {
			env[name] = v
		}
	}
	return env
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// profileWarnings returns every reason this observation may be short of what the run
// really needs, in the order a reader should see them: whether the run finished, then
// whether the observer could name everything it saw. They are independent - a clean
// exit says nothing about dropped accesses - so both are reported, not just the first.
func profileWarnings(obs profile.Observation) []string {
	var out []string
	if w := partialRunWarning(obs); w != "" {
		out = append(out, w)
	}
	if obs.Dropped > 0 {
		out = append(out, fmt.Sprintf("[bento] WARNING: the observer could not name %d file access(es) this run made - the proposed manifest is missing them. Profile again, and if it repeats, add the paths by hand.", obs.Dropped))
	}
	return out
}

// partialRunWarning returns a warning when the profiled run may not have finished -
// killed by a signal (crash, OOM, timeout) or exited nonzero - so its observations,
// and the manifest synthesized from them, can be silently over-tight. It returns ""
// for a clean run. Signaled takes priority since it implies a nonzero exit.
func partialRunWarning(obs profile.Observation) string {
	switch {
	case obs.Signaled:
		return fmt.Sprintf("[bento] WARNING: the profiled run was killed by signal %d - it may not have finished, so the proposed manifest may be missing accesses. Fix the run and profile again to widen it.", obs.Signal)
	case obs.ExitCode != 0:
		return fmt.Sprintf("[bento] WARNING: the profiled run exited with code %d - it may not have finished, so the proposed manifest may be missing accesses. Fix the run and profile again to widen it.", obs.ExitCode)
	default:
		return ""
	}
}

// clampShieldedGrants drops read and write grants that fall at or inside a mandatory
// DenyAll home shield (~/.ssh, ~/.aws, ~/.gnupg, ...). These are credential stores, so
// the profiler never proposes them automatically - the observer records the attempt (the
// consent surface) even though default-deny never mounted the path, and the user opts in
// by hand if the program genuinely needs it. A grant that names the shield exactly is
// honorable at run time (an explicit, warned opt-in); a grant strictly inside one is
// refused there. Either way it is dropped from the auto-proposal, so this is a proposal-
// quality filter, not a security check. A grant that merely CONTAINS a shield (read: ~
// with ~/.ssh shielded inside it) is legitimate and kept - only a grant at or under a
// shield goes.
func clampShieldedGrants(reads, writes []string) (keptReads, keptWrites, dropped, writeShielded []string) {
	// The same anchors the enforcer shields on, so the proposal is clamped against the
	// shields the run will actually apply - a filter keyed on $HOME alone would skip a
	// store the run then hides, and draft a manifest that dies at the shield refusal.
	// The error means no anchor at all - not merely an unusable $HOME, which drops to the
	// passwd home - so there are no shields to clamp against and the run this proposal
	// feeds would be refused anyway.
	anchors, err := denylist.HomeAnchors()
	if err != nil {
		return reads, writes, nil, nil
	}
	// Each anchor is shielded in both its configured and its symlink-resolved form. A
	// symlinked home (Fedora Silverblue's /home -> /var/home) means an observed
	// credential path can arrive resolved (/var/home/u/.ssh, anchored at a resolved cwd)
	// while $HOME is the unresolved /home/u, or the reverse; shielding against both
	// forms drops the grant either way. It only ever adds matches, so a grant is never
	// wrongly kept. A home that does not resolve (nonexistent) falls back to raw.
	homes := slices.Clone(anchors)
	for _, h := range anchors {
		if resolved, err := filepath.EvalSymlinks(h); err == nil && !slices.Contains(homes, resolved) {
			homes = append(homes, resolved)
		}
	}
	seenShield := map[string]bool{}
	var shields []string
	addShields := func(rules []denylist.Rule) {
		for _, r := range rules {
			if r.Deny == denylist.DenyAll && !seenShield[r.Path] {
				seenShield[r.Path] = true
				shields = append(shields, r.Path)
			}
		}
	}
	for _, h := range homes {
		addShields(denylist.Home(h, homes...))
	}
	// The runtime shields land at /run on an ordinary host, where the proposal never
	// reaches them (isSystemPath drops /run outright). They are here for the host that
	// parks XDG_RUNTIME_DIR under /tmp, which the proposal DOES reach: that directory
	// holds the gpg-agent, dbus, and wayland sockets and the podman auth.json, and a
	// grant naming one is refused at run time - so proposing it drafts a manifest that
	// cannot be approved into a working run.
	addShields(denylist.Runtime(denylist.RuntimeDir(), homes...))
	inShield := func(g string) bool {
		for _, s := range shields {
			if g == s || policy.CoversResolved(s, g) {
				return true
			}
		}
		return false
	}
	filter := func(grants []string) (kept []string) {
		for _, g := range grants {
			if inShield(g) {
				dropped = append(dropped, g)
			} else {
				kept = append(kept, g)
			}
		}
		return kept
	}
	keptReads = filter(reads)
	keptWrites, writeShielded = clampWriteShieldedGrants(homes, filter(writes))
	return keptReads, keptWrites, dropped, writeShielded
}

// clampWriteShieldedGrants drops write grants at or inside a DenyWrite home shield
// (~/.local/bin, ~/.cargo/bin, ~/.rustup, ~/.bashrc, ...). checkWriteNotUnderReadOnlyShield
// hard-refuses these at run time and there is no opt-in, so proposing one would hand the
// reviewer a manifest that cannot be approved into a working run. Reads are untouched:
// a DenyWrite shield leaves its content readable, so a read grant there is honored.
//
// Unlike clampShieldedGrants this is not merely a proposal-quality filter - it is what
// keeps the profiler's output and the enforcer's refusal from disagreeing.
func clampWriteShieldedGrants(homes, writes []string) (kept, dropped []string) {
	seen := map[string]bool{}
	var shields []string
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			shields = append(shields, p)
		}
	}
	for _, h := range homes {
		for _, r := range denylist.Home(h, homes...) {
			if r.Deny != denylist.DenyWrite {
				continue
			}
			add(r.Path)
			// The enforcer compares against the shield's RESOLVED path, and the observer
			// records resolved paths, so a symlinked shield (~/.local/bin or ~/.bashrc
			// pointing into a dotfiles repo or the nix store, which home-manager and stow
			// both produce) is observed at its target. Matching only the literal path
			// would keep that write in the proposal and let compile refuse it - the
			// disagreement this clamp exists to prevent. Resolving here closes it; a path
			// that does not resolve is simply not added.
			if resolved, err := filepath.EvalSymlinks(r.Path); err == nil {
				add(resolved)
			}
		}
	}
	for _, g := range writes {
		shielded := false
		for _, s := range shields {
			if g == s || policy.CoversResolved(s, g) {
				shielded = true
				break
			}
		}
		if shielded {
			dropped = append(dropped, g)
		} else {
			kept = append(kept, g)
		}
	}
	return kept, dropped
}

// foreignHomeShields returns the proposed grants that reach a shielded path under a home
// directory other than the profiler's own. clampShieldedGrants drops grants inside the
// PROFILER's home shields, but a script that reaches a protected path under a different
// home - profiled under sudo (HOME=/root) touching /home/u/.ssh, or with HOME unset so
// the clamp is skipped - is not clamped and lands in the proposal. It is reported, not
// dropped: a home-shaped heuristic strong enough to drop on would also gut legitimate
// cross-home data grants (/home/u/project/data), so the reviewer decides.
//
// The match against denylist.Home(root, homes...) tests containment in EITHER direction: a grant
// at or under a shield (write: ~/.ssh/id_rsa), and - the case that matters most - a grant
// that ENCLOSES a shield (write: ~, which Synthesize produces by collapsing a file write
// to its directory, sweeping in ~/.ssh). For the profiler's own home clampShieldedGrants
// can safely keep an enclosing grant because the enforced run re-shields the interior;
// for a foreign home it cannot, since the run shields only the home it executes as, so
// both directions must warn. Both shield classes count - a foreign DenyWrite persistence
// path (~/.config/systemd/user) is unshielded at run time just like a DenyAll credential.
// A data path enclosing no shield still stays quiet.
//
// The run's own anchors are passed to Home even though the root is foreign. They do not
// place shields - the root does that - they only tell Home which env-relocated stores are
// already covered by an anchor's own pass, which is the same question the enforcer asks.
// Keyed on the foreign root alone, a KUBECONFIG under the profiler's ~/.kube produces an
// interior file rule here that the enforced run does not carry, and the warning names a
// shield the run has no such rule for.
//
// Raw anchors, unlike the symlink-augmented set the clamps above match grants against:
// this argument decides which rules exist, and the enforcer builds its own from raw
// HomeAnchors (see the Linux backend's homeShields). Adding a resolved anchor here would
// let Home's swallow guard drop an env relocation the run does emit - a relocation to an
// ancestor of the resolved home is shieldable for the enforcer and not for this pass -
// and the warning would go quiet on a shield the run really carries.
func foreignHomeShields(grants []string) []string {
	// Every anchor the run shields on counts as "own", not just $HOME: under sudo -H the
	// two disagree, and treating the passwd home as foreign would warn about a store the
	// run shields anyway - noise the reviewer learns to skip past.
	anchors, _ := denylist.HomeAnchors()
	selves := map[string]bool{}
	for _, self := range anchors {
		selves[self] = true
		if resolved, err := filepath.EvalSymlinks(self); err == nil {
			selves[resolved] = true
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, g := range grants {
		root, ok := homeRoot(g)
		if !ok || selves[root] || seen[g] {
			continue
		}
		for _, r := range denylist.Home(root, anchors...) {
			if g == r.Path || policy.CoversResolved(r.Path, g) || policy.CoversResolved(g, r.Path) {
				seen[g] = true
				out = append(out, g)
				break
			}
		}
	}
	return out
}

// homeRoot reports the per-user home directory a path lives under, when the path sits
// beneath a conventional home root (/root, /home/<user>, /Users/<user>). It is a
// heuristic used only to warn, never to drop, so a home in an unconventional location
// (a container image or Silverblue's /var/home) simply yields no warning rather than a
// wrong one.
func homeRoot(path string) (string, bool) {
	// A cleaned absolute path splits to ["", "home", "u", ...] - segs[0] is empty.
	segs := strings.Split(filepath.Clean(path), "/")
	switch {
	case len(segs) >= 2 && segs[1] == "root":
		return "/root", true
	case len(segs) >= 3 && (segs[1] == "home" || segs[1] == "Users"):
		return "/" + segs[1] + "/" + segs[2], true
	default:
		return "", false
	}
}

// clampProposal filters a synthesized proposal for review, in an order that is
// load-bearing (bv2-2wy): drop grants inside a mandatory shield, then drop over-broad
// read and write grants, and ONLY THEN dedup reads a surviving write already covers.
// Deduping last is what keeps a read near a credential store (~/.ssh under a $HOME-level
// write) from being swallowed by a broad write before the shield clamp can surface it.
// The broad-read clamp is the read-side twin of the write clamp: a proposal of read: ~
// (or read: /) - which a script that lists its home or the root produces - would, once
// approved, bind the whole tree minus only the enumerated shields, re-exposing every
// credential the deny-list misses; the specific sub-paths the script read are proposed
// on their own, so dropping the umbrella loses nothing real. It mutates p and returns
// the shielded, over-broad read, and over-broad write paths to warn about.
func clampProposal(p *policy.Policy) (shielded, writeShielded, broadReads, broadWrites []string) {
	p.Read, p.Write, shielded, writeShielded = clampShieldedGrants(p.Read, p.Write)
	p.Write, broadWrites = clampBroadWrites(p.Write)
	p.Read, broadReads = clampBroadReads(p.Read)
	p.Read = profile.DropCovered(p.Read, p.Write)
	return shielded, writeShielded, broadReads, broadWrites
}

func clampBroadWrites(writes []string) (kept, dropped []string) {
	return partitionBroad(writes)
}

func clampBroadReads(reads []string) (kept, dropped []string) {
	return partitionBroad(reads)
}

// partitionBroad splits grants into those safe to bind whole and those too broad
// (see isBroadDir), preserving order.
func partitionBroad(paths []string) (kept, dropped []string) {
	for _, p := range paths {
		if isBroadDir(p) {
			dropped = append(dropped, p)
		} else {
			kept = append(kept, p)
		}
	}
	return kept, dropped
}

// isBroadDir reports whether path is too broad to bind as a whole: the root, a
// top-level directory (a direct child of "/", such as /etc or /home), or the user's
// home directory itself. Binding any of these exposes far more than a profiled script
// needs - as an automatic write grant (clampBroadWrites) or as the discovery run's own
// script-directory grant (discoveryPolicy).
func isBroadDir(path string) bool {
	if path == "/" || filepath.Dir(path) == "/" {
		return true
	}
	// Every anchor counts, since either can be the home the script actually walked -
	// under sudo -H a proposal of the passwd home is just as broad as one of $HOME. The
	// values are already cleaned, which proposal paths are too (Synthesize), so a $HOME
	// carrying a trailing slash cannot slip the whole home tree through as non-broad.
	anchors, _ := denylist.HomeAnchors()
	return slices.Contains(anchors, path)
}

// guessInterpreter picks an interpreter from the script's extension. An empty
// result means the script is its own interpreter (a compiled binary).
func guessInterpreter(path string) string {
	switch filepath.Ext(path) {
	case ".py":
		return "python3"
	case ".sh", ".bash":
		return "bash"
	case ".js":
		return "node"
	case ".rb":
		return "ruby"
	default:
		return ""
	}
}

// seedGrants returns the grants an existing manifest at path contributes to the
// convergence loop's first round, so quitting mid-loop and re-running resumes instead
// of re-prompting every path. It returns nil when there is nothing to resume from.
//
// Seeding mounts real content with no prompt in this session, so it takes the stamp as
// the consent the prompt otherwise gives: an unstamped or stale manifest seeds nothing
// and every path is asked again. The stamp is unkeyed drift detection, not a signature
// (see `bento approve`), so it does not by itself prove the file is one the user wrote -
// which is why the seeded grants are listed as they are mounted, why a manifest approved
// for a different entrypoint is not honored here, and why converge still prompts for a
// seeded path the enforced run will not re-shield. A missing path is the first run.
func seedGrants(path, script string, out io.Writer) (*policy.Policy, error) {
	doc, _, err := loadDocument(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		// mergeExisting refuses this same file at the end; refusing it now spares the user
		// a whole profiling session whose result cannot be written out.
		return nil, fmt.Errorf("refusing to profile against unreadable manifest %s: %w", path, err)
	}
	if checkApproval(doc) != approvalCurrent {
		fmt.Fprintf(out, "[bento] %s is not approved, so its grants are not mounted - review and `bento approve` it to resume from them.\n", path)
		return nil, nil
	}
	// After the approval check, never before: the fingerprint attests the manifest as
	// written, so resolving its relative paths first would make a valid stamp read stale.
	if err := manifest.Resolve(doc.Policy, path); err != nil {
		return nil, err
	}
	// The approval says "this script may see these paths". Profiling a different target
	// against the same --out is outside what was approved, so it starts fresh.
	if doc.Policy.Entrypoint != script {
		fmt.Fprintf(out, "[bento] %s is approved for %s, not %s, so its grants are not mounted.\n", path, doc.Policy.Entrypoint, script)
		return nil, nil
	}
	// A path the enforced run will not re-shield is not listed as mounted: converge
	// prompts for it rather than taking the stamp as consent, so announcing it here
	// would name a mount that may never happen.
	for _, it := range seedItems(doc.Policy) {
		if foreignShielded(it.path) {
			continue
		}
		fmt.Fprintf(out, "[bento] resuming from %s: mounting approved %s %s\n", path, it.kind, it.path)
	}
	return doc.Policy, nil
}

// mergeExisting folds proposed into an existing manifest at path so re-profiling
// widens rather than replaces it. A path that does not exist is the first run, so
// proposed is returned unchanged. Any other load error means a file is present at
// --out that cannot be parsed; overwriting it would silently discard whatever grants
// it held - contradicting the merge-not-overwrite contract the help text promises -
// so it is refused rather than clobbered.
//
// The trust comes back so the write lands at the location this load inspected rather than
// at the name resolved a second time; it is zero on the first run, where there is no file
// to have gathered it from. The existing provenance comes back for the same reason the
// grants are merged: the block a re-profile writes is its own, so without carrying it the
// hosts an earlier --allow-network run recorded as guard-refused would be dropped while
// the network rules they describe survive the merge.
func mergeExisting(path string, proposed *policy.Policy) (*policy.Policy, manifest.Provenance, manifestTrust, error) {
	existing, trust, err := loadDocument(path)
	switch {
	case err == nil:
		// Resolve before the union: a proposal names absolute paths, so a relative grant
		// in the existing manifest would survive the merge as a second spelling of a path
		// the proposal already carries, and the written manifest would hold both.
		if err := manifest.Resolve(existing.Policy, path); err != nil {
			return nil, manifest.Provenance{}, manifestTrust{}, err
		}
		return mergePolicies(existing.Policy, proposed), existing.Provenance, trust, nil
	case errors.Is(err, fs.ErrNotExist):
		return proposed, manifest.Provenance{}, manifestTrust{}, nil
	default:
		return nil, manifest.Provenance{}, manifestTrust{}, fmt.Errorf("refusing to overwrite existing manifest %s: %w", path, err)
	}
}

// mergePolicies unions the permission fields of two policies, keeping the base's
// entrypoint/interpreter/args. Used so re-profiling widens a manifest.
func mergePolicies(base, add *policy.Policy) *policy.Policy {
	out := &policy.Policy{
		Entrypoint:  base.Entrypoint,
		Interpreter: base.Interpreter,
		Args:        base.Args,
		Env:         union(base.Env, add.Env),
		Read:        union(base.Read, add.Read),
		Write:       union(base.Write, add.Write),
		Exec:        base.Exec,
		Limits:      base.Limits,
	}
	if add.Exec == policy.ExecAll {
		out.Exec = policy.ExecAll
	}
	seen := map[string]bool{}
	for _, r := range append(append([]policy.NetworkRule{}, base.Network...), add.Network...) {
		key := r.Host + ":" + r.Port
		if seen[key] {
			continue
		}
		seen[key] = true
		out.Network = append(out.Network, r)
	}
	return out
}

func union(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range append(append([]string{}, a...), b...) {
		if seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	return out
}
