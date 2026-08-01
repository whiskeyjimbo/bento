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
		asJSON        bool
	)
	cmd := &cobra.Command{
		Use:   "profile <script> [-- args...]",
		Short: "Run a script under observation and propose a manifest",
		Long: "profile runs the script under the same default-deny sandbox a real run\n" +
			"gets, recording every file it tries to open and every host it reaches, then\n" +
			"writes a proposed manifest of exactly that.\n\n" +
			"The manifest is written in the relocatable form: a path under the manifest's\n" +
			"own directory is emitted as ./-relative and one under your home as ~/-prefixed,\n" +
			"so the result can be committed and used by someone else. A path under neither\n" +
			"stays absolute, and names this machine.\n\n" +
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
			"profile again to converge; grants are merged, not overwritten. The merge\n" +
			"widens more than grants - exec can be escalated to `all`, and any approval\n" +
			"stamp on the file is dropped - so profile says what it changed, and it\n" +
			"refuses a manifest at --out written for a different program rather than\n" +
			"leaving one that names one script and grants what another did.\n\n" +
			"On a terminal, an existing manifest at --out that is currently approved for\n" +
			"this same script is resumed: its grants are listed and mounted from the first\n" +
			"round instead of being asked again, so quitting mid-session and re-running\n" +
			"picks up where you left off. An unapproved or stale manifest mounts nothing\n" +
			"and every path is asked again.\n\n" +
			"A run that failed only because a directory it writes into does not exist yet is\n" +
			"profiled once more with that directory created, the way an enforced run creates a\n" +
			"granted write directory - so a first proposal that is already correct is not\n" +
			"reported as one bento cannot vouch for.\n\n" +
			"--json puts the result on stdout as one envelope - the policy as written, whether\n" +
			"it can be vouched for, every access profiling declined to propose and why, and\n" +
			"every grant it proposes but wants reviewed - so a harness that generates manifests\n" +
			"reads those decisions rather than scraping them. Everything else stays on stderr.\n\n" +
			"The manifest is always written, but profile exits 4 when it cannot vouch for\n" +
			"it: the profiled run did not finish, the observer dropped accesses it could\n" +
			"not name, or the granting session ended before it converged. That is what\n" +
			"keeps `profile && approve` from stamping a manifest built on a crashed run.",
		Args:        minArgs(1, "a script path"),
		Annotations: map[string]string{jsonRefusalAnnotation: "yes"},
		RunE: func(cmd *cobra.Command, args []string) error {
			// Every refusal this command raises goes through this, so --json never
			// answers one with an empty stdout and a machine gate can tell a refusal from
			// a crash. It is run's refuseJSON, which carries the host report when the
			// error is one. A usage error cobra rejects before RunE is reached never gets
			// here at all - the frontend answers that one, off the annotation below.
			refuse := func(err error) error { return refuseJSON(os.Stdout, asJSON, err) }

			script, err := filepath.Abs(args[0])
			if err != nil {
				return refuse(err)
			}
			// The sandbox stats the entrypoint too, but not until after the banner below
			// has announced a profiling session - so a typo would read as a session that
			// started and then fell over. Checked here, it reads as what it is.
			if _, err := os.Stat(script); err != nil {
				return refuse(fmt.Errorf("entrypoint %q: %w", args[0], err))
			}
			// Before the banner too, and for a stronger reason than the typo above: a host
			// that cannot sandbox announced a profiling session, passed bwrap's own stderr
			// through, and then hedged about a condition bento can state exactly.
			if err := preflightHost(cmd.Context()); err != nil {
				var refusal *enforce.Refusal
				if !asJSON && errors.As(err, &refusal) {
					// Rendered here rather than by main's generic printer for the reason run
					// renders its own: the layer reasons are paragraphs, and that printer
					// would put each on one unreadable line.
					writeRefusal(os.Stderr, "refusing to profile", refusal)
					return &exitError{code: bentoFailed}
				}
				return refuse(err)
			}
			if interpreter == "" {
				interpreter = guessInterpreter(script)
			}
			if out == "" {
				out = args[0] + ".manifest.yaml"
			}
			if err := checkMergeable(out, script); err != nil {
				return refuse(err)
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
						return refuse(err)
					}
				}
				var seedErr error
				if seed, seedErr = seedGrants(out, script, os.Stderr); seedErr != nil {
					return refuse(seedErr)
				}
				fmt.Fprintf(os.Stderr, "[bento] profiling %s under default-deny; grant what it needs to converge (real content is mounted only for paths you accept)...\n", args[0])
				round := func(d *policy.Policy) (*policy.Policy, error) {
					p, s, err := profileRound(cfg, d)
					// The proposal comes from the last round, so that round's completion is
					// the one that matters; a dropped access from any round is gone for good.
					status.unfinished = s.unfinished
					status.dropped = status.dropped || s.dropped
					status.blocked = union(status.blocked, s.blocked)
					status.withheld = mergeNotes(status.withheld, s.withheld)
					status.flagged = mergeNotes(status.flagged, s.flagged)
					return p, err
				}
				proposed, stop, err = converge(base, seed, round, newGrantPrompter(tty, os.Stderr), foreignShielded, os.Stderr)
			} else {
				// No terminal to prompt on (a pipe or CI): keep the non-interactive contract -
				// one default-deny pass and write, plus at most the one retry below. A
				// content-branching target under-reports; the footer says to profile again
				// with grants to widen it.
				cfg.targetStdin = os.Stdin
				if allowNetwork {
					fmt.Fprintf(os.Stderr, "[bento] profiling %s under default-deny (egress allowed)...\n", args[0])
				} else {
					fmt.Fprintf(os.Stderr, "[bento] profiling %s under default-deny (egress recorded, not forwarded; --allow-network to permit)...\n", args[0])
				}
				proposed, status, err = profileRound(cfg, base)
				// A target that died only because a directory it writes into does not exist
				// yet described a manifest that works: `bento run` creates a granted write
				// directory. Reporting that pass as unfinished tells a first-time user their
				// first profile is untrustworthy when it is correct, and the advice - widen
				// the proposal - names nothing to widen. So do here what the run does and
				// profile once more. The interactive loop reaches the same place through its
				// prompts, which is why this is only the single-pass path.
				if err == nil && status.unfinished {
					if dirs := missingGrantedWriteDirs(base.Write, proposed.Write); len(dirs) > 0 {
						fmt.Fprintf(os.Stderr, "[bento] the run did not finish and wrote into %s, which does not exist on the host yet - `bento run` creates a granted write directory, so this runs the target a second time with it created.\n", strings.Join(dirs, ", "))
						retry := *base
						retry.Write = append(slices.Clone(base.Write), dirs...)
						first := status
						second, s, rerr := profileRound(cfg, &retry)
						if rerr != nil {
							// The first pass produced a proposal, and the manifest is always
							// written - so a second pass that could not run costs the session its
							// retry, not its result. Returning the error here would be the one
							// path on which profiling writes nothing.
							fmt.Fprintf(os.Stderr, "[bento] the second pass did not run (%v), so this keeps the first pass's proposal.\n", rerr)
						} else {
							// The retry supersedes the first pass's verdict, but not what it saw:
							// an access declined in round 1 is declined for good.
							proposed, status = second, s
							status.withheld = mergeNotes(first.withheld, status.withheld)
							status.flagged = mergeNotes(first.flagged, status.flagged)
							status.dropped = status.dropped || first.dropped
							status.blocked = union(first.blocked, status.blocked)
						}
					}
				}
			}
			if err != nil {
				return refuse(err)
			}

			// Merge into an existing manifest rather than overwriting it, so a second
			// profile run widens the policy instead of replacing it.
			accepted := proposed
			merge, err := mergeExisting(out, script, proposed)
			if err != nil {
				return refuse(err)
			}
			proposed, trust := merge.policy, merge.trust
			// A manifest that does not exist yet still has a location to judge, and the first
			// run is the case nothing else looks at - seedGrants returns on a missing file,
			// and only an interactive session calls it at all.
			if trust.realPath == "" {
				if trust, err = inspectNewManifest(out); err != nil {
					return refuse(err)
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

			// From the final policy rather than per round: this names a grant the script's own
			// directory produces, so it survives every round and a per-round callout would
			// repeat itself until the reviewer learned to skip it.
			status.flagged = mergeNotes(status.flagged, printWorkdirGrants(os.Stderr, proposed, script))

			doc := manifest.Provenance{
				GeneratedBy:  "bento profile",
				GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
				BlockedHosts: blockedHostsGranted(proposed, union(merge.carried.BlockedHosts, status.blocked)),
			}
			// Last, after every merge, drop and union above: those all compare grant
			// strings, and comparing two spellings of one directory would leave both in
			// the file or fail to collapse a covered one.
			written := relocatable(proposed, out)
			data, err := manifest.Marshal(written, doc)
			if err != nil {
				return refuse(err)
			}
			if err := writeManifestAtomically(trust, data, os.Stderr); err != nil {
				return refuse(err)
			}

			fmt.Fprintf(os.Stderr, "\n[bento] wrote %s - review it, then run `bento validate %s` and `bento approve %s`.\n", out, out, out)
			writeMergeNotice(os.Stderr, out, merge)

			reason := incompleteReason(status, stop)
			if asJSON {
				if err := writeJSON(os.Stdout, profileResultJSON(out, proposed, written, doc, status, merge, reason)); err != nil {
					// The manifest is on disk and the stderr account above stands, so this
					// says what failed rather than claiming the profiling did. But the exit
					// code cannot stay 0: Encode marshals and writes once, so a stdout that
					// is full or gone leaves truncated JSON there, and a success code would
					// tell a machine gate to parse it.
					fmt.Fprintf(os.Stderr, "[bento] the manifest was written, but the JSON result could not be delivered (%v), so this exits %d - what is on stdout may be truncated.\n", err, bentoFailed)
					return &exitError{code: bentoFailed}
				}
			}
			// The manifest is written either way - it is where the next pass starts from -
			// but a proposal built on a partial observation, or on a session the user left
			// before it converged, is not what the target needs. Exiting 0 would let
			// `profile && approve` stamp it as though it were.
			if reason != "" {
				fmt.Fprintf(os.Stderr, "[bento] the proposal is incomplete (%s), so this exits %d rather than 0 - review and widen it before approving.\n", reason, profileIncomplete)
				return &exitError{code: profileIncomplete}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&interpreter, "interpreter", "", "interpreter to run the script with (guessed from the extension if omitted)")
	cmd.Flags().StringVar(&out, "out", "", "manifest path to write (default: <script>.manifest.yaml)")
	cmd.Flags().StringArrayVar(&acceptAliases, "accept-alias", nil, "acknowledge the credential aliases under a host tree (a snapshot or deduplicated backup) instead of refusing; repeatable; same meaning as on `bento run`")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the result as a JSON envelope on stdout: what was written, whether it can be vouched for, and every proposal decision. Everything else - the target's own output, the prose, any grant prompts - stays on stderr, so the envelope is the only thing on stdout")
	cmd.Flags().BoolVar(&allowNetwork, "allow-network", false, "let the script's network traffic reach the host during profiling (default: record destinations but do not forward them)")
	return cmd
}

// profileResultJSON assembles the --json envelope from what the session decided.
//
// proposed is the policy as profiling observed it, absolute; written is the same policy
// in the relocatable spelling the manifest carries. Both are needed. A flagged note
// points at a grant the file holds, so it is respelled to match - a consumer told to
// review `/home/u/work` cannot find it in a policy that says `.`. A withheld note is
// not a grant, has no spelling in the file, and stays the host path profiling saw.
func profileResultJSON(path string, proposed, written *policy.Policy, doc manifest.Provenance, status roundStatus, merge mergeOutcome, incomplete string) profileJSON {
	spelling := manifestSpelling(proposed, written)
	env := profileJSON{
		Manifest:         path,
		Complete:         incomplete == "",
		IncompleteReason: incomplete,
		// The absolute proposal stands in for the resolved policy, which is what it is:
		// relocatable rewrote those very paths into the spelling written above, so
		// resolved_read names what each grant reaches on this host without resolving
		// anything a second time.
		Policy:       toPolicyJSON(written, proposed, doc.BlockedHosts),
		Withheld:     status.withheld,
		Flagged:      respell(status.flagged, spelling),
		BlockedHosts: doc.BlockedHosts,
	}
	if merge.widened {
		env.Merged = &mergeJSON{
			KeptRead:       merge.keptRead,
			KeptWrite:      merge.keptWrite,
			KeptEnv:        merge.keptEnv,
			KeptNetwork:    merge.keptNetwork,
			ExecWidened:    merge.execWidened,
			ApprovalVoided: merge.approvalVoided,
		}
	}
	return env
}

// manifestSpelling maps each absolute grant to the way the written manifest spells it.
// relocatable rewrites the grants element-wise, so the two policies' Read and Write line
// up by index; a rewrite it declined (the whole policy stayed absolute) yields an
// identity entry, which is the right answer there.
func manifestSpelling(proposed, written *policy.Policy) map[string]string {
	out := map[string]string{}
	for _, pair := range [][2][]string{{proposed.Read, written.Read}, {proposed.Write, written.Write}} {
		if len(pair[0]) != len(pair[1]) {
			continue
		}
		for i, abs := range pair[0] {
			out[abs] = pair[1][i]
		}
	}
	return out
}

// respell rewrites each note's path to the manifest's own spelling of that grant. A note
// naming something the manifest does not grant is left alone rather than guessed at.
func respell(notes []accessNoteJSON, spelling map[string]string) []accessNoteJSON {
	if len(notes) == 0 {
		return nil
	}
	out := make([]accessNoteJSON, 0, len(notes))
	for _, n := range notes {
		if s, ok := spelling[n.Path]; ok {
			n.Path = s
		}
		out = append(out, n)
	}
	return out
}

// preflightHost refuses to profile on a host that cannot fully enforce a guarantee
// every run needs, before any session is announced. It asks the same question doctor
// gates its exit code on, so the two agree by construction rather than by two rules kept
// in step by hand - and so the reader meets bento's own account of the shortfall rather
// than the distro bubblewrap's advice, which bento did not author.
//
// It is not enforce.Run's admission: that judges the layers a policy needs, and the
// discovery policy's open network and exec describe the observation, not a posture to
// enforce (see linux.Profile). The baseline is what profiling really depends on.
//
// run offers --allow-degraded against the same shortfall and profiling deliberately
// does not. The reduced tier applies no deny-list shields at all, and profiling runs the
// target against the real $HOME so it names the credential paths it reaches - so the
// hatch that makes a run possible would turn profiling into the exposure it exists to
// avoid. The refusal points at doctor instead.
func preflightHost(ctx context.Context) error {
	e, err := backend.New()
	if err != nil {
		return err
	}
	report := e.Probe(ctx)
	short := gatedShortfall(report)
	if len(short) == 0 {
		return nil
	}
	return &enforce.Refusal{
		Report: report,
		Reason: "a core guarantee cannot be fully enforced on this host, and profiling has no reduced " +
			"tier to fall back on - it always needs the full sandbox, because it runs the target against " +
			"your real environment to record what it reaches. Fix the shortfall below; `bento doctor` " +
			"reports every layer",
		Short: short,
	}
}

// relocatable rewrites a proposal's paths into the vocabulary the manifest format
// already documents, so a generated manifest is the same artifact a hand-written one is:
// a path under the manifest's own directory becomes `./`-relative, one under the invoking
// user's home becomes `~/`-prefixed, and anything under neither stays absolute.
//
// Profiling observed host paths, so without this every generated manifest names one
// machine. Committing it hands a teammate a manifest that cannot run for them and hands
// the repository the author's home directory and directory layout. The hand-written
// example manifests already use the relative form; only the generated ones did not.
//
// The manifest directory wins over home because manifests usually live under home, and
// `~/`-anchoring the common case would leave the artifact just as unshareable. A rewrite
// is taken only where filepath.Rel stays inside the anchor: `..` climbing out is less
// relocatable than the absolute path, and a prefix test would read /home/alice-backup as
// living under /home/alice.
func relocatable(p *policy.Policy, manifestPath string) *policy.Policy {
	base, err := filepath.Abs(filepath.Dir(manifestPath))
	if err != nil {
		// The manifest is about to be written to this path, so a directory that cannot be
		// named absolutely is a problem the write itself will report. Here it only means
		// the paths stay as profiling found them.
		return p
	}
	// An unusable $HOME is not worth refusing over: home-anchoring is the second-best of
	// the two rewrites, and dropping it leaves absolute paths, which is what profiling
	// wrote before any of this. A $HOME of "/" - a system account, a minimal container -
	// is unusable in the way that matters here: every absolute path is under it, so the
	// whole policy would be written `~/`-anchored and land somewhere else entirely on a
	// host whose home is a real directory.
	home, homeErr := os.UserHomeDir()
	if homeErr != nil || !filepath.IsAbs(home) || filepath.Clean(home) == string(filepath.Separator) {
		home = ""
	}
	rewrite := func(path string) string {
		if !filepath.IsAbs(path) {
			return path
		}
		if s, ok := under(base, path); ok {
			if s == "." {
				return "."
			}
			return "./" + s
		}
		if home != "" {
			if s, ok := under(home, path); ok {
				if s == "." {
					return "~"
				}
				return "~/" + s
			}
		}
		return path
	}
	cp := *p
	cp.Entrypoint = rewrite(p.Entrypoint)
	// A bare interpreter name means "the host's python3" and is already relocatable;
	// only a path-shaped one names a machine. Spelled as manifest.Resolve's own rule,
	// since that is what reads this field back - and a re-profile resolves an existing
	// manifest's interpreter to an absolute path before the merge, so leaving the field
	// alone here would quietly de-relativize a manifest that already had it right.
	if strings.ContainsRune(p.Interpreter, filepath.Separator) {
		cp.Interpreter = rewrite(p.Interpreter)
	}
	cp.Read = mapSlice(p.Read, rewrite)
	cp.Write = mapSlice(p.Write, rewrite)
	// The rewrite is a change of spelling, not of policy, so it must not turn a policy
	// bento would write into one Marshal's gate refuses - `write: /home/you` spelled
	// absolutely passes, and `write: ~` is refused outright. Failing there would end a
	// whole granting session over a spelling the user never wrote; the absolute form is
	// the same permissions and is what profiling wrote before any of this.
	if cp.Validate() != nil {
		return p
	}
	return &cp
}

// under reports path's spelling relative to anchor, and whether it is beneath it at all.
// The anchor itself yields ".".
func under(anchor, path string) (string, bool) {
	rel, err := filepath.Rel(anchor, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return rel, true
}

func mapSlice(in []string, f func(string) string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = f(v)
	}
	return out
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
	// Each of these says on stderr what it decided and returns the same decision as a
	// note, so --json carries what the prose does rather than a consumer scraping it.
	withheld := slices.Concat(
		printFlooredWrites(os.Stderr, obs.Writes),
		printScratchWrites(os.Stderr, obs.Writes),
		printSocketAccesses(os.Stderr, obs),
		printUnrepresentable(os.Stderr, obs),
	)
	clamped, flagged := printProposalWarnings(os.Stderr, proposed)
	return proposed, roundStatus{
		unfinished: partialRunWarning(obs) != "",
		dropped:    obs.Dropped > 0,
		blocked:    blockedHostKeys(obs.Blocked),
		withheld:   append(withheld, clamped...),
		flagged:    append(flagged, printTmpGrants(os.Stderr, proposed)...),
	}, nil
}

// kindedPath pairs an observed path with the access that produced it, so the printers
// that report reads and writes in one pass can still say which a note came from.
type kindedPath struct{ kind, path string }

func kinded(kind string, paths []string) []kindedPath {
	out := make([]kindedPath, 0, len(paths))
	for _, p := range paths {
		out = append(out, kindedPath{kind, p})
	}
	return out
}

// missingGrantedWriteDirs returns the proposal's write grants that are absent from the
// host and lie inside a tree profiling already granted write to. Those are exactly the
// directories an enforced run creates for a granted write (prepareWriteDirs), so a
// target that failed only on one of them is describing a manifest that already works.
//
// Confined to the already-granted tree deliberately. Profiling mounted that tree
// writable during this same pass, so creating a directory inside it exposes nothing the
// round did not already permit; a proposed write anywhere else is a path the target
// chose, and profiling must not create host directories at an untrusted target's
// request. Like the mkdir the convergence loop's grants produce, the directory is not
// removed afterwards - an enforced run of the resulting manifest would create it anyway.
func missingGrantedWriteDirs(granted, proposed []string) []string {
	var out []string
	for _, w := range proposed {
		// Lstat, not Stat: a dangling symlink is not a missing directory. Stat follows it
		// and reports ENOENT, and the mkdir the retry would then make fails EEXIST on the
		// link - turning a session that wrote a manifest and exited 4 into one that
		// refuses. Any other stat error (EACCES, ELOOP) leaves the path alone too: it is
		// not one this can show is absent, and the enforced run reports it in its own
		// words.
		if _, err := os.Lstat(w); !os.IsNotExist(err) {
			continue
		}
		for _, g := range granted {
			// Strictly inside: a grant that IS the granted tree cannot be the missing one,
			// since profiling just bound it.
			if rel, ok := under(g, w); ok && rel != "." {
				out = append(out, w)
				break
			}
		}
	}
	return out
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
	// withheld and flagged are the round's proposal decisions, for --json. They
	// accumulate like blocked and for the same reason: a path round 1 declined to
	// propose is a fact about the drafting, and a later round that never reached for it
	// again does not undo it. Duplicates across rounds are collapsed (mergeNotes),
	// because the same path is decided the same way every round it is seen.
	withheld, flagged []accessNoteJSON
}

// mergeNotes appends the notes of b that a does not already carry, so a converging
// session reports each decision once rather than once per round.
//
// Compared field by field rather than with slices.Contains: a note's Absent is a
// pointer, and each round builds its own, so the equality that matters here is what the
// two notes say and not which round said it.
func mergeNotes(a, b []accessNoteJSON) []accessNoteJSON {
	for _, n := range b {
		if !slices.ContainsFunc(a, func(have accessNoteJSON) bool { return sameNote(have, n) }) {
			a = append(a, n)
		}
	}
	return a
}

func sameNote(a, b accessNoteJSON) bool {
	if a.Kind != b.Kind || a.Path != b.Path || a.Host != b.Host || a.Port != b.Port || a.Reason != b.Reason {
		return false
	}
	if a.Absent == nil || b.Absent == nil {
		return a.Absent == b.Absent
	}
	return *a.Absent == *b.Absent
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
func printTmpGrants(w io.Writer, p *policy.Policy) []accessNoteJSON {
	grants := tmpGrants(p)
	if len(grants) == 0 {
		return nil
	}
	var notes []accessNoteJSON
	for _, g := range grants {
		notes = append(notes, grantKinds(p, g, "target-steerable-tmp")...)
	}
	fmt.Fprintf(w, "[bento] %d proposed grant(s) name a path under /tmp: %s.\n", len(grants), strings.Join(grants, ", "))
	fmt.Fprintf(w, "[bento] Those reach the proposal because the name exists on this host, which is the only way\n")
	fmt.Fprintf(w, "[bento] a real workspace there can be told from the sandbox's own scratch - so a script that\n")
	fmt.Fprintf(w, "[bento] opens guessed names under /tmp can put them here. Treat them as the script's request\n")
	fmt.Fprintf(w, "[bento] rather than as something profiling discovered, and keep only the ones it needs.\n")
	return notes
}

// printWorkdirGrants names a proposed grant that is the whole directory the script runs
// from, rather than the files under it the run actually opened.
//
// It is the broadest grant profiling still proposes: isBroadDir already drops the home
// directory and a top-level one, so the working directory is what survives, and a script
// that merely lists its own directory produces it. Every other narrowing decision the
// round makes is said out loud, and this one was not - so the run that printed a
// paragraph about a single unproposable toolchain path said nothing about a grant on
// everything beside the script. For the agent-harness case that directory holds whatever
// the harness put there, which is exactly what a reviewer needs pointed at.
//
// Said, not withheld, for the same reason the /tmp grants are: it is often the right
// resolution - a script and its data files are one tree - and dropping it would draft a
// manifest that cannot run. The reviewer decides.
func printWorkdirGrants(w io.Writer, p *policy.Policy, script string) []accessNoteJSON {
	// Both spellings: the observer records resolved paths, so a grant on a workdir
	// reached through a symlinked component arrives resolved while filepath.Abs left the
	// script path as the user typed it. Matching only the literal one would go quiet on
	// exactly the grant this exists to name.
	dirs := []string{filepath.Dir(script)}
	if resolved, err := filepath.EvalSymlinks(dirs[0]); err == nil && resolved != dirs[0] {
		dirs = append(dirs, resolved)
	}
	var notes []accessNoteJSON
	for _, g := range []struct {
		kind   string
		grants []string
	}{{"read", p.Read}, {"write", p.Write}} {
		dir := ""
		for _, d := range dirs {
			if slices.Contains(g.grants, d) {
				dir = d
				break
			}
		}
		if dir == "" {
			continue
		}
		notes = append(notes, accessNoteJSON{Kind: g.kind, Path: dir, Reason: "whole-workdir"})
		// "the manifest grants", not "proposing": this runs on the merged policy, so the
		// grant can be one the file already held rather than one this run showed. Either
		// way it is what the reviewer is about to approve.
		fmt.Fprintf(w, "[bento] the manifest grants %s %q - that is the entire directory the script runs from, not only\n", g.kind, dir)
		fmt.Fprintf(w, "[bento] the paths this run opened, so the grant covers whatever else is in there when it\n")
		fmt.Fprintf(w, "[bento] runs. Narrow it to the paths the script needs if the directory holds more than it\n")
		fmt.Fprintf(w, "[bento] should see.\n")
	}
	return notes
}

// grantKinds returns one note per list the grant appears in, so a path granted both read
// and write is named as both. Kind says which access a note is about, and answering
// "write" for a path that is also read would drop half of what the manifest carries.
func grantKinds(p *policy.Policy, path, reason string) []accessNoteJSON {
	var out []accessNoteJSON
	if slices.Contains(p.Read, path) {
		out = append(out, accessNoteJSON{Kind: "read", Path: path, Reason: reason})
	}
	if slices.Contains(p.Write, path) {
		out = append(out, accessNoteJSON{Kind: "write", Path: path, Reason: reason})
	}
	return out
}

// printFlooredWrites names the observed writes Synthesize withheld as system trees or
// another user's home. Those are dropped inside Synthesize, before the proposal the
// clamps below report on, so without this they are the one withheld class that leaves
// no trace: the script fails EACCES at enforce time and the reviewer has nothing to
// read. It reports the collapsed directory, which is the granularity the grant would
// have had.
func printFlooredWrites(out io.Writer, writes []string) []accessNoteJSON {
	var notes []accessNoteJSON
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
		notes = append(notes, accessNoteJSON{Kind: "write", Path: dir, Reason: "system-tree"})
		fmt.Fprintf(out, "[bento] not proposing write access to %q - it is a system tree or another user's home, where a writable grant is a privilege-escalation vector rather than a script's own storage. The attempt was recorded; if the script genuinely needs it, add the write: grant by hand.\n", dir)
	}
	return notes
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
func printScratchWrites(out io.Writer, writes []string) []accessNoteJSON {
	var notes []accessNoteJSON
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
		notes = append(notes, accessNoteJSON{Kind: "write", Path: dir, Reason: "sandbox-scratch"})
		fmt.Fprintf(out, "[bento] not proposing write access to %q - no such directory exists on the host, so inside the box that name is in the private /tmp every run mounts and there is nothing to grant. Nothing written there survives the run; if that output is meant to persist, have the script write it somewhere the manifest grants.\n", dir)
	}
	return notes
}

// printSocketAccesses names the observed accesses to a unix socket, which Synthesize
// withholds whether the target read one or wrote one. Like the floored writes above they
// are dropped before the proposal the clamps report on, so without this the reviewer has
// no trace: the script fails at enforce time and there is nothing to read.
//
// The observed name is reported rather than the resolved one, because that is the name
// the reviewer would go looking for. Writes are named at the file, not at the directory
// they would have collapsed to, since the collapse is what Synthesize declined to do.
func printSocketAccesses(out io.Writer, obs profile.Observation) []accessNoteJSON {
	var notes []accessNoteJSON
	seen := map[string]bool{}
	for _, e := range append(kinded("read", obs.Reads), kinded("write", obs.Writes)...) {
		p := e.path
		if !filepath.IsAbs(p) || seen[p] || !profile.Socket(p) {
			continue
		}
		seen[p] = true
		notes = append(notes, accessNoteJSON{Kind: e.kind, Path: p, Reason: "unix-socket"})
		fmt.Fprintf(out, "[bento] not proposing access to %q - it is a unix socket, which is a two-way channel to whatever process is listening rather than storage of the script's own, so a grant of it confers whatever that process will do (an X11 socket is control of your session; an ssh-agent socket is use of your keys). The access was recorded; if the script genuinely needs that socket, add the grant by hand.\n", p)
	}
	return notes
}

// printUnrepresentable names the observations Synthesize withheld because a manifest
// cannot hold them: a path carrying a character the policy grammar refuses in a path
// field, or a CONNECT host that is not a hostname, a canonical address, or a wildcard.
// Both are values the TARGET chose - a filename it created, a host it dialed - so a
// hostile or merely sloppy one can produce them, and proposing one would fail the
// marshal that ends the run. Like the floored writes above, they are dropped inside
// Synthesize, so without this the reviewer has no trace of the access at all.
func printUnrepresentable(out io.Writer, obs profile.Observation) []accessNoteJSON {
	var notes []accessNoteJSON
	// A write collapses to its parent before Synthesize screens it, so the write side is
	// judged and reported at that same granularity: a bad filename in a clean directory
	// still yields the directory grant, and warning about the file would name a grant
	// that was in fact proposed.
	names := kinded("read", obs.Reads)
	for _, w := range obs.Writes {
		names = append(names, kindedPath{"write", filepath.Dir(w)})
	}
	absent := map[string]bool{}
	for _, p := range obs.Absent {
		absent[p] = true
	}
	seen := map[string]bool{}
	for _, e := range names {
		p := e.path
		if !profile.Unrepresentable(p) || seen[p] {
			continue
		}
		seen[p] = true
		note := accessNoteJSON{Kind: e.kind, Path: p, Reason: "unrepresentable"}
		if e.kind == "read" {
			probed := absent[p]
			note.Absent = &probed
		}
		notes = append(notes, note)
		// The deception the full warning describes needs a file to deceive about. A path
		// nothing was ever found at was probed and no more: nothing was read, and no
		// grant of it would have meant anything either way - so saying the name is how a
		// path is made to read as something other than what it grants would be noise on
		// the case that produces it most often, an interpreter's search miss. Only the
		// read side can be told apart this way; a write is judged at its parent
		// directory, which no observation names the existence of.
		if absent[p] {
			fmt.Fprintf(out, "[bento] not proposing access to %q - the name carries a character a manifest path cannot hold (a control, bidi, invisible, or line-separating one, or a byte that is not valid UTF-8). Nothing was found at that path, so the run only probed for it; if the script genuinely needs a file there, rename it.\n", p)
			continue
		}
		fmt.Fprintf(out, "[bento] not proposing access to %q - the name carries a character a manifest path cannot hold (a control, bidi, invisible, or line-separating one, or a byte that is not valid UTF-8), which is how a path is made to read as something other than what it grants. The access was recorded; if the script genuinely needs that file, rename it.\n", p)
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
		notes = append(notes, accessNoteJSON{Kind: "network", Host: h.Host, Port: h.Port, Reason: "unrepresentable"})
		// Quoted, not %s: the host is target-chosen, and this is the one place such a
		// value is echoed to the operator's terminal. readConnect holds a CONNECT target
		// to the same screen, so nothing deceiving should reach here - but a rendering
		// that depends on a screen upstream is one refactor away from being wrong, and
		// quoting also delimits a host that is empty or carries spaces.
		fmt.Fprintf(out, "[bento] not proposing network access to %q port %q - %v. The connection was recorded; if the script needs it, add a network: rule naming the host in that form by hand.\n", h.Host, h.Port, err)
	}
	return notes
}

// printProposalWarnings clamps p in place (dropping shielded credential paths and
// over-broad grants from the auto-proposal) and prints why each was withheld, so a
// path the tool wants but bento will not auto-grant is never silently missing.
func printProposalWarnings(out io.Writer, p *policy.Policy) (withheld, flagged []accessNoteJSON) {
	shielded, writeShielded, broadReads, broadWrites := clampProposal(p)
	for _, d := range shielded {
		withheld = append(withheld, accessNoteJSON{Kind: "read", Path: d, Reason: "shielded-credential"})
		fmt.Fprintf(out, "[bento] not proposing access to %q - it is a shielded credential path, not granted automatically. The script's attempt was recorded; if it genuinely needs it, add a read:/write: grant for that path by hand - the run then exposes it and warns you each time.\n", d)
	}
	for _, d := range writeShielded {
		withheld = append(withheld, accessNoteJSON{Kind: "write", Path: d, Reason: "write-shielded"})
		fmt.Fprintf(out, "[bento] not proposing write access to %q - it is always write-shielded, because a file planted there is run by the host later. Unlike a credential path there is no hand-added opt-in: a write: grant for it is refused, not warned. The path stays readable; if the script must install there, run it outside bento.\n", d)
	}
	for _, d := range broadReads {
		withheld = append(withheld, accessNoteJSON{Kind: "read", Path: d, Reason: "too-broad"})
		fmt.Fprintf(out, "[bento] not proposing read access to %q - too broad to grant automatically (it would re-expose every credential the deny-list does not enumerate); the specific paths under it the script actually read are proposed on their own, so add a narrower read: directory by hand only if it needs more.\n", d)
	}
	for _, d := range broadWrites {
		withheld = append(withheld, accessNoteJSON{Kind: "write", Path: d, Reason: "too-broad"})
		fmt.Fprintf(out, "[bento] not proposing write access to %q - too broad to grant automatically; add a narrower write: directory by hand if the script needs it.\n", d)
	}
	for _, d := range foreignHomeShields(append(append([]string{}, p.Read...), p.Write...)) {
		flagged = append(flagged, grantKinds(p, d, "foreign-home-shield")...)
		fmt.Fprintf(out, "[bento] proposing %q - it reaches shielded credential or persistence paths in a home directory profiling did not shield; the enforced run only shields the home it executes as, so these would be exposed. Confirm the script needs it before approving.\n", d)
	}
	return withheld, flagged
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

// mergeOutcome is what folding a round's proposal into whatever was already at --out
// produced. It carries the deltas as well as the result because what lands on disk is
// this run unioned with a file the user is not shown again and may not remember writing,
// and only the deltas can say which half a grant came from.
type mergeOutcome struct {
	policy *policy.Policy
	// carried is the existing provenance, kept for the same reason the grants are
	// merged: the block a re-profile writes is its own, so without carrying it the hosts
	// an earlier --allow-network run recorded as guard-refused would be dropped while the
	// network rules they describe survive the merge.
	carried manifest.Provenance
	// trust is where the write must land - the location this load inspected, rather than
	// the name resolved a second time. Zero on the first run, where there is no file to
	// have gathered it from.
	trust manifestTrust
	// widened is whether there was a manifest to merge into at all. The deltas below are
	// meaningless without it: on a first run everything is "added".
	widened bool
	// kept are the grants that came from the existing manifest and not from this run.
	// Named rather than counted: the whole point is that the reviewer can no longer
	// assume the file describes what they just watched.
	keptRead, keptWrite, keptEnv, keptNetwork []string
	// execWidened is whether the union escalated exec from a blocked mode to `all`.
	execWidened bool
	// approvalVoided is whether the file being widened carried a current approval, which
	// the re-profile drops. validate reports it on the next command; saying it here is
	// what keeps "profile again to converge" from quietly costing an approval.
	approvalVoided bool
}

// mergeExisting folds proposed into an existing manifest at path so re-profiling
// widens rather than replaces it. A path that does not exist is the first run, so
// proposed is returned unchanged. Any other load error means a file is present at
// --out that cannot be parsed; overwriting it would silently discard whatever grants
// it held - contradicting the merge-not-overwrite contract the help text promises -
// so it is refused rather than clobbered.
//
// script is the target that was profiled, absolute. A manifest whose entrypoint names a
// different program is refused rather than merged: the union keeps the base's
// entrypoint, so merging would leave a manifest naming one program and carrying the
// other's grants - and seedGrants already declines to mount such a file, so the run that
// produced the proposal was not resuming from it either. Refusing says which file and
// which two programs, which is what picking a different --out needs.
func mergeExisting(path, script string, proposed *policy.Policy) (mergeOutcome, error) {
	existing, trust, err := loadDocument(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return mergeOutcome{policy: proposed}, nil
	case err != nil:
		return mergeOutcome{}, fmt.Errorf("refusing to overwrite existing manifest %s: %w", path, err)
	}
	approved := checkApproval(existing) == approvalCurrent
	// Resolve before the union: a proposal names absolute paths, so a relative grant
	// in the existing manifest would survive the merge as a second spelling of a path
	// the proposal already carries, and the written manifest would hold both.
	if err := manifest.Resolve(existing.Policy, path); err != nil {
		return mergeOutcome{}, err
	}
	if err := foreignEntrypointError(path, existing.Policy.Entrypoint, script); err != nil {
		return mergeOutcome{}, err
	}
	out := mergeOutcome{
		policy:      mergePolicies(existing.Policy, proposed),
		carried:     existing.Provenance,
		trust:       trust,
		widened:     true,
		keptRead:    only(existing.Policy.Read, proposed.Read),
		keptWrite:   only(existing.Policy.Write, proposed.Write),
		keptEnv:     only(existing.Policy.Env, proposed.Env),
		keptNetwork: only(networkKeys(existing.Policy.Network), networkKeys(proposed.Network)),
		execWidened: existing.Policy.Exec != policy.ExecAll && proposed.Exec == policy.ExecAll,
		// Reported whenever the file was approved: profile writes its own provenance
		// block, so the stamp is dropped by the write regardless of whether the grants
		// moved.
		approvalVoided: approved,
	}
	return out, nil
}

// foreignEntrypointError refuses a manifest at --out that was written for a different
// program. Shared by the write and by the preflight below so the rule is stated once:
// a session refused at the end is one the user has already spent.
func foreignEntrypointError(path, existing, script string) error {
	if existing == script {
		return nil
	}
	return fmt.Errorf("refusing to merge into %s: it is a manifest for %s, not %s - "+
		"profiling would leave it naming one program and granting what the other did. Pass --out to write elsewhere, or delete it",
		path, existing, script)
}

// checkMergeable refuses before the profiling session what mergeExisting would refuse
// after it. The write is the enforcement point - a manifest can be replaced while the
// session runs - but finding out that the result cannot be written only once an
// interactive granting session has converged throws the whole session away. A missing
// file is the ordinary first run; every other refusal is worded exactly as the write's,
// because it is the same refusal arriving earlier.
//
// It does not replace the checks at the write: the file can be replaced while the
// session runs, so what this reads is not necessarily what the merge will.
func checkMergeable(path, script string) error {
	doc, _, err := loadDocument(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("refusing to overwrite existing manifest %s: %w", path, err)
	}
	if err := manifest.Resolve(doc.Policy, path); err != nil {
		return err
	}
	return foreignEntrypointError(path, doc.Policy.Entrypoint, script)
}

// only returns the entries of a that b does not carry - the grants that survive a merge
// because the existing manifest held them, not because this run showed them.
func only(a, b []string) []string {
	var out []string
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

// writeMergeNotice says what folding this run's proposal into an existing manifest
// changed. Profiling ends by sending the user to validate and approve, so this is the
// last thing said before they review: a manifest that is partly the session they watched
// and partly a file they are not being shown, with an exec the union may have widened
// and an approval this write has just dropped.
func writeMergeNotice(w io.Writer, path string, m mergeOutcome) {
	if !m.widened {
		fmt.Fprintf(w, "[bento] it reflects only this run; profile again with other inputs to widen it.\n")
		return
	}
	fmt.Fprintf(w, "[bento] %s already existed, so this widened it rather than replacing it - it reflects\n", path)
	fmt.Fprintf(w, "[bento] this run unioned with what was already there.\n")
	// Quoted for the reason every host-enumerated path in this frontend is: these came
	// off a file bento did not write, and a grant holding a newline would otherwise forge
	// a line of bento's own.
	for _, group := range []struct {
		kind string
		kept []string
	}{{"read", m.keptRead}, {"write", m.keptWrite}, {"env", m.keptEnv}, {"network", m.keptNetwork}} {
		for _, g := range group.kept {
			fmt.Fprintf(w, "[bento]   kept from the existing manifest, not shown by this run: %s %q\n", group.kind, g)
		}
	}
	if m.execWidened {
		fmt.Fprintf(w, "[bento] exec was widened to `all` by this run: the manifest no longer blocks subprocesses.\n")
	}
	if m.approvalVoided {
		fmt.Fprintf(w, "[bento] its approval is gone - a re-profile rewrites the provenance block, so review\n")
		fmt.Fprintf(w, "[bento] the widened policy and `bento approve` it again.\n")
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
