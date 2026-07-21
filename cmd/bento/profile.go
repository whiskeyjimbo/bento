package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/whiskeyjimbo/bento-v2/backend"
	"github.com/whiskeyjimbo/bento-v2/enforce"
	"github.com/whiskeyjimbo/bento-v2/internal/denylist"
	"github.com/whiskeyjimbo/bento-v2/manifest"
	"github.com/whiskeyjimbo/bento-v2/policy"
	"github.com/whiskeyjimbo/bento-v2/profile"
)

func newProfileCmd() *cobra.Command {
	var (
		interpreter  string
		out          string
		allowNetwork bool
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
			"profile again to converge; grants are merged, not overwritten.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			script, err := filepath.Abs(args[0])
			if err != nil {
				return err
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
			}
			base := discoveryPolicy(script, interpreter, args[1:])

			var proposed *policy.Policy
			if interactiveStdin() {
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
				fmt.Fprintf(os.Stderr, "[bento] profiling %s under default-deny; grant what it needs to converge (real content is mounted only for paths you accept)...\n", args[0])
				round := func(d *policy.Policy) (*policy.Policy, error) { return profileRound(cfg, d) }
				proposed, err = converge(base, round, newGrantPrompter(tty, os.Stderr), os.Stderr)
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
				proposed, err = profileRound(cfg, base)
			}
			if err != nil {
				return err
			}

			// Merge into an existing manifest rather than overwriting it, so a second
			// profile run widens the policy instead of replacing it.
			proposed, err = mergeExisting(out, proposed)
			if err != nil {
				return err
			}

			doc := manifest.Provenance{
				GeneratedBy: "bento profile",
				GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			}
			data, err := manifest.Marshal(proposed, doc)
			if err != nil {
				return err
			}
			if err := os.WriteFile(out, data, 0o644); err != nil {
				return err
			}

			fmt.Fprintf(os.Stderr, "\n[bento] wrote %s - review it, then run `bento validate %s` and `bento approve %s`.\n", out, out, out)
			fmt.Fprintf(os.Stderr, "[bento] it reflects only this run; profile again with other inputs to widen it.\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&interpreter, "interpreter", "", "interpreter to run the script with (guessed from the extension if omitted)")
	cmd.Flags().StringVar(&out, "out", "", "manifest path to write (default: <script>.manifest.yaml)")
	cmd.Flags().BoolVar(&allowNetwork, "allow-network", false, "let the script's network traffic reach the host during profiling (default: record destinations but do not forward them)")
	return cmd
}

// profileConfig carries the inputs a profiling round needs that do not change between
// rounds, so the convergence loop can re-run rounds without re-threading them.
type profileConfig struct {
	ctx          context.Context
	script       string
	interpreter  string
	args         []string
	env          map[string]string
	allowNetwork bool
	targetStdin  io.Reader // the profiled target's stdin: os.Stdin for a single pass, nil in the interactive loop where the human answers prompts instead
}

// profileRound runs one profiling pass under discovery and returns the clamped
// proposal of what the target attempted (reads, writes, exec, network), printing the
// round's shield and broad-grant warnings. It is the unit the convergence loop repeats
// with a widening grant set; discovery carries the grants accepted so far, mounted with
// real content so the target proceeds past accesses it already has.
func profileRound(cfg profileConfig, discovery *policy.Policy) (*policy.Policy, error) {
	obs, err := backend.Profile(cfg.ctx, discovery,
		enforce.Process{Stdin: cfg.targetStdin, Stdout: os.Stderr, Stderr: os.Stderr, Env: cfg.env},
		backend.ProfileOptions{AllowNetwork: cfg.allowNetwork})
	if err != nil {
		return nil, err
	}
	// A run that was signaled or exited nonzero may have stopped before exercising all
	// its code paths, so the observations - and the manifest synthesized from them - can
	// be silently over-tight. Warn before proposing it.
	if w := partialRunWarning(obs); w != "" {
		fmt.Fprintln(os.Stderr, w)
	}
	proposed := profile.Synthesize(cfg.script, cfg.interpreter, obs)
	// Allowlist the discovery env so the enforced run rebuilds $HOME-relative paths to
	// the same names profiling recorded and granted.
	proposed.Env = sortedKeys(cfg.env)
	printProposalWarnings(proposed)
	return proposed, nil
}

// printProposalWarnings clamps p in place (dropping shielded credential paths and
// over-broad grants from the auto-proposal) and prints why each was withheld, so a
// path the tool wants but bento will not auto-grant is never silently missing.
func printProposalWarnings(p *policy.Policy) {
	shielded, broadReads, broadWrites := clampProposal(p)
	for _, d := range shielded {
		fmt.Fprintf(os.Stderr, "[bento] not proposing access to %q - it is a shielded credential path, not granted automatically. The script's attempt was recorded; if it genuinely needs it, add a read:/write: grant for that path by hand - the run then exposes it and warns you each time.\n", d)
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

// converge repeats profiling rounds, mounting the grants the user accepts so a
// content-branching target proceeds past its error branch and reveals the next layer
// of accesses, until a round surfaces nothing new. round is the profiling seam (the
// real backend-backed profileRound in production, a fake in tests): it receives the
// discovery policy carrying the accepted grants and returns the clamped proposal.
// prompt asks about one newly-attempted path; declining it (or anything but yes/all)
// leaves it recorded-only and never mounts it - the consent that keeps real content off
// a path the user did not approve. It returns the final proposal with reads/writes
// narrowed to exactly the accepted set.
func converge(base *policy.Policy, round func(*policy.Policy) (*policy.Policy, error), prompt func(kind, path string) (grantChoice, error), out io.Writer) (*policy.Policy, error) {
	acceptedR := map[string]bool{}
	acceptedW := map[string]bool{}
	declined := map[string]bool{} // key() -> asked and refused, so it is not re-asked
	acceptAll := false
	accept := func(it grantItem) {
		if it.kind == "read" {
			acceptedR[it.path] = true
		} else {
			acceptedW[it.path] = true
		}
	}

	var last *policy.Policy
loop:
	for r := 1; ; r++ {
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
			return nil, err
		}
		last = proposal
		items := newGrants(proposal, acceptedR, acceptedW, declined)
		if len(items) == 0 {
			fmt.Fprintf(out, "[bento] round %d: no new attempted paths - converged.\n", r)
			break
		}
		fmt.Fprintf(out, "[bento] round %d: the target attempted %d new path(s):\n", r, len(items))
		for _, it := range items {
			if acceptAll {
				accept(it)
				continue
			}
			c, err := prompt(it.kind, it.path)
			if err != nil {
				return nil, err
			}
			switch c {
			case grantAll:
				acceptAll = true
				accept(it)
			case grantYes:
				accept(it)
			case grantQuit:
				break loop
			default: // grantNo and any unrecognized answer: decline, do not re-ask
				declined[it.key()] = true
			}
		}
	}

	final := last
	final.Read = sortedBoolKeys(acceptedR)
	final.Write = sortedBoolKeys(acceptedW)
	return final, nil
}

// grantItem is one filesystem access the target attempted but has not been granted yet.
type grantItem struct{ kind, path string } // kind is "read" or "write"

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
		fmt.Fprintf(out, "[bento]   grant %s %s? [y]es / [n]o / [a]ll / [q]uit > ", kind, path)
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
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
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
	sort.Strings(out)
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
// mislead) and XDG_RUNTIME_DIR (it points into the always-shielded runtime directory,
// which no grant can honor).
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
	sort.Strings(keys)
	return keys
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
func clampShieldedGrants(reads, writes []string) (keptReads, keptWrites, dropped []string) {
	home, _ := os.UserHomeDir()
	// A relative home yields relative shield paths that never match the absolute grants
	// below, silently keeping a grant this filter meant to drop. Treat it like an unset
	// home and skip the clamp; the run-time refusal is the backstop either way.
	if home == "" || !filepath.IsAbs(home) {
		return reads, writes, nil
	}
	// Build shields against both the home as configured and its symlink-resolved form.
	// A symlinked home (Fedora Silverblue's /home -> /var/home) means an observed
	// credential path can arrive resolved (/var/home/u/.ssh, anchored at a resolved cwd)
	// while $HOME is the unresolved /home/u, or the reverse; shielding against both
	// forms drops the grant either way. It only ever adds matches, so a grant is never
	// wrongly kept. A home that does not resolve (nonexistent) falls back to raw.
	homes := []string{home}
	if resolved, err := filepath.EvalSymlinks(home); err == nil && resolved != home {
		homes = append(homes, resolved)
	}
	seenShield := map[string]bool{}
	var shields []string
	for _, h := range homes {
		for _, r := range denylist.Home(h) {
			if r.Deny == denylist.DenyAll && !seenShield[r.Path] {
				seenShield[r.Path] = true
				shields = append(shields, r.Path)
			}
		}
	}
	inShield := func(g string) bool {
		for _, s := range shields {
			if g == s || underDir(s, g) {
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
	return filter(reads), filter(writes), dropped
}

// foreignHomeShields returns the proposed grants that reach a shielded path under a home
// directory other than the profiler's own. clampShieldedGrants drops grants inside the
// PROFILER's home shields, but a script that reaches a protected path under a different
// home - profiled under sudo (HOME=/root) touching /home/u/.ssh, or with HOME unset so
// the clamp is skipped - is not clamped and lands in the proposal. It is reported, not
// dropped: a home-shaped heuristic strong enough to drop on would also gut legitimate
// cross-home data grants (/home/u/project/data), so the reviewer decides.
//
// The match against denylist.Home(root) tests containment in EITHER direction: a grant
// at or under a shield (write: ~/.ssh/id_rsa), and - the case that matters most - a grant
// that ENCLOSES a shield (write: ~, which Synthesize produces by collapsing a file write
// to its directory, sweeping in ~/.ssh). For the profiler's own home clampShieldedGrants
// can safely keep an enclosing grant because the enforced run re-shields the interior;
// for a foreign home it cannot, since the run shields only the home it executes as, so
// both directions must warn. Both shield classes count - a foreign DenyWrite persistence
// path (~/.config/systemd/user) is unshielded at run time just like a DenyAll credential.
// A data path enclosing no shield still stays quiet.
func foreignHomeShields(grants []string) []string {
	self, _ := os.UserHomeDir()
	selves := map[string]bool{}
	if filepath.IsAbs(self) {
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
		for _, r := range denylist.Home(root) {
			if g == r.Path || underDir(r.Path, g) || underDir(g, r.Path) {
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

// underDir reports whether child is inside parent (parent contains child).
func underDir(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
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
func clampProposal(p *policy.Policy) (shielded, broadReads, broadWrites []string) {
	p.Read, p.Write, shielded = clampShieldedGrants(p.Read, p.Write)
	p.Write, broadWrites = clampBroadWrites(p.Write)
	p.Read, broadReads = clampBroadReads(p.Read)
	p.Read = profile.DropCovered(p.Read, p.Write)
	return shielded, broadReads, broadWrites
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
	// Clean the home value: proposal paths are already filepath.Clean'd (Synthesize),
	// so a $HOME carrying a trailing slash would otherwise never compare equal and the
	// whole home tree would slip through as a non-broad grant.
	home, _ := os.UserHomeDir()
	return home != "" && path == filepath.Clean(home)
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

// mergeExisting folds proposed into an existing manifest at path so re-profiling
// widens rather than replaces it. A path that does not exist is the first run, so
// proposed is returned unchanged. Any other load error means a file is present at
// --out that cannot be parsed; overwriting it would silently discard whatever grants
// it held - contradicting the merge-not-overwrite contract the help text promises -
// so it is refused rather than clobbered.
func mergeExisting(path string, proposed *policy.Policy) (*policy.Policy, error) {
	existing, err := loadDocument(path)
	switch {
	case err == nil:
		return mergePolicies(existing.Policy, proposed), nil
	case errors.Is(err, fs.ErrNotExist):
		return proposed, nil
	default:
		return nil, fmt.Errorf("refusing to overwrite existing manifest %s: %w", path, err)
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
