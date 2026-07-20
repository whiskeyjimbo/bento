package main

import (
	"fmt"
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

			discovery := discoveryPolicy(script, interpreter, args[1:])

			// Run with the real HOME (and the config-anchor vars derived from it) so a
			// $HOME-relative probe names the real host path, which the observer records
			// even though default-deny leaves that path unmounted. The same names go
			// into the proposed manifest's env allowlist below so the enforced run
			// rebuilds the identical paths; if they diverge the grant would not match.
			env := discoveryEnv()

			if allowNetwork {
				fmt.Fprintf(os.Stderr, "[bento] profiling %s under default-deny (egress allowed)...\n", args[0])
			} else {
				fmt.Fprintf(os.Stderr, "[bento] profiling %s under default-deny (egress recorded, not forwarded; --allow-network to permit)...\n", args[0])
			}
			obs, err := backend.Profile(cmd.Context(), discovery,
				enforce.Process{Stdin: os.Stdin, Stdout: os.Stderr, Stderr: os.Stderr, Env: env},
				backend.ProfileOptions{AllowNetwork: allowNetwork})
			if err != nil {
				return err
			}

			// A run that was signaled or exited nonzero may have stopped before
			// exercising all its code paths, so the observations - and the manifest
			// synthesized from them - can be silently over-tight. Warn before writing it.
			if w := partialRunWarning(obs); w != "" {
				fmt.Fprintln(os.Stderr, w)
			}

			proposed := profile.Synthesize(script, interpreter, obs)
			// Allowlist the discovery env so the enforced run rebuilds $HOME-relative
			// paths to the same names profiling recorded and granted.
			proposed.Env = sortedKeys(env)

			shielded, broadReads, broadWrites := clampProposal(proposed)
			for _, d := range shielded {
				fmt.Fprintf(os.Stderr, "[bento] not proposing access to %q - it is a shielded credential path, not granted automatically. The script's attempt was recorded; if it genuinely needs it, add a read:/write: grant for that path by hand - the run then exposes it and warns you each time.\n", d)
			}
			for _, d := range broadReads {
				fmt.Fprintf(os.Stderr, "[bento] not proposing read access to %q - too broad to grant automatically (it would re-expose every credential the deny-list does not enumerate); the specific paths under it the script actually read are proposed on their own, so add a narrower read: directory by hand only if it needs more.\n", d)
			}
			for _, d := range broadWrites {
				fmt.Fprintf(os.Stderr, "[bento] not proposing write access to %q - too broad to grant automatically; add a narrower write: directory by hand if the script needs it.\n", d)
			}

			// Merge into an existing manifest rather than overwriting it, so a second
			// profile run widens the policy instead of replacing it.
			if existing, err := loadDocument(out); err == nil {
				proposed = mergePolicies(existing.Policy, proposed)
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
	var shields []string
	for _, r := range denylist.Home(home) {
		if r.Deny == denylist.DenyAll {
			shields = append(shields, r.Path)
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
