package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/whiskeyjimbo/bento-v2/backend"
	"github.com/whiskeyjimbo/bento-v2/enforce"
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
		Long: "profile runs the script permissively while observing what it opens and where\n" +
			"it connects, then writes a proposed manifest tightened to just that.\n\n" +
			"WARNING: profiling executes the script with broad read access so it runs\n" +
			"its real code paths. Only profile code you would run unsandboxed, in a\n" +
			"context you trust. A built-in set of sensitive paths (SSH keys, cloud and\n" +
			"VCS credentials) stays shielded, but that list is not exhaustive - assume\n" +
			"the script can read anything else. Egress is recorded but not forwarded by\n" +
			"default, so the script's data stays on the host; --allow-network forwards it\n" +
			"for a faithful run of network-dependent code. Review the proposed manifest,\n" +
			"then `bento approve` it.\n\n" +
			"The proposal reflects only the code paths this run exercised; profile again\n" +
			"with different inputs to widen it (grants are merged, not overwritten).",
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

			// A permissive policy so the run exercises the script's real behavior;
			// the deny-list still shields the known-sensitive paths. Write is granted
			// only to the script's own directory: the sandbox already provides a
			// private writable /tmp, so granting host /tmp is both unnecessary and
			// unsafe (it would overmount the private tmpfs with the real one). Writes
			// elsewhere still fail during the run but are observed as intent.
			permissive := &policy.Policy{
				Entrypoint:  script,
				Interpreter: interpreter,
				Args:        args[1:],
				Read:        []string{"/"},
				Write:       []string{filepath.Dir(script)},
				Network:     []policy.NetworkRule{{Host: "*", Port: "*"}},
				Exec:        policy.ExecAll,
			}

			if allowNetwork {
				fmt.Fprintf(os.Stderr, "[bento] profiling %s permissively (egress allowed)...\n", args[0])
			} else {
				fmt.Fprintf(os.Stderr, "[bento] profiling %s permissively (egress recorded, not forwarded; --allow-network to permit)...\n", args[0])
			}
			obs, err := backend.Profile(cmd.Context(), permissive,
				enforce.Process{Stdin: os.Stdin, Stdout: os.Stderr, Stderr: os.Stderr},
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

			// A write to a file directly in a broad directory (the home directory, a
			// top-level system directory, or the root) collapses to a grant of that
			// whole directory, since write grants are directory-granular. Refuse to
			// propose such a grant automatically - it would expose far more than the
			// script needs - and tell the user to add a narrower one by hand.
			if kept, dropped := clampBroadWrites(proposed.Write); len(dropped) > 0 {
				proposed.Write = kept
				for _, d := range dropped {
					fmt.Fprintf(os.Stderr, "[bento] not proposing write access to %q - too broad to grant automatically; add a narrower write: directory by hand if the script needs it.\n", d)
				}
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

// clampBroadWrites splits proposed write directories into those safe to grant
// automatically and those too broad to. A directory is too broad if it is the
// root, a top-level directory (a direct child of "/", such as /etc or /home), or
// the user's home directory itself - granting write to any of those exposes far
// more than a profiled script needs.
func clampBroadWrites(writes []string) (kept, dropped []string) {
	home, _ := os.UserHomeDir()
	for _, w := range writes {
		switch {
		case w == "/", filepath.Dir(w) == "/", home != "" && w == home:
			dropped = append(dropped, w)
		default:
			kept = append(kept, w)
		}
	}
	return kept, dropped
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
		Env:         base.Env,
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
