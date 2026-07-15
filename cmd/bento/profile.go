package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/whiskeyjimbo/bento-v2/internal/backend"
	"github.com/whiskeyjimbo/bento-v2/internal/enforce"
	"github.com/whiskeyjimbo/bento-v2/internal/manifest"
	"github.com/whiskeyjimbo/bento-v2/internal/policy"
	"github.com/whiskeyjimbo/bento-v2/internal/profile"
)

func newProfileCmd() *cobra.Command {
	var (
		interpreter string
		out         string
	)
	cmd := &cobra.Command{
		Use:   "profile <script> [-- args...]",
		Short: "Run a script under observation and propose a manifest",
		Long: "profile runs the script permissively while observing what it opens and where\n" +
			"it connects, then writes a proposed manifest tightened to just that.\n\n" +
			"WARNING: profiling runs the script — do it on code you are willing to execute,\n" +
			"in a context you trust. Mandatory-deny paths (credentials, SSH keys) stay\n" +
			"shielded even during profiling, but the script otherwise runs with broad\n" +
			"access. Review the proposed manifest, then `bento approve` it.\n\n" +
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
			// the deny-list still shields credentials.
			permissive := &policy.Policy{
				Entrypoint:  script,
				Interpreter: interpreter,
				Args:        args[1:],
				Read:        []string{"/"},
				Write:       []string{filepath.Dir(script), "/tmp"},
				Network:     []policy.NetworkRule{{Host: "*", Port: "*"}},
				Exec:        policy.ExecAll,
			}

			fmt.Fprintf(os.Stderr, "[bento] profiling %s permissively...\n", args[0])
			obs, err := backend.Profile(cmd.Context(), permissive,
				enforce.Process{Stdin: os.Stdin, Stdout: os.Stderr, Stderr: os.Stderr})
			if err != nil {
				return err
			}

			proposed := profile.Synthesize(script, interpreter, obs)

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

			fmt.Fprintf(os.Stderr, "\n[bento] wrote %s — review it, then run `bento validate %s` and `bento approve %s`.\n", out, out, out)
			fmt.Fprintf(os.Stderr, "[bento] it reflects only this run; profile again with other inputs to widen it.\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&interpreter, "interpreter", "", "interpreter to run the script with (guessed from the extension if omitted)")
	cmd.Flags().StringVar(&out, "out", "", "manifest path to write (default: <script>.manifest.yaml)")
	return cmd
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
