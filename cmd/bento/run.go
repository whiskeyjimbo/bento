package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/whiskeyjimbo/bento-v2/internal/backend"
	"github.com/whiskeyjimbo/bento-v2/internal/enforce"
)

func newRunCmd() *cobra.Command {
	var (
		strict        bool
		allowDegraded bool
		envFlags      []string
		asJSON        bool
	)

	cmd := &cobra.Command{
		Use:   "run <manifest>",
		Short: "Run a script under the permissions its manifest declares",
		Long: "run enforces the manifest's policy and executes the script.\n\n" +
			"The script's exit code is passed through. If bento itself could not run the\n" +
			"script — a bad manifest, or a guarantee this host cannot enforce — it exits 2.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			overrides, err := parseEnvFlags(envFlags)
			if err != nil {
				return err
			}
			p, err := loadManifest(args[0])
			if err != nil {
				return err
			}
			env, unset, err := enforce.ResolveEnv(p, overrides, os.LookupEnv)
			if err != nil {
				return err
			}
			for _, name := range unset {
				fmt.Fprintf(os.Stderr, "[bento] note: env %s is allowed by the manifest but not set on this host; "+
					"the script will not see it. Pass it with --env %s=VALUE.\n", name, name)
			}

			e, err := backend.New()
			if err != nil {
				return err
			}

			proc := enforce.Process{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Env: env}
			res, err := enforce.Run(cmd.Context(), e, p, proc, enforce.Options{
				Strict:        strict,
				AllowDegraded: allowDegraded,
			})

			var refusal *enforce.Refusal
			if errors.As(err, &refusal) {
				if asJSON {
					_ = writeJSON(os.Stdout, struct {
						Refused bool       `json:"refused"`
						Reason  string     `json:"reason"`
						Report  reportJSON `json:"report"`
					}{true, refusal.Reason, toReportJSON(refusal.Report)})
				}
				return err
			}
			if err != nil {
				return err
			}

			if asJSON {
				return writeJSON(os.Stdout, struct {
					ExitCode int        `json:"exit_code"`
					Report   reportJSON `json:"report"`
				}{res.ExitCode, toReportJSON(res.Report)})
			}
			writeDegradations(os.Stderr, res.Report)

			// The script ran; its exit code is the command's result, not bento's.
			os.Exit(res.ExitCode)
			return nil
		},
	}

	cmd.Flags().BoolVar(&strict, "strict", false, "refuse to run unless every guarantee the policy needs is fully enforced")
	cmd.Flags().BoolVar(&allowDegraded, "allow-degraded", false, "run even when a core guarantee can only be partially enforced")
	cmd.Flags().StringArrayVar(&envFlags, "env", nil, "supply a value for an allowlisted env var (NAME=VALUE); repeatable")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit machine-readable output instead of the script's own streams being summarized")
	return cmd
}

func parseEnvFlags(flags []string) (map[string]string, error) {
	if len(flags) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(flags))
	for _, f := range flags {
		name, value, ok := strings.Cut(f, "=")
		if !ok || name == "" {
			return nil, fmt.Errorf("--env %q: want NAME=VALUE", f)
		}
		out[name] = value
	}
	return out, nil
}
