package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/whiskeyjimbo/bento/backend"
	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/manifest"
	"github.com/whiskeyjimbo/bento/policy"
)

func newRunCmd() *cobra.Command {
	var (
		strict          bool
		allowDegraded   bool
		allowUnapproved bool
		envFlags        []string
		acceptAliases   []string
		asJSON          bool
	)

	cmd := &cobra.Command{
		Use:   "run <manifest>",
		Short: "Run a script under the permissions its manifest declares",
		Long: "run enforces the manifest's policy and executes the script.\n\n" +
			"The script's exit code is passed through untouched. If bento itself could not\n" +
			"run the script - a bad manifest, or a guarantee this host cannot enforce - it\n" +
			"exits 125, following the convention env(1) and docker use for \"the command\n" +
			"could not be executed\", so it is distinct from any code the script itself returns.\n" +
			"Under --strict a script that ran while a guarantee it needed lapsed mid-run exits\n" +
			"126, distinct from both.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			overrides, err := parseEnvFlags(envFlags)
			if err != nil {
				return err
			}
			// Parse the manifest once: the same bytes are approval-checked and executed,
			// so a swap between two opens cannot run a different policy than the one
			// approved.
			doc, err := loadDocument(args[0])
			if err != nil {
				return err
			}
			if err := requireApproval(doc, allowUnapproved); err != nil {
				return err
			}
			// Resolve paths for execution only after the fingerprint check above, which
			// must see the manifest as written.
			p := doc.Policy
			resolveManifestPaths(p, args[0])
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

			// In --json mode the script's streams are captured into the envelope
			// rather than shared with bento's own stdout - otherwise the script's
			// output interleaves with the JSON and corrupts the machine contract.
			proc := enforce.Process{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Env: env}
			var out, errOut bytes.Buffer
			if asJSON {
				proc.Stdin, proc.Stdout, proc.Stderr = nil, &out, &errOut
			}

			res, err := enforce.Run(cmd.Context(), e, p, proc, enforce.Options{
				Strict:             strict,
				AllowDegraded:      allowDegraded,
				AcceptAliasesUnder: acceptAliases,
			})
			return writeRunResult(os.Stdout, os.Stderr, asJSON, p, res, out.String(), errOut.String(), err)
		},
	}

	cmd.Flags().BoolVar(&strict, "strict", false, "refuse to run unless every guarantee the policy needs is fully enforced")
	cmd.Flags().BoolVar(&allowDegraded, "allow-degraded", false, "run even when a core guarantee can only be partially enforced")
	cmd.Flags().StringArrayVar(&acceptAliases, "accept-alias", nil, "acknowledge the credential aliases under a host tree (a snapshot or deduplicated backup) instead of refusing; repeatable; --allow-degraded never scans for aliases at all, so it exposes them rather than acknowledging them")
	cmd.Flags().BoolVar(&allowUnapproved, "allow-unapproved", false, "run even if the manifest is unapproved or its approval is stale (the profile-then-run inner loop)")
	cmd.Flags().StringArrayVar(&envFlags, "env", nil, "supply a value for an allowlisted env var (NAME=VALUE); repeatable")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit machine-readable output instead of the script's own streams being summarized")
	return cmd
}

// writeRunResult turns the outcome of enforce.Run into the frontend's contract: it
// writes the human or --json output and returns the error the command propagates. The
// exit-code mapping is the load-bearing invariant - a refusal (bento could not run the
// script) becomes exitError{bentoFailed}, distinct from the target's own code, which is
// passed through untouched via exitError{res.ExitCode}. capturedOut/capturedErr are the
// target's streams, captured only in --json mode (empty otherwise, where they went
// straight to the real streams).
func writeRunResult(stdout, stderr io.Writer, asJSON bool, p *policy.Policy, res enforce.Result, capturedOut, capturedErr string, runErr error) error {
	var (
		refusal   *enforce.Refusal
		shortfall *enforce.Shortfall
	)
	switch {
	case errors.As(runErr, &refusal):
		if asJSON {
			_ = writeJSON(stdout, struct {
				Refused bool       `json:"refused"`
				Reason  string     `json:"reason"`
				Report  reportJSON `json:"report"`
			}{true, refusal.Reason, toReportJSON(refusal.Report)})
			return &exitError{code: bentoFailed}
		}
		return runErr
	case errors.As(runErr, &shortfall):
		// The target ran, so its output and report are reported exactly as a clean run's
		// are; only the exit code differs, below.
	case runErr != nil:
		return runErr
	}

	if asJSON {
		// The script already ran and its exit code is the result. If writing the
		// JSON envelope fails (a redirected stdout that is full or gone), reporting
		// that as bentoFailed would overwrite the real exit code with 125 - a lie
		// that bento could not run the script. Warn and still pass the code through.
		if err := writeJSON(stdout, struct {
			ExitCode          int          `json:"exit_code"`
			Stdout            string       `json:"stdout"`
			Stderr            string       `json:"stderr"`
			EgressConnections int          `json:"egress_connections"`
			ShieldedGrants    []string     `json:"shielded_grants,omitempty"`
			Shields           []shieldJSON `json:"shields,omitempty"`
			Exposed           []shieldJSON `json:"exposed,omitempty"`
			AcceptedAliases   []aliasJSON  `json:"accepted_aliases,omitempty"`
			Report            reportJSON   `json:"report"`
			// StrictShortfall says the run was admitted under --strict but a guarantee it
			// required lapsed while the target ran, so exit_code below is the code of a run
			// whose posture did not hold. Without it a machine consumer reading the envelope
			// alone would see an ordinary completed run.
			StrictShortfall bool `json:"strict_shortfall,omitempty"`
		}{res.ExitCode, capturedOut, capturedErr, res.EgressConnections, res.ShieldedGrants, toShieldsJSON(res.Shields), toShieldsJSON(res.Exposed), toAliasesJSON(res.AcceptedAliases), toReportJSON(res.Report), shortfall != nil}); err != nil {
			fmt.Fprintf(stderr, "[bento] warning: could not encode the JSON result: %v\n", err)
		}
	} else {
		writeAcceptedAliasWarning(stderr, res)
		writeShieldSummary(stderr, res)
		writeShieldedGrantWarning(stderr, res)
		writeExposedWarning(stderr, res)
		writeDegradations(stderr, res.Report)
		writeEgressHint(stderr, p, res)
	}

	// The script ran under --strict, but a guarantee strict required lapsed during the
	// run. Passing the script's own code through would report a clean run over a
	// posture that did not hold, which is the one thing strict exists to prevent - so
	// it gets its own code, distinct from both.
	if shortfall != nil {
		if !asJSON {
			fmt.Fprintf(stderr, "[bento] %v\n", shortfall)
		}
		return &exitError{code: strictShortfall}
	}
	// The script ran; its exit code is the result, passed up so cleanup
	// unwinds before the process exits.
	return &exitError{code: res.ExitCode}
}

// requireApproval refuses to run a manifest whose approval is not current. The stamp
// attests that the permissions have not changed since it was written, so a manifest
// edited after approval (permissions widened) is caught here, not only by `validate
// --strict`. It is drift detection, not authentication: the unkeyed stamp lives in
// the manifest and does not record who wrote it, so a manifest carrying a stamp you
// did not make yourself - a downloaded one stamped by its author - is "approved" only
// in that its permissions match its own stamp; review it before trusting it.
// --allow-unapproved opts out for the profile-then-run inner loop, where a manifest
// is run before a human has stamped it.
func requireApproval(doc *manifest.Document, allow bool) error {
	if allow {
		return nil
	}
	switch checkApproval(doc) {
	case approvalCurrent:
		return nil
	case approvalStale:
		return fmt.Errorf("refusing to run: the manifest's permissions changed since it was approved; " +
			"re-review and run `bento approve`, or pass --allow-unapproved")
	default:
		return fmt.Errorf("refusing to run: the manifest is not approved; " +
			"review it and run `bento approve`, or pass --allow-unapproved")
	}
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
