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
			"124, reserved the same way. A script can return any code itself, so a machine\n" +
			"gate should read --json, where the outcome is a field rather than a code.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Every refusal raised before enforce.Run - a bad --env, an unparseable or
			// unapproved manifest, an env that cannot be resolved, a backend this host
			// cannot provide - goes through refuse, so --json always leaves an envelope
			// on stdout. Returning these bare wrote nothing there, and a machine gate
			// could not tell a refusal from a crash.
			refuse := func(err error) error { return refuseJSON(os.Stdout, asJSON, err) }

			overrides, err := parseEnvFlags(envFlags)
			if err != nil {
				return refuse(err)
			}
			// Parse the manifest once: the same bytes are approval-checked and executed,
			// so a swap between two opens cannot run a different policy than the one
			// approved.
			doc, trust, err := loadDocument(args[0])
			if err != nil {
				return refuse(err)
			}
			warnStampAtRisk(cmd.ErrOrStderr(), doc, trust)
			if err := requireApproval(doc, allowUnapproved); err != nil {
				return refuse(err)
			}
			// Resolve paths for execution only after the fingerprint check above, which
			// must see the manifest as written.
			p := doc.Policy
			if err := manifest.Resolve(p, args[0]); err != nil {
				return refuse(err)
			}
			env, unset, err := enforce.ResolveEnv(p, overrides, os.LookupEnv)
			if err != nil {
				return refuse(err)
			}
			for _, name := range unset {
				fmt.Fprintf(os.Stderr, "[bento] note: env %s is allowed by the manifest but not set on this host; "+
					"the script will not see it. Pass it with --env %s=VALUE.\n", name, name)
			}

			writeBlockedHostNotes(os.Stderr, p, doc.Provenance.BlockedHosts)

			e, err := backend.New()
			if err != nil {
				return refuse(err)
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

	cmd.Flags().BoolVar(&strict, "strict", false, "refuse to run unless every guarantee the policy needs is fully enforced, and report it if one lapses while the script runs")
	cmd.Flags().BoolVar(&allowDegraded, "allow-degraded", false, "run even when a core guarantee can only be partially enforced")
	cmd.Flags().StringArrayVar(&acceptAliases, "accept-alias", nil, "acknowledge the credential aliases under a host tree (a snapshot or deduplicated backup) instead of refusing; repeatable; --allow-degraded never scans for aliases at all, so it exposes them rather than acknowledging them")
	cmd.Flags().BoolVar(&allowUnapproved, "allow-unapproved", false, "run even if the manifest is unapproved or its approval is stale (the profile-then-run inner loop)")
	cmd.Flags().StringArrayVar(&envFlags, "env", nil, "supply a value for an allowlisted env var (NAME=VALUE); repeatable")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit machine-readable output instead of the script's own streams being summarized")
	return cmd
}

// refuseJSON reports a refusal raised before enforce.Run was ever reached in the same
// envelope enforcement's own refusals use, so --json never answers a refusal with an
// empty stdout. Outside --json the error is returned untouched and main renders it;
// inside it, the message is the envelope's reason and the exit code is bentoFailed,
// mirroring the enforcement path exactly - including that nothing is written to stderr.
func refuseJSON(stdout io.Writer, asJSON bool, err error) error {
	if err == nil || !asJSON {
		return err
	}
	_ = writeJSON(stdout, refusalJSON{true, err.Error(), noReport})
	return &exitError{code: bentoFailed}
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
			_ = writeJSON(stdout, refusalJSON{true, refusal.Reason, toReportJSON(refusal.Report)})
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
			ExitCode int `json:"exit_code"`
			// Signal names the signal that killed the sandbox, present only where that is
			// KNOWN: exit_code is 128+signal there. The human output additionally reads a
			// code in that range as a probable signal and says so, hedged; this field does
			// not, because a machine consumer cannot hedge - it would read an inference
			// about a target that chose to exit 137 as the fact that something killed it.
			Signal            int      `json:"signal,omitempty"`
			Stdout            string   `json:"stdout"`
			Stderr            string   `json:"stderr"`
			EgressConnections int      `json:"egress_connections"`
			ShieldedGrants    []string `json:"shielded_grants,omitempty"`
			// ShieldedGrantTargets names what an opted-in grant bound, for the entries where
			// that differs from the spelling. shielded_grants carries the spelling that opted
			// in, and the deny-list builds those spellings from $HOME - so under a
			// caller-chosen environment the name a consumer sees can be a link while the
			// exposure lands elsewhere. Resolved by the backend as it bound them, so a target
			// that moved a symlink mid-run cannot rewrite what this reports.
			ShieldedGrantTargets []grantTargetJSON `json:"shielded_grant_targets,omitempty"`
			// GuardBlocked names the destinations the allowlist permitted but the egress guard
			// refused to dial. The sandbox was told only that it could not connect, so this is
			// the operator's only signal that a permitted name resolved somewhere it must not
			// reach. Each host is the sandbox's own CONNECT target, so a consumer rendering it
			// is rendering attacker-chosen bytes.
			GuardBlocked    []hostPortJSON `json:"guard_blocked,omitempty"`
			Shields         []shieldJSON   `json:"shields,omitempty"`
			Exposed         []shieldJSON   `json:"exposed,omitempty"`
			AcceptedAliases []aliasJSON    `json:"accepted_aliases,omitempty"`
			Report          reportJSON     `json:"report"`
			// StrictShortfall says the run was admitted under --strict but a guarantee it
			// required lapsed while the target ran, so exit_code below is the code of a run
			// whose posture did not hold. Without it a machine consumer reading the envelope
			// alone would see an ordinary completed run.
			StrictShortfall bool `json:"strict_shortfall,omitempty"`
		}{res.ExitCode, res.Signal, capturedOut, capturedErr, res.EgressConnections, res.ShieldedGrants, toShieldedTargetsJSON(res.ShieldedGrantTargets), toHostPortsJSON(res.GuardBlocked), toShieldsJSON(res.Shields), toShieldsJSON(res.Exposed), toAliasesJSON(res.AcceptedAliases), toReportJSON(res.Report), shortfall != nil}); err != nil {
			fmt.Fprintf(stderr, "[bento] warning: could not encode the JSON result: %v\n", err)
		}
	} else {
		writeAcceptedAliasWarning(stderr, res)
		writeShieldSummary(stderr, res)
		writeShieldedGrantWarning(stderr, res)
		writeExposedWarning(stderr, res)
		writeDegradations(stderr, res.Report)
		// Before the bypass hint: a guard block is a connection that DID reach the proxy,
		// so it explains a network failure the hint would otherwise blame on a bypass.
		writeGuardBlockedWarning(stderr, res)
		// Last, and only where nothing above already explained the failure. A signal
		// death is not a script failure at all, a strict shortfall gets its own line
		// below, and a guard block is a destination no amount of profiling will widen
		// the manifest into reaching - pointing at profile in any of those sends the
		// reader at the wrong problem.
		if !writeSignalNotice(stderr, p, res) && !writeEgressHint(stderr, p, res) &&
			shortfall == nil && len(res.GuardBlocked) == 0 {
			writeProfileHint(stderr, p, res)
		}
	}

	// The script ran under --strict, but a guarantee strict required lapsed during the
	// run. Passing the script's own code through would report a clean run over a
	// posture that did not hold, which is the one thing strict exists to prevent - so
	// it gets its own code, distinct from both.
	if shortfall != nil {
		if !asJSON {
			// writeDegradations above already named each layer that fell short, so this
			// says only what the report cannot: the script ran anyway, and under --strict
			// that makes its exit code no longer the answer.
			fmt.Fprintln(stderr, "[bento] --strict: the script ran, but the guarantees above did not hold for the whole run, so its exit code is not reported.")
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
