package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

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
		Args:        exactArgs(1, "a manifest path"),
		Annotations: map[string]string{jsonRefusalAnnotation: "yes"},
		RunE: func(cmd *cobra.Command, args []string) error {
			// Every refusal raised before enforce.Run - a bad --env, an unparseable or
			// unapproved manifest, an env that cannot be resolved, a backend this host
			// cannot provide - goes through refuse, so --json always leaves an envelope
			// on stdout. Returning these bare wrote nothing there, and a machine gate
			// could not tell a refusal from a crash.
			refuse := func(err error) error { return refuseJSON(os.Stdout, asJSON, err) }

			// Rejected here rather than with MarkFlagsMutuallyExclusive, which refuses
			// before RunE and so would leave --json an empty stdout.
			if strict && allowDegraded {
				return refuse(errors.New("--strict and --allow-degraded are opposites: strict refuses anything less " +
					"than full enforcement, allow-degraded opts into less. Pass one"))
			}

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

			// Statted before the script runs, and carried through to the envelope, so
			// what --json reports is the same verdict the note above gave: a grant the
			// script itself then created was still missing when the run started.
			missingReads := missingReadGrants(p.Read)
			writeMissingReadNotes(os.Stderr, missingReads)
			writeBlockedHostNotes(os.Stderr, p, doc.Provenance.BlockedHosts)

			e, err := backend.New()
			if err != nil {
				return refuse(err)
			}

			// In --json mode the script's streams are captured into the envelope
			// rather than shared with bento's own stdout - otherwise the script's
			// output interleaves with the JSON and corrupts the machine contract.
			// They are also copied to stderr as they arrive, since the envelope alone
			// says nothing until the script exits: a pipeline running a long build
			// under bento would show no logs at all, and none if it was killed on a
			// timeout. One writer for both, because exec pumps them from separate
			// goroutines and unsynchronized writes would splice their lines together.
			proc := enforce.Process{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Env: env}
			var out, errOut bytes.Buffer
			if asJSON {
				live := &syncWriter{w: os.Stderr}
				proc.Stdin = nil
				proc.Stdout = io.MultiWriter(&out, live)
				proc.Stderr = io.MultiWriter(&errOut, live)
			}

			res, err := enforce.Run(cmd.Context(), e, p, proc, enforce.Options{
				Strict:             strict,
				AllowDegraded:      allowDegraded,
				AcceptAliasesUnder: acceptAliases,
			})
			return writeRunResult(os.Stdout, os.Stderr, asJSON, p, res, missingReads, out.String(), errOut.String(), err)
		},
	}

	cmd.Flags().BoolVar(&strict, "strict", false, "refuse to run unless every guarantee the policy needs is fully enforced, and report it if one lapses while the script runs")
	cmd.Flags().BoolVar(&allowDegraded, "allow-degraded", false, "run even when a core guarantee can only be partially enforced; the widest escape hatch there is - the degraded tier it selects never scans for aliases at all, so it exposes them rather than acknowledging them")
	cmd.Flags().StringArrayVar(&acceptAliases, "accept-alias", nil, "acknowledge the credential aliases under a host tree (a snapshot or deduplicated backup) instead of refusing; repeatable; --allow-degraded never scans for aliases at all, so it exposes them rather than acknowledging them")
	cmd.Flags().BoolVar(&allowUnapproved, "allow-unapproved", false, "run even if the manifest is unapproved or its approval is stale (the profile-then-run inner loop)")
	cmd.Flags().StringArrayVar(&envFlags, "env", nil, "supply a value for an allowlisted env var (NAME=VALUE); repeatable")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit a machine-readable envelope on stdout; the script's own streams are carried in it, and copied to stderr as they arrive so a long run still shows progress, but it is given no stdin. A refusal - including a mistake in this command line - is an envelope too, and so is a run that failed part-way, so stdout is never empty. Switch on refused, then failed, then exit_code")
	return cmd
}

// syncWriter serializes writes from the two stream pumps onto one destination, so a
// write that arrives mid-write on the other goroutine follows it instead of splicing
// into it. It holds the lock across the write rather than buffering: the point of the
// live copy is that it appears while the script runs.
//
// It never reports an error, and abandons the destination after the first one. It is
// half of an io.MultiWriter whose other half is the buffer the envelope is built from,
// and MultiWriter stops at the first writer that fails - so a stderr that goes away
// mid-run (a supervisor died, a redirect target closed) would otherwise stop exec from
// draining the target's pipe: the envelope's own streams would be silently truncated
// and the target would block once the pipe filled. The live copy is a courtesy; the
// envelope is the contract, and it must not be able to fail with it.
type syncWriter struct {
	mu   sync.Mutex
	w    io.Writer
	gone bool
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gone {
		return len(p), nil
	}
	if _, err := s.w.Write(p); err != nil {
		s.gone = true
	}
	return len(p), nil
}

// refuseJSON reports a refusal raised before enforce.Run was ever reached in the same
// envelope enforcement's own refusals use, so --json never answers a refusal with an
// empty stdout. Outside --json the error is returned untouched and main renders it;
// inside it, the message is the envelope's reason and the exit code is bentoFailed,
// mirroring the enforcement path exactly - including that nothing is written to stderr.
//
// A host shortfall arrives here as an *enforce.Refusal, which carries the probe that
// judged it: report that rather than noReport, so a consumer reading the envelope alone
// sees which layer fell short. Its Reason, not Error(), for the same reason
// writeRunResult uses it - Error() prepends a verb the caller may not have refused with.
// Shared with `bento profile`, which raises every one of its refusals before any sandbox
// exists.
func refuseJSON(stdout io.Writer, asJSON bool, err error) error {
	if err == nil || !asJSON {
		return err
	}
	reason, report := err.Error(), noReport
	var refusal *enforce.Refusal
	if errors.As(err, &refusal) {
		reason, report = refusal.Reason, toReportJSON(refusal.Report)
	}
	_ = writeJSON(stdout, refusalJSON{true, reason, report})
	return &exitError{code: bentoFailed}
}

// failJSON reports a run that neither refused nor completed - an error from enforce.Run
// that is neither a Refusal nor a Shortfall - so --json answers it with an envelope
// instead of an empty stdout. Outside --json the error is returned untouched and main
// renders it, exactly as refuseJSON leaves the human path alone.
//
// It is deliberately not the refusal envelope. The target may already have started, and
// refused:true would say bento declined a run it in fact began. It cannot say which
// happened either: Result.Setup answers that only when Run returned nil or a Shortfall,
// and on this path its zero value reads as a silent stage without one having died. So
// the envelope reports what is known - the reason, the streams captured before it went
// wrong, and the report of what was enforced around them - and claims nothing about
// where the target got to.
//
// exit_code carries bentoFailed rather than being omitted, because a consumer written
// against the two shapes that existed before this one switches on refused and then reads
// exit_code: absent, it would decode as 0 and read this as a clean run. 125 is the code
// the process really exits with here, and it is the one thing about this envelope an
// unaware consumer cannot misread.
func failJSON(stdout io.Writer, asJSON bool, res enforce.Result, capturedOut, capturedErr string, runErr error) error {
	if !asJSON {
		return runErr
	}
	// A run that failed before any stage existed (an invalid policy, a nil enforcer)
	// carries the zero Report, which toReportJSON would answer fully_enforced:true for -
	// a clean posture on a run that never had one. See noReport.
	report := noReport
	if len(res.Report.Layers) > 0 {
		report = toReportJSON(res.Report)
	}
	_ = writeJSON(stdout, struct {
		Failed   bool       `json:"failed"`
		Reason   string     `json:"reason"`
		ExitCode int        `json:"exit_code"`
		Stdout   string     `json:"stdout"`
		Stderr   string     `json:"stderr"`
		Report   reportJSON `json:"report"`
	}{true, runErr.Error(), bentoFailed, capturedOut, capturedErr, report})
	return &exitError{code: bentoFailed}
}

// writeRunResult turns the outcome of enforce.Run into the frontend's contract: it
// writes the human or --json output and returns the error the command propagates. The
// exit-code mapping is the load-bearing invariant - a refusal (bento could not run the
// script) becomes exitError{bentoFailed}, distinct from the target's own code, which is
// passed through untouched via exitError{res.ExitCode}. capturedOut/capturedErr are the
// target's streams, captured only in --json mode (empty otherwise, where they went
// straight to the real streams). missingReads is the pre-run verdict on the read grants,
// not re-taken here: a grant the script created during the run was still missing when it
// started, which is what the note on the way in said and what validate answers.
func writeRunResult(stdout, stderr io.Writer, asJSON bool, p *policy.Policy, res enforce.Result, missingReads []string, capturedOut, capturedErr string, runErr error) error {
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
		// Rendered here rather than returned to main's generic printer: the shortfall
		// reasons include the degraded filesystem tier's thousand-character disclosure,
		// which that printer would put on one unreadable line.
		writeRefusal(stderr, "refusing to run", refusal)
		return &exitError{code: bentoFailed}
	case errors.As(runErr, &shortfall):
		// The target ran, so its output and report are reported exactly as a clean run's
		// are; only the exit code differs, below.
	case runErr != nil:
		return failJSON(stdout, asJSON, res, capturedOut, capturedErr, runErr)
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
			GuardBlocked []hostPortJSON `json:"guard_blocked,omitempty"`
			// EgressDenied names the destinations the allowlist refused outright, which
			// egress_connections counts but does not identify - it is what lets a consumer
			// answer "what did it try to reach and what did we refuse". Attacker-chosen bytes,
			// like guard_blocked.
			EgressDenied    []hostPortJSON `json:"egress_denied,omitempty"`
			Shields         []shieldJSON   `json:"shields,omitempty"`
			Exposed         []shieldJSON   `json:"exposed,omitempty"`
			AcceptedAliases []aliasJSON    `json:"accepted_aliases,omitempty"`
			Report          reportJSON     `json:"report"`
			// StrictShortfall says the run was admitted under --strict but a guarantee it
			// required lapsed while the target ran, so exit_code below is the code of a run
			// whose posture did not hold. Without it a machine consumer reading the envelope
			// alone would see an ordinary completed run.
			StrictShortfall bool `json:"strict_shortfall,omitempty"`
			// MissingReadGrants are the read grants that named nothing on this host when the
			// run started, spelled as validate spells them. A note, not a verdict - the run
			// proceeds - but it is the field that connects a script dying on a file it could
			// not open to the manifest grant that no longer resolves, which is otherwise only
			// prose on stderr and unreadable to the gate --help sends here.
			MissingReadGrants []string `json:"missing_read_grants,omitempty"`
		}{res.ExitCode, res.Signal, capturedOut, capturedErr, res.EgressConnections, res.ShieldedGrants, toShieldedTargetsJSON(res.ShieldedGrantTargets), toHostPortsJSON(res.GuardBlocked), toHostPortsJSON(res.Denied), toShieldsJSON(res.Shields), toShieldsJSON(res.Exposed), toAliasesJSON(res.AcceptedAliases), toReportJSON(res.Report), shortfall != nil, missingReads}); err != nil {
			fmt.Fprintf(stderr, "[bento] warning: could not encode the JSON result: %v\n", err)
		}
	} else {
		writeAcceptedAliasWarning(stderr, res)
		writeShieldSummary(stderr, res)
		writeShieldedGrantWarning(stderr, res)
		writeExposedWarning(stderr, res)
		writeDegradations(stderr, res.Report)
		// Before the bypass hint: each is a connection that DID reach the proxy, so it
		// explains a network failure the hint would otherwise blame on a bypass.
		writeGuardBlockedWarning(stderr, res)
		denied := writeDeniedWarning(stderr, p, res)
		// Last, and only where nothing above already explained the failure. A signal
		// death is not a script failure at all, a strict shortfall gets its own line
		// below, and a guard block is a destination no amount of profiling will widen
		// the manifest into reaching - pointing at profile in any of those sends the
		// reader at the wrong problem. A denial has just named the destination and the
		// one profiling mode that would rediscover it, which the bare hint would send
		// the reader around the wrong loop for. Both hints below explain a failure the
		// TARGET reported, so a run whose target never started gets its own line instead.
		if res.Setup == enforce.SetupTargetUnreached {
			writeTargetUnreached(stderr, res)
		} else if !writeSignalNotice(stderr, p, res) && !writeEgressHint(stderr, p, res) &&
			shortfall == nil && len(res.GuardBlocked) == 0 && !denied {
			// Before the hint, not after: profiling reproduces the same wrong path, so a
			// reader who has this cause in hand should not be sent around that loop first.
			writeSandboxHomeMiss(stderr, p, res)
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
