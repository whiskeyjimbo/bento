package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/whiskeyjimbo/bento/backend"
	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/gate"
	"github.com/whiskeyjimbo/bento/manifest"
	"github.com/whiskeyjimbo/bento/policy"
	"github.com/whiskeyjimbo/bento/trust"
)

func newRunCmd() *cobra.Command {
	var (
		strict          bool
		allowDegraded   bool
		allowUnapproved bool
		envFlags        []string
		acceptAliases   []string
		asJSON          bool
		runID           string
		recordExec      bool
	)

	cmd := &cobra.Command{
		Use:   "run <manifest>",
		Short: "Run a script under the permissions its manifest declares",
		Long: "run enforces the manifest's policy and executes the script.\n\n" +
			"The script's exit code is passed through untouched. If bento itself could not\n" +
			"run the script - a bad manifest, or a guarantee this host cannot enforce - it\n" +
			"exits 125, following the convention env(1) and docker use for \"the command\n" +
			"could not be executed\", so it is distinct from any code the script itself returns.\n" +
			"A script that ran while a guarantee the run was admitted on lapsed mid-run exits\n" +
			"124, reserved the same way. A script can return any code itself, so a machine\n" +
			"gate should read --json, where the outcome is a field rather than a code.\n\n" +
			"--json makes stdout a stream of JSON objects, one per line: the script's own\n" +
			"output as it arrives, each object saying which of its streams it came from and\n" +
			"carrying the bytes base64-encoded, then exactly one final object with the\n" +
			"outcome. Switch on the event field - \"stdout\" and \"stderr\" for the script's\n" +
			"output, then \"verdict\", \"refusal\" or \"failed\". Nothing is held in memory\n" +
			"until the run ends, so a chatty job costs no more than a quiet one.",
		Args:        exactArgs(1, "a manifest path"),
		Annotations: map[string]string{jsonRefusalAnnotation: jsonRefusalStream},
		RunE: func(cmd *cobra.Command, args []string) error {
			// Every refusal raised before enforce.Run - a bad --env, an unparseable or
			// unapproved manifest, an env that cannot be resolved, a backend this host
			// cannot provide - goes through refuse, so --json always leaves a refusal
			// object on stdout. Returning these bare wrote nothing there, and a machine
			// gate could not tell a refusal from a crash.
			refuse := func(err error) error { return refuseStreamJSON(os.Stdout, asJSON, err) }

			// Answered inside RunE rather than by a hook above it, for the same reason
			// the mutually-exclusive flags below are: a refusal raised before RunE leaves
			// --json an empty stdout, which is the one thing a machine consumer cannot
			// tell from a crash.
			if err := checkPlatform(); err != nil {
				return refuse(err)
			}

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
			doc, mt, err := loadDocument(args[0])
			if err != nil {
				return refuse(err)
			}
			warnStampAtRisk(cmd.ErrOrStderr(), doc, mt)
			// After the at-risk warning and before the refusal: both are about how much the
			// stamp is worth, and this one is inapplicable to the manifest the refusal below
			// turns away.
			if stampUnrecorded(mt.RealPath, doc) {
				fmt.Fprintf(cmd.ErrOrStderr(), "[bento] %s\n", unrecordedStamp)
			}
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
			// script itself then created was still missing when the run started. The
			// file-ish write note beside it stays on stderr - see writeFileishWriteNotes.
			missingReads := gate.MissingReads(p.Read)
			writeMissingReadNotes(os.Stderr, missingReads)
			writeFileishWriteNotes(os.Stderr, gate.FileishWrites(p.Write))
			writeBlockedHostNotes(os.Stderr, p, doc.Provenance.BlockedHosts)
			writeRuntimeDirNote(os.Stderr)

			e, err := backend.New()
			if err != nil {
				return refuse(err)
			}

			// In --json mode the script's streams become events on the stream stdout
			// carries, each tagged with which stream it came from, rather than being
			// shared with bento's own stdout - the script's output interleaved with the
			// JSON would corrupt the machine contract. They go out as they arrive, so a
			// pipeline running a long build shows its logs and a job killed on a timeout
			// leaves them behind, and nothing is held: the memory a run costs no longer
			// grows with what the target printed. It is given no stdin.
			proc := enforce.Process{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Env: env}
			var stream *eventStream
			if asJSON {
				stream = newEventStream(os.Stdout)
				proc.Stdin = nil
				proc.Stdout = stream.output("stdout")
				proc.Stderr = stream.output("stderr")
			}

			res, err := enforce.Run(cmd.Context(), e, p, proc, enforce.Options{
				Strict:             strict,
				AllowDegraded:      allowDegraded,
				AcceptAliasesUnder: acceptAliases,
				RunID:              runID,
				RecordExec:         recordExec,
			})
			return writeRunResult(os.Stderr, asJSON, p, env, res, missingReads, stream, err)
		},
	}

	cmd.Flags().BoolVar(&strict, "strict", false, "refuse to run unless every guarantee the policy needs is fully enforced, and report it if one lapses while the script runs")
	cmd.Flags().BoolVar(&allowDegraded, "allow-degraded", false, "run even when a core guarantee can only be partially enforced; the widest escape hatch there is - the degraded tier it selects applies no shields, so a credential under a granted tree is readable whether or not anything aliases it")
	cmd.Flags().StringArrayVar(&acceptAliases, "accept-alias", nil, "acknowledge the credential aliases under a host tree (a snapshot or deduplicated backup) instead of refusing; repeatable; the degraded tier scans and refuses the same way, so this is needed there too")
	cmd.Flags().BoolVar(&allowUnapproved, "allow-unapproved", false, "run even if the manifest is unapproved or its approval is stale (the profile-then-run inner loop)")
	cmd.Flags().StringArrayVar(&envFlags, "env", nil, "supply a value for an allowlisted env var (NAME=VALUE); repeatable")
	cmd.Flags().StringVar(&runID, "run-id", "", "name this run so a supervisor can reap the whole process tree it leaves behind, not just bento's own pid. The run gets a transient systemd user scope named bento-run-<id>.scope, which `systemctl --user kill` ends and `systemctl --user show -p ControlGroup` resolves to a cgroup path. The id is letters, digits and underscore, up to 64. It needs a scope to name, so a manifest that sets no resource limits, or a host that cannot create one, is refused rather than run without a handle")
	cmd.Flags().BoolVar(&recordExec, "record-exec", false, "record every command the run actually executed and print the tree afterwards. It takes ptrace away from everything inside the sandbox, so strace, gdb, rr and a test harness attaching to its own child stop working under it - which is why it is off unless asked for. A run that cannot have a recorder (--allow-degraded's tier, an exec: none manifest, or a host whose yama ptrace_scope refuses the attach) is not refused: it reports that nothing was watching, and why")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit machine-readable JSON on stdout, one object per line: the script's own output as it arrives, tagged with which stream produced it and base64-encoded, then one final object with the outcome. The script is given no stdin. Switch on the event field - stdout, stderr, then verdict, refusal or failed. A refusal, including a mistake in this command line, is an object too, so stdout is never empty")
	return cmd
}

// eventStream is what `bento run --json` puts on stdout: JSON objects, one per line, in
// the order they happened. Every object carries an event naming its shape - "stdout" and
// "stderr" for the target's own output as it arrives, and exactly one "verdict",
// "refusal" or "failed" object, always last. A consumer switches on that field.
//
// The lock serializes the two stream pumps, which exec runs from separate goroutines: an
// object written mid-write by the other would splice into it and the line would not
// parse. It is held across the write rather than buffering, because appearing while the
// target runs is the whole point.
//
// The lock orders the writes but does not order them against the end of the run, and the
// terminal object being last is a contract a consumer reads the stream by. A backend that
// runs the target through exec.Cmd.Run with no WaitDelay set gets that for free - Wait
// blocks until both copy goroutines have finished, so no pump is live by the time the
// outcome is emitted. The degraded tier does set WaitDelay (the usual fix for an orphaned
// grandchild holding the pipe open), which leaves a pump live and would otherwise let a
// chunk land after the outcome; nothing but ordering breaks there, so the race detector
// would not see it. So the terminal object seals the stream instead, and the contract
// holds whatever the backend does.
type eventStream struct {
	mu     sync.Mutex
	enc    *json.Encoder
	err    error
	sealed bool
}

func newEventStream(w io.Writer) *eventStream {
	// No SetIndent, unlike every other envelope bento writes: one object per line is the
	// contract here, and an indented object spans lines.
	return &eventStream{enc: json.NewEncoder(w)}
}

// emit writes one object, keeping the first error and dropping every write after it.
//
// It does not report that error to its caller, and the reason is the target rather than
// the stream: exec pumps the target's output through this, and an error returned there
// stops it draining the pipe, so the target blocks once the pipe fills. Dropping keeps
// it running. The error is not swallowed, though - failed() is what the run reports at
// the end, because a truncated stream capped with a verdict that reads clean is the one
// answer this must never give.
func (e *eventStream) emit(v any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.err != nil || e.sealed {
		return
	}
	e.err = e.enc.Encode(v)
}

// emitTerminal writes the object that ends the stream and closes it to everything after,
// so the terminal-object-last contract holds even where a pump is still live - a
// descendant the target leaked still holding the pipe when the degraded tier's WaitDelay
// expired. What that pump writes next is dropped: it arrived after the target exited and
// after the grace period, and a consumer that has already read the outcome cannot use it.
// A truncation the drop causes is not reported the way a write error is, because the last
// chunk can arrive after failed() has been read.
//
// The write and the seal are one critical section, not emit followed by a seal: a pump
// that took the lock between the two would land its chunk after the terminal object,
// which is the ordering this exists to prevent.
func (e *eventStream) emitTerminal(v any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.err == nil && !e.sealed {
		e.err = e.enc.Encode(v)
	}
	e.sealed = true
}

// failed reports the first write error the stream hit, if any. Everything after it is
// missing from stdout.
func (e *eventStream) failed() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.err
}

// output returns the writer exec pumps one of the target's streams into, tagging each
// chunk with the stream it came from.
func (e *eventStream) output(name string) io.Writer { return &eventWriter{stream: e, name: name} }

type eventWriter struct {
	stream *eventStream
	name   string
}

func (w *eventWriter) Write(p []byte) (int, error) {
	w.stream.emit(streamEventJSON{w.name, p})
	return len(p), nil
}

// streamEventJSON is one chunk of the target's output, tagged with which of its two
// streams produced it. That labelling is live, which the shape this replaced could not
// do: it merged both onto bento's stderr as they arrived and separated them only in the
// envelope, after the run.
//
// A chunk is whatever exec's pump happened to read, not a line. Bounding what a run
// costs is the point, so nothing here waits for a newline a target may never write.
//
// Data is []byte, so it is base64 in the JSON. A target is untrusted and prints whatever
// it likes; encoding/json replaces invalid UTF-8 in a Go string with U+FFFD, so a string
// field would hand a consumer corrupted bytes for any target that emits binary, with
// nothing to tell it that happened. base64 round-trips whatever the target wrote.
type streamEventJSON struct {
	Event string `json:"event"`
	Data  []byte `json:"data"`
}

// refuseJSON reports a refusal in the single indented document `bento profile --json`
// answers with, so --json never answers a refusal with an empty stdout. It is profile's
// shape and no longer run's - see refuseStreamJSON. Outside --json the error is returned
// untouched and main renders it; inside it, the message is the document's reason and the
// exit code is bentoFailed, including that nothing is written to stderr.
func refuseJSON(stdout io.Writer, asJSON bool, err error) error {
	if err == nil || !asJSON {
		return err
	}
	reason, report := refusalDetail(err)
	_ = writeJSON(stdout, refusalJSON{true, reason, report})
	return &exitError{code: bentoFailed}
}

// refuseStreamJSON is refuseJSON in `bento run`'s shape: one refusal object on the event
// stream rather than the single indented document profile answers with. The two cannot
// share a shape - a consumer of the stream switches on event, and a run's stdout must be
// one object per line whether the run produced output or was refused before it started.
func refuseStreamJSON(stdout io.Writer, asJSON bool, err error) error {
	if err == nil || !asJSON {
		return err
	}
	reason, report := refusalDetail(err)
	newEventStream(stdout).emitTerminal(streamRefusalJSON{Event: "refusal", Reason: reason, Report: report})
	return &exitError{code: bentoFailed}
}

// refusalDetail pulls the reason and the report out of a refusal raised before the
// target ran, for whichever shape the command answers in.
//
// A host shortfall arrives as an *enforce.Refusal, which carries the probe that judged
// it: report that rather than noReport, so a consumer reading stdout alone sees which
// layer fell short. Its Reason, not Error(), for the same reason writeRunResult uses it
// - Error() prepends a verb the caller may not have refused with.
func refusalDetail(err error) (string, reportJSON) {
	var refusal *enforce.Refusal
	if errors.As(err, &refusal) {
		return refusal.Reason, toReportJSON(refusal.Report)
	}
	return err.Error(), noReport
}

// streamRefusalJSON ends a stream that produced no verdict, under whichever of the two
// events applies: "refusal" for a run bento declined, where the target never started,
// and "failed" for one that began and could not be finished. Distinct events rather than
// one with a flag, because they are answers to different questions - a gate retries a
// refusal against a different host and does not retry the other.
type streamRefusalJSON struct {
	Event  string     `json:"event"`
	Reason string     `json:"reason"`
	Report reportJSON `json:"report"`
	// ChangedAutoExec is the failed event's alone - a refusal is a run that never began,
	// so it has nothing to have changed. It is the same field the verdict carries, under
	// the same name, because a consumer gating a merge on review has to find it in the
	// same place whichever object ended the stream.
	ChangedAutoExec []string `json:"changed_auto_exec,omitempty"`
	// RedirectedHooks travels beside it for the same reason, and separately from it because
	// it is a different claim; see enforce.Result.
	RedirectedHooks []string `json:"redirected_hooks,omitempty"`
	// The grants whose hook directory git could not resolve, so a consumer can tell a
	// short report from a clean one; see enforce.Result.UnresolvedHooks.
	UnresolvedHooks []string `json:"unresolved_hooks,omitempty"`
	// The shield audit is the failed event's alone as well, and under the verdict's names.
	// A run that began engaged its boundary, and on the degraded tier left credentials
	// reachable; dropping the record because the run then failed reports the exposure as
	// never having happened, which is the one claim this tier must never make.
	Shields         []shieldJSON        `json:"shields,omitempty"`
	Exposed         []shieldJSON        `json:"exposed,omitempty"`
	ShieldedGrants  []shieldedGrantJSON `json:"shielded_grants,omitempty"`
	AcceptedAliases []aliasJSON         `json:"accepted_aliases,omitempty"`
	// ShadowedPathDirs is the failed event's as well, under the verdict's name and read
	// the same way: a run that died for another reason still ran whatever the box
	// resolved, and the wrong toolchain is a candidate explanation for the failure.
	ShadowedPathDirs []string `json:"shadowed_path_dirs,omitempty"`
}

// failJSON ends the stream for a run that neither refused nor completed - an error from
// enforce.Run that is not a Refusal, and not one of the Shortfalls describing a completed
// run (a Shortfall carrying the backend's own failure is routed here) - so --json answers it with an
// object instead of a stream that just stops. Outside --json the error is returned
// untouched and main renders it, exactly as refuseJSON leaves the human path alone.
//
// Deliberately not the refusal event. The target may already have started, and refusal
// would say bento declined a run it in fact began. It cannot say which happened either:
// Result.Setup answers that only when Run returned nil or a Shortfall, and on this path
// its zero value reads as a silent stage without one having died. So it reports what is
// known - the reason, and the report of what was enforced around the run - and claims
// nothing about where the target got to. Whatever the target printed before it went
// wrong is already on the stream above, which is what the buffered envelope could not
// do: it dropped the captured streams on this path entirely.
func failJSON(stderr io.Writer, stream *eventStream, asJSON bool, res enforce.Result, shadowed []string, runErr error) error {
	if !asJSON {
		return runErr
	}
	// A run that failed before any stage existed (an invalid policy, a nil enforcer)
	// carries the zero Report; toReportJSON answers that with noReport rather than the
	// clean posture !HasDegradation() would read as.
	stream.emitTerminal(streamRefusalJSON{Event: "failed", Reason: runErr.Error(), Report: toReportJSON(res.Report), ChangedAutoExec: res.ChangedAutoExec, RedirectedHooks: res.RedirectedHooks, UnresolvedHooks: res.UnresolvedHooks, Shields: toShieldsJSON(res.Shields), Exposed: toShieldsJSON(res.Exposed), ShieldedGrants: toShieldedGrantsJSON(res.ShieldedGrants), AcceptedAliases: toAliasesJSON(res.AcceptedAliases), ShadowedPathDirs: shadowed})
	return reportStreamed(stderr, stream, bentoFailed)
}

// reportStreamed turns the code a run earned into the one it can honestly deliver, and
// is the last thing every --json path does.
//
// The target's own output is on this stream, so a write that failed part-way left stdout
// truncated - with an unknown amount of the run missing, and the object naming the
// outcome either not landed at all or landed on a stream missing everything before it. A
// consumer reading what is there would be reading a partial run with no sign that it was
// partial, so say so on stderr and answer with bento's own code. The target's code is
// exactly what must not stand: it would tell a gate to trust what is on stdout. What
// could not be delivered is bento's answer about the run, not the run.
func reportStreamed(stderr io.Writer, stream *eventStream, code int) error {
	if err := stream.failed(); err != nil {
		fmt.Fprintf(stderr, "[bento] the JSON event stream could not be written (%v), so what is on stdout is truncated - the outcome is not reported there.\n", err)
		return &exitError{code: bentoFailed}
	}
	return &exitError{code: code}
}

// writeRunResult turns the outcome of enforce.Run into the frontend's contract: it
// writes the human or --json output and returns the error the command propagates. The
// exit-code mapping is the load-bearing invariant - a refusal (bento could not run the
// script) becomes exitError{bentoFailed}, distinct from the target's own code, which is
// passed through untouched via exitError{res.ExitCode}. stream is the event stream the
// target's output already went out on, set only in --json mode (nil otherwise, where it
// went straight to the real streams); the verdict is the last object on it. missingReads is the pre-run verdict on the read grants,
// not re-taken here: a grant the script created during the run was still missing when it
// started, which is what the note on the way in said and what validate answers. env is
// what the sandbox was actually given, not what the manifest allowed: a name the host
// never set never reaches the box, so the notes that turn on a variable's absence have to
// read the resolved map rather than p.Env.
func writeRunResult(stderr io.Writer, asJSON bool, p *policy.Policy, env map[string]string, res enforce.Result, missingReads []string, stream *eventStream, runErr error) error {
	var (
		refusal   *enforce.Refusal
		shortfall *enforce.Shortfall
	)
	switch {
	case errors.As(runErr, &refusal):
		if asJSON {
			stream.emitTerminal(streamRefusalJSON{Event: "refusal", Reason: refusal.Reason, Report: toReportJSON(refusal.Report)})
			return reportStreamed(stderr, stream, bentoFailed)
		}
		// Rendered here rather than returned to main's generic printer: the shortfall
		// reasons include the degraded filesystem tier's thousand-character disclosure,
		// which that printer would put on one unreadable line.
		writeRefusal(stderr, "refusing to run", refusal)
		writeLimitsRemedy(stderr, refusal)
		return &exitError{code: bentoFailed}
	case errors.As(runErr, &shortfall) && shortfall.Err == nil:
		// The target ran, so its output and report are reported exactly as a clean run's
		// are; only the exit code differs, below. A shortfall that also carries the
		// backend's own failure is not that run - nothing here would print the cause, and
		// "the script ran, but" below would assert a run that may never have started - so
		// it takes the failure path instead, where the report already discloses the layers.
	case runErr != nil:
		// The auto-exec notice rides the failure out. A run killed partway - a cancelled
		// context, a teardown that died - is the one most likely to have rewritten a
		// package.json and least likely to be looked at afterwards, and on this path
		// nothing else says what the host now holds. In --json failJSON carries the same
		// field; here it is the notice, before the error main renders.
		if !asJSON {
			// The shield audit rides out here for the same reason, and in the clean path's
			// relative order so an operator reading two runs side by side does not find the
			// exposure warning in a different place because one of them failed. The clean
			// path's shield summary stays out: it says what the boundary held, which the error
			// beneath it is already the answer to.
			writeAcceptedAliasWarning(stderr, res)
			writeShieldedGrantWarning(stderr, res)
			writeExposedWarning(stderr, res)
			writeSandboxPathShadow(stderr, p, env)
			writeChangedAutoExecNotice(stderr, res)
			writeRedirectedHooksNotice(stderr, res)
			// The layers a shortfall named are rendered here, wrapped, for the reason the
			// refusal above is rendered rather than returned: the error main prints goes out
			// through one unwrapped Fprintf, and the degraded tier's disclosure is a
			// thousand-character paragraph that nobody reads sideways.
			if shortfall != nil {
				writeDegradations(stderr, res.Report)
			}
		}
		// Stripped to the cause for the same reason: the layers have just been rendered
		// above, and the --json envelope carries the report whole, so what is left to say
		// is why the run failed.
		if shortfall != nil {
			runErr = shortfall.Err
		}
		return failJSON(stderr, stream, asJSON, res, shadowedPathDirs(p, env), runErr)
	}

	if asJSON {
		stream.emitTerminal(struct {
			// Event is "verdict", the last object on the stream and the only one that
			// carries an outcome. See eventStream for the others.
			Event    string `json:"event"`
			ExitCode int    `json:"exit_code"`
			// Signal names the signal that killed the sandbox, present only where that is
			// KNOWN: exit_code is 128+signal there. The human output additionally reads a
			// code in that range as a probable signal and says so, hedged; this field does
			// not, because a machine consumer cannot hedge - it would read an inference
			// about a target that chose to exit 137 as the fact that something killed it.
			Signal int `json:"signal,omitempty"`
			// The target's own output is not here: it went out as stdout and stderr events
			// while the run happened, so nothing about a run is held in memory until it ends.
			EgressConnections int `json:"egress_connections"`
			// ShieldedGrants names each always-shielded path the manifest granted, which
			// lifted the shield for this run. path is the spelling that opted in, and the
			// deny-list builds those spellings from $HOME - so under a caller-chosen
			// environment the name a consumer sees can be a link while the exposure lands
			// elsewhere, which is what on_host says. Resolved by the backend as it bound
			// them, so a target that moved a symlink mid-run cannot rewrite what this
			// reports. holds is what was behind the shield, so a gate can tell a lifted
			// credential store from a lifted history store without a path table of its own.
			ShieldedGrants []shieldedGrantJSON `json:"shielded_grants,omitempty"`
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
			EgressDenied []hostPortJSON `json:"egress_denied,omitempty"`
			// GateDenied names the destinations a network gate was asked about and refused.
			// Separate from egress_denied because a gate answer is not a manifest fact: a
			// harness reconciling the run against the policy would otherwise read an
			// operator's "no" as a missing rule. Attacker-chosen bytes, like guard_blocked.
			GateDenied []hostPortJSON `json:"gate_denied,omitempty"`
			// Untunneled names the destinations addressed without a CONNECT - plain http://
			// through the proxy. Separate from egress_denied because a manifest rule can
			// cover one of these and still carry no traffic, so a gate reconciling the run
			// against the policy would otherwise read the rule as honored. Attacker-chosen
			// bytes, like guard_blocked.
			Untunneled      []hostPortJSON `json:"untunneled,omitempty"`
			Shields         []shieldJSON   `json:"shields,omitempty"`
			Exposed         []shieldJSON   `json:"exposed,omitempty"`
			AcceptedAliases []aliasJSON    `json:"accepted_aliases,omitempty"`
			// The auto-executing files the run changed, for a consumer that gates a merge
			// on review rather than reading the stderr notice.
			ChangedAutoExec []string `json:"changed_auto_exec,omitempty"`
			// The hook directories the run pointed the checkout at. Separate from the list
			// above because it is a different claim; see enforce.Result.RedirectedHooks.
			RedirectedHooks []string `json:"redirected_hooks,omitempty"`
			// The grants whose hook directory git could not resolve; see
			// enforce.Result.UnresolvedHooks.
			UnresolvedHooks []string `json:"unresolved_hooks,omitempty"`
			// ExecRecord is present only for a run that asked with --record-exec, and is
			// then present whatever came back: a run the recorder could not watch reports
			// that and why, which is the answer an empty list would misreport as "nothing
			// ran". It is a diagnostic and never a verdict - a consumer must not read a
			// shortfall out of it.
			ExecRecord *execRecordJSON `json:"exec_record,omitempty"`
			Report     reportJSON      `json:"report"`
			// PostureShortfall says a guarantee the run was admitted on lapsed while the
			// target ran, so exit_code below is the code of a run whose posture did not hold.
			// Without it a machine consumer reading the envelope alone would see an ordinary
			// completed run.
			PostureShortfall bool `json:"posture_shortfall,omitempty"`
			// MissingReadGrants are the read grants that named nothing on this host when the
			// run started, spelled as validate spells them. A note, not a verdict - the run
			// proceeds - but it is the field that connects a script dying on a file it could
			// not open to the manifest grant that no longer resolves, which is otherwise only
			// prose on stderr and unreadable to the gate --help sends here.
			MissingReadGrants []string `json:"missing_read_grants,omitempty"`
			// ShadowedPathDirs are the PATH directories nothing carried into the box, so a
			// bare command name resolved to whatever the box had instead. A note beside
			// missing_read_grants and read the same way: the run proceeds, and this is what
			// connects a card that came out wrong - built by the base image's toolchain
			// rather than the operator's - to the read grant that would have fixed it. On
			// stderr it is prose; a lane harness can only gate on it here.
			ShadowedPathDirs []string `json:"shadowed_path_dirs,omitempty"`
		}{"verdict", res.ExitCode, res.Signal, res.EgressConnections, toShieldedGrantsJSON(res.ShieldedGrants), toHostPortsJSON(res.GuardBlocked), toHostPortsJSON(res.Denied), toHostPortsJSON(res.GateDenied), toHostPortsJSON(res.Untunneled), toShieldsJSON(res.Shields), toShieldsJSON(res.Exposed), toAliasesJSON(res.AcceptedAliases), res.ChangedAutoExec, res.RedirectedHooks, res.UnresolvedHooks, toExecRecordJSON(res.ExecRecord), toReportJSON(res.Report), shortfall != nil, missingReads, shadowedPathDirs(p, env)})
	} else {
		writeAcceptedAliasWarning(stderr, res)
		writeShieldSummary(stderr, res)
		writeShieldedGrantWarning(stderr, res)
		writeExposedWarning(stderr, res)
		// Not in the failure chain below with its cousin writeSandboxPathMiss: the run it
		// describes exits 0, so a placement keyed on a nonzero exit would be silent in
		// exactly the case it exists for.
		writeSandboxPathShadow(stderr, p, env)
		writeDegradations(stderr, res.Report)
		// After the shield block and before the network half: it belongs with what the
		// run touched on the host, and it is a place to review rather than a failure to
		// explain, so it must not sit among the lines diagnosing a nonzero exit.
		writeChangedAutoExecNotice(stderr, res)
		writeRedirectedHooksNotice(stderr, res)
		// Before the bypass hint: each is a connection that DID reach the proxy, so it
		// explains a network failure the hint would otherwise blame on a bypass.
		writeGuardBlockedWarning(stderr, res)
		denied := writeDeniedWarning(stderr, p, res)
		// After the denial for the reason the untunneled notice is: a run can have both,
		// and this one has to say the manifest remedy the denial just named does not
		// apply to its half.
		gateDenied := writeGateDeniedWarning(stderr, res)
		// After the denial: a run can have both, and the denial names the manifest edit
		// that fixes its own half, which this one has to say does NOT apply to its half.
		untunneled := writeUntunneledWarning(stderr, res)
		// Last, and only where nothing above already explained the failure. A signal
		// death is not a script failure at all, a posture shortfall gets its own line
		// below, and a guard block is a destination no amount of profiling will widen
		// the manifest into reaching - pointing at profile in any of those sends the
		// reader at the wrong problem. A denial has just named the destination and the
		// one profiling mode that would rediscover it, which the bare hint would send
		// the reader around the wrong loop for. Both hints below explain a failure the
		// TARGET reported, so a run whose target never started gets its own line instead.
		// The exec hint precedes the egress one: 126 under a manifest that blocks exec names
		// a cause the bypass hint would otherwise blame on the network.
		hinted := false
		if res.Setup == enforce.SetupTargetUnreached {
			writeTargetUnreached(stderr, res)
		} else if !writeSignalNotice(stderr, p, res) && !writeExecHint(stderr, p, res) &&
			!writeEgressHint(stderr, p, res) &&
			shortfall == nil && len(res.GuardBlocked) == 0 && !denied && !gateDenied && !untunneled {
			// Before the hint, not after: profiling reproduces the same wrong path, so a
			// reader who has this cause in hand should not be sent around that loop first.
			// Neither suppresses the legend below, though both name a cause: the hint
			// between them still claims the sandbox denies silently, and that claim
			// travels with its mapping or not at all. The HOME note settles it either
			// way - it fires on any non-zero exit under a home-relative grant, so it
			// suspects a cause rather than establishing one.
			writeSandboxHomeMiss(stderr, p, env, res)
			writeSandboxPathMiss(stderr, p, env, res)
			hinted = writeProfileHint(stderr, p, res)
		}
		// Outside the chain above, which explains failures: this covers the run that
		// reported none, and the one the chain left with the generic hint - which says
		// the sandbox denies silently without saying what a denial looks like. The
		// warnings above it are not all keyed on a failure - a refused destination and a
		// guard block are reported on their own count and do reach a clean run - so this
		// sits under them rather than instead of them. A target that never started denied
		// nothing, whatever code the refusal carried.
		if res.Setup != enforce.SetupTargetUnreached {
			writeDenialLegend(stderr, p, res, hinted)
		}
		// Last of the block, because it is the only section whose length is set by what the
		// target did rather than by what the sandbox found: a build's exec tree is hundreds
		// of lines, and printing it above the warnings would scroll every one of them away.
		// It is also the only section the reader explicitly asked for, so it is the one they
		// are already looking for at the bottom.
		//
		// Deliberately outside the legend's target-unreached guard, and not by oversight: a
		// stage that never reached the target writes the unreached marker INSTEAD of the
		// record section, which comes back as nothing having watched rather than as a run
		// that exec'd nothing - a true answer for a reader who asked. Suppressing it here
		// would also split the two output paths, since the --json envelope carries the
		// record whatever the setup state.
		writeExecRecord(stderr, res)
	}

	// The script ran, but a guarantee the run was admitted on lapsed during it. Passing
	// the script's own code through would report a clean run over a posture that did not
	// hold, which is the one thing the posture exists to prevent - so it gets its own
	// code, distinct from both.
	code := res.ExitCode
	if shortfall != nil {
		if !asJSON {
			// writeDegradations above already named each layer that fell short, so this
			// says only what the report cannot: the script ran anyway, and that makes its
			// exit code no longer the answer.
			fmt.Fprintln(stderr, "[bento] the script ran, but the guarantees above did not hold for the whole run, so its exit code is not reported.")
		}
		code = postureShortfall
	}
	if asJSON {
		return reportStreamed(stderr, stream, code)
	}
	// The script ran; its exit code is the result, passed up so cleanup
	// unwinds before the process exits.
	return &exitError{code: code}
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
	switch trust.CheckApproval(doc) {
	case trust.ApprovalCurrent:
		return nil
	case trust.ApprovalStale:
		return fmt.Errorf("refusing to run: the manifest's permissions changed since it was approved; %s - "+
			"re-review it there, or pass --allow-unapproved", noStampDiff)
	case trust.ApprovalUnstamped:
	}
	// Unstamped, and the state the enum does not name yet: refused, so a value added to
	// trust.ApprovalState cannot open a run - strictApprovalError already lands that way round.
	return fmt.Errorf("refusing to run: the manifest is not approved; " +
		"review it and run `bento approve`, or pass --allow-unapproved")
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
