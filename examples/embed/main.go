// Command embed hosts bento's enforcement backend in-process, using only bento's
// public packages - backend, enforce, manifest - and nothing under internal/. It
// takes a manifest path, runs the script it describes under the sandbox, prints
// every honesty field the structured Result carries - what the host could not
// enforce, what the gate let out, and every credential path the run exposed or
// could not shield - and passes the target's exit code through.
//
// It prints all of them, including the ones that stay empty under its own options: an
// example is a template, and a field a frontend never reads is a silence an operator
// reads as nothing to report. writeResult below is that surface, and its test guards
// it against a new Result field arriving unprinted.
//
// It also demonstrates the interactive supervision seam: a NetworkGate that
// prompts a human to admit egress the manifest did not declare, remembering the
// answer for the run - the model an editor agent uses. bento supplies the seam
// and the honesty accounting (Result.GateAdmitted); the prompt, the session
// memory, and the persist decision are the wrapper's, and they live in the
// supervisor type below.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/whiskeyjimbo/bento/backend"
	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/manifest"
	"github.com/whiskeyjimbo/bento/policy"
)

func main() {
	// To confine a target the backend re-executes THIS binary inside the sandbox
	// as a hidden stage, so dispatch that before anything else in main - any
	// earlier flag parsing or side effect would run in the wrong context, and a
	// normal invocation falls straight through. Because the whole binary re-runs
	// inside the sandbox under a cleared environment, keep package init cheap and
	// free of environment or other side-effect dependencies.
	backend.DispatchReexec()

	args := os.Args[1:]
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		usage(os.Stdout)
		os.Exit(0)
	}
	if len(args) != 1 {
		usage(os.Stderr)
		os.Exit(2)
	}
	os.Exit(run(args[0]))
}

func usage(w io.Writer) {
	fmt.Fprint(w, `embed - run a script under bento's sandbox, in-process via the public API

Usage:
  embed <manifest.yaml>
  embed -h | --help

It loads the manifest, runs the target it describes under the sandbox, reports any
enforcement shortfall, surfaces any egress the network gate admitted beyond the
manifest, and passes the target's exit code through.

Network gate (interactive supervision):
  On a controlling terminal, egress to a host the manifest did not declare prompts
  you to allow it, and the answer is remembered for the rest of the run. With no
  terminal and no pre-approval, undeclared egress is denied - the declarative box.

Environment:
  BENTO_GATE_ALLOW   comma-separated hosts or host:port admitted without a prompt
                     (e.g. "example.com,10.0.0.5:443"), so the gate runs unattended.

Try it (from this directory):
  go build -o embed .
  ./embed demo/reach.yaml                                # denied: example.com is undeclared
  BENTO_GATE_ALLOW=example.com ./embed demo/reach.yaml   # admitted, then surfaced
  ./embed demo/reach.yaml                                # in a terminal: prompts you

See README.md for the full walkthrough.
`)
}

func run(manifestPath string) int {
	f, err := os.Open(manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "embed: %v\n", err)
		return 2
	}
	defer f.Close()

	// manifest.Load -> a validated *policy.Policy. The whole enforcement API takes
	// domain values like this; a library embedder never shells out or parses CLI
	// text.
	p, err := manifest.Load(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "embed: %v\n", err)
		return 2
	}

	// A manifest's relative read/write/entrypoint means "beside the manifest", not
	// "beside whatever cwd embed was started from", so anchor before anything reads
	// the policy. Resolve is separate from Load because it must follow an approval
	// check - this example has none, so it goes directly after the load.
	if err := manifest.Resolve(p, manifestPath); err != nil {
		fmt.Fprintf(os.Stderr, "embed: %v\n", err)
		return 2
	}

	// The policy names which env vars may pass through; resolving those names
	// against the host is the core's job, exposed here so the values a target sees
	// are explicit.
	env, unset, err := enforce.ResolveEnv(p, nil, os.LookupEnv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "embed: %v\n", err)
		return 2
	}
	// A variable the manifest allows but the host does not set is the difference between
	// "the target read it" and "the target saw nothing" - a missing GITHUB_TOKEN that
	// fails the script deep inside its own logic. ResolveEnv reports those names; a
	// frontend that drops them leaves the user debugging silence.
	for _, name := range unset {
		fmt.Fprintf(os.Stderr, "embed: note: env %s is allowed by the manifest but not set on this host; the target will not see it\n", name)
	}

	e, err := backend.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "embed: %v\n", err)
		return 2
	}

	// The network gate turns the declarative box into a supervised one. This example
	// prompts a human on the controlling terminal (/dev/tty, kept separate from the
	// target's own stdin) and remembers each answer for the run; BENTO_GATE_ALLOW
	// pre-approves hosts so the example also runs unattended. With neither a terminal
	// nor a pre-approval the gate stays nil - the declarative default, denying any
	// undeclared egress exactly as the box does.
	preApproved := parseAllow(os.Getenv("BENTO_GATE_ALLOW"))
	// The prompt takes the controlling terminal in BOTH directions, so the security
	// dialogue is on no fd the target holds. Prompting on os.Stderr would hand the
	// confined target the same stream the human reads, where it could print a lookalike
	// prompt while the real gate blocks on an attacker-chosen host, or flood the stream
	// to scroll the genuine one away - undoing the quoting that neutralizes escapes in
	// the hostname the prompt displays.
	//
	// How much that buys depends on where the target's own output goes. Redirected or
	// captured - what an embedder wrapping this does - the target cannot reach the
	// dialogue at all. Sharing a bare terminal with it, as the demo does, the target
	// still writes to the same screen through its inherited stderr and can forge
	// convincing lines there; what it cannot do is read the human's keystrokes or
	// inject into the terminal, because the sandbox starts a new session. (The degraded
	// tier does not: it only starts a new process group, so a target there keeps the
	// controlling terminal.)
	//
	// os.OpenFile returns a nil *os.File on failure; assign it into the interfaces only
	// when real, so newSupervisor sees a true nil (a typed-nil *os.File in an interface
	// is non-nil and would be read as a live but broken reader).
	var promptIn io.Reader
	// With no terminal the gate exists only for BENTO_GATE_ALLOW, and the only prompt
	// it can reach is one no human will read (an unapproved host, answered by the
	// closed reader as a denial), so stderr is a harmless place for that dead text.
	promptOut := io.Writer(os.Stderr)
	if tty, _ := os.OpenFile("/dev/tty", os.O_RDWR, 0); tty != nil {
		defer tty.Close()
		promptIn, promptOut = tty, tty
	}
	var gate enforce.NetworkGate
	if len(preApproved) > 0 || promptIn != nil {
		gate = newSupervisor(preApproved, promptIn, promptOut).gate
	}

	proc := enforce.Process{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Env: env}
	// The zero-value Options refuses only on a core-tier shortfall; a hardening gap
	// (e.g. exec-block unavailable, so the target can spawn subprocesses) is reported
	// but the run proceeds. An embedder confining genuinely untrusted code wants
	// Strict: true, which refuses unless every layer, hardening included, is enforced.
	res, err := enforce.Run(context.Background(), e, p, proc, enforce.Options{NetworkGate: gate})

	var refusal *enforce.Refusal
	var shortfall *enforce.Shortfall
	switch {
	case errors.As(err, &refusal):
		// The host cannot enforce a guarantee the policy needs. Print the error, not
		// refusal.Reason: Reason is the posture ("a core guarantee cannot be fully
		// enforced on this host") and Error() appends Short, which is the part that names
		// whether Landlock, the mount namespace, or userns is what fell short. Error()
		// already opens with "refusing to run", so this adds no second word for it.
		fmt.Fprintf(os.Stderr, "embed: %v\n", err)
		return 125
	case errors.As(err, &shortfall):
		// Strict admitted the run and then a guarantee it required lapsed while the target
		// ran. Unreachable under the zero-value Options below, but an embedder who copies
		// this and sets Strict: true reaches it - and it is a COMPLETED run, so the report
		// and the target's own exit code below still hold and must not be discarded. The
		// exit code is overridden at the end instead: a lapsed posture must not be
		// reported as a clean run. Nothing is printed here: Shortfall.Error() enumerates
		// the layers that fell short, and writeResult below names those same layers from
		// the report - so the note at the end says only what the report cannot.
	case err != nil:
		// res carries a populated Report even here, so name any shortfall the run did
		// reach before the failure rather than only the error.
		fmt.Fprintf(os.Stderr, "embed: %v\n", err)
		for _, d := range res.Report.Degradations() {
			fmt.Fprintf(os.Stderr, "embed: degraded: %s (%s): %s\n", d.Layer, d.State, d.Disclosure())
		}
		return 125
	}

	// A structured Result, not scraped output: report everything the run could not
	// guarantee and everything it exposed anyway, then pass the target's exit code
	// through.
	writeResult(os.Stderr, p, gate != nil, res)
	if shortfall != nil {
		// The target ran, but under Strict its guarantees lapsed partway. Passing its own
		// code through would report a clean run over a posture that did not hold, so it
		// gets its own code - 124, the same one the bento CLI uses for this, distinct from
		// both a refusal (125) and any code the target can return itself.
		fmt.Fprintln(os.Stderr, "embed: the target ran, but the guarantees above did not hold for the whole run, so its exit code is not reported.")
		return 124
	}
	return res.ExitCode
}

// writeResult prints every honesty field of a Result. A frontend's job is not to
// summarize the run: it is to say what the run could not guarantee and what it exposed
// anyway, and any field left unread is a silence an operator reads as "nothing to
// report". So each of these prints unconditionally, including the ones that stay empty
// under this example's own Options - an embedder copying this file inherits the warning
// rather than having to discover the field.
//
// It takes the writer and the policy rather than reaching for os.Stderr, so the whole
// surface is exercised by a test with a synthetic Result. The bento CLI's own renderer
// (cmd/bento/render.go) is the same shape, and TestWriteResultSurfacesEveryField guards
// this one against a new Result field arriving unprinted.
func writeResult(w io.Writer, p *policy.Policy, gated bool, res enforce.Result) {
	// Degradations: what the host could only partially enforce.
	for _, d := range res.Report.Degradations() {
		fmt.Fprintf(w, "embed: degraded: %s (%s): %s\n", d.Layer, d.State, d.Disclosure())
	}
	// Shields is the positive evidence: the credential and host-service paths the
	// sandbox actually hid or froze for this policy. An empty list is not proof nothing
	// sensitive was in scope - the degraded tier shields nothing at all and reports that
	// through the Report - so this is a count, not a guarantee.
	if len(res.Shields) > 0 {
		fmt.Fprintf(w, "embed: sandbox engaged: %d credential/host-service path(s) shielded from the target\n", len(res.Shields))
	}
	// GateAdmitted: hosts the gate let out beyond the manifest. A wrapper would offer to
	// persist these into the manifest via the normal approve/fingerprint path, turning
	// ad-hoc runtime approvals back into declared, attested policy. The host is quoted
	// for the same reason the prompt quotes it: the sandboxed target chose it, and a
	// human approving the quoted form does not make the raw bytes safe to replay here.
	for _, hp := range res.GateAdmitted {
		fmt.Fprintf(w, "embed: gate admitted undeclared egress to %q port %s\n", hp.Host, hp.Port)
	}
	// GuardBlocked: destinations the allowlist permitted but the egress guard refused to
	// dial, because the name resolved to an address the sandbox must not reach. The target
	// was told only that it could not connect - telling it apart from a dial failure would
	// let it classify names against the host's internal DNS - so a wrapper that stays quiet
	// leaves an ordinary split-horizon DNS misconfiguration looking like an unexplained
	// network failure. Quoted: the target chose the name.
	for _, hp := range res.GuardBlocked {
		fmt.Fprintf(w, "embed: the egress guard refused %q port %s: it resolved to an address the sandbox may not reach (list a private address as an explicit IP rule to allow it)\n", hp.Host, hp.Port)
	}
	// Denied: destinations that were refused - no rule named them, and no gate admitted
	// them. The target met the refusal as a 403 from the proxy inside its own error, with
	// nothing naming the rule it fell outside of, so an embedder that stays quiet turns a
	// one-letter typo in a manifest into a script that looks broken. It does not say which
	// of the two refused it: a gate that declined is the same fact to the target, and a
	// wrapper that asserted "no rule covers it" would misdescribe a host its own gate was
	// asked about and said no to. Quoted: the target chose the name.
	for _, hp := range res.Denied {
		fmt.Fprintf(w, "embed: egress to %q port %s was refused: no network rule covers it, and no gate admitted it\n", hp.Host, hp.Port)
	}
	// ShieldedGrants: always-shielded credential stores the manifest explicitly granted,
	// so the backend honored the grant over its own shield. bento does not refuse this -
	// the operator chose it - so a frontend that stays quiet makes the exposure silent.
	// ShieldedGrantTargets names the store a grant actually bound where the two differ:
	// the deny-list builds the grantable names from $HOME, so a grant can name a symlink
	// while the exposure lands elsewhere, and naming only the spelling would point a
	// reviewer at a scratch path instead of the private key that was handed over.
	lands := make(map[string]string, len(res.ShieldedGrantTargets))
	for _, t := range res.ShieldedGrantTargets {
		lands[t.Path] = t.Credential
	}
	for _, path := range res.ShieldedGrants {
		fmt.Fprintf(w, "embed: WARNING: exposed shielded credential path to the target: %q\n", path)
		if target, ok := lands[path]; ok {
			fmt.Fprintf(w, "embed: WARNING:   on this host that path is %q\n", target)
		}
	}
	// AcceptedAliases: paths the run could read as a second name for a shielded
	// credential, because AcceptAliasesUnder acknowledged the tree they sit in. That
	// acknowledgement is per-invocation and easily left behind in a wrapper script, so
	// printing it only sometimes is how a real leak hides behind a flag someone added for
	// a backup directory.
	for _, a := range res.AcceptedAliases {
		fmt.Fprintf(w, "embed: WARNING: %q was readable as a second name for the shielded credential %q\n", a.Path, a.Credential)
	}
	// Exposed: what a full run would have shielded but this tier could not (the degraded,
	// no-mount-namespace tier). The mirror image of Shields, and the same contract as
	// ShieldedGrants - bento does not refuse, so silence here hides the exposure.
	for _, s := range res.Exposed {
		fmt.Fprintf(w, "embed: WARNING: host cannot shield %q (%s), left exposed to the target\n", s.Path, s.Kind)
	}
	// Setup: whether the exit code above is the TARGET's answer or bento's. 125 is
	// bento's "could not run the target" code and a target may exit it too, so nothing
	// else in this Result separates the two - an embedder mapping them onto different
	// codes of its own reads this rather than the Report's human-facing prose.
	if res.Setup != enforce.SetupAttested {
		fmt.Fprintf(w, "embed: the sandbox did not reach the target (%s); exit code %d is bento's, not the target's\n",
			res.Setup, res.ExitCode)
	}
	// Signaled: the run ended on a signal, so the exit code below is 128+signal and not
	// an answer the target chose. An embedder that reported the code alone would present
	// a limits kill as a target that failed, and every hint after this one is written for
	// a target that ran to its own conclusion - which is why it returns here rather than
	// adding a line. It does not say what did the killing: on the degraded tier the
	// launcher execs into the target, so this is also how the target's own crash arrives.
	if res.Signaled {
		fmt.Fprintf(w, "embed: the target did not exit: the run was killed by signal %d (exit %d)", res.Signal, res.ExitCode)
		if !p.Limits.IsZero() {
			fmt.Fprint(w, "; the policy declares resource limits, and exceeding one ends a run this way")
		}
		fmt.Fprintln(w)
		return
	}
	// EgressConnections, read as a bypass signature. bento intercepts egress
	// cooperatively through HTTP_PROXY, so a target that ignores proxy settings dials
	// into the empty network namespace and fails closed; a network run that failed having
	// reached nothing through the proxy is what that looks like, and a bare "connection
	// refused" leaves the user with no idea why. It is a heuristic, not proof - a target
	// can make no connections and fail for its own reasons - so it is worded as a
	// possibility.
	//
	// A gate makes the count meaningful even over a manifest with no network rules,
	// which is precisely this example's demo: reach.yaml declares none and relies on the
	// gate, so gating only on the declared rules would skip the hint in the one scenario
	// the example is built around.
	// Gated on an attested setup: a stage that died before the target also made no
	// connection, and the proxy hint there points at a network problem that is not one.
	if res.Setup == enforce.SetupAttested && (len(p.Network) > 0 || gated) && res.ExitCode != 0 && res.EgressConnections == 0 {
		fmt.Fprintln(w, "embed: the target exited non-zero having made no connection through the egress proxy;")
		fmt.Fprintln(w, "embed: if it needs network, note that bento intercepts egress via HTTP_PROXY, so a target")
		fmt.Fprintln(w, "embed: that ignores proxy settings cannot reach even its allowlisted hosts.")
	}
}

// parseAllow reads a comma-separated allowlist of "host" or "host:port" entries
// (from BENTO_GATE_ALLOW) into a set the supervisor admits without prompting.
func parseAllow(spec string) map[string]bool {
	allow := make(map[string]bool)
	for _, e := range strings.Split(spec, ",") {
		if e = strings.TrimSpace(e); e != "" {
			allow[e] = true
		}
	}
	return allow
}

// supervisor is the interactive layer a wrapper such as tack-cli builds on top of
// bento's NetworkGate. bento consults the gate for every undeclared egress host
// and stays stateless about the answer; the supervisor adds the two things that
// make it feel like an editor agent's prompt: it asks a human, and it remembers
// the answer for the rest of the run, so the same host is asked once. "Allow for
// this session" is exactly this cache; "always allow" would be persisting the
// host into the manifest via bento's approve/fingerprint path, after which the
// gate is never consulted for it again.
type supervisor struct {
	// preApproved is admitted without a prompt - the out-of-band "already decided"
	// set (here BENTO_GATE_ALLOW), which also lets this example run unattended.
	preApproved map[string]bool
	out         io.Writer

	// mu serializes prompts and guards session: bento runs one handler goroutine
	// per connection, so several undeclared hosts can reach the gate at once, and
	// asking one human two questions at the same time is nonsense. Holding mu across
	// the prompt is the "serialize concurrent prompts" the seam leaves to the caller.
	mu      sync.Mutex
	session map[string]bool // dest -> admitted, remembered for the run
	// lines carries one human answer at a time from a single reader that owns the
	// terminal, so prompts never race on it. Closed when there is no terminal.
	lines <-chan string
}

func newSupervisor(preApproved map[string]bool, in io.Reader, out io.Writer) *supervisor {
	lines := make(chan string)
	if in == nil {
		// No terminal to prompt on: a non-pre-approved host is denied.
		close(lines)
	} else {
		go func() {
			// One reader owns the terminal for the whole run. It leaks when the run
			// ends blocked in Read, which is fine: the process is about to exit.
			r := bufio.NewReader(in)
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					close(lines)
					return
				}
				lines <- line
			}
		}()
	}
	return &supervisor{preApproved: preApproved, out: out, session: make(map[string]bool), lines: lines}
}

// gate is the enforce.NetworkGate bento calls per undeclared host.
func (s *supervisor) gate(ctx context.Context, host, port string) bool {
	dest := net.JoinHostPort(host, port)
	if s.preApproved[host] || s.preApproved[dest] {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if admitted, asked := s.session[dest]; asked {
		return admitted // answered earlier this run; do not ask again
	}
	admitted := s.ask(ctx, host, port)
	s.session[dest] = admitted
	return admitted
}

// ask prompts for one undeclared host and returns false if the run ends first: a
// prompt that ignored ctx would pin a proxy handler slot and stall teardown. host
// is attacker-controlled (the sandboxed target chose it), so it is quoted to
// neutralize terminal escapes and look-alikes before it is shown to a human.
func (s *supervisor) ask(ctx context.Context, host, port string) bool {
	fmt.Fprintf(s.out, "bento: allow egress to %s port %s? [y/N] ", strconv.Quote(host), port)
	select {
	case <-ctx.Done():
		fmt.Fprintln(s.out, "(run ended)")
		return false
	case line, ok := <-s.lines:
		return ok && strings.EqualFold(strings.TrimSpace(line), "y")
	}
}
