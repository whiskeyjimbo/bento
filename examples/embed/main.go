// Command embed hosts bento's enforcement backend in-process, using only bento's
// public packages - backend, enforce, manifest - and nothing under internal/. It
// takes a manifest path, runs the script it describes under the sandbox, prints
// what the structured Result reports - any enforcement shortfall and any shielded
// credential path the manifest exposed to the target - and passes the target's
// exit code through.
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

	"github.com/whiskeyjimbo/bento-v2/backend"
	"github.com/whiskeyjimbo/bento-v2/enforce"
	"github.com/whiskeyjimbo/bento-v2/manifest"
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
	policy, err := manifest.Load(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "embed: %v\n", err)
		return 2
	}

	// The policy names which env vars may pass through; resolving those names
	// against the host is the core's job, exposed here so the values a target sees
	// are explicit.
	env, _, err := enforce.ResolveEnv(policy, nil, os.LookupEnv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "embed: %v\n", err)
		return 2
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
	// Prompt on the controlling terminal, not the target's stdin. os.OpenFile
	// returns a nil *os.File on failure; assign it into the io.Reader only when
	// real, so newSupervisor sees a true nil (a typed-nil *os.File in an interface
	// is non-nil and would be read as a live but broken reader).
	var promptIn io.Reader
	if tty, _ := os.OpenFile("/dev/tty", os.O_RDWR, 0); tty != nil {
		defer tty.Close()
		promptIn = tty
	}
	var gate enforce.NetworkGate
	if len(preApproved) > 0 || promptIn != nil {
		gate = newSupervisor(preApproved, promptIn, os.Stderr).gate
	}

	proc := enforce.Process{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Env: env}
	// The zero-value Options refuses only on a core-tier shortfall; a hardening gap
	// (e.g. exec-block unavailable, so the target can spawn subprocesses) is reported
	// but the run proceeds. An embedder confining genuinely untrusted code wants
	// Strict: true, which refuses unless every layer, hardening included, is enforced.
	res, err := enforce.Run(context.Background(), e, policy, proc, enforce.Options{NetworkGate: gate})

	var refusal *enforce.Refusal
	switch {
	case errors.As(err, &refusal):
		// The host cannot enforce a guarantee the policy needs; Refusal names which.
		fmt.Fprintf(os.Stderr, "embed: refused: %s\n", refusal.Reason)
		return 125
	case err != nil:
		fmt.Fprintf(os.Stderr, "embed: %v\n", err)
		return 125
	}

	// A structured Result, not scraped output: report what the host could only
	// partially enforce, then pass the target's own exit code through.
	for _, d := range res.Report.Degradations() {
		fmt.Fprintf(os.Stderr, "embed: degraded: %s (%s): %s\n", d.Layer, d.State, d.Reason)
	}
	// GateAdmitted is the honesty surface: hosts the gate let out beyond the
	// manifest. A wrapper would offer to persist these into the manifest via the
	// normal approve/fingerprint path, turning ad-hoc runtime approvals back into
	// declared, attested policy.
	for _, hp := range res.GateAdmitted {
		fmt.Fprintf(os.Stderr, "embed: gate admitted undeclared egress to %s:%s\n", hp.Host, hp.Port)
	}
	// ShieldedGrants are always-shielded credential stores the manifest explicitly
	// granted, so the backend exposed them to the target. The backend does not refuse
	// this - the operator chose it - so the frontend must surface it loudly, or the
	// exposure is silent.
	for _, path := range res.ShieldedGrants {
		fmt.Fprintf(os.Stderr, "embed: WARNING: exposed shielded credential path to the target: %s\n", path)
	}
	return res.ExitCode
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
