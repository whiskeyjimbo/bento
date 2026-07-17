// Command supervise runs an untrusted script under bento the way an editor agent
// would: it discovers what the script wants, asks a human to approve it, then runs
// it enforced with a live prompt for any egress reached at runtime. It uses only
// bento's public packages - no internal/ imports.
//
// It shows bento's two honest interaction models, which differ because the kernel
// enforces them differently:
//
//   - Filesystem is approved from a TRIAL run. bento observes what the script
//     reads and writes during a permissive, non-forwarding pass, and you approve
//     paths before the enforced run. A denied read then fails inside the kernel;
//     there is no per-access callback to prompt on mid-read, so the decision is
//     made up front, not live.
//   - Network is gated LIVE. During the enforced run bento consults a gate for any
//     host the manifest did not declare, so you are prompted at connect time and a
//     denial blocks that connection in real time.
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/whiskeyjimbo/bento-v2/backend"
	"github.com/whiskeyjimbo/bento-v2/enforce"
	"github.com/whiskeyjimbo/bento-v2/policy"
	"github.com/whiskeyjimbo/bento-v2/profile"
)

func main() {
	// The backend re-execs this binary inside the sandbox as a hidden stage, so
	// dispatch that before anything else; a normal invocation falls straight through.
	backend.DispatchReexec()

	args := os.Args[1:]
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		usage(os.Stdout)
		os.Exit(0)
	}
	if len(args) != 2 || args[0] != "run" {
		usage(os.Stderr)
		os.Exit(2)
	}
	os.Exit(run(args[1]))
}

func usage(w io.Writer) {
	fmt.Fprint(w, `supervise - run a script under bento with interactive approval

Usage:
  supervise run <script>
  supervise -h | --help

It runs the script twice. First a TRIAL pass observes what the script reads,
writes, and reaches (nothing leaves the host), and asks you to approve each with
[y]es / [n]o / [A]ll. Then an ENFORCED pass runs the script under exactly what you
approved, denying the rest - and prompts you LIVE for any host it reaches that you
did not declare.

Prompts read the controlling terminal, so answer at the keyboard even when the
script has its own stdin.

Try it (from this directory):
  go build -o supervise .
  ./supervise run demo/agent.sh
`)
}

func run(scriptArg string) int {
	script, err := filepath.Abs(scriptArg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "supervise: %v\n", err)
		return 2
	}
	if _, err := os.Stat(script); err != nil {
		fmt.Fprintf(os.Stderr, "supervise: %v\n", err)
		return 2
	}
	interp := guessInterpreter(script)
	name := filepath.Base(script)

	// Prompts read the controlling terminal, kept separate from the target's own
	// stdin. Fall back to stdin when there is no tty, so the demo is still drivable
	// through a pipe or pty.
	termIn := io.Reader(os.Stdin)
	if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		defer tty.Close()
		termIn = tty
	}
	p := newPrompter(termIn, os.Stderr)

	// Act 1: trial run under observation, then approve what it wants.
	fmt.Fprintf(os.Stderr, "\n== trial run: watching %s (permissive, nothing leaves the host) ==\n", name)
	obs, err := backend.Profile(context.Background(), permissivePolicy(script, interp),
		enforce.Process{Stdout: io.Discard, Stderr: io.Discard}, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "supervise: trial run: %v\n", err)
		return 1
	}
	proposal := profile.Synthesize(script, interp, obs)
	approved := approve(p, script, interp, proposal)

	// Act 2: enforced run under exactly what was approved, with a live gate for any
	// undeclared host the script reaches at runtime.
	fmt.Fprintf(os.Stderr, "\n== enforced run: %s under your approvals ==\n", name)
	e, err := backend.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "supervise: %v\n", err)
		return 1
	}
	env, _, err := enforce.ResolveEnv(approved, nil, os.LookupEnv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "supervise: %v\n", err)
		return 1
	}
	sup := &supervisor{p: p, name: name, session: make(map[string]bool)}
	res, err := enforce.Run(context.Background(), e, approved,
		enforce.Process{Stdout: os.Stdout, Stderr: os.Stderr, Env: env},
		enforce.Options{NetworkGate: sup.gate})
	if err != nil {
		fmt.Fprintf(os.Stderr, "supervise: %v\n", err)
		return 1
	}

	// Summary: what the live gate let out beyond the manifest, and any shortfall.
	for _, d := range res.Report.Degradations() {
		fmt.Fprintf(os.Stderr, "supervise: degraded: %s (%s): %s\n", d.Layer, d.State, d.Reason)
	}
	if len(res.GateAdmitted) > 0 {
		fmt.Fprintln(os.Stderr, "\nsupervise: the live gate admitted egress beyond the manifest:")
		for _, hp := range res.GateAdmitted {
			fmt.Fprintf(os.Stderr, "  %s:%s   (a real wrapper would offer to add this to the manifest)\n", hp.Host, hp.Port)
		}
	}
	return res.ExitCode
}

// permissivePolicy is the broad policy the trial run uses so the script exercises
// its real behavior: everything readable, its own directory writable, egress
// recorded but (because Profile is called with allowNetwork=false) not forwarded,
// subprocesses allowed. bento's deny-list still shields known-sensitive paths.
func permissivePolicy(script, interp string) *policy.Policy {
	return &policy.Policy{
		Entrypoint:  script,
		Interpreter: interp,
		Read:        []string{"/"},
		Write:       []string{filepath.Dir(script)},
		Network:     []policy.NetworkRule{{Host: "*", Port: "*"}},
		Exec:        policy.ExecAll,
	}
}

// approve walks the synthesized proposal and asks the human which parts to keep,
// building the policy the enforced run is held to. Synthesize has already dropped
// the noise (the interpreter's runtime, /proc, /dev, the script itself), so these
// are the accesses that describe what this script needs.
func approve(p *prompter, script, interp string, proposal *policy.Policy) *policy.Policy {
	final := &policy.Policy{Entrypoint: script, Interpreter: interp, Exec: policy.ExecNone}
	all := false
	keep := func(kind, item string) bool {
		if all {
			fmt.Fprintf(p.out, "  %-6s %-34s allow (A)\n", kind, item)
			return true
		}
		switch p.ask(context.Background(), fmt.Sprintf("  %-6s %-34s [y/n/A] ", kind, item)) {
		case choiceAll:
			all = true
			return true
		case choiceAllow:
			return true
		default:
			return false
		}
	}

	for _, r := range trimScratch(proposal.Read) {
		if keep("read", pretty(r)) {
			final.Read = append(final.Read, r)
		}
	}
	for _, w := range trimScratch(proposal.Write) {
		if keep("write", pretty(w)) {
			final.Write = append(final.Write, w)
		}
	}
	if proposal.Exec == policy.ExecAll {
		if keep("exec", "run subprocesses") {
			final.Exec = policy.ExecAll
		}
	}
	for _, h := range proposal.Network {
		if keep("reach", h.Host+":"+h.Port) {
			final.Network = append(final.Network, h)
		}
	}
	return final
}

// supervisor is the live network gate: bento consults it for every undeclared
// host during the enforced run, and it prompts the human, remembering the answer
// for the rest of the run so a host is asked once. It mirrors an editor agent's
// per-connection prompt.
type supervisor struct {
	p    *prompter
	name string

	mu      sync.Mutex      // serializes prompts and guards session (handlers are concurrent)
	session map[string]bool // dest -> admitted, remembered for the run
}

func (s *supervisor) gate(ctx context.Context, host, port string) bool {
	dest := net.JoinHostPort(host, port)
	s.mu.Lock()
	defer s.mu.Unlock()
	if admitted, asked := s.session[dest]; asked {
		return admitted
	}
	// host is attacker-controlled (the sandboxed target chose it), so quote it to
	// neutralize terminal escapes before showing it to a human.
	c := s.p.ask(ctx, fmt.Sprintf("\n[gate] %s is reaching %s port %s now - allow? [y/n/A] ", s.name, strconv.Quote(host), port))
	admitted := c != choiceDeny
	s.session[dest] = admitted
	if c == choiceAll {
		fmt.Fprintf(s.p.out, "  (would persist %s to the manifest)\n", dest)
	}
	return admitted
}

// prompter reads single y/n/A answers from one reader that owns the terminal, so
// concurrent gate prompts never race on it. It is ctx-aware: a prompt returns a
// denial when the run ends, so a pending human prompt cannot pin a proxy handler
// slot and stall teardown.
type prompter struct {
	out   io.Writer
	lines <-chan string
}

type choice int

const (
	choiceDeny choice = iota
	choiceAllow
	choiceAll
)

func newPrompter(in io.Reader, out io.Writer) *prompter {
	lines := make(chan string)
	go func() {
		// One reader owns the terminal for the whole run; it leaks when the run ends
		// blocked in Read, which is fine because the process is about to exit.
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
	return &prompter{out: out, lines: lines}
}

func (p *prompter) ask(ctx context.Context, prompt string) choice {
	fmt.Fprint(p.out, prompt)
	select {
	case <-ctx.Done():
		fmt.Fprintln(p.out, "(run ended)")
		return choiceDeny
	case line, ok := <-p.lines:
		if !ok {
			return choiceDeny
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
			return choiceAllow
		case "a", "all":
			return choiceAll
		default:
			return choiceDeny
		}
	}
}

// trimScratch drops runtime scratch and tool-config paths a supervising wrapper
// should not bother a human with: the sandbox already provides /tmp, /dev, /proc
// as writable scratch, and a program's own dotfiles and /etc config are its
// business, not the manifest's. Profiling's writes are dir-granular, so a write to
// /tmp/x is observed as "/tmp", which slips past the profiler's own /tmp/ prefix
// filter - this catches that leftover. It keeps the accesses that describe what
// the target actually needs.
func trimScratch(paths []string) []string {
	scratch := []string{"/tmp", "/dev", "/proc", "/sys", "/run", "/nix", "/etc"}
	home, _ := os.UserHomeDir()
	var out []string
	for _, p := range paths {
		skip := false
		for _, s := range scratch {
			if p == s || strings.HasPrefix(p, s+"/") {
				skip = true
				break
			}
		}
		// A dotfile sitting directly in the home directory (~/.curlrc, ~/.netrc) is
		// tool config, not application data.
		if home != "" && filepath.Dir(p) == home && strings.HasPrefix(filepath.Base(p), ".") {
			skip = true
		}
		if !skip {
			out = append(out, p)
		}
	}
	return out
}

// pretty shortens a home-anchored path to ~ for display; the policy keeps the
// real absolute path.
func pretty(path string) string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if rest, ok := strings.CutPrefix(path, home); ok {
			return "~" + rest
		}
	}
	return path
}

// guessInterpreter picks an interpreter from the script's extension; an empty
// result means the entrypoint is its own interpreter (a compiled binary).
func guessInterpreter(path string) string {
	switch filepath.Ext(path) {
	case ".py":
		return "python3"
	case ".sh":
		return "sh"
	case ".bash":
		return "bash"
	case ".js":
		return "node"
	}
	return ""
}
