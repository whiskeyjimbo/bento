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
	"time"

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
	if len(args) >= 1 && args[0] == "perms" {
		os.Exit(perms(args[1:], os.Stdin, os.Stdout))
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
  supervise perms list | forget | reset
  supervise -h | --help

It runs the script twice. First a TRIAL pass observes what the script reads,
writes, and reaches (nothing leaves the host), and asks you to approve each with
[y]es / [n]o / [o]nce. Then an ENFORCED pass runs the script under exactly what you
approved, denying the rest - and prompts you LIVE for any host it reaches that you
did not declare, where you can also [B]lock it for every script.

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

	// The permission store is this wrapper's memory of past answers. Loading it lets
	// the run auto-apply known decisions and prompt only for the unknown; the app is
	// keyed by the SHA of its entrypoint bytes, so changed code re-prompts.
	s, err := loadStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "supervise: %v\n", err)
		return 1
	}
	key, err := appKey(script)
	if err != nil {
		fmt.Fprintf(os.Stderr, "supervise: %v\n", err)
		return 1
	}

	// Surface any disagreement between a committed manifest and the store up front,
	// before the trial, so the user sees that `bento run` would enforce something
	// different from what supervise remembers.
	warnManifestDrift(os.Stderr, s, key, script)

	// Prompts read the controlling terminal, kept separate from the target's own
	// stdin. Fall back to stdin when there is no tty, so the demo is still drivable
	// through a pipe or pty.
	termIn := io.Reader(os.Stdin)
	if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		defer tty.Close()
		termIn = tty
	}
	p := newPrompter(termIn, os.Stderr)
	t := p.t // one theme, detected on os.Stderr, shared by the banners below

	// Act 1: trial run under observation, then approve what it wants. The store dir
	// is shielded from the permissive trial (bv2-16h): the trial grants Read:["/"],
	// so without this the untrusted target could read the store during profiling.
	fmt.Fprintf(os.Stderr, "\n%s %s\n", t.bold("trial run · "+name), t.dim("(permissive - nothing leaves the host)"))
	obs, err := backend.Profile(context.Background(), permissivePolicy(script, interp),
		enforce.Process{Stdout: io.Discard, Stderr: io.Discard},
		backend.ProfileOptions{DenyPaths: []string{s.dir}})
	if err != nil {
		fmt.Fprintf(os.Stderr, "supervise: trial run: %v\n", err)
		return 1
	}
	proposal := profile.Synthesize(script, interp, obs)
	approved := approve(p, s, key, script, interp, proposal)
	// Record identity for a faithful future manifest export.
	s.app(key).Entrypoint = script
	s.app(key).Interpreter = interp

	// Drop anything typed past the approval prompts, so a stray keystroke during
	// Act 1 cannot silently answer the first live gate prompt in Act 2 (both phases
	// share one terminal reader). Best-effort: a production tool would flush the
	// terminal's input buffer (tcflush) to also discard input the OS holds but the
	// reader has not read yet.
	p.drain()

	// Belt-and-suspenders behind the store shield: the enforced run passes no
	// DenyPaths (the linux backend takes nil for an enforced run by design), so the
	// store's protection rests entirely on approve() having refused every grant that
	// covers it. Re-check the assembled policy so a future edit that builds it by some
	// path other than consider/coversStore cannot silently expose the store. Reaching
	// here with a covering grant is a bug, so fail closed rather than run.
	if err := assertStoreShielded(approved, s.dir); err != nil {
		fmt.Fprintf(os.Stderr, "supervise: %v\n", err)
		return 1
	}

	// Act 2: enforced run under exactly what was approved, with a live gate for any
	// undeclared host the script reaches at runtime.
	fmt.Fprintf(os.Stderr, "\n%s %s\n", t.bold("enforced run · "+name), t.dim("(a live gate prompts for any undeclared host)"))
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
	sup := &supervisor{p: p, s: s, key: key, name: name, session: make(map[string]bool)}
	res, err := enforce.Run(context.Background(), e, approved,
		enforce.Process{Stdout: os.Stdout, Stderr: os.Stderr, Env: env},
		enforce.Options{NetworkGate: sup.gate})
	if err != nil {
		fmt.Fprintf(os.Stderr, "supervise: %v\n", err)
		return 1
	}

	// Persist the run's decisions so the next run of this app prompts only for what
	// is new.
	saveErr := s.save()
	if saveErr != nil {
		fmt.Fprintf(os.Stderr, "supervise: saving permission store: %v\n", saveErr)
	}

	// Summary: what the live gate let out beyond the manifest, and any shortfall.
	for _, d := range res.Report.Degradations() {
		fmt.Fprintf(os.Stderr, "%s %s (%s): %s\n", t.warn("degraded:"), d.Layer, d.State, d.Reason)
	}
	if len(res.GateAdmitted) > 0 {
		fmt.Fprintf(os.Stderr, "\n%s\n", t.warn("the live gate admitted egress beyond the manifest:"))
		for _, hp := range res.GateAdmitted {
			fmt.Fprintf(os.Stderr, "  %s %s\n", t.bold(hp.Host+":"+hp.Port), t.dim("(a real wrapper would offer to add this to the manifest)"))
		}
	}
	return finalExitCode(res.ExitCode, saveErr, s.recordedDeny)
}

// finalExitCode is the process exit code. It is the target's own code untouched,
// except when persisting the store failed AND this run recorded a deny or standing
// block: that lost a security decision the human made, so a zero target code would
// falsely report a clean run over a dropped block. Signal it with a distinct non-zero
// code. A target that already failed keeps its own (already non-zero) code.
func finalExitCode(targetExit int, saveErr error, recordedDeny bool) int {
	if saveErr != nil && recordedDeny && targetExit == 0 {
		return 1
	}
	return targetExit
}

// assertStoreShielded refuses a final policy that grants any path covering the
// permission store. It is the backstop described where it is called: the enforced run
// carries no DenyPaths, so this is the last check that a copyist widening the approval
// path cannot expose the store to the supervised script.
func assertStoreShielded(final *policy.Policy, storeDir string) error {
	for _, g := range append(append([]string{}, final.Read...), final.Write...) {
		if coversStore(g, storeDir) {
			return fmt.Errorf("refusing to run: the approved policy grants %q, which covers the permission store %q", g, storeDir)
		}
	}
	return nil
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

// approve walks the synthesized proposal and builds the policy the enforced run is
// held to. For each access it consults the permission store: a remembered decision
// applies silently, an unknown one prompts and (for y/n) is remembered. A grant
// that would expose the store is refused outright. Synthesize has already dropped
// the noise (the interpreter's runtime, /proc, /dev, the script itself).
func approve(p *prompter, s *store, key, script, interp string, proposal *policy.Policy) *policy.Policy {
	final := &policy.Policy{Entrypoint: script, Interpreter: interp, Exec: policy.ExecNone}

	fmt.Fprintln(p.out, p.t.dim("  approve what the trial touched  ·  y allow (this script) · n deny · o once"))

	// consider decides one item. path is the real path for a filesystem access (used
	// for the store-covers refusal), empty for exec/network. remembered reports a
	// stored decision; persist records a new one for this script. The trial only ever
	// decides per-script - standing rules for every script are a deliberate `perms
	// global` act, never a keystroke away from a routine yes.
	consider := func(kind, display, path string, remembered func() (decision, bool), persist func(decision)) bool {
		if path != "" && coversStore(path, s.dir) {
			p.row(p.t.markDeny(), kind, display, p.t.dim("refused - would expose the permission store"))
			return false
		}
		if d, ok := remembered(); ok {
			mark, word := p.t.markAllow(), "allowed"
			if d == deny {
				mark, word = p.t.markDeny(), "denied"
			}
			p.row(mark, kind, display, p.t.dim(word+" (remembered)"))
			return d == allow
		}
		keys := p.t.dim("[y]es [n]o [o]nce")
		prompt := fmt.Sprintf("    %s %s %s %s ", p.t.kindLabel(pad(kind, 5)), pad(display, 38), keys, p.t.caret())
		switch p.ask(context.Background(), prompt) {
		case choiceAllow:
			persist(allow)
			return true
		case choiceOnce:
			return true
		case choiceDeny:
			persist(deny)
			return false
		default: // deny once
			return false
		}
	}

	for _, r := range trimScratch(proposal.Read) {
		if consider("read", quotePath(r), r,
			func() (decision, bool) { return s.decidePath(key, "read", r) },
			func(d decision) { s.rememberPath(key, "read", r, d, false) }) {
			final.Read = append(final.Read, r)
		}
	}
	for _, w := range trimScratch(proposal.Write) {
		if consider("write", quotePath(w), w,
			func() (decision, bool) { return s.decidePath(key, "write", w) },
			func(d decision) { s.rememberPath(key, "write", w, d, false) }) {
			final.Write = append(final.Write, w)
		}
	}
	if proposal.Exec == policy.ExecAll {
		if consider("exec", "run subprocesses", "",
			func() (decision, bool) { return s.decideExec(key) },
			func(d decision) { s.rememberExec(key, d, false) }) {
			final.Exec = policy.ExecAll
		}
	}
	for _, h := range proposal.Network {
		host, port := h.Host, h.Port
		if consider("reach", strconv.Quote(host)+":"+port, "",
			func() (decision, bool) { return s.decideNetwork(key, host, port) },
			func(d decision) { s.rememberNetwork(key, host, port, d, false) }) {
			final.Network = append(final.Network, h)
		}
	}

	warnDenyUnderAllow(p, s, key, final)
	return final
}

// warnDenyUnderAllow flags a stored filesystem deny that lies under an allowed
// grant: bento has no per-path deny, so the enforced run cannot honor it (the
// covering grant binds the whole tree). It draws on the effective, cross-layer deny
// set, so a global standing-deny under a freshly-approved allow is flagged too -
// the same case export refuses; leaving it silent would undercut the standing
// denylist exactly where the warning exists to catch it.
func warnDenyUnderAllow(p *prompter, s *store, key string, final *policy.Policy) {
	_, readDenies := s.effectivePaths(key, "read")
	_, writeDenies := s.effectivePaths(key, "write")
	for _, c := range append(
		deniesUnderAllows(readGrants(final.Read, final.Write), readDenies, "read"),
		deniesUnderAllows(final.Write, writeDenies, "write")...) {
		fmt.Fprintf(p.out, "  note: %s %s is denied but lies under the allowed %s; bento cannot enforce the sub-deny\n",
			c.kind, quotePath(c.deny), quotePath(c.allow))
	}
}

// supervisor is the live network gate: bento consults it for every undeclared
// host during the enforced run, and it prompts the human, remembering the answer
// for the rest of the run so a host is asked once. It mirrors an editor agent's
// per-connection prompt.
type supervisor struct {
	p    *prompter
	s    *store
	key  string
	name string

	mu      sync.Mutex      // serializes prompts and guards session (handlers are concurrent)
	session map[string]bool // dest -> admitted, remembered for the run
}

func (s *supervisor) gate(ctx context.Context, host, port string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	dest := net.JoinHostPort(host, port)
	if admitted, asked := s.session[dest]; asked {
		return admitted
	}
	// A remembered decision (deny-wins across global + per-app) applies with no
	// prompt; a stored deny is printed so a silent block is never a mystery.
	if d, ok := s.s.decideNetwork(s.key, host, port); ok {
		if d == deny {
			fmt.Fprintf(s.p.out, "\n  %s %s reaching %s port %s - denied by the permission store\n",
				s.p.t.markDeny(), s.name, s.p.t.bold(strconv.Quote(host)), port)
		}
		admitted := d == allow
		s.session[dest] = admitted
		return admitted
	}
	// host is attacker-controlled (the sandboxed target chose it), so quote it to
	// neutralize terminal escapes before showing it to a human.
	c := s.p.ask(ctx, fmt.Sprintf("\n  %s %s is reaching %s port %s now\n      allow? %s %s ",
		s.p.t.warn("net"), s.name, s.p.t.bold(strconv.Quote(host)), port,
		s.p.t.dim("[y]es [n]o [o]nce [B]lock-everywhere"), s.p.t.caret()))
	admitted := false
	switch c {
	case choiceAllow:
		s.s.rememberNetwork(s.key, host, port, allow, false)
		admitted = true
	case choiceOnce:
		admitted = true
	case choiceDeny:
		s.s.rememberNetwork(s.key, host, port, deny, false)
	case choiceBlock:
		// The standing block: deny this host for EVERY script, surviving code changes.
		// It is an explicit, distinctly-labeled key (no shift-pair to slip into), and a
		// mistaken block is undone with `perms forget global`.
		s.s.rememberNetwork(s.key, host, port, deny, true)
	}
	s.session[dest] = admitted
	return admitted
}

// prompter reads single-key answers from one reader that owns the terminal, so
// concurrent gate prompts never race on it. It is ctx-aware: a prompt returns a
// denial when the run ends, so a pending human prompt cannot pin a proxy handler
// slot and stall teardown.
type prompter struct {
	out   io.Writer
	t     theme
	lines <-chan string
}

// row prints one aligned decision line: a status mark, the colored access kind, the
// access target, and a trailing note. mark is a rendered glyph (or a blank column,
// so a prompt line that has no verdict yet still lines up under the verdicts).
func (p *prompter) row(mark, kind, display, tail string) {
	fmt.Fprintf(p.out, "  %s %s %s %s\n", mark, p.t.kindLabel(pad(kind, 5)), pad(display, 38), tail)
}

type choice int

const (
	choiceDenyOnce choice = iota // blank / unrecognized: deny this run, do not remember
	choiceAllow                  // y: allow, and remember for this app
	choiceOnce                   // o: allow this run only, do not remember
	choiceDeny                   // n: deny, and remember for this app
	choiceBlock                  // b: deny for EVERY app - the standing block, offered at the gate
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
	return &prompter{out: out, t: newTheme(out), lines: lines}
}

// drain discards lines the reader has already read past the last consumed answer,
// so input typed during one phase does not leak into the next. It waits briefly
// for a read-ahead line to surface, then returns once the input is quiet.
func (p *prompter) drain() {
	for {
		select {
		case _, ok := <-p.lines:
			if !ok {
				return // reader closed (EOF): nothing more can arrive
			}
		case <-time.After(20 * time.Millisecond):
			return
		}
	}
}

func (p *prompter) ask(ctx context.Context, prompt string) choice {
	fmt.Fprint(p.out, prompt)
	select {
	case <-ctx.Done():
		fmt.Fprintln(p.out, "(run ended)")
		return choiceDenyOnce // teardown, not a human choice: do not persist a deny
	case line, ok := <-p.lines:
		if !ok {
			return choiceDenyOnce
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
			return choiceAllow
		case "o", "once":
			return choiceOnce
		case "n", "no":
			return choiceDeny
		case "b", "block":
			return choiceBlock
		default:
			return choiceDenyOnce
		}
	}
}

// trimScratch drops paths the sandbox already provides for free, so a human is
// never asked to grant them: /tmp, /dev, /proc, /sys, /run are mounted as scratch
// in every sandbox, and /nix is bound read-only when a Nix interpreter needs it.
// Granting them is meaningless, and approving the /tmp or /dev that profiling's
// dir-granular writes leave in the proposal actively breaks the run. Everything
// else is kept: it is deliberately narrow, because dropping a path here means the
// enforced run will DENY it, so it must never hide something the script needs.
func trimScratch(paths []string) []string {
	provided := []string{"/tmp", "/dev", "/proc", "/sys", "/run", "/nix"}
	var out []string
	for _, p := range paths {
		skip := false
		for _, s := range provided {
			if p == s || strings.HasPrefix(p, s+"/") {
				skip = true
				break
			}
		}
		if !skip {
			out = append(out, p)
		}
	}
	return out
}

// quotePath shortens a path for display and quotes it. The path comes from the
// untrusted trial (a filename the script chose), so it can carry terminal escape
// sequences; quoting neutralizes them at the approval prompt, the same as the gate
// quotes an attacker-chosen host. The policy keeps the literal path.
func quotePath(p string) string { return strconv.Quote(pretty(p)) }

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
