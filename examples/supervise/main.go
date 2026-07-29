// Command supervise runs an untrusted script under bento the way an editor agent
// would: it discovers what the script wants, asks a human to approve it, then runs
// it enforced with a live prompt for any egress reached at runtime. It uses only
// bento's public packages - no internal/ imports.
//
// It shows bento's two honest interaction models, which differ because the kernel
// enforces them differently:
//
//   - Filesystem is approved from a TRIAL run. bento observes what the script
//     reads and writes during a default-deny, non-forwarding pass, and you approve
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
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/whiskeyjimbo/bento/backend"
	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
	"github.com/whiskeyjimbo/bento/profile"
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

	// Ctrl-C at a prompt used to kill the process where it stood, discarding every deny
	// and standing block the run had recorded. Catching it instead cancels the run's
	// context, which unwinds the normal path (prompts return a non-answer, the enforced
	// child is killed) down to the single save below. Nothing saves from the handler: the
	// in-memory store has no lock of its own, so a save racing the approval prompts or a
	// gate handler would be reading maps they are still writing.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The permission store is this wrapper's memory of past answers. Loading it lets
	// the run auto-apply known decisions and prompt only for the unknown; the app is
	// keyed by the SHA of its entrypoint bytes, so changed code re-prompts.
	s, err := loadStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "supervise: %v\n", err)
		return 1
	}
	// Every way out of the supervised run persists what it recorded. Most of its
	// failure returns happen AFTER the approval prompts, where the human has already
	// answered - dropping those answers on the floor loses a deny a human made, which
	// is the one outcome the exit code exists to never hide.
	code := supervised(ctx, s, script)
	// Hand SIGINT back to the kernel before the save. While the notifier is installed a
	// second Ctrl-C is swallowed, so a save parked on the store's flock behind another
	// process would be unkillable from the terminal that started the run. The store's
	// write is a temp file and a rename, so aborting here cannot leave a torn store -
	// only the answers this run would have added, which is the user asking twice to quit.
	stop()
	return persistDecisions(s, code, os.Stderr)
}

// persistDecisions saves the run's decisions and folds the outcome into the exit code.
// The run's own code wins whenever it is already non-zero: it is the more specific
// answer, and a lost deny does not make a failed run more informative. A failed save
// that dropped a deny or standing block turns an otherwise clean run non-zero, so a
// lost security decision is never reported as success.
func persistDecisions(s *store, code int, out io.Writer) int {
	err := s.save()
	if err == nil {
		return code
	}
	fmt.Fprintf(out, "supervise: saving permission store: %v\n", err)
	if s.recordedDeny {
		fmt.Fprintln(out, "supervise: a deny or standing block from this run was NOT persisted; exiting non-zero so the loss is not silent.")
	}
	return finalExitCode(code, err, s.recordedDeny)
}

// supervised is the run itself: trial, approval, enforced run. Its caller persists
// whatever it recorded, so every return here - including a failure - keeps the human's
// answers.
func supervised(ctx context.Context, s *store, script string) int {
	interp := guessInterpreter(script)
	name := filepath.Base(script)

	key, err := appKey(script)
	if err != nil {
		fmt.Fprintf(os.Stderr, "supervise: %v\n", err)
		return 1
	}

	// Surface any disagreement between a committed manifest and the store up front,
	// before the trial, so the user sees that `bento run` would enforce something
	// different from what supervise remembers.
	warnManifestDrift(os.Stderr, s, key, script)

	// The prompts take the controlling terminal in BOTH directions, so the security
	// dialogue is on no fd the target holds. Writing them to os.Stderr would hand the
	// confined target the same stream the human reads, where it could print a lookalike
	// prompt while the real gate blocks on an attacker-chosen host, or flood the stream
	// to scroll the genuine one away - undoing the quoting that neutralizes escapes in
	// the paths and hosts these prompts display.
	//
	// How much that buys depends on where the target's own output goes: redirected or
	// captured, it cannot reach the dialogue at all; sharing a bare terminal with it, it
	// still writes to the same screen through its inherited stderr and can forge lines
	// there. What it cannot do either way is read the human's keystrokes, and on the
	// full tier it cannot inject into the terminal (the sandbox starts a new session;
	// the degraded tier only starts a new process group). Fall back to stdin/stderr when
	// there is no tty, so the demo is still drivable through a pipe.
	termIn, termOut := io.Reader(os.Stdin), io.Writer(os.Stderr)
	if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		defer tty.Close()
		termIn, termOut = tty, tty
	}
	p := newPrompter(termIn, termOut)
	// The banners and the run summary below are the run's report, not the dialogue, so
	// they stay on stderr - and their theme is detected there, not on the prompt stream,
	// so a redirected stderr does not collect ANSI meant for the terminal.
	t := newTheme(os.Stderr)

	// Act 1: trial run under default-deny observation, then approve what it wants.
	// The target runs with the real HOME (and its config anchors) so a $HOME-relative
	// probe names the real path the observer records; the same names go into the
	// approved policy's env allowlist so the enforced run rebuilds them.
	trialEnv := discoveryEnv()
	fmt.Fprintf(os.Stderr, "\n%s %s\n", t.bold("trial run · "+name), t.dim("(default-deny - nothing leaves the host)"))
	obs, err := trialProfile(ctx, s, discoveryPolicy(script, interp),
		enforce.Process{Stdout: io.Discard, Stderr: io.Discard, Env: trialEnv})
	if err != nil {
		// A cancelled trial fails with whatever the killed child left behind, which is a
		// teardown artifact rather than a diagnosis; report the interrupt instead.
		if ctx.Err() != nil {
			return reportInterrupt()
		}
		fmt.Fprintf(os.Stderr, "supervise: trial run: %v\n", err)
		// A script in or beside its permission store makes discoveryPolicy's script-dir
		// grant cover the store, which trialProfile's store deny path refuses fail-closed
		// with a cryptic backend message. That is the likely cause when the placement
		// overlaps, so add the actionable fix - printed alongside the real error, never
		// instead of it, so an unrelated failure (bwrap missing, a script fault) is not
		// masked by a wrong explanation.
		if scriptDirCoversStore(script, interp, s.dir) {
			fmt.Fprintf(os.Stderr, "supervise: the script's directory overlaps its permission store %q; move the script to a directory that neither contains nor sits inside the store, or point XDG_CONFIG_HOME at a location that does not contain it.\n", s.dir)
		}
		return 1
	}
	proposal, err := profile.Synthesize(script, interp, obs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "supervise: %v\n", err)
		return 1
	}
	// Allowlist the discovery anchors so the enforced run resolves the same
	// $HOME-relative paths the trial recorded and the human approved.
	proposal.Env = sortedEnvNames(trialEnv)
	approved := approve(ctx, p, s, key, script, interp, proposal)
	// Record identity for a faithful future manifest export.
	s.app(key).Entrypoint = script
	s.app(key).Interpreter = interp

	// An interrupt during the approval prompts leaves the rest of the proposal
	// unanswered, so the assembled policy is narrower than anything the human agreed
	// to. Stop here rather than enforcing it: the caller still saves the answers that
	// were given.
	if ctx.Err() != nil {
		return reportInterrupt()
	}

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
		fmt.Fprintf(os.Stderr, "supervise: refusing to run: %v\n", err)
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
	res, err := enforce.Run(ctx, e, approved,
		enforce.Process{Stdout: os.Stdout, Stderr: os.Stderr, Env: env},
		enforce.Options{NetworkGate: sup.gate})
	// An interrupt kills the sandboxed child, so the run's outcome - a signal-killed
	// exit code, or an error from the teardown - describes the cancel, not the target.
	// Checked before err so the interrupt is not reported as a sandbox failure.
	if ctx.Err() != nil {
		return reportInterrupt()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "supervise: %v\n", err)
		return 1
	}

	// Summary: what the live gate let out beyond the manifest, and any shortfall.
	for _, d := range res.Report.Degradations() {
		fmt.Fprintf(os.Stderr, "%s %s (%s): %s\n", t.warn("degraded:"), d.Layer, d.State, d.Reason)
	}
	if len(res.GateAdmitted) > 0 {
		fmt.Fprintf(os.Stderr, "\n%s\n", t.warn("the live gate admitted egress beyond the manifest:"))
		for _, hp := range res.GateAdmitted {
			// Quoted for the same reason the gate prompt quotes it: the target chose the
			// host, and a human approving the quoted form does not make the raw bytes safe
			// to replay in the summary.
			fmt.Fprintf(os.Stderr, "  %s %s\n", t.bold(strconv.Quote(hp.Host)+" port "+hp.Port), t.dim("(a real wrapper would offer to add this to the manifest)"))
		}
	}
	// A guard block is the one outcome a supervised run cannot explain from the prompt
	// alone: the human just approved the host, the guard then refused the dial because
	// the name resolved somewhere the sandbox may not reach, and the target was told
	// only that it could not connect. Without this the approval looks honored and the
	// failure looks unexplained. Quoted for the reason the admitted list is.
	if len(res.GuardBlocked) > 0 {
		fmt.Fprintf(os.Stderr, "\n%s\n", t.warn("the egress guard refused these destinations: each resolved to an address the sandbox may not reach"))
		for _, hp := range res.GuardBlocked {
			fmt.Fprintf(os.Stderr, "  %s %s\n", t.bold(strconv.Quote(hp.Host)+" port "+hp.Port), t.dim("(a private address is reachable only as an explicit IP rule; loopback and metadata never)"))
		}
	}
	return res.ExitCode
}

// reportInterrupt is the exit for a signalled run: it is supervise's own failure code,
// not the target's, because the target never got to finish. It deliberately does not
// use 130 - the target dies on the same Ctrl-C and can report 130 itself, so reusing it
// here would make the two indistinguishable. The stderr line is what tells the human;
// the code just keeps the run from being reported as clean.
func reportInterrupt() int {
	fmt.Fprintln(os.Stderr, "\nsupervise: interrupted - the answers given so far are being saved")
	return 1
}

// finalExitCode is the process exit code. It is the target's own code untouched,
// except when persisting the store failed AND this run recorded a deny or standing
// block: that lost a security decision the human made, so a zero target code would
// falsely report a clean run over a dropped block. Signal it with a non-zero code
// (paired with a stderr note at the save site). A target that already failed keeps its
// own (already non-zero) code.
func finalExitCode(targetExit int, saveErr error, recordedDeny bool) int {
	if saveErr != nil && recordedDeny && targetExit == 0 {
		return 1
	}
	return targetExit
}

// assertStoreShielded refuses a policy that grants any path covering the permission
// store. It backstops the enforced run, which carries no DenyPaths, so this is the last
// check that a copyist widening the approval path cannot expose the store to the
// supervised script; `perms export` runs it too, since a manifest leaves the wrapper's
// shielding behind entirely. Both callers word the refusal, so this names only the
// grant.
func assertStoreShielded(final *policy.Policy, storeDir string) error {
	for _, g := range append(append([]string{}, final.Read...), final.Write...) {
		if coversStore(g, storeDir) {
			return fmt.Errorf("the policy grants %q, which covers the permission store %q", g, storeDir)
		}
	}
	return nil
}

// scriptDirCoversStore reports whether the trial's script-dir grant would cover the
// permission store - the placement (script in or beside the store dir) that makes
// trialProfile's store deny path refuse the trial. It reuses the coverage predicate of
// assertStoreShielded, the enforced-run backstop, so the two share one definition of
// "covers". It is a best-effort match for the trial refusal, which resolves a not-yet-
// created store's path slightly differently; the message is additive, so a miss only
// falls back to the raw backend error, never a wrong abort.
func scriptDirCoversStore(script, interp, storeDir string) bool {
	return assertStoreShielded(discoveryPolicy(script, interp), storeDir) != nil
}

// trialProfile runs the observed trial pass under default-deny, always shielding the
// permission store. Only the script's own directory is mounted, so the store is absent
// unless the script sits in or beside it (a dev-set XDG_CONFIG_HOME the script dir also
// contains), where the script-dir grant would otherwise cover the store; the store deny
// path shields it regardless of where the script lives. Owning the deny here, not at the
// call site, keeps that shield from being dropped by a future edit to the trial call -
// the fail-open regression the store must never suffer.
func trialProfile(ctx context.Context, s *store, discovery *policy.Policy, proc enforce.Process) (profile.Observation, error) {
	return backend.Profile(ctx, discovery, proc, backend.ProfileOptions{DenyPaths: []string{s.dir}})
}

// discoveryPolicy is the default-deny policy the trial run uses. Only the script's
// own directory is mounted; every other path the script touches is absent, so the
// attempt is RECORDED without the content ever being exposed, and the human grants
// it explicitly before the enforced run. Egress is recorded but (because Profile is
// called with allowNetwork=false) not forwarded, and subprocesses are allowed so the
// script exercises its real behavior. This binds only the script's directory, so
// the caller shields the permission store separately (via a trial deny path): a
// script that lives in or beside the store would otherwise get it through this
// script-dir grant.
func discoveryPolicy(script, interp string) *policy.Policy {
	p := &policy.Policy{
		Entrypoint:  script,
		Interpreter: interp,
		Network:     []policy.NetworkRule{{Host: "*", Port: "*"}},
		Exec:        policy.ExecAll,
	}
	// Bind the script's own directory unless it is broad (the home directory or a
	// top-level dir): mounting a broad directory during discovery would re-expose the
	// credentials that live beside the script, defeating the default-deny the run
	// relies on. A broad-dir script still runs - the entrypoint is bound regardless -
	// with its sibling reads recorded as intent, not honored.
	if dir := filepath.Dir(script); !isBroadDir(dir) {
		p.Read = []string{dir}
		p.Write = []string{dir}
	}
	return p
}

// isBroadDir reports whether dir is too broad to bind during the trial: the
// filesystem root, any top-level directory, or the home directory itself.
func isBroadDir(dir string) bool {
	if dir == "/" || filepath.Dir(dir) == "/" {
		return true
	}
	home, _ := os.UserHomeDir()
	return home != "" && dir == filepath.Clean(home)
}

// discoveryEnvNames are the variables that anchor $HOME-relative paths. The trial
// passes their host values to the target so it names real paths (which the observer
// records even though default-deny leaves them unmounted), and they are allowlisted
// in the approved policy so the enforced run rebuilds the identical paths.
var discoveryEnvNames = []string{
	"HOME", "USER", "LOGNAME",
	"XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME",
}

// discoveryEnv reads the discovery variables actually set on the host. An unset
// variable is left out rather than passed empty, so the enforced run's env allowlist
// names only variables it will really see.
func discoveryEnv() map[string]string {
	env := make(map[string]string)
	for _, name := range discoveryEnvNames {
		if v, ok := os.LookupEnv(name); ok && v != "" {
			env[name] = v
		}
	}
	return env
}

// sortedEnvNames returns the env variable names present in m, sorted, for a stable
// env allowlist on the approved policy.
func sortedEnvNames(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// approve walks the synthesized proposal and builds the policy the enforced run is
// held to. For each access it consults the permission store: a remembered decision
// applies silently, an unknown one prompts and (for y/n) is remembered. A grant
// that would expose the store is refused outright. Synthesize has already dropped
// the noise (the interpreter's runtime, /proc, /dev, the script itself).
func approve(ctx context.Context, p *prompter, s *store, key, script, interp string, proposal *policy.Policy) *policy.Policy {
	// Carry the discovery env allowlist through unprompted: HOME and the XDG anchors
	// are low-risk name bindings, and the enforced run needs them to rebuild the same
	// $HOME-relative paths the trial recorded. They name variables, not grants; a path
	// under one is still bound only if its own read/write grant is approved below.
	final := &policy.Policy{Entrypoint: script, Interpreter: interp, Exec: policy.ExecNone, Env: proposal.Env}

	fmt.Fprintln(p.out, p.t.dim("  approve what the trial touched  ·  y allow (this script) · n deny · o once"))

	// consider decides one item. path is the real path for a filesystem access (used
	// for the store-covers refusal), empty for exec/network. remembered reports a
	// stored decision; persist records a new one for this script. The trial only ever
	// decides per-script - standing rules for every script are a deliberate `perms
	// global` act, never a keystroke away from a routine yes.
	consider := func(kind, display, path string, remembered func() (decision, bool), persist func(decision)) bool {
		// Once the run is cancelled, deny the rest silently. ask() prints its prompt
		// before it notices the cancel, so without this every remaining item would print
		// a prompt and answer itself, burying the interrupt in a wall of dead questions.
		if ctx.Err() != nil {
			return false
		}
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
		switch p.ask(ctx, prompt) {
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
		deniesUnderAllows(final.Write, writeDenies, "write")...,
	) {
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

	// promptMu, not mu, is what a parked human holds. It serializes everything that
	// touches the terminal - the prompts share one reader, and two handlers printing
	// at once would interleave a verdict into another's prompt - while mu covers only
	// the short session and store accesses, so the connections that do not need to ask
	// are not blocked behind someone's keyboard.
	promptMu sync.Mutex
	mu       sync.Mutex      // guards session and the store (handlers are concurrent)
	session  map[string]bool // dest -> admitted, remembered for the run
}

func (s *supervisor) gate(ctx context.Context, host, port string) bool {
	dest := net.JoinHostPort(host, port)
	if admitted, asked := s.recall(dest); asked {
		return admitted
	}
	// A remembered decision (deny-wins across global + per-app) applies with no prompt.
	// A remembered ALLOW needs the terminal for nothing at all, so answer it before
	// taking promptMu: it is the common case in a run whose hosts are already known, and
	// making it wait on someone else's keyboard is the stall this lock split exists to
	// remove. A stored deny is printed - so a silent block is never a mystery - which
	// does need the terminal.
	if d, ok := s.decide(host, port); ok {
		if d == allow {
			return s.record(dest, true)
		}
		s.promptMu.Lock()
		defer s.promptMu.Unlock()
		fmt.Fprintf(s.p.out, "\n  %s %s reaching %s port %s - denied by the permission store\n",
			s.p.t.markDeny(), s.name, s.p.t.bold(strconv.Quote(host)), port)
		return s.record(dest, false)
	}
	s.promptMu.Lock()
	defer s.promptMu.Unlock()
	// Another handler may have answered this dest while this one waited for the
	// terminal. Its answer is the run's answer, so honor it rather than asking twice
	// for a host the human has already ruled on. A decision persisted by that handler
	// is covered too: it recorded the dest in the session before releasing the lock.
	if admitted, asked := s.recall(dest); asked {
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
		s.remember(host, port, allow, false)
		admitted = true
	case choiceOnce:
		admitted = true
	case choiceDeny:
		s.remember(host, port, deny, false)
	case choiceBlock:
		// The standing block: deny this host for EVERY script, surviving code changes.
		// It is an explicit, distinctly-labeled key (no shift-pair to slip into), and a
		// mistaken block is undone with `perms forget global`.
		s.remember(host, port, deny, true)
	}
	return s.record(dest, admitted)
}

// recall reports this run's answer for dest, if one has been recorded.
func (s *supervisor) recall(dest string) (admitted, asked bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	admitted, asked = s.session[dest]
	return admitted, asked
}

func (s *supervisor) decide(host, port string) (decision, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.s.decideNetwork(s.key, host, port)
}

func (s *supervisor) remember(host, port string, d decision, global bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.s.rememberNetwork(s.key, host, port, d, global)
}

// record fixes dest's answer for the rest of the run and returns it, so the gate's
// verdict and what a later connection recalls cannot diverge.
func (s *supervisor) record(dest string, admitted bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
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
