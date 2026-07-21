// Package linux enforces a policy with bubblewrap.
//
// It is an adapter behind the enforce.Enforcer seam: the core hands it a
// validated policy and it answers with what it actually enforced. Nothing here
// decides policy - that is the core's job - and no type from here appears in the
// core's signatures.
package linux

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/whiskeyjimbo/bento-v2/enforce"
	"github.com/whiskeyjimbo/bento-v2/internal/denylist"
	"github.com/whiskeyjimbo/bento-v2/internal/proxy"
	"github.com/whiskeyjimbo/bento-v2/policy"
)

// Enforcer applies policies with bubblewrap.
type Enforcer struct {
	// selfPath overrides the path to the bento binary used as the in-sandbox
	// egress forwarder. Empty means "the running executable", which is correct in
	// production; tests set it because the test process is not bento.
	selfPath string
}

// New returns a bubblewrap-backed Enforcer.
func New() *Enforcer { return &Enforcer{} }

var _ enforce.Enforcer = (*Enforcer)(nil)

// Run compiles the policy into a bubblewrap invocation and executes the target
// inside it. A non-zero exit from the target is returned in the Result; err is
// reserved for a failure to build or start the sandbox, so a script that merely
// fails is never confused with a sandbox that did not hold.
func (e *Enforcer) Run(ctx context.Context, p *policy.Policy, proc enforce.Process, gate enforce.NetworkGate, degraded bool) (enforce.Result, error) {
	// A degraded run cannot use bubblewrap (user namespaces are blocked); take the
	// Landlock-only no-bwrap tier instead. The caller (enforce.Run) only sets this
	// after admitting the run under --allow-degraded, so this never silently downgrades.
	if degraded {
		return e.runDegraded(ctx, p, proc)
	}

	report := e.Probe(ctx)

	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return enforce.Result{}, fmt.Errorf("linux: bubblewrap (bwrap) not found: %w", err)
	}
	// A gate forces the egress stack up even with zero rules: a supervised run with
	// no manifest network means "prompt on every host", so the proxy must exist for
	// the gate to be consulted at all. Enforced runs take no caller deny paths - that
	// seam is profiling-only (see Profile).
	sb, cleanup, err := newSandbox(p, e.selfPath, gate != nil, nil)
	if err != nil {
		return enforce.Result{}, err
	}
	defer cleanup()

	if err := prepareWriteDirs(p, sb); err != nil {
		return enforce.Result{}, err
	}

	// bwrap creates a directory shield mount point on the host when the shielded
	// path does not exist yet and a write grant makes its parent writable (e.g. a
	// project's unborn .git/hooks). Remove those after the run so the sandbox leaves
	// no directory artifact; see removeCreatedShieldDirs for why this is safe and
	// best-effort.
	if reads, writes, err := resolveGrants(p); err == nil {
		_, optIns := explicitShieldOptIns(sb, p.Read)
		defer removeCreatedShieldDirs(createdShieldDirs(sb, exposedPaths(sb, reads, writes), writes, optIns))
	}

	// When the policy allows egress (or a gate supervises it), run the allowlist
	// proxy on the sandbox's unix socket for the lifetime of the run. The sandbox
	// reaches it only through that socket; nothing else can leave the network
	// namespace. stopProxy waits for every in-flight handler (Serve's wg.Wait), so
	// it is called explicitly before each success return - not just deferred - so
	// a gate admitted during target teardown is recorded before the result is read.
	// It is idempotent (sync.OnceFunc inside startProxy), so the defer stays as a
	// safety net for the error paths without double-closing.
	stopProxy := func() {}
	egress := func() int { return 0 }
	admitted := func() []enforce.HostPort { return nil }
	if sb.proxySocket != "" {
		stopProxy, egress, admitted, err = startProxy(ctx, p, sb.proxySocket, gate)
		if err != nil {
			return enforce.Result{}, err
		}
		defer stopProxy()
	}

	args, shields, err := compile(p, proc, sb)
	if err != nil {
		return enforce.Result{}, err
	}

	// Surface any always-shielded credential store the policy explicitly opted back into
	// the sandbox (yz3.2) for the frontend to warn about, named by its literal deny-list
	// path. The shields still protect every path not opted into.
	optedIn, _ := explicitShieldOptIns(sb, p.Read)

	// When the policy sets limits and this host can enforce them, run bwrap inside
	// a transient systemd scope carrying the limits. When it cannot, the run has
	// already been admitted (refused by default, or permitted under
	// --allow-degraded) - here it simply proceeds unwrapped.
	exe, cargs := bwrap, args
	if !p.Limits.IsZero() {
		if ok, _ := canCreateScope(); ok {
			// Preflight the exact limits so a scope-creation failure surfaces as a
			// clear error, never as the target's exit code for a target that never
			// ran.
			if err := preflightLimits(p.Limits); err != nil {
				return enforce.Result{}, fmt.Errorf("linux: %w", err)
			}
			exe, cargs = wrapWithLimits(bwrap, args, p.Limits)
			// An undelegated cpu controller is reported by the probe as LayerLimitsCPU
			// Unavailable and refused at admission; a run that reaches here with a cpu
			// limit was either delegated or explicitly permitted under --allow-degraded,
			// and the probe's LayerLimitsCPU state carries through to the final report.
		}
	}

	cmd := exec.CommandContext(ctx, exe, cargs...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = proc.Stdin, proc.Stdout, proc.Stderr

	switch err := cmd.Run(); {
	case err == nil:
		stopProxy()
		return enforce.Result{ExitCode: 0, Report: report, EgressConnections: egress(), GateAdmitted: admitted(), ShieldedGrants: optedIn, Shields: shields}, nil
	case isExitError(err):
		var ee *exec.ExitError
		errors.As(err, &ee)
		stopProxy()
		return enforce.Result{ExitCode: ee.ExitCode(), Report: report, EgressConnections: egress(), GateAdmitted: admitted(), ShieldedGrants: optedIn, Shields: shields}, nil
	default:
		return enforce.Result{Report: report}, fmt.Errorf("linux: running sandbox: %w", err)
	}
}

func isExitError(err error) bool {
	var ee *exec.ExitError
	return errors.As(err, &ee)
}

// prepareWriteDirs makes each granted write directory exist on the host before it
// is bound, so writes persist. bwrap can only bind an existing path, and only a
// directory can be made writable in a way that supports creating and renaming
// files inside it - binding a file makes it a mount point, which breaks atomic
// save-and-rename. A write grant is therefore a directory: a missing one is
// created, an existing file is refused. The shield check runs first so a grant
// that lands inside an always-shielded path is rejected before anything is
// created under it (never mkdir inside ~/.ssh only to reject the grant).
func prepareWriteDirs(p *policy.Policy, sb sandbox) error {
	writes, err := resolveAll(p.Write)
	if err != nil {
		return err
	}
	_, optInShields := explicitShieldOptIns(sb, p.Read)
	if err := checkNotShielded(sb, writes, optInShields); err != nil {
		return err
	}
	// Refuse a grant above a credential shield before creating any directory, so a
	// to-be-refused grant does not leave a host artifact from the MkdirAll below.
	if err := checkWriteNotAboveShield(sb, writes); err != nil {
		return err
	}
	for _, w := range writes {
		switch fi, err := os.Stat(w); {
		case err == nil && fi.IsDir():
			// Already a directory: nothing to prepare.
		case err == nil:
			return fmt.Errorf("linux: write grant %q is a file; grant its parent directory instead", w)
		case os.IsNotExist(err):
			if err := os.MkdirAll(w, 0o755); err != nil {
				return fmt.Errorf("linux: creating write directory %q: %w", w, err)
			}
		case errors.Is(err, syscall.ELOOP):
			// Reached before compile's own check, so refuse it in the same words a
			// looping read grant gets rather than leaking a bare stat error.
			return loopedGrantError(w)
		default:
			return fmt.Errorf("linux: checking write grant %q: %w", w, err)
		}
	}
	return nil
}

// newSandbox resolves the host facts the argv compiler needs, and returns a
// cleanup for the temporary files it creates.
func newSandbox(p *policy.Policy, selfPath string, gated bool, denyPaths []string) (sandbox, func(), error) {
	noop := func() {}

	entrypoint, err := resolve(p.Entrypoint)
	if err != nil {
		return sandbox{}, noop, err
	}
	if _, err := os.Stat(entrypoint); err != nil {
		return sandbox{}, noop, fmt.Errorf("linux: entrypoint %q: %w", p.Entrypoint, err)
	}

	// An empty interpreter means the entrypoint runs itself: a compiled binary.
	var interp string
	if p.Interpreter != "" {
		found, err := exec.LookPath(p.Interpreter)
		if err != nil {
			return sandbox{}, noop, fmt.Errorf("linux: interpreter %q not found: %w", p.Interpreter, err)
		}
		if interp, err = resolve(found); err != nil {
			return sandbox{}, noop, err
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return sandbox{}, noop, fmt.Errorf("linux: resolving home directory: %w", err)
	}
	// os.UserHomeDir returns $HOME verbatim, which a caller can set to a relative path.
	// The credential shields join onto it (denylist.Home), so a relative home yields
	// relative Rule.Path values that bwrap would apply at the wrong (or no) location,
	// silently leaving the real credential dirs exposed. Refuse it rather than shield air.
	if !filepath.IsAbs(home) {
		return sandbox{}, noop, fmt.Errorf("linux: home directory %q is not absolute", home)
	}

	dir, err := os.MkdirTemp("", "bento-run-")
	if err != nil {
		return sandbox{}, noop, fmt.Errorf("linux: creating run directory: %w", err)
	}
	cleanup := func() { os.RemoveAll(dir) }

	empty := filepath.Join(dir, "shield")
	if err := writeEmptyFile(empty); err != nil {
		cleanup()
		return sandbox{}, noop, err
	}

	sb := sandbox{
		home:        home,
		emptyFile:   empty,
		entrypoint:  entrypoint,
		interpreter: interp,
		exists:      hostExists,
		isDir:       hostIsDir,
		rootDirs:    hostRootDirs,
		resolve:     hostResolve,
		listDir:     hostListDir,
	}

	// The in-sandbox launcher (the bento binary) runs on every sandbox: it is the
	// one process bento controls between bwrap and the target, so it is where every
	// inherited file descriptor is dropped before the target sees it (a descriptor
	// bento's parent leaked without O_CLOEXEC would otherwise bypass the mount
	// namespace and the deny-list entirely). So bentoPath is always bound. The proxy
	// socket is separate: it is set up only for egress or a supervising gate.
	if sb.bentoPath, err = bentoSelfPath(selfPath); err != nil {
		cleanup()
		return sandbox{}, noop, err
	}
	if len(p.Network) > 0 || gated {
		sb.proxySocket = filepath.Join(dir, "proxy.sock")
	}

	// Caller-supplied deny paths join the built-in deny-list. Built here, after the
	// resolve/stat seams are set, so the shield-cleanup defer in Profile sees them.
	if sb.extraDeny, err = buildExtraDeny(denyPaths, sb); err != nil {
		cleanup()
		return sandbox{}, noop, err
	}
	return sb, cleanup, nil
}

// buildExtraDeny turns caller-supplied deny paths into DenyAll shield rules. Each
// must be absolute and must not resolve to the root; a path that does not exist
// yet (the common first-run case for a wrapper's own store directory) is shielded
// as a directory, so it never leaves a host file artifact, while an existing
// regular file is shielded as a file. The rule keeps the unresolved path; the
// shield machinery resolves it the same way it resolves grants.
func buildExtraDeny(denyPaths []string, sb sandbox) ([]denylist.Rule, error) {
	var rules []denylist.Rule
	for _, p := range denyPaths {
		if !filepath.IsAbs(p) {
			return nil, fmt.Errorf("linux: deny path %q must be absolute", p)
		}
		// Classify by the RESOLVED path, since the shield binds there (denyArgs
		// resolves r.Path). Only an existing regular file gets a file shield; a
		// directory, an absent path, or a dangling symlink (resolves to an absent
		// target) all get a directory shield - so a nonexistent target never leaves an
		// uncleanable empty host file.
		rp := sb.resolve(p)
		if rp == "/" {
			return nil, fmt.Errorf("linux: deny path %q resolves to the root and cannot be shielded", p)
		}
		dir := true
		if sb.exists(rp) && !sb.isDir(rp) {
			dir = false
		}
		rules = append(rules, denylist.Rule{Path: p, Deny: denylist.DenyAll, Dir: dir})
	}
	return rules, nil
}

// bentoSelfPath returns the path to the bento binary to bind as the in-sandbox
// launcher. selfPath overrides it (tests set it because the test process is not
// bento); empty means the running executable.
func bentoSelfPath(selfPath string) (string, error) {
	if selfPath != "" {
		return selfPath, nil
	}
	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("linux: locating the bento binary for the in-sandbox launcher: %w", err)
	}
	return self, nil
}

// writeEmptyFile creates the empty file the deny-list binds over paths that must
// be shielded even though they do not exist on the host yet. It lives in the
// per-run temp directory, so it is created fresh and removed with it.
func writeEmptyFile(path string) error {
	if err := os.WriteFile(path, nil, 0o444); err != nil {
		return fmt.Errorf("linux: creating deny-list shield: %w", err)
	}
	return nil
}

// startProxy serves the egress allowlist on socket for the run's lifetime,
// optionally consulting gate for hosts the manifest does not declare. It returns
// an idempotent stop function, a count of how many connections reached the proxy
// (a zero count on an egress-capable run tells the frontend the target never went
// through the proxy - used no network, or bypassed it), and the hosts the gate
// admitted beyond the manifest.
func startProxy(ctx context.Context, p *policy.Policy, socket string, gate enforce.NetworkGate) (stop func(), count func() int, admitted func() []enforce.HostPort, err error) {
	c := &egressCollector{}
	// Discover the host's NAT64 prefix so a synthesized RFC1918 target cannot reach
	// the LAN through a permitted public hostname (RFC 7050). The profiling path
	// applies the same discovery in its forwarding (allowNetwork) mode, where it too
	// dials upstream.
	opts := []proxy.Option{proxy.WithNAT64Discovery(proxy.DefaultNAT64Lookup)}
	if gate != nil {
		opts = append(opts, proxy.WithGatekeeper(gate))
	}
	stop, err = startProxyWith(ctx, p, socket, c.observe, opts...)
	if err != nil {
		return nil, nil, nil, err
	}
	return sync.OnceFunc(stop), c.counted, c.gateAdmitted, nil
}

// egressCollector records the proxy's per-connection decisions for the run
// result: a total count and the deduped set of hosts the gate admitted beyond
// the manifest. The observer runs in each handler's own goroutine, so a mutex
// guards the shared state; the gate itself is never called under this lock (it
// runs in the handler, the observer only records the outcome).
type egressCollector struct {
	mu       sync.Mutex
	count    int
	admitted map[string]enforce.HostPort
}

func (c *egressCollector) observe(d proxy.Decision, host, port string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count++
	if d == proxy.AdmittedByGate {
		if c.admitted == nil {
			c.admitted = make(map[string]enforce.HostPort)
		}
		// Key on JoinHostPort so an IPv6 host:port dedupes correctly.
		c.admitted[net.JoinHostPort(host, port)] = enforce.HostPort{Host: host, Port: port}
	}
}

func (c *egressCollector) counted() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

// gateAdmitted returns a copy of the admitted set, sorted so the result is
// deterministic (map iteration order would flap tests and JSON output).
func (c *egressCollector) gateAdmitted() []enforce.HostPort {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]enforce.HostPort, 0, len(c.admitted))
	for _, hp := range c.admitted {
		out = append(out, hp)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// startProxyWith serves the egress allowlist on socket with a caller-supplied
// observer, returning a stop function.
func startProxyWith(ctx context.Context, p *policy.Policy, socket string, observe func(proxy.Decision, string, string), opts ...proxy.Option) (stop func(), err error) {
	l, err := net.Listen("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("linux: starting egress proxy: %w", err)
	}
	proxyCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		proxy.New(p.Network, append([]proxy.Option{proxy.WithObserver(observe)}, opts...)...).Serve(proxyCtx, l)
		close(done)
	}()
	return func() { cancel(); <-done }, nil
}

// ResolveInterpreter guesses the interpreter for a script from its extension or
// shebang, so a policy need not spell out what a `.py` file runs with. An empty
// result means the file is its own interpreter (a compiled binary).
func ResolveInterpreter(path string) string {
	switch filepath.Ext(path) {
	case ".py":
		return "python3"
	case ".sh", ".bash":
		return "bash"
	case ".js":
		return "node"
	case ".rb":
		return "ruby"
	}
	return shebang(path)
}

func shebang(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	var buf [256]byte
	n, _ := f.Read(buf[:])
	line, _, _ := strings.Cut(string(buf[:n]), "\n")
	if !strings.HasPrefix(line, "#!") {
		return ""
	}
	fields := strings.Fields(strings.TrimPrefix(line, "#!"))
	if len(fields) == 0 {
		return ""
	}
	// "#!/usr/bin/env python3" runs the interpreter named after env. env may be
	// given options first - notably `-S`/`--split-string`, the standard way a
	// shebang passes multiple args to the interpreter (`env -S python3 -u`) - and
	// NAME=VALUE assignments; the interpreter is the first field that is neither, not
	// simply fields[1] (which would be `-S`).
	if filepath.Base(fields[0]) == "env" {
		for _, f := range fields[1:] {
			// Skip env's leading options and NAME=VALUE assignments; an interpreter
			// (a path or a bare name) contains neither, so any '='-bearing word is an
			// assignment, matching env's own handling.
			if strings.HasPrefix(f, "-") || strings.Contains(f, "=") {
				continue
			}
			return f
		}
		return ""
	}
	return fields[0]
}
