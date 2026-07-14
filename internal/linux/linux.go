// Package linux enforces a policy with bubblewrap.
//
// It is an adapter behind the enforce.Enforcer seam: the core hands it a
// validated policy and it answers with what it actually enforced. Nothing here
// decides policy — that is the core's job — and no type from here appears in the
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
	"strings"
	"sync/atomic"

	"github.com/whiskeyjimbo/bento-v2/internal/enforce"
	"github.com/whiskeyjimbo/bento-v2/internal/policy"
	"github.com/whiskeyjimbo/bento-v2/internal/proxy"
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
func (e *Enforcer) Run(ctx context.Context, p *policy.Policy, proc enforce.Process) (enforce.Result, error) {
	report := e.Probe(ctx)

	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return enforce.Result{}, fmt.Errorf("linux: bubblewrap (bwrap) not found: %w", err)
	}
	sb, cleanup, err := newSandbox(p, e.selfPath)
	if err != nil {
		return enforce.Result{}, err
	}
	defer cleanup()

	// When the policy allows egress, run the allowlist proxy on the sandbox's
	// unix socket for the lifetime of the run. The sandbox reaches it only through
	// that socket; nothing else can leave the network namespace.
	egress := func() int { return 0 }
	if sb.proxySocket != "" {
		stopProxy, count, err := startProxy(ctx, p, sb.proxySocket)
		if err != nil {
			return enforce.Result{}, err
		}
		egress = count
		defer stopProxy()
	}

	args, err := compile(p, proc, sb)
	if err != nil {
		return enforce.Result{}, err
	}

	// When the policy sets limits and this host can enforce them, run bwrap inside
	// a transient systemd scope carrying the limits. When it cannot, the run has
	// already been admitted (refused by default, or permitted under
	// --allow-degraded) — here it simply proceeds unwrapped.
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

			// systemd-run accepts an undelegated controller (typically cpu) and
			// silently does not enforce it. Report that specific controller as not
			// enforced rather than claiming the whole limits layer holds.
			if missing := undelegatedController(p.Limits); missing != "" {
				report.Set(enforce.LayerLimits, enforce.Degraded,
					fmt.Sprintf("%s limit not enforced: the %s controller is not delegated to your systemd user manager (a one-time admin step: Delegate=%s on user@.service)", missing, missing, missing))
			}
		}
	}

	cmd := exec.CommandContext(ctx, exe, cargs...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = proc.Stdin, proc.Stdout, proc.Stderr

	switch err := cmd.Run(); {
	case err == nil:
		return enforce.Result{ExitCode: 0, Report: report, EgressConnections: egress()}, nil
	case isExitError(err):
		var ee *exec.ExitError
		errors.As(err, &ee)
		return enforce.Result{ExitCode: ee.ExitCode(), Report: report, EgressConnections: egress()}, nil
	default:
		return enforce.Result{Report: report}, fmt.Errorf("linux: running sandbox: %w", err)
	}
}

func isExitError(err error) bool {
	var ee *exec.ExitError
	return errors.As(err, &ee)
}

// newSandbox resolves the host facts the argv compiler needs, and returns a
// cleanup for the temporary files it creates.
func newSandbox(p *policy.Policy, selfPath string) (sandbox, func(), error) {
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
	}

	// The in-sandbox launcher (the bento binary) is bound whenever egress or
	// exec-blocking is in play; the proxy socket only when egress is.
	execMode := p.Exec
	if execMode == "" {
		execMode = policy.ExecNone
	}
	if len(p.Network) > 0 || execMode != policy.ExecAll {
		self := selfPath
		if self == "" {
			self, err = os.Executable()
			if err != nil {
				cleanup()
				return sandbox{}, noop, fmt.Errorf("linux: locating the bento binary for the in-sandbox launcher: %w", err)
			}
		}
		sb.bentoPath = self
	}
	if len(p.Network) > 0 {
		sb.proxySocket = filepath.Join(dir, "proxy.sock")
	}
	return sb, cleanup, nil
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

// startProxy serves the egress allowlist on socket for the run's lifetime. It
// returns a stop function and a count function reporting how many connections
// reached the proxy — a zero count on a network-using run tells the frontend the
// target never went through the proxy (used no network, or bypassed it).
func startProxy(ctx context.Context, p *policy.Policy, socket string) (stop func(), count func() int, err error) {
	l, err := net.Listen("unix", socket)
	if err != nil {
		return nil, nil, fmt.Errorf("linux: starting egress proxy: %w", err)
	}
	var connections atomic.Int64
	observe := func(proxy.Decision, string, string) { connections.Add(1) }

	proxyCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		proxy.New(p.Network, proxy.WithObserver(observe)).Serve(proxyCtx, l)
		close(done)
	}()
	return func() { cancel(); <-done }, func() int { return int(connections.Load()) }, nil
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
	// "#!/usr/bin/env python3" names the interpreter in the second field.
	if filepath.Base(fields[0]) == "env" && len(fields) > 1 {
		return fields[1]
	}
	return fields[0]
}
