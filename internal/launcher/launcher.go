// Package launcher is the in-sandbox stage bento re-execs into.
//
// bwrap runs a single entrypoint; when a run needs setup that must happen inside
// the sandbox — the egress bridge and/or the seccomp exec-block filter — that
// setup happens here, in one place, before the real target runs. Doing both in
// one stage is deliberate: they must not become two competing entrypoints, and
// their ordering matters (the bridge is started before the filter, because
// starting it uses execve, which the filter denies).
package launcher

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/whiskeyjimbo/bento-v2/internal/landlock"
	"github.com/whiskeyjimbo/bento-v2/internal/observe"
	"github.com/whiskeyjimbo/bento-v2/internal/seccomp"
)

// proxyAddr is the fixed loopback address the egress bridge listens on. The
// sandbox has its own isolated network namespace, so nothing else uses it.
const proxyAddr = "127.0.0.1:3128"

// Config describes the in-sandbox setup for one run.
type Config struct {
	// Socket is the bind-mounted unix socket reaching the host-side egress proxy.
	// Empty means the policy allows no egress, so no bridge is set up.
	Socket string
	// Block installs the exec-block seccomp filter (policy exec is none or
	// none-strict). When false the target may spawn subprocesses freely.
	Block bool
	// Writable are the policy's resolved write-grant paths. Landlock confines
	// writes to these (plus runtime scratch) as a second layer behind bwrap.
	Writable []string
	// Observe, when set, runs the target under the ptrace observer instead of
	// enforcing, writing the files it opened and whether it exec'd to this path.
	// The profiler uses it to synthesize a manifest from a permissive run; no
	// seccomp or Landlock is applied, so what the target does is fully observed.
	Observe string
	// Target is the absolute command to run: interpreter, script, and args.
	Target []string
}

// Run performs the in-sandbox setup and runs the target, returning its exit code.
//
// Order is load-bearing. The bridge child is started first, while execve still
// works. The exec-block filter is installed next; if it cannot be installed the
// run is refused rather than proceeding unconfined — a report that claims
// "enforced" must never accompany a target that ran without the filter. Finally
// the target is started: under the filter it is reached via execveat (which the
// filter allows), replacing this process; without the filter it is supervised as
// a child so its exit code can be returned.
func Run(cfg Config) (int, error) {
	if len(cfg.Target) == 0 {
		return 0, fmt.Errorf("launcher: no target command")
	}

	env := os.Environ()
	if cfg.Socket != "" {
		if err := startBridge(cfg.Socket); err != nil {
			return 0, err
		}
		env = append(env, proxyEnv()...)
	}

	if cfg.Observe != "" {
		return runObserve(cfg, env)
	}

	if cfg.Block {
		if err := seccomp.BlockExec(); err != nil {
			// Fail closed: never run the target unconfined while claiming to block
			// subprocesses.
			return 0, fmt.Errorf("launcher: refusing to run — could not install the exec-block filter: %w", err)
		}
	}

	// The Landlock backstop is applied last, after the egress bridge has already
	// started (the bridge must open its socket before writes are confined) and
	// after seccomp. It is inherited across the coming exec, so the target runs
	// under it.
	//
	// It is a best-effort second layer, not the primary guarantee: bwrap already
	// confines the filesystem. So a failure to apply it warns and proceeds rather
	// than aborting the run — failing here would make bwrap's confinement
	// contingent on the backstop, inverting the relationship. (An absent Landlock
	// is a silent no-op inside Restrict, not an error.)
	if err := landlock.Restrict(cfg.Writable); err != nil {
		fmt.Fprintf(os.Stderr, "[bento] warning: the Landlock filesystem backstop could not be applied (%v); bwrap confinement still holds\n", err)
	}

	if cfg.Block {
		// execveat replaces this process with the target under the filters, so this
		// returns only if the transition itself fails.
		return 0, seccomp.Exec(cfg.Target, env)
	}
	return superviseTarget(cfg.Target, env)
}

// runObserve profiles the target: it runs under the ptrace observer (no seccomp,
// no Landlock — a permissive run so every access is seen) and writes what the
// target opened, and whether it exec'd, to the report path for the host to read.
func runObserve(cfg Config, env []string) (int, error) {
	res, traceErr := observe.Trace(cfg.Target, env, os.Stdin, os.Stdout, os.Stderr)

	// The report is written unconditionally, and always here — after Trace returns,
	// when the target and every subprocess are ptrace-stopped and cannot run — so
	// this write is the last one to the bind-mounted report path, truncating
	// anything the (unsandboxed, profiled) target may have written there to forge
	// its own observations. Paths are quoted (%q) so a newline embedded in a path
	// cannot forge extra R/W/EXEC records. The completion marker is written LAST and
	// only on a successful trace: its presence means the report is genuinely
	// complete, so a failed or truncated trace lacks it and the reader rejects it.
	var b strings.Builder
	if traceErr == nil {
		for _, a := range res.Accesses {
			verb := "R"
			if a.Write {
				verb = "W"
			}
			fmt.Fprintf(&b, "%s %q\n", verb, a.Path)
		}
		if res.Execed {
			b.WriteString("EXEC\n")
		}
		b.WriteString(observe.ReportStart + "\n")
	}
	if err := os.WriteFile(cfg.Observe, []byte(b.String()), 0o644); err != nil {
		return 0, fmt.Errorf("launcher: writing observations: %w", err)
	}
	if traceErr != nil {
		return 0, fmt.Errorf("launcher: observing target: %w", traceErr)
	}
	return res.ExitCode, nil
}

// startBridge launches the bridge as a separate child process before any filter
// is installed. It must be its own process, not a goroutine: when the exec-block
// filter is in play the launcher execveats the target and is replaced, which
// would kill an in-process bridge. As a child it survives until the pid namespace
// is torn down at the end of the run.
func startBridge(socket string) error {
	cmd := exec.Command("/proc/self/exe", "__bridge", socket)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("launcher: starting egress bridge: %w", err)
	}
	return nil
}

func proxyEnv() []string {
	u := "http://" + proxyAddr
	// NO_PROXY exempts loopback so a script that runs its own in-sandbox service
	// (a local server on 127.0.0.1) can reach it directly, instead of the client
	// sending that connection to the host-side proxy — which would try to dial the
	// host's loopback, not the sandbox's. The tradeoff: a manifest cannot allowlist
	// a loopback address as an egress target; `validate` warns when one does. Both
	// casings are set because different tools read different ones.
	const noProxy = "localhost,127.0.0.1,::1"
	return []string{
		"HTTP_PROXY=" + u, "HTTPS_PROXY=" + u,
		"http_proxy=" + u, "https_proxy=" + u,
		"NO_PROXY=" + noProxy, "no_proxy=" + noProxy,
	}
}

// superviseTarget runs the target as a child and returns its exit code. Used
// only when the target is not exec-blocked (nothing needs to replace this
// process, and supervising lets us return the exit code directly).
//
// reapUntil waits on all of this process's children until the target exits, so
// the egress bridge started alongside it is reaped too. Orphaned *grandchildren*
// of a subprocess-spawning target are not this process's concern: bwrap runs its
// own init as PID 1 (this launcher is PID 2), so an orphan reparents to bwrap's
// init, which reaps it. The whole pid namespace is torn down at the end of the
// run regardless.
func superviseTarget(target, env []string) (int, error) {
	cmd := exec.Command(target[0], target[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = env

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("launcher: starting target: %w", err)
	}
	return reapUntil(cmd.Process.Pid)
}

// reapUntil reaps every child that exits until the target does, then returns the
// target's exit code. Wait4(-1) blocks until any child exits, so orphaned
// grandchildren are collected as they finish rather than lingering as zombies.
func reapUntil(targetPid int) (int, error) {
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, 0, nil)
		switch {
		case err == syscall.EINTR:
			continue
		case err != nil:
			return 0, fmt.Errorf("launcher: reaping children: %w", err)
		case pid == targetPid:
			return waitExitCode(ws), nil
		}
		// Any other pid was an orphaned grandchild, now reaped — keep going.
	}
}

// waitExitCode maps a wait status to a conventional exit code: a signalled
// process reports 128+signal, matching what a shell would return.
func waitExitCode(ws syscall.WaitStatus) int {
	if ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ws.ExitStatus()
}

// BridgeMain is the `bento __bridge <socket>` child: it forwards every loopback
// connection on proxyAddr to the host-side proxy socket until the process is
// torn down with the sandbox.
func BridgeMain(socket string) error {
	l, err := net.Listen("tcp", proxyAddr)
	if err != nil {
		return fmt.Errorf("bridge: cannot listen on %s inside the sandbox: %w", proxyAddr, err)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go bridgeConn(c, socket)
	}
}

// bridgeConn forwards one loopback connection to the host-side proxy socket in
// both directions, half-closing each side when its source is done so a
// half-closed tunnel is not truncated.
func bridgeConn(client net.Conn, socket string) {
	defer client.Close()
	upstream, err := net.Dial("unix", socket)
	if err != nil {
		return
	}
	defer upstream.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); copyIdle(upstream, client, client); halfClose(upstream) }()
	go func() { defer wg.Done(); copyIdle(client, upstream, upstream); halfClose(client) }()
	wg.Wait()
}

// idleTimeout tears down a bridged connection that has sat with no traffic this
// long, so a stalled connection cannot pin a goroutine for the life of the run.
const idleTimeout = 5 * time.Minute

// copyIdle copies src→dst, resetting ctl's deadline on every read so an active
// connection stays open while an idle one is dropped after idleTimeout.
func copyIdle(dst io.Writer, src io.Reader, ctl net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		ctl.SetDeadline(time.Now().Add(idleTimeout))
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func halfClose(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	c.SetDeadline(time.Now())
}
