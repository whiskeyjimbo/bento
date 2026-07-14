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
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"

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

	if cfg.Block {
		if err := seccomp.BlockExec(); err != nil {
			// Fail closed: never run the target unconfined while claiming to block
			// subprocesses.
			return 0, fmt.Errorf("launcher: refusing to run — could not install the exec-block filter: %w", err)
		}
		// execveat replaces this process with the target under the filter, so this
		// returns only if the transition itself fails.
		return 0, seccomp.Exec(cfg.Target, env)
	}

	return superviseTarget(cfg.Target, env)
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
func superviseTarget(target, env []string) (int, error) {
	cmd := exec.Command(target[0], target[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = env

	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	return 0, fmt.Errorf("launcher: running target: %w", err)
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
	go func() { defer wg.Done(); io.Copy(upstream, client); halfClose(upstream) }()
	go func() { defer wg.Done(); io.Copy(client, upstream); halfClose(client) }()
	wg.Wait()
}

func halfClose(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	c.SetDeadline(time.Now())
}
