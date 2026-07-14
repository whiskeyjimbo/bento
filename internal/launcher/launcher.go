// Package launcher is the in-sandbox stage bento re-execs into.
//
// bwrap runs a single entrypoint; when a run needs setup that must happen inside
// the sandbox — today the egress bridge, and in a later phase the seccomp filter
// — that setup happens here, in one place, before the real target is run. Keeping
// it a package (rather than inline in the CLI) makes the byte-plumbing testable
// without a sandbox and gives the future seccomp stage a home that will not
// collide with a second entrypoint.
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
)

// proxyAddr is the fixed loopback address the egress bridge listens on. The
// sandbox has its own isolated network namespace, so nothing else uses it.
const proxyAddr = "127.0.0.1:3128"

// Run performs in-sandbox setup and runs target, returning the target's exit
// code. When socket is non-empty, it first starts the egress bridge: a loopback
// listener that forwards to the bind-mounted unix socket reaching the host-side
// allowlist proxy, and points the target's proxy environment at it. The listener
// is started before the target, so there is no readiness race.
func Run(socket string, target []string) (int, error) {
	if len(target) == 0 {
		return 0, fmt.Errorf("launcher: no target command")
	}
	if socket != "" {
		l, err := net.Listen("tcp", proxyAddr)
		if err != nil {
			return 0, fmt.Errorf("launcher: cannot listen on %s inside the sandbox: %w", proxyAddr, err)
		}
		// The listener and its goroutines live until the process exits, which is
		// correct: this is the sandbox entrypoint, and it exits when the target does.
		go serveBridge(l, socket)
	}
	return runTarget(target, socket != "")
}

func serveBridge(l net.Listener, socket string) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
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

// runTarget runs the sandboxed command, pointing its proxy environment at the
// bridge when egress is enabled, and propagates its exit code.
func runTarget(target []string, withProxy bool) (int, error) {
	cmd := exec.Command(target[0], target[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = os.Environ()
	if withProxy {
		u := "http://" + proxyAddr
		cmd.Env = append(cmd.Env,
			"HTTP_PROXY="+u, "HTTPS_PROXY="+u,
			"http_proxy="+u, "https_proxy="+u,
		)
	}

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
