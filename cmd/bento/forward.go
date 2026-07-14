package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

// forwardPort is the fixed loopback port the in-sandbox forwarder listens on.
// The sandbox has its own isolated network namespace, so nothing else can be
// using it and a fixed value keeps the proxy URL we hand the target constant.
const forwardPort = "127.0.0.1:3128"

// newForwardCmd is the in-sandbox half of egress enforcement, not a user
// command. bento re-execs itself as `bento __forward <socket> -- <cmd>...`
// inside the sandbox: the sandbox has no network but loopback, so the forwarder
// bridges a loopback TCP port to the bind-mounted unix socket that reaches the
// host-side allowlist proxy, then runs the real target pointed at that port.
//
// The forwarder listens *before* starting the target, so there is no readiness
// race — the proxy endpoint exists the instant the target can dial it.
func newForwardCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "__forward <socket> -- <command>...",
		Hidden:             true,
		Args:               cobra.MinimumNArgs(2),
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			socket := args[0]
			target := args[1:]
			if target[0] == "--" {
				target = target[1:]
			}
			if len(target) == 0 {
				return fmt.Errorf("__forward: no command to run")
			}

			l, err := net.Listen("tcp", forwardPort)
			if err != nil {
				return fmt.Errorf("__forward: cannot listen on %s inside the sandbox: %w", forwardPort, err)
			}
			defer l.Close()
			go bridge(l, socket)

			return runTarget(target)
		},
	}
}

// bridge forwards each accepted loopback connection to the host-side proxy
// socket, both directions, until the listener closes.
func bridge(l net.Listener, socket string) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			u, err := net.Dial("unix", socket)
			if err != nil {
				return
			}
			defer u.Close()
			done := make(chan struct{}, 2)
			go func() { io.Copy(u, c); done <- struct{}{} }()
			go func() { io.Copy(c, u); done <- struct{}{} }()
			<-done
		}()
	}
}

// runTarget runs the sandboxed command with the proxy environment set, and
// propagates its exit code.
func runTarget(target []string) error {
	c := exec.Command(target[0], target[1:]...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	proxyURL := "http://" + forwardPort
	c.Env = append(os.Environ(),
		"HTTP_PROXY="+proxyURL, "HTTPS_PROXY="+proxyURL,
		"http_proxy="+proxyURL, "https_proxy="+proxyURL,
	)

	err := c.Run()
	if err == nil {
		return nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return &exitError{code: ee.ExitCode()}
	}
	return fmt.Errorf("__forward: running target: %w", err)
}
