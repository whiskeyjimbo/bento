package linux

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/internal/enforce"
	"github.com/whiskeyjimbo/bento-v2/internal/policy"
)

// These tests exercise the whole egress path: a real sandbox, the re-exec'd
// forwarder, the bind-mounted socket, and the host-side allowlist proxy. The
// forwarder is the bento binary, so the tests build it once.
//
// The "upstream" is a loopback listener started by the test - no real internet is
// needed, and the allowlist is checked against the host we tell the sandbox to
// reach, which is exactly what the proxy sees.

var (
	bentoOnce sync.Once
	bentoBin  string
	bentoErr  error
)

// testBento builds the bento binary once per test run and returns its path. The
// in-sandbox launcher is bento re-exec'd, so any sandbox test that routes through
// the launcher - which is every test not running with exec: all - needs the real
// binary, not the test process. Building once keeps the suite from recompiling it
// for each test.
func testBento(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	bentoOnce.Do(func() {
		dir, err := os.MkdirTemp("", "bento-test-bin-")
		if err != nil {
			bentoErr = err
			return
		}
		bin := filepath.Join(dir, "bento")
		cmd := exec.Command("go", "build", "-o", bin, "github.com/whiskeyjimbo/bento-v2/cmd/bento")
		cmd.Env = append(os.Environ(), "GOWORK=off")
		if out, err := cmd.CombinedOutput(); err != nil {
			bentoErr = fmt.Errorf("building bento: %v\n%s", err, out)
			return
		}
		bentoBin = bin
	})
	if bentoErr != nil {
		t.Fatal(bentoErr)
	}
	return bentoBin
}

// enforcerUsing returns an Enforcer whose in-sandbox launcher is the built bento
// binary rather than the test process (which is not bento).
func enforcerUsing(bento string) *Enforcer { return &Enforcer{selfPath: bento} }

// sandboxEnforcer is the enforcer sandbox tests should use: it routes the
// in-sandbox launcher to the real bento binary.
func sandboxEnforcer(t *testing.T) *Enforcer { return enforcerUsing(testBento(t)) }

// A curl-based probe reaching an allowlisted host must succeed; a non-allowlisted
// host must be refused by the proxy.
func TestEgressAllowlistEndToEnd(t *testing.T) {
	requireSandbox(t)
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	// The upstream must be bound on a NON-loopback address: the proxy runs on the
	// host, so a loopback target names the host's own loopback, which the resolved-IP
	// guard now refuses even for an explicit rule. Bind on the machine's outbound IP
	// and allowlist it as an explicit literal. When that IP is private (the common
	// case) this also exercises the guard's explicit-private-IP exemption; on a
	// public-IP host it is a plain allowlist test. The explicit-loopback-still-blocked
	// behavior is regression-tested in the proxy package's unit tests, not here.
	host := outboundIP(t)
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"))
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	// --proxytunnel forces curl to CONNECT even for an http:// URL, which is the
	// tunnel path the proxy implements (it tunnels TLS; it does not relay plain
	// HTTP). The upstream is a bare listener, so no TLS is needed.
	curl := "curl -sS --proxytunnel -o /dev/null -w '%{http_code}' --max-time 5 "
	script := "" +
		"echo -n allowed=; " + curl + "http://" + net.JoinHostPort(host, port) + "/ 2>/dev/null || echo failed\n" +
		"echo\n" +
		"echo -n denied=; " + curl + "http://169.254.254.254:" + port + "/ >/dev/null 2>&1 && echo REACHED || echo blocked\n"

	// exec: all because the script legitimately spawns curl as a subprocess; this
	// test is about egress, not exec-blocking.
	p := &policy.Policy{
		Network: []policy.NetworkRule{{Host: host, Port: port}},
		Exec:    policy.ExecAll,
	}
	out := runShell(t, sandboxEnforcer(t), p, script)

	if !strings.Contains(out, "allowed=204") {
		t.Errorf("allowlisted host was not reachable through the proxy: %q", out)
	}
	if !strings.Contains(out, "denied=blocked") || strings.Contains(out, "denied=REACHED") {
		t.Errorf("a non-allowlisted host was not blocked: %q", out)
	}
}

// outboundIP returns the machine's primary non-loopback IP, or skips the test if
// there is none. A UDP "dial" sends no packets; it just selects the local address
// the kernel would route from, which is the address a host-side listener is
// reachable at through the proxy.
func outboundIP(t *testing.T) string {
	t.Helper()
	c, err := net.Dial("udp", "192.0.2.1:9") // TEST-NET-1, unrouted
	if err != nil {
		t.Skip("no outbound route to bind a non-loopback upstream")
	}
	defer c.Close()
	ip := c.LocalAddr().(*net.UDPAddr).IP
	if ip == nil || ip.IsLoopback() {
		t.Skip("no non-loopback local IP to reach an upstream through the proxy")
	}
	return ip.String()
}

// runShell runs sh -c script under the enforcer with the given policy.
func runShell(t *testing.T, e *Enforcer, p *policy.Policy, script string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	p.Entrypoint = path
	p.Interpreter = "sh"
	p.Read = append(p.Read, dir)

	var buf strings.Builder
	if _, err := e.Run(context.Background(), p, enforce.Process{Stdout: &buf, Stderr: &buf}); err != nil {
		t.Fatalf("Run: %v (output: %s)", err, buf.String())
	}
	return buf.String()
}
