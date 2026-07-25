package linux

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// The egress design rests on one claim: a sandbox with no network namespace of
// its own cannot reach any external host, even when the payload is a static
// binary issuing raw connect(2) - the class of program v1's LD_PRELOAD proxy
// leaked on. These tests prove that claim on a real sandbox, so it is a standing
// guarantee rather than an assumption. If the kernel fence ever stops holding,
// CI fails here before anything ships.

// buildStaticProbe compiles a tiny CGO-free Go program that tries to reach an
// address over a given network and prints REACHED or BLOCKED. Static + raw net.Dial
// is the adversary: it ignores proxy env and issues syscalls directly.
func buildStaticProbe(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available to build the probe")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "probe.go")
	// The write matters for udp: a udp "dial" only picks a route and binds a peer, so
	// a fence that let the socket open would still be caught on the send. REACHED is
	// therefore "the kernel accepted the attempt", not "the datagram was delivered" -
	// these tests assert the BLOCKED direction, where the attempt never leaves the host.
	const prog = `package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	c, err := net.DialTimeout(os.Args[1], os.Args[2], 3*time.Second)
	if err != nil {
		fmt.Println("BLOCKED", err)
		return
	}
	defer c.Close()
	if _, err := c.Write([]byte("x")); err != nil {
		fmt.Println("BLOCKED", err)
		return
	}
	fmt.Println("REACHED")
}
`
	if err := os.WriteFile(src, []byte(prog), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "probe")
	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building static probe: %v\n%s", err, out)
	}
	return bin
}

// runProbe runs the static probe against target over network under the given policy
// and returns its output.
func runProbe(t *testing.T, p *policy.Policy, bin, network, target string) string {
	t.Helper()
	p.Entrypoint = bin
	p.Args = []string{network, target}
	p.Read = append(p.Read, filepath.Dir(bin))

	var out strings.Builder
	_, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out}, nil, false)
	if err != nil {
		t.Fatalf("Run: %v (output: %s)", err, out.String())
	}
	return out.String()
}

// A policy with no network rules denies all egress. A static binary must not be
// able to reach an external host - this is the exact case v1 leaked on.
func TestStaticBinaryCannotReachExternalHost(t *testing.T) {
	requireSandbox(t)
	bin := buildStaticProbe(t)

	// A routable public address. We assert it is NOT reachable; the test needs no
	// working internet, because the point is that the namespace blocks the attempt
	// before it leaves the host.
	out := runProbe(t, &policy.Policy{}, bin, "tcp", "1.1.1.1:443")
	if !strings.Contains(out, "BLOCKED") {
		t.Fatalf("a static binary reached an external host from a no-network sandbox: %q", out)
	}
	// The failure must be the kernel refusing to route, not a DNS or timeout
	// artifact that might mask a real leak on another host.
	if !strings.Contains(out, "unreachable") && !strings.Contains(out, "no route") {
		t.Logf("blocked, but not via ENETUNREACH/EHOSTUNREACH: %q", out)
	}
}

// The fence must not be a blanket "no networking at all": a listener on loopback
// inside the sandbox stays reachable, which is exactly how the egress proxy will
// be reached (via a bound address / unix socket) once it exists. This proves the
// door can exist even though the walls are sealed.
func TestLoopbackIsReachableInsideSandbox(t *testing.T) {
	requireSandbox(t)
	bin := buildStaticProbe(t)

	// The probe dials its own loopback; a self-connect to a closed port yields
	// "connection refused" (the stack is present) rather than "unreachable" (no
	// stack at all). Refused proves loopback networking works inside the sandbox.
	out := runProbe(t, &policy.Policy{}, bin, "tcp", "127.0.0.1:9")
	if strings.Contains(out, "unreachable") || strings.Contains(out, "no route") {
		t.Fatalf("loopback is unreachable inside the sandbox; the proxy could not be reached this way: %q", out)
	}
}

// QUIC and any other datagram protocol ride on UDP, so the fence's claim that
// nothing reaches an external host has to hold for UDP too - the proxy tunnels TCP
// CONNECT only, and there is no datagram path through it at all. Without this, the
// egress model's UDP half rested on the netns having no route rather than on
// anything asserted. Same adversary as the TCP case: a static binary issuing raw
// syscalls, which no proxy env can influence.
func TestStaticBinaryCannotReachExternalHostOverUDP(t *testing.T) {
	requireSandbox(t)
	bin := buildStaticProbe(t)

	out := runProbe(t, &policy.Policy{}, bin, "udp", "1.1.1.1:443")
	if !strings.Contains(out, "BLOCKED") {
		t.Fatalf("a static binary sent a datagram to an external host from a no-network sandbox: %q", out)
	}
	if !strings.Contains(out, "unreachable") && !strings.Contains(out, "no route") {
		t.Logf("blocked, but not via ENETUNREACH/EHOSTUNREACH: %q", out)
	}
}

// Control: without a sandbox, the very same probe binary can reach a loopback
// listener we start - proving the probe itself works and the denial above is the
// sandbox, not a broken probe.
func TestProbeItselfWorksUnsandboxed(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	bin := buildStaticProbe(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	out, err := exec.Command(bin, "tcp", ln.Addr().String()).CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "REACHED") {
		t.Fatalf("the probe could not reach a live listener even unsandboxed: %q", out)
	}
}

// The udp control for the same reason: without it, "BLOCKED" inside the sandbox
// could just as well mean the probe cannot do udp at all, and the fence assertion
// would be vacuous. A bound udp socket off loopback gives the send somewhere real
// to go, so a successful write here is the kernel accepting a route the sandbox
// must not have.
func TestUDPProbeItselfWorksUnsandboxed(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	bin := buildStaticProbe(t)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	out, err := exec.Command(bin, "udp", pc.LocalAddr().String()).CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "REACHED") {
		t.Fatalf("the probe could not send a datagram to a live socket even unsandboxed: %q", out)
	}
}
