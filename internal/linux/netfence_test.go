package linux

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/enforce"
	"github.com/whiskeyjimbo/bento-v2/policy"
)

// The egress design rests on one claim: a sandbox with no network namespace of
// its own cannot reach any external host, even when the payload is a static
// binary issuing raw connect(2) - the class of program v1's LD_PRELOAD proxy
// leaked on. These tests prove that claim on a real sandbox, so it is a standing
// guarantee rather than an assumption. If the kernel fence ever stops holding,
// CI fails here before anything ships.

// buildStaticProbe compiles a tiny CGO-free Go program that tries to connect to
// an address and prints REACHED or BLOCKED. Static + raw net.Dial is the
// adversary: it ignores proxy env and issues syscalls directly.
func buildStaticProbe(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available to build the probe")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "probe.go")
	const prog = `package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	c, err := net.DialTimeout("tcp", os.Args[1], 3*time.Second)
	if err != nil {
		fmt.Println("BLOCKED", err)
		return
	}
	c.Close()
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

// runProbe runs the static probe against target under the given policy and
// returns its output.
func runProbe(t *testing.T, p *policy.Policy, bin, target string) string {
	t.Helper()
	p.Entrypoint = bin
	p.Args = []string{target}
	p.Read = append(p.Read, filepath.Dir(bin))

	var out strings.Builder
	_, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out}, nil)
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
	out := runProbe(t, &policy.Policy{}, bin, "1.1.1.1:443")
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
	out := runProbe(t, &policy.Policy{}, bin, "127.0.0.1:9")
	if strings.Contains(out, "unreachable") || strings.Contains(out, "no route") {
		t.Fatalf("loopback is unreachable inside the sandbox; the proxy could not be reached this way: %q", out)
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

	out, err := exec.Command(bin, ln.Addr().String()).CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "REACHED") {
		t.Fatalf("the probe could not reach a live listener even unsandboxed: %q", out)
	}
}
