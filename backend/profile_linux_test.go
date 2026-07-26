//go:build linux

package backend

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// The linux backend confines a target by re-executing this binary as a hidden
// launch stage, so the test process must itself dispatch those stages - the same
// contract an embedder honors in its own main(). Without this, Profile's sandbox
// re-execs the test binary and it runs the test suite again instead of the launcher.
func TestMain(m *testing.M) {
	DispatchReexec()
	os.Exit(m.Run())
}

// outboundIP returns the machine's primary non-loopback IP, or skips the test if there
// is none. A UDP "dial" sends no packets; it just selects the local address the kernel
// would route from, which is the address a host-side listener is reachable at through the
// proxy. The in-sandbox bridge sets NO_PROXY for loopback, so an upstream must be bound
// off loopback for the target's CONNECT to traverse (and be recorded by) the proxy.
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

func requireSandbox(t *testing.T) {
	t.Helper()
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		skipMissingDep(t, "bwrap not installed")
	}
	// bwrap alone is not enough: a host with unprivileged user namespaces disabled has
	// bwrap in PATH but cannot create the namespace, so Profile fails to complete rather
	// than shielding anything. Probe the same way the enforcer's admission does, so this
	// test skips (not fails) on that supported-but-degraded host class.
	if err := exec.Command(bwrap, "--unshare-user", "--unshare-net", "--bind", "/", "/", "/bin/true").Run(); err != nil {
		skipMissingDep(t, "unprivileged user namespaces unavailable on this host")
	}
}

// skipMissingDep skips for a missing host dependency, or fails when
// BENTO_REQUIRE_TEST_DEPS is set. A behavioral test that self-skips reports a pass having
// asserted nothing, so on a host without bwrap or unprivileged user namespaces a run is
// indistinguishable from one that exercised the shield; the variable is how a host that
// is supposed to have them - CI, and `make test` - says so.
func skipMissingDep(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("BENTO_REQUIRE_TEST_DEPS") != "" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

// Profile's refusals, which run on any Linux host: the two tests below need a real
// sandbox and skip without one, so on a box with no bwrap or no unprivileged user
// namespaces these are all that is left of this file. They are deliberately not guarded
// by requireSandbox - the refusals happen before a namespace is ever created, and
// guarding them would put the whole file behind the condition they exist to survive.
//
// The DenyPath cases reach the enforcer's shield construction, which reads the host
// filesystem but creates no namespace, so they need bwrap on PATH and nothing more. A
// relative path is refused because the shield would bind somewhere that depends on the
// caller's working directory, and a path resolving to the root because shielding it would
// hide the whole filesystem from the run.
func TestProfileRefusesBadInput(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(script, []byte("true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ok := &policy.Policy{Entrypoint: script, Interpreter: "sh"}

	t.Run("invalid policy", func(t *testing.T) {
		_, err := Profile(context.Background(), &policy.Policy{}, enforce.Process{}, ProfileOptions{})
		if err == nil || !strings.Contains(err.Error(), "entrypoint is required") {
			t.Errorf("a policy with no entrypoint must be refused by validation; got %v", err)
		}
	})

	// An absent bwrap has to be named, not discovered as a launch failure inside the
	// sandbox that reads as a broken target.
	t.Run("bwrap not in PATH", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		_, err := Profile(context.Background(), ok, enforce.Process{}, ProfileOptions{})
		if err == nil || !strings.Contains(err.Error(), "bwrap") {
			t.Errorf("a missing bwrap must be reported by name; got %v", err)
		}
	})

	if _, err := exec.LookPath("bwrap"); err != nil {
		skipMissingDep(t, "bwrap not installed, so the deny-path refusals cannot be reached")
	}
	// Each case asserts the error TEXT, not merely that one came back. On a host with
	// bwrap present but unprivileged user namespaces disabled, a valid deny path also
	// errors - the run fails later with "profiling did not complete" - so an any-error
	// assertion would still pass with the validation deleted, on exactly the host class
	// this test exists for.
	for name, tc := range map[string]struct{ deny, want string }{
		"relative deny path":       {"relative/store", "must be absolute"},
		"root-resolving deny path": {"/", "resolves to the root"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Profile(context.Background(), ok, enforce.Process{}, ProfileOptions{DenyPaths: []string{tc.deny}})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%q must be refused with %q; got %v", tc.deny, tc.want, err)
			}
		})
	}
}

// Profile forwards ProfileOptions.DenyPaths to the enforcer, and a dropped DenyPath
// is a silent fail-open: a supervising embedder's store shield relies on it, so the
// grant-broad Read the profiling policy carries would otherwise expose the store. This
// guards the forwarding end-to-end (backend.Profile -> a real sandbox), the seam the
// internal enforcement test cannot see. The store lives under $HOME, not /tmp, because
// the sandbox always overmounts /tmp with its own tmpfs.
func TestProfileForwardsDenyPaths(t *testing.T) {
	requireSandbox(t)

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	storeDir, err := os.MkdirTemp(home, "bento-backend-denytest-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(storeDir)
	const secret = "TOPSECRET-BACKEND-STORE"
	storeFile := filepath.Join(storeDir, "perms.json")
	if err := os.WriteFile(storeFile, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(script, []byte("cat "+storeFile+" 2>&1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Read: []string{"/"}, Exec: policy.ExecAll}

	run := func(deny []string) string {
		var out bytes.Buffer
		if _, err := Profile(context.Background(), p,
			enforce.Process{Stdout: &out, Stderr: &out},
			ProfileOptions{DenyPaths: deny}); err != nil {
			t.Fatalf("Profile: %v", err)
		}
		return out.String()
	}

	// Baseline: with the broad Read and no deny path the trial reads the store, so a
	// dropped DenyPath would look identical to a passing shield if we only checked the
	// shielded case.
	if base := run(nil); !strings.Contains(base, secret) {
		t.Fatalf("baseline: the trial should read the store with no deny path; got %q", base)
	}
	if shielded := run([]string{storeDir}); strings.Contains(shielded, secret) {
		t.Errorf("DenyPaths did not reach the sandbox: store leaked %q", shielded)
	}
}

// Profile with AllowNetwork=false is the record-only default supervise relies on: the
// recording proxy must log every destination the target reaches for while forwarding
// none of the traffic. A hardcoded true here is a silent fail-open (profiling untrusted
// code would exfiltrate), and the bool/[]string types make a positional transposition
// uncompilable, so only a value test catches it. The two assertions together pin it and
// keep the check honest: the recorded host proves the CONNECT traversed the bridge, curl,
// and the socket (so "listener untouched" is not vacuously true), and the untouched
// listener proves the traffic was refused, not forwarded. The upstream is bound on a
// non-loopback address because the in-sandbox bridge sets NO_PROXY for loopback, so a
// loopback target would bypass the proxy and never be recorded.
func TestProfileWithoutAllowNetworkRecordsButDoesNotForward(t *testing.T) {
	requireSandbox(t)
	if _, err := exec.LookPath("curl"); err != nil {
		skipMissingDep(t, "curl not available")
	}
	host := outboundIP(t)
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var reached atomic.Bool
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			reached.Store(true)
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	dir := t.TempDir()
	script := filepath.Join(dir, "probe.sh")
	// --proxytunnel forces a CONNECT (the tunnel the proxy implements) even for an
	// http:// URL; the destination is the host-side listener's non-loopback address.
	body := "curl -sS --proxytunnel -o /dev/null --max-time 5 http://" + net.JoinHostPort(host, port) + "/ 2>/dev/null || true\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	// exec: all because the script spawns curl; an explicit rule for the target so this
	// pins the AllowNetwork gate, not the allowlist. Network is recorded regardless.
	p := &policy.Policy{
		Entrypoint:  script,
		Interpreter: "sh",
		Network:     []policy.NetworkRule{{Host: host, Port: port}},
		Exec:        policy.ExecAll,
	}

	var out bytes.Buffer
	obs, err := Profile(context.Background(), p,
		enforce.Process{Stdout: &out, Stderr: &out},
		ProfileOptions{AllowNetwork: false})
	if err != nil {
		t.Fatalf("Profile: %v (output: %s)", err, out.String())
	}

	recorded := false
	for _, h := range obs.Hosts {
		if h.Host == host && h.Port == port {
			recorded = true
		}
	}
	if !recorded {
		t.Errorf("the target's egress was not recorded: hosts=%v (output: %s)", obs.Hosts, out.String())
	}
	if reached.Load() {
		t.Error("AllowNetwork=false forwarded the traffic: the upstream listener was reached")
	}
}
