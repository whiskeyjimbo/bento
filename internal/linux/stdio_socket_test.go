package linux

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// An inherited network socket on stdio is a live, unfiltered channel: a netns binds
// at socket creation, the seccomp egress block filters socket(2), and Landlock
// governs paths, so none of them revokes an already-open description. The refusal
// used to run only where the policy granted no egress, which left every
// egress-allowed manifest handing the socket straight to the target - and the CLI
// reaches that path with no embedder involved, since `bento run` passes os.Stdin.
//
// The probe is the spike that found it: the test dials its own listener and hands
// the client end to the target as fd 0, under a manifest whose only grant is an
// unrelated host.
func TestNetworkStdioIsRefusedUnderAnEgressAllowedManifest(t *testing.T) {
	requireSandbox(t)

	p, stdin := networkStdioProbe(t)
	var out strings.Builder
	// The refusal happens in the launcher stage, which is a child process: it reaches
	// the caller as bento's setup-failure exit code and the message on stderr, never as
	// a Go error here.
	res, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{Stdin: stdin, Stdout: &out, Stderr: &out}, enforce.RunOptions{})
	if err != nil {
		t.Fatalf("Run: %v (output: %s)", err, out.String())
	}
	if res.ExitCode != 125 {
		t.Errorf("exit = %d, want 125: an inherited TCP socket on stdio was accepted under an egress-allowed manifest (output: %s)", res.ExitCode, out.String())
	}
	if !strings.Contains(out.String(), "inherited socket of family") {
		t.Errorf("wrong refusal: %q", out.String())
	}
}

// The socket-activation embedder - a server handing a per-connection handler its
// accepted conn - passes the socket deliberately, and says so through the Go API.
// No manifest field and no CLI flag can, which is what keeps the refusal above in
// force for every `bento run`.
func TestNetworkStdioIsAllowedWhenTheEmbedderOptsIn(t *testing.T) {
	requireSandbox(t)

	p, stdin := networkStdioProbe(t)
	var out strings.Builder
	proc := enforce.Process{Stdin: stdin, Stdout: &out, Stderr: &out, AllowNetworkStdio: true}
	res, err := sandboxEnforcer(t).Run(context.Background(), p, proc, enforce.RunOptions{})
	if err != nil {
		t.Fatalf("the opt-in must let a deliberately passed connection through: %v (output: %s)", err, out.String())
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit = %d, want 0 (output: %s)", res.ExitCode, out.String())
	}
	if !strings.Contains(out.String(), "FROM-HOST") {
		t.Errorf("the target did not read the passed connection: %q", out.String())
	}
	// The channel is outside the manifest's allowlist, so a run that takes it says so
	// rather than looking clean.
	if !strings.Contains(out.String(), "bypasses the manifest's egress allowlist") {
		t.Errorf("the opt-in ran without warning that the allowlist is bypassed: %q", out.String())
	}
}

// The opt-in describes what the embedder passed, not a standing state, so a run that
// sets it and then passes an ordinary stream has bypassed nothing and must say nothing.
func TestNetworkStdioOptInIsSilentWithoutASocket(t *testing.T) {
	requireSandbox(t)

	p, _ := networkStdioProbe(t)
	var out strings.Builder
	proc := enforce.Process{Stdout: &out, Stderr: &out, AllowNetworkStdio: true}
	if _, err := sandboxEnforcer(t).Run(context.Background(), p, proc, enforce.RunOptions{}); err != nil {
		t.Fatalf("Run: %v (output: %s)", err, out.String())
	}
	if strings.Contains(out.String(), "egress allowlist") {
		t.Errorf("the opt-in warned about a bypass with no socket on stdio: %q", out.String())
	}
}

// networkStdioProbe returns a policy granting egress to an unrelated host, and a
// connected TCP client socket as an *os.File - the form os/exec hands to the child
// as a raw descriptor, which is how it survives to the target at all. The server
// side writes a marker the target echoes to stdout.
func networkStdioProbe(t *testing.T) (*policy.Policy, *os.File) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback TCP available: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("FROM-HOST\n"))
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	f, err := conn.(*net.TCPConn).File()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })

	dir := t.TempDir()
	path := filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(path, []byte("head -c 9 <&0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// exec: all keeps the launcher supervising the target, so the refusal is the only
	// thing under test. Any granted host makes this an egress-allowed manifest, which
	// is the condition that used to skip the check; the target never reaches it.
	p := &policy.Policy{
		Entrypoint:  path,
		Interpreter: "sh",
		Read:        []string{dir},
		Network:     []policy.NetworkRule{{Host: "example.com", Port: "443"}},
		Exec:        policy.ExecAll,
	}
	return p, f
}
