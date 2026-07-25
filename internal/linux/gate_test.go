package linux

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/proxy"
	"github.com/whiskeyjimbo/bento/policy"
)

// runGated runs sh -c script under the enforcer with the given policy and gate,
// returning the run result (for GateAdmitted/EgressConnections) and combined
// output.
func runGated(t *testing.T, p *policy.Policy, script string, gate enforce.NetworkGate) (enforce.Result, string) {
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
	res, err := sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{Stdout: &buf, Stderr: &buf}, enforce.RunOptions{Gate: gate})
	if err != nil {
		t.Fatalf("Run: %v (output: %s)", err, buf.String())
	}
	return res, buf.String()
}

// A supervised run with no manifest network rules still stands up the egress
// stack (the gate forces it), so the gate is consulted for a host the empty
// allowlist denies. This proves the gate is threaded all the way from Run
// through startProxy into the proxy handler. It also proves the SSRF property
// survives the gate: guardUpstream blocks the admitted host because it resolves
// to host-reserved (link-local) space, so it never reaches the target and is NOT
// listed in GateAdmitted - a gate widens to public/declared-private hosts, never
// to the host's own infrastructure.
func TestGateConsultedButGuardBlocksHostReserved(t *testing.T) {
	requireSandbox(t)
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}

	// 169.254.254.254 is link-local: guardUpstream refuses it regardless of the
	// host's own addresses, so this test is deterministic on any machine (unlike a
	// public-IP admit-success, which is proven at the proxy unit level).
	const target = "169.254.254.254:1"

	var mu sync.Mutex
	var consulted []string
	gate := func(_ context.Context, host, port string) bool {
		mu.Lock()
		consulted = append(consulted, host+":"+port)
		mu.Unlock()
		return true // admit; the upstream guard must still block it
	}

	curl := "curl -sS --proxytunnel -o /dev/null -w '%{http_code}' --max-time 5 "
	script := "echo -n reached=; " + curl + "http://" + target + "/ >/dev/null 2>&1 && echo YES || echo no\n"

	// No network rules, exec: all (the script spawns curl legitimately).
	p := &policy.Policy{Exec: policy.ExecAll}
	res, out := runGated(t, p, script, gate)

	mu.Lock()
	defer mu.Unlock()
	if len(consulted) == 0 {
		t.Fatal("the gate was never consulted; it was not threaded to the proxy handler")
	}
	found := false
	for _, hp := range consulted {
		if hp == target {
			found = true
		}
	}
	if !found {
		t.Errorf("gate consulted with %v, want it to include %q", consulted, target)
	}
	if strings.Contains(out, "reached=YES") {
		t.Errorf("a gate-admitted link-local host was reached; the upstream guard must still block it: %q", out)
	}
	if len(res.GateAdmitted) != 0 {
		t.Errorf("GateAdmitted = %v, want empty: a host the guard blocked was never admitted past it", res.GateAdmitted)
	}
	if res.EgressConnections == 0 {
		t.Error("EgressConnections = 0, want the guard-blocked connection to have been counted")
	}
}

// egressCollector is the honesty surface a wrapper reads: it must count every
// decision, dedupe gate admissions by host:port, sort them, and keep a
// guard-blocked (Denied) host out of the admitted list. The real-sandbox test
// only reaches the empty path (guard blocks), and the proxy unit tests use their
// own observer, so this exercises the populated collector directly.
func TestEgressCollectorDedupesAndSorts(t *testing.T) {
	c := &egressCollector{}
	c.observe(proxy.AdmittedByGate, "b.example", "443")
	c.observe(proxy.AdmittedByGate, "b.example", "443") // duplicate: same key
	c.observe(proxy.AdmittedByGate, "a.example", "443") // sorts before b
	c.observe(proxy.AdmittedByGate, "a.example", "22")  // same host, tiebreak on port
	c.observe(proxy.Denied, "blocked.example", "443")   // counted, never admitted
	c.observe(proxy.Allowed, "declared.example", "443") // counted, not a gate admission
	c.observe(proxy.Refused, "", "")                    // at capacity: counted, no host to admit

	if got := c.counted(); got != 7 {
		t.Errorf("counted() = %d, want 7 (every decision counts, duplicates included)", got)
	}

	want := []enforce.HostPort{
		{Host: "a.example", Port: "22"},
		{Host: "a.example", Port: "443"},
		{Host: "b.example", Port: "443"},
	}
	got := c.gateAdmitted()
	if len(got) != len(want) {
		t.Fatalf("gateAdmitted() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("gateAdmitted()[%d] = %v, want %v (deduped, sorted, blocked host absent)", i, got[i], want[i])
		}
	}
}

// A gate with no network rules must still bring the proxy socket up, so a
// gate + no rules + exec: all sandbox funnels egress through it. bentoPath is set
// on every sandbox now (the launcher always runs), so this guards the gate→socket
// pairing specifically, without a real sandbox.
func TestNewSandboxGatedNoRulesExecAll(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "p.sh")
	if err := os.WriteFile(script, []byte("echo hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Exec: policy.ExecAll}

	sb, cleanup, err := newSandbox(p, "bento-placeholder", true, nil)
	if err != nil {
		t.Fatalf("newSandbox: %v", err)
	}
	defer cleanup()
	if sb.proxySocket == "" {
		t.Error("a gate must force the proxy socket up even with no network rules")
	}
	if sb.bentoPath == "" {
		t.Error("bentoPath must be set alongside the gated proxy socket, or --ro-bind emits an empty source")
	}

	// The same policy WITHOUT a gate needs no proxy socket, but the launcher still
	// runs on every sandbox (it drops inherited descriptors), so bentoPath stays set.
	sbNo, cleanupNo, err := newSandbox(p, "bento-placeholder", false, nil)
	if err != nil {
		t.Fatalf("newSandbox (ungated): %v", err)
	}
	defer cleanupNo()
	if sbNo.proxySocket != "" {
		t.Errorf("ungated exec:all + no rules needs no proxy socket; got %q", sbNo.proxySocket)
	}
	if sbNo.bentoPath == "" {
		t.Error("bentoPath must be set on every sandbox: the launcher always runs")
	}
}

// $HOME can be set to a relative path. The credential shields join onto it, so a
// relative home would produce relative (non-enforcing) Rule.Path values that bwrap
// applies at the wrong place, silently leaving the real stores exposed. newSandbox
// must refuse it rather than shield air.
func TestNewSandboxRefusesRelativeHome(t *testing.T) {
	t.Setenv("HOME", "relhome")
	dir := t.TempDir()
	script := filepath.Join(dir, "p.sh")
	if err := os.WriteFile(script, []byte("echo hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Exec: policy.ExecAll}
	_, _, err := newSandbox(p, "bento-placeholder", false, nil)
	if err == nil || !strings.Contains(err.Error(), "not absolute") {
		t.Fatalf("newSandbox with a relative HOME: err = %v, want it to reject a non-absolute home", err)
	}
}

// Enforcer.Run is exported and satisfies enforce.Enforcer, so an embedder can reach it
// without going through enforce.Run's validation. It must refuse a malformed policy
// itself rather than compile one into a bwrap invocation - Profile already does.
func TestRunValidatesThePolicyItself(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "p.sh")
	if err := os.WriteFile(script, []byte("echo hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: script, Interpreter: "sh", Env: []string{"NOT A NAME"}}
	// Bounded: a regression here means Run proceeds into the real sandbox instead of
	// refusing, and without a deadline that stalls the package until the test binary
	// times out rather than reporting a failure.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := New().Run(ctx, p, enforce.Process{}, enforce.RunOptions{})
	if err == nil || !strings.Contains(err.Error(), "invalid env name") {
		t.Fatalf("Run with an invalid policy: err = %v, want the policy validation error", err)
	}
}

// A grant the run is going to refuse must not leave a directory behind. The write
// grant here is legal on its own, so nothing but the ordering of the checks decides
// whether prepareWriteDirs creates it before the /proc refusal fires - and that
// refusal is one of the four that used to run only later, inside compile.
func TestRunRefusesBeforeCreatingWriteDirs(t *testing.T) {
	requireSandbox(t)
	dir := t.TempDir()
	script := filepath.Join(dir, "p.sh")
	if err := os.WriteFile(script, []byte("echo hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "unborn-output")
	p := &policy.Policy{
		Entrypoint:  script,
		Interpreter: "sh",
		Read:        []string{dir, "/proc/self"},
		Write:       []string{out},
	}
	_, err := New().Run(context.Background(), p, enforce.Process{}, enforce.RunOptions{})
	if err == nil || !strings.Contains(err.Error(), "a host process's directory in /proc") {
		t.Fatalf("Run = %v, want the /proc refusal; any other error would pass this test for the wrong reason", err)
	}
	if _, err := os.Stat(out); err == nil {
		t.Errorf("the refused run created %q; every refusal must be decided before anything touches the host", out)
	}
}
