package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/backend"
	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// TestMain routes a re-exec sub-invocation before the testing package parses
// flags, the same hook an embedder's own tests need.
func TestMain(m *testing.M) {
	backend.DispatchReexec()
	os.Exit(m.Run())
}

// approve keeps exactly what the human says yes (or "all") to, and drops the rest,
// building the policy the enforced run is held to.
func TestApproveKeepsAnswers(t *testing.T) {
	proposal := &policy.Policy{
		Read:    []string{"/data.csv", "/secret.txt"},
		Write:   []string{"/out"},
		Network: []policy.NetworkRule{{Host: "example.com", Port: "443"}, {Host: "ads.example", Port: "443"}},
		Exec:    policy.ExecAll,
	}
	// read data.csv=y, secret.txt=n; write=y; exec=y; reach example.com=y, ads.example=n.
	answers := "y\nn\ny\ny\ny\nn\n"
	p := newPrompter(strings.NewReader(answers), &strings.Builder{})

	got := approve(t.Context(), p, newTestStore(), "k", "/script.sh", "sh", proposal)

	if len(got.Read) != 1 || got.Read[0] != "/data.csv" {
		t.Errorf("Read = %v, want just /data.csv (secret.txt denied)", got.Read)
	}
	if len(got.Write) != 1 || got.Write[0] != "/out" {
		t.Errorf("Write = %v, want /out", got.Write)
	}
	if got.Exec != policy.ExecAll {
		t.Errorf("Exec = %q, want all (subprocesses approved)", got.Exec)
	}
	if len(got.Network) != 1 || got.Network[0].Host != "example.com" {
		t.Errorf("Network = %v, want just example.com (ads.example denied)", got.Network)
	}
}

// The chain down to the script is a walk, not a decision, and asking about it invites a
// routine yes onto a recursive read grant several levels above anything the script named.
func TestApproveSkipsTheChainDownToTheScript(t *testing.T) {
	proposal := &policy.Policy{
		Read: []string{"/home/u", "/home/u/src", "/home/u/src/app", "/home/u/src/app/data.csv", "/home/u/other"},
	}
	// /home/u and /home/u/src are the walk and never reach a human. The script's own
	// directory is a real grant and stays, so three prompts are left.
	p := newPrompter(strings.NewReader("y\ny\ny\n"), &strings.Builder{})

	got := approve(t.Context(), p, newTestStore(), "k", "/home/u/src/app/run.sh", "sh", proposal)

	want := []string{"/home/u/src/app", "/home/u/src/app/data.csv", "/home/u/other"}
	if len(got.Read) != len(want) {
		t.Fatalf("Read = %v, want %v (the ancestor chain should never be asked about)", got.Read, want)
	}
	for i, w := range want {
		if got.Read[i] != w {
			t.Errorf("Read[%d] = %q, want %q", i, got.Read[i], w)
		}
	}
}

// A deliberate grant on an ancestor has to survive the trimming, or the remedy for the
// case it hides - a script that lists one of its own parents - is one the store records,
// perms list reports, and the run silently ignores.
func TestApproveKeepsAnAncestorTheStoreDecided(t *testing.T) {
	s := newTestStore()
	s.rememberPath("", "read", "/home/u/src", allow, true)

	proposal := &policy.Policy{Read: []string{"/home/u", "/home/u/src", "/home/u/src/app"}}
	// Only the script's own directory prompts: /home/u is trimmed as an undecided part
	// of the walk, and /home/u/src applies from the store without asking.
	p := newPrompter(strings.NewReader("y\n"), &strings.Builder{})

	got := approve(t.Context(), p, s, "k", "/home/u/src/app/run.sh", "sh", proposal)

	want := []string{"/home/u/src", "/home/u/src/app"}
	if len(got.Read) != len(want) {
		t.Fatalf("Read = %v, want %v (a globally allowed ancestor must reach the policy)", got.Read, want)
	}
	for i, w := range want {
		if got.Read[i] != w {
			t.Errorf("Read[%d] = %q, want %q", i, got.Read[i], w)
		}
	}
}

// Root is the ancestor a routine yes hurts most, and its own trailing separator is what
// a naive prefix test trips over.
func TestTrimAncestorsTrimsRoot(t *testing.T) {
	undecided := func(string) bool { return false }
	got := trimAncestors([]string{"/", "/home", "/home/u/src/app"}, "/home/u/src/app/run.sh", undecided)
	if len(got) != 1 || got[0] != "/home/u/src/app" {
		t.Errorf("trimAncestors = %v, want just the script's own directory", got)
	}
}

// A sibling of the script's directory shares a textual prefix with it but is not on the
// path down to it, so it stays a real decision.
func TestTrimAncestorsKeepsASiblingPrefix(t *testing.T) {
	undecided := func(string) bool { return false }
	got := trimAncestors([]string{"/home/u/app", "/home/u/appendix", "/home/u/app/sub"}, "/home/u/app/sub/run.sh", undecided)
	want := []string{"/home/u/appendix", "/home/u/app/sub"}
	if len(got) != len(want) {
		t.Fatalf("trimAncestors = %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("[%d] = %q, want %q", i, got[i], w)
		}
	}
}

// drain discards input typed past the approval prompts, so a stray line from Act 1
// cannot silently answer the first live gate prompt in Act 2 (both share one
// terminal reader).
func TestPrompterDrainDiscardsStaleInput(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	p := newPrompter(pr, io.Discard)

	// A stale line is already waiting, as if typed during Act 1.
	go func() { io.WriteString(pw, "stale\n") }()
	p.drain()

	// A fresh answer must now be what ask returns; if drain missed the stale line,
	// ask would consume "stale" (-> deny) instead of the fresh "y".
	go func() { io.WriteString(pw, "y\n") }()
	if got := p.ask(context.Background(), ""); got != choiceAllow {
		t.Errorf("ask after drain = %v, want allow from the fresh line (stale input must be discarded)", got)
	}
}

// This wrapper shields the store by refusing a covering grant, not by DenyPaths, so it rests on approve()
// refusing a covering grant. assertStoreShielded is the backstop for a policy built
// by some other path: it must refuse a final policy whose read OR write grant covers
// the store dir (in either direction), and pass a policy that stays clear of it.
func TestAssertStoreShielded(t *testing.T) {
	const storeDir = "/home/u/.config/bento-supervise"

	clear := &policy.Policy{Read: []string{"/home/u/proj"}, Write: []string{"/home/u/proj/out"}}
	if err := assertStoreShielded(clear, storeDir); err != nil {
		t.Errorf("a policy clear of the store must pass; got %v", err)
	}

	// A grant that IS the store, a grant strictly inside it, and a grant that ENCLOSES
	// it (a broad ~/.config read) must all be refused - the last is the copyist trap
	// the assertion exists to catch.
	for name, g := range map[string]string{
		"exact":     storeDir,
		"inside":    filepath.Join(storeDir, "permissions.json"),
		"enclosing": "/home/u/.config",
	} {
		t.Run(name, func(t *testing.T) {
			if err := assertStoreShielded(&policy.Policy{Read: []string{g}}, storeDir); err == nil {
				t.Errorf("a read grant %q covering the store must be refused", g)
			}
			if err := assertStoreShielded(&policy.Policy{Write: []string{g}}, storeDir); err == nil {
				t.Errorf("a write grant %q covering the store must be refused", g)
			}
		})
	}
}

// The trial runs under default-deny: discoveryPolicy binds only the script's own
// directory (unless that directory is broad), so a script anywhere else in the home
// tree probes credential paths that are simply absent. It grants exactly its dir and
// nothing more.
func TestDiscoveryPolicyBindsOnlyScriptDir(t *testing.T) {
	t.Setenv("HOME", "/home/u")

	p := discoveryPolicy("/home/u/proj/agent.sh", "sh")
	if len(p.Read) != 1 || p.Read[0] != "/home/u/proj" {
		t.Errorf("Read = %v, want just the script dir /home/u/proj", p.Read)
	}
	if len(p.Write) != 1 || p.Write[0] != "/home/u/proj" {
		t.Errorf("Write = %v, want just the script dir /home/u/proj", p.Write)
	}
	if p.Exec != policy.ExecAll {
		t.Errorf("Exec = %q, want all so the script exercises subprocesses", p.Exec)
	}

	// A script whose directory is broad (home itself, or a top-level dir) must not
	// bind that tree - it would re-expose every credential beside it, the fail-open
	// model default-deny inverts away from. The entrypoint alone still runs.
	for name, script := range map[string]string{
		"home root":  "/home/u/agent.sh",
		"top-level":  "/opt/agent.sh",
		"filesystem": "/agent.sh",
	} {
		t.Run(name, func(t *testing.T) {
			p := discoveryPolicy(script, "sh")
			if len(p.Read) != 0 || len(p.Write) != 0 {
				t.Errorf("broad dir %q: Read=%v Write=%v, want no host grant", script, p.Read, p.Write)
			}
		})
	}
}

// discoveryPolicy does NOT itself shield the permission store: a script living in or
// beside the store makes its script-dir grant cover the store, so the trial's
// protection rests on the caller passing the store as a ProfileOptions deny path (the
// linux backend applies deny paths after grants, last-wins). This pins that the grant
// really does cover the store in those placements, so the deny path is load-bearing
// and must never be dropped on the theory that default-deny alone hides the store.
func TestDiscoveryPolicyGrantCoversStoreWhenAdjacent(t *testing.T) {
	t.Setenv("HOME", "/home/u")
	for name, tc := range map[string]struct{ script, storeDir string }{
		"script in config dir": {"/home/u/.config/agent.sh", "/home/u/.config/bento-supervise"},
		"script in store dir":  {"/home/u/.config/bento-supervise/agent.sh", "/home/u/.config/bento-supervise"},
		"dev XDG_CONFIG_HOME":  {"/home/u/proj/agent.sh", "/home/u/proj/bento-supervise"},
	} {
		t.Run(name, func(t *testing.T) {
			p := discoveryPolicy(tc.script, "sh")
			if err := assertStoreShielded(p, tc.storeDir); err == nil {
				t.Errorf("discoveryPolicy(%q) grant %v must be shown to cover store %q, proving the trial deny path is required",
					tc.script, append(p.Read, p.Write...), tc.storeDir)
			}
		})
	}
}

// scriptDirCoversStore drives the diagnostic run() prints instead of the cryptic backend
// refusal when a script sits in or beside its permission store. It must fire for exactly
// the placements where the trial's script-dir grant covers the store, and stay quiet for a
// script kept well away from it, so an ordinary trial failure keeps its own error.
func TestScriptDirCoversStore(t *testing.T) {
	t.Setenv("HOME", "/home/u")
	overlap := map[string]struct{ script, storeDir string }{
		"script in config dir": {"/home/u/.config/agent.sh", "/home/u/.config/bento-supervise"},
		"script in store dir":  {"/home/u/.config/bento-supervise/agent.sh", "/home/u/.config/bento-supervise"},
		"dev XDG_CONFIG_HOME":  {"/home/u/proj/agent.sh", "/home/u/proj/bento-supervise"},
	}
	for name, tc := range overlap {
		t.Run(name, func(t *testing.T) {
			if !scriptDirCoversStore(tc.script, "sh", tc.storeDir) {
				t.Errorf("scriptDirCoversStore(%q, %q) = false, want true (grant covers the store)", tc.script, tc.storeDir)
			}
		})
	}
	// A script in an unrelated directory must not be misdiagnosed: a real trial failure
	// there should surface its own error, not the store-overlap message.
	if scriptDirCoversStore("/home/u/proj/agent.sh", "sh", "/home/u/.config/bento-supervise") {
		t.Error("scriptDirCoversStore fired for a script that does not overlap the store")
	}
}

func requireSandbox(t *testing.T) {
	t.Helper()
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		t.Skip("bwrap not installed")
	}
	// bwrap in PATH is not enough: a host with unprivileged user namespaces disabled
	// cannot create the namespace, and one that masks paths under /proc (docker's
	// default) grants the namespace but refuses the procfs mount inside it - either way
	// the trial fails to confine rather than shielding. Probe it the way admission does,
	// so this skips (not fails) on those host classes.
	if err := exec.Command(bwrap, "--unshare-user", "--unshare-net", "--bind", "/", "/", "--proc", "/proc", "/bin/true").Run(); err != nil {
		t.Skip("the bwrap sandbox cannot be built on this host (user namespace or /proc mount refused)")
	}
}

// trialProfile must keep the untrusted script out of the permission store even when
// the script sits in or beside it (a dev-set XDG_CONFIG_HOME the script dir also
// contains), where discoveryPolicy's script-dir grant covers the store. This drives
// trialProfile - the seam run() uses - so it guards the actual wiring, not just the
// backend mechanism: a baseline calling Profile with no deny shows the script-dir
// grant reaching the store (the fail-open regression), and trialProfile shields it
// fail-closed (refusing the writable-parent-over-shield combination outright), so the
// store never reaches the trial. Dropping the deny inside trialProfile fails this. The
// store lives under $HOME, not /tmp, because the sandbox always overmounts /tmp.
func TestTrialProfileShieldsAdjacentStore(t *testing.T) {
	requireSandbox(t)

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	proj, err := os.MkdirTemp(home, "bento-supervise-adjtest-") // a dev-set XDG_CONFIG_HOME the script also lives in
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(proj)
	storeDir := filepath.Join(proj, "bento-supervise")
	if err := os.MkdirAll(storeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const secret = "TOPSECRET-SUPERVISE-STORE"
	storeFile := filepath.Join(storeDir, "permissions.json")
	if err := os.WriteFile(storeFile, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(proj, "peek.sh")
	if err := os.WriteFile(script, []byte("cat "+storeFile+" 2>&1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	discovery := discoveryPolicy(script, "sh")

	// Baseline: Profile with no deny path shows discoveryPolicy's script-dir grant does
	// reach the adjacent store, so the shield trialProfile adds is genuinely load-bearing.
	var base bytes.Buffer
	if _, err := backend.Profile(context.Background(), discovery,
		enforce.Process{Stdout: &base, Stderr: &base}, backend.ProfileOptions{}); err != nil {
		t.Fatalf("baseline Profile: %v", err)
	}
	if !strings.Contains(base.String(), secret) {
		t.Fatalf("baseline: the script-dir grant should reach the adjacent store with no deny path; got %q", base.String())
	}

	// trialProfile owns the store deny path. Fail-closed: either the run is refused
	// (err != nil) or it ran without the secret; the only failure is a completed run
	// that exposed it. Removing the deny inside trialProfile makes this leak.
	var out bytes.Buffer
	_, err = trialProfile(context.Background(), &store{dir: storeDir}, discovery,
		enforce.Process{Stdout: &out, Stderr: &out})
	if err == nil && strings.Contains(out.String(), secret) {
		t.Errorf("trialProfile did not shield the store: it leaked %q", out.String())
	}
}

// A failed save loses the run's decisions. When one of those was a deny or standing
// block, a zero target code would report a clean run over a dropped security decision,
// so finalExitCode forces non-zero. A clean save, a run with no deny, and an already-
// failed target each keep the target's own code.
func TestFinalExitCode(t *testing.T) {
	saveErr := os.ErrPermission
	cases := []struct {
		name         string
		targetExit   int
		saveErr      error
		recordedDeny bool
		want         int
	}{
		{"clean save passes target code", 0, nil, true, 0},
		{"save fail but no deny recorded", 0, saveErr, false, 0},
		{"save fail loses a deny", 0, saveErr, true, 1},
		{"save fail, target already failed", 7, saveErr, true, 7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := finalExitCode(tc.targetExit, tc.saveErr, tc.recordedDeny); got != tc.want {
				t.Errorf("finalExitCode(%d,%v,%v) = %d, want %d", tc.targetExit, tc.saveErr, tc.recordedDeny, got, tc.want)
			}
		})
	}
}

// A recorded deny (or standing block) sets the flag finalExitCode reads, across all
// three permission dimensions; an allow leaves it clear.
func TestStoreRecordedDenyTracksDenies(t *testing.T) {
	allowOnly := newTestStore()
	allowOnly.rememberNetwork("k", "a", "443", allow, false)
	if allowOnly.recordedDeny {
		t.Error("an allow must not set recordedDeny")
	}
	for name, record := range map[string]func(*store){
		"network deny":   func(s *store) { s.rememberNetwork("k", "a", "443", deny, false) },
		"standing block": func(s *store) { s.rememberNetwork("k", "a", "443", deny, true) },
		"path deny":      func(s *store) { s.rememberPath("k", "read", "/x", deny, false) },
		"exec deny":      func(s *store) { s.rememberExec("k", deny, false) },
	} {
		t.Run(name, func(t *testing.T) {
			s := newTestStore()
			record(s)
			if !s.recordedDeny {
				t.Error("a recorded deny must set recordedDeny")
			}
		})
	}
}

// The live gate prompts once per host and remembers the answer for the run, and a
// denial (n or anything not y/o) blocks the connection.
func TestGateRemembersPerHost(t *testing.T) {
	var out strings.Builder
	// example.com=y, then ads.example=n. Repeats must not consume more input.
	p := newPrompter(strings.NewReader("y\nn\n"), &out)
	s := &supervisor{p: p, s: newTestStore(), key: "k", name: "agent.sh", session: make(map[string]bool)}
	ctx := context.Background()

	if !s.gate(ctx, "example.com", "443") {
		t.Error("answering y should admit example.com")
	}
	if !s.gate(ctx, "example.com", "443") {
		t.Error("a second connection to an admitted host must come from the session cache")
	}
	if s.gate(ctx, "ads.example", "443") {
		t.Error("answering n should deny ads.example")
	}
	if got := strings.Count(out.String(), "reaching"); got != 2 {
		t.Errorf("prompted %d times, want 2 (once per unique host)", got)
	}
}

// Every failure return from the supervised run happens after the approval prompts,
// where the human has already answered. Those answers used to be discarded: only the
// success path reached save(), so a failed enforced run threw away every deny and
// standing block the trial recorded (bv2-q5qm).
func TestPersistDecisionsSavesOnAFailedRun(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	s, err := loadStore()
	if err != nil {
		t.Fatal(err)
	}
	s.rememberNetwork("", "tracker.example", "443", deny, true)

	// The run failed for its own reason; the deny it recorded must still land.
	if got := persistDecisions(s, 1, io.Discard); got != 1 {
		t.Errorf("exit code = %d, want the run's own 1 - a successful save must not change it", got)
	}
	reloaded, err := loadStore()
	if err != nil {
		t.Fatal(err)
	}
	if d, ok := reloaded.decideNetwork("", "tracker.example", "443"); !ok || d != deny {
		t.Errorf("the standing block from a failed run was lost; decideNetwork = %v,%v", d, ok)
	}
}

// A save that fails after a deny was recorded turns a clean run non-zero, but never
// overwrites a more specific failure code the run already returned.
func TestPersistDecisionsExitCodes(t *testing.T) {
	cases := map[string]struct {
		code, want int
	}{
		"clean run, lost deny":          {0, 1},
		"failed run keeps its own code": {2, 2},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// A store whose directory cannot be created is one whose save always fails.
			s := &store{Version: storeVersion, Apps: map[string]*appPerms{}, dir: "/proc/nonexistent/store"}
			s.path = filepath.Join(s.dir, "permissions.json")
			s.rememberPath("k", "read", "/tmp/x", deny, false)
			if got := persistDecisions(s, tc.code, io.Discard); got != tc.want {
				t.Errorf("persistDecisions(code=%d) = %d, want %d", tc.code, got, tc.want)
			}
		})
	}
}
