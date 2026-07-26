package main

import (
	"os"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/policy"
)

// The headline of a global rule: it applies to an app the store has never seen. A
// changed script mints a fresh app key, so the standing denylist must fire without a
// per-app record and without a prompt.
func TestGlobalDenyAppliesToUnknownApp(t *testing.T) {
	s := newTestStore()
	s.rememberNetwork("", "tracker.example", "443", deny, true)
	s.rememberPath("", "read", "/etc/ssh", deny, true)
	s.Global.Exec = string(policy.ExecNone)

	const unseen = "sha256:neverseen"
	if d, ok := s.decideNetwork(unseen, "tracker.example", "443"); !ok || d != deny {
		t.Errorf("global network deny must apply to an unseen app: got %v,%v", d, ok)
	}
	if d, ok := s.decidePath(unseen, "read", "/etc/ssh/id_ed25519"); !ok || d != deny {
		t.Errorf("global read deny must cover a child path for an unseen app: got %v,%v", d, ok)
	}
	if d, ok := s.decideExec(unseen); !ok || d != deny {
		t.Errorf("global exec deny must apply to an unseen app: got %v,%v", d, ok)
	}
}

// A broad global deny must beat a more-specific per-app allow: the layers are
// matched separately then combined deny-wins, so specificity within the app layer
// cannot defeat the standing denylist.
func TestGlobalDenyBeatsMoreSpecificAppAllow(t *testing.T) {
	s := newTestStore()
	s.rememberPath("k", "read", "/home/u/proj/data", allow, false) // specific app allow
	s.rememberPath("", "read", "/home/u", deny, true)              // broad global deny

	if d, ok := s.decidePath("k", "read", "/home/u/proj/data"); !ok || d != deny {
		t.Errorf("a broad global deny must beat a specific app allow: got %v,%v", d, ok)
	}
}

// The live gate's [B]lock-everywhere answer records a standing global deny for the
// host and blocks the connection now. It is the one cross-script action reachable
// interactively - the standing denylist for a tracker seen in the moment.
func TestGateBlockEverywhere(t *testing.T) {
	s := newTestStore()
	sup := &supervisor{p: newPrompter(strings.NewReader("b\n"), &strings.Builder{}), s: s, key: "k", name: "agent", session: map[string]bool{}}

	if admitted := sup.gate(t.Context(), "ads.example", "443"); admitted {
		t.Error("block-everywhere must block the connection now")
	}
	if s.Global.Network["ads.example:443"] != deny {
		t.Errorf("the gate did not persist the standing global deny: %+v", s.Global.Network)
	}
}

// The trial approval prompt no longer offers a cross-script choice: a "g" or "G" is
// just an unrecognized answer, denying this run and persisting nothing global, so a
// standing rule is never a keystroke away from a routine yes.
func TestApproveHasNoGlobalKey(t *testing.T) {
	s := newTestStore()
	proposal := &policy.Policy{Network: []policy.NetworkRule{{Host: "cdn.example", Port: "443"}}}
	final := approve(t.Context(), newPrompter(strings.NewReader("g\n"), &strings.Builder{}), s, "k", "/s", "sh", proposal)

	if len(s.Global.Network) != 0 {
		t.Errorf("the trial prompt must not set a global rule: %+v", s.Global.Network)
	}
	if len(final.Network) != 0 {
		t.Errorf("an unrecognized answer must deny this run: %+v", final.Network)
	}
}

// `perms global allow|deny` is the deliberate way to set a standing rule, and it
// takes effect (a non-folding write) even over a pre-existing conflicting decision.
func TestGlobalPermsCommandSetsStandingRule(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	var out strings.Builder
	if rc := perms([]string{"global", "deny", "net", "tracker.example:443"}, strings.NewReader(""), &out); rc != 0 {
		t.Fatalf("perms global deny net rc=%d out=%q", rc, out.String())
	}
	if rc := perms([]string{"global", "allow", "read", "/etc/hosts"}, strings.NewReader(""), &out); rc != 0 {
		t.Fatalf("perms global allow read rc=%d out=%q", rc, out.String())
	}
	reloaded, err := loadStore()
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Global.Network["tracker.example:443"] != deny {
		t.Errorf("global net deny not persisted: %+v", reloaded.Global.Network)
	}
	if reloaded.Global.Read["/etc/hosts"] != allow {
		t.Errorf("global read allow not persisted: %+v", reloaded.Global.Read)
	}
	// A relative path is rejected.
	if rc := perms([]string{"global", "allow", "read", "relative/path"}, strings.NewReader(""), &out); rc == 0 {
		t.Error("a relative path must be rejected")
	}
}

// A global standing-deny nested under a freshly-approved broad allow is
// unenforceable (bento has no per-path deny), so approve must warn about it - the
// same cross-layer case export refuses, not just per-app sub-denies.
func TestApproveWarnsGlobalDenyUnderApprovedAllow(t *testing.T) {
	s := newTestStore()
	s.rememberPath("", "read", "/home/u/secret", deny, true) // global standing-deny of a child
	// The trial proposes the parent; the operator approves it with "y".
	var out strings.Builder
	proposal := &policy.Policy{Read: []string{"/home/u"}}
	approve(t.Context(), newPrompter(strings.NewReader("y\n"), &out), s, "k", "/s", "sh", proposal)

	if !strings.Contains(out.String(), "cannot enforce the sub-deny") ||
		!strings.Contains(out.String(), "/home/u/secret") {
		t.Errorf("approve must warn a global deny lies under the approved allow; got %q", out.String())
	}
}

// list shows the global read/write/exec dimensions, not just network.
func TestListShowsGlobalReadWriteExec(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	s, _ := loadStore()
	s.rememberPath("", "read", "/etc/ssh", deny, true)
	s.Global.Exec = string(policy.ExecNone)
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	perms([]string{"list"}, strings.NewReader(""), &out)
	got := out.String()
	if !strings.Contains(got, "read") || !strings.Contains(got, "/etc/ssh") {
		t.Errorf("global read rule missing from list:\n%s", got)
	}
	if !strings.Contains(got, "exec") {
		t.Errorf("global exec rule missing from list:\n%s", got)
	}
}

// Export folds the global layer in: a path a global rule denies must not reach the
// manifest's read allowlist.
func TestExportExcludesGloballyDeniedPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	s, _ := loadStore()
	key := "sha256:cccc"
	a := s.app(key)
	a.Entrypoint = "/home/u/agent.sh"
	s.rememberPath(key, "read", "/home/u/data", allow, false)   // app allows
	s.rememberPath("", "read", "/home/u/data", deny, true)      // global denies the same
	s.rememberPath(key, "read", "/home/u/public", allow, false) // cleanly allowed
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	outPath := dir + "/out.yaml"
	var out strings.Builder
	if rc := exportPerms(s, []string{shortKey(key), "-o", outPath}, &out); rc != 0 {
		t.Fatalf("export rc=%d out=%q", rc, out.String())
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	yaml := string(raw)
	if strings.Contains(yaml, "/home/u/data") {
		t.Errorf("a globally-denied path leaked into the manifest:\n%s", yaml)
	}
	if !strings.Contains(yaml, "/home/u/public") {
		t.Errorf("the cleanly-allowed path is missing:\n%s", yaml)
	}
}

// A global deny nested under a per-app allow is unrepresentable in a pure allowlist,
// so export must refuse it across layers, not just within one.
func TestExportRefusesGlobalDenyUnderAppAllow(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	s, _ := loadStore()
	key := "sha256:eeee"
	s.app(key).Entrypoint = "/home/u/agent.sh"
	s.rememberPath(key, "read", "/home/u/proj", allow, false)     // app allows the dir
	s.rememberPath("", "read", "/home/u/proj/secret", deny, true) // global denies a child
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	outPath := dir + "/out.yaml"
	var out strings.Builder
	if rc := exportPerms(s, []string{shortKey(key), "-o", outPath}, &out); rc == 0 {
		t.Errorf("export must refuse a global deny under an app allow; out=%q", out.String())
	}
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Error("a refused export must not write a manifest")
	}
}
