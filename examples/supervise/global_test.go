package main

import (
	"os"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/policy"
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

// The g choice remembers a decision for every app, but only after the confirm the
// case-slip guard requires.
func TestApproveGlobalAllowPersistsAfterConfirm(t *testing.T) {
	s := newTestStore()
	proposal := &policy.Policy{Network: []policy.NetworkRule{{Host: "cdn.example", Port: "443"}}}
	// "g" picks global-allow; the confirm reads "y".
	final := approve(newPrompter(strings.NewReader("g\ny\n"), &strings.Builder{}), s, "k", "/s", "sh", proposal)

	if s.Global.Network["cdn.example:443"] != allow {
		t.Errorf("global allow was not persisted: %+v", s.Global.Network)
	}
	if len(final.Network) != 1 {
		t.Errorf("the item should be admitted this run: %+v", final.Network)
	}
}

// Declining the confirm (the case-slip escape) persists nothing and denies the item
// this run - so a lowercase-habit typo of G->g, or cold feet, is harmless.
func TestApproveGlobalConfirmDeclinePersistsNothing(t *testing.T) {
	s := newTestStore()
	proposal := &policy.Policy{Network: []policy.NetworkRule{{Host: "cdn.example", Port: "443"}}}
	// "G" picks global-deny; the confirm reads "n" - abort.
	final := approve(newPrompter(strings.NewReader("G\nn\n"), &strings.Builder{}), s, "k", "/s", "sh", proposal)

	if len(s.Global.Network) != 0 {
		t.Errorf("a declined confirm must persist nothing: %+v", s.Global.Network)
	}
	if len(final.Network) != 0 {
		t.Errorf("the item must be denied this run: %+v", final.Network)
	}
}

// The gate offers g/G too; a confirmed global deny persists and blocks the
// connection in real time.
func TestGateGlobalDenyPersistsAfterConfirm(t *testing.T) {
	s := newTestStore()
	sup := &supervisor{p: newPrompter(strings.NewReader("G\ny\n"), &strings.Builder{}), s: s, key: "k", name: "agent", session: map[string]bool{}}

	if admitted := sup.gate(t.Context(), "ads.example", "443"); admitted {
		t.Error("a confirmed global deny must block the connection")
	}
	if s.Global.Network["ads.example:443"] != deny {
		t.Errorf("the gate did not persist the global deny: %+v", s.Global.Network)
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
	approve(newPrompter(strings.NewReader("y\n"), &out), s, "k", "/s", "sh", proposal)

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
