package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/policy"
)

// newTestStore is an empty in-memory store whose dir cannot cover any test grant.
func newTestStore() *store {
	return &store{Version: 1, Apps: map[string]*appPerms{}, dir: "/nonexistent/bento-supervise"}
}

// Deny wins across the global and per-app layers, and network keys normalize so a
// deny cannot be evaded by case or a trailing dot.
func TestStoreDecideNetworkDenyWinsAndNormalizes(t *testing.T) {
	s := newTestStore()
	s.rememberNetwork("k", "example.com", "443", allow, false) // per-app allow
	s.rememberNetwork("k", "example.com", "443", deny, true)   // global deny of the same

	if d, ok := s.decideNetwork("k", "EXAMPLE.com.", "443"); !ok || d != deny {
		t.Errorf("decideNetwork = %v,%v; want deny (global deny beats per-app allow, case/dot normalized)", d, ok)
	}
	if _, ok := s.decideNetwork("k", "unknown.example", "443"); ok {
		t.Error("an unseen host must be unknown (prompt), not decided")
	}
}

// A directory allow answers a prompt for a file inside it (longest-prefix), and a
// more-specific deny wins over a broader allow.
func TestStoreDecidePathLongestPrefix(t *testing.T) {
	s := newTestStore()
	s.rememberPath("k", "read", "/home/u/proj", allow, false)
	s.rememberPath("k", "read", "/home/u/proj/secret", deny, false)

	if d, ok := s.decidePath("k", "read", "/home/u/proj/data.csv"); !ok || d != allow {
		t.Errorf("data.csv under an allowed dir = %v,%v; want allow", d, ok)
	}
	if d, ok := s.decidePath("k", "read", "/home/u/proj/secret/key"); !ok || d != deny {
		t.Errorf("under a more-specific deny = %v,%v; want deny", d, ok)
	}
	if _, ok := s.decidePath("k", "read", "/home/u/other"); ok {
		t.Error("an unrelated path must be unknown")
	}
	// A sibling that only shares a string prefix must not match (/projX vs /proj).
	if _, ok := s.decidePath("k", "read", "/home/u/projX"); ok {
		t.Error("/home/u/projX must not match the allow of /home/u/proj (component boundary)")
	}
}

// A grant that would expose the store is refused outright, never granted or
// prompted.
func TestApproveRefusesStoreCoveringGrant(t *testing.T) {
	s := newTestStore()
	s.dir = "/home/u/.config/bento-supervise"
	var out strings.Builder
	// No input: if the covering grant prompted, ask would block/deny; we assert it
	// is refused without consuming input.
	p := newPrompter(strings.NewReader(""), &out)
	proposal := &policy.Policy{Read: []string{"/home/u/.config"}} // contains the store dir

	got := approve(p, s, "k", "/s", "sh", proposal)
	if len(got.Read) != 0 {
		t.Errorf("a grant covering the store must be refused; got Read=%v", got.Read)
	}
	if !strings.Contains(out.String(), "refused") {
		t.Errorf("the refusal should be reported; got %q", out.String())
	}
}

// A path from the untrusted trial can carry terminal escapes; the approval prompt
// must quote it (as the gate quotes a host), or a crafted filename spoofs what the
// operator sees while a different path is stored/granted.
func TestApproveQuotesAttackerPath(t *testing.T) {
	s := newTestStore()
	evil := "/home/u/proj/\x1b[2Kinnocent"
	var out strings.Builder
	// "y" grants it; the display must not contain the raw ESC byte.
	p := newPrompter(strings.NewReader("y\n"), &out)
	got := approve(p, s, "k", "/s", "sh", &policy.Policy{Read: []string{evil}})

	if len(got.Read) != 1 || got.Read[0] != evil {
		t.Fatalf("the literal path must be granted; got %v", got.Read)
	}
	if strings.ContainsRune(out.String(), '\x1b') {
		t.Errorf("the approval prompt leaked a raw escape byte: %q", out.String())
	}
}

// save folds in a concurrent run's writes instead of clobbering them: after run A
// saves app "a", run B (which loaded before A saved) saves app "b" and both survive.
func TestStoreSaveMergesConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	mk := func() *store {
		return &store{Version: 1, Apps: map[string]*appPerms{}, dir: dir, path: filepath.Join(dir, "permissions.json")}
	}
	a := mk()
	a.rememberNetwork("a", "a.example", "443", allow, false)
	if err := a.save(); err != nil {
		t.Fatal(err)
	}
	// b was loaded empty before a's save; it must not erase a's record on its own save.
	b := mk()
	b.rememberNetwork("b", "b.example", "443", deny, false)
	if err := b.save(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "permissions.json"))
	if err != nil {
		t.Fatal(err)
	}
	var final store
	if err := json.Unmarshal(data, &final); err != nil {
		t.Fatal(err)
	}
	if _, ok := final.Apps["a"]; !ok {
		t.Error("app 'a' was clobbered by a concurrent save")
	}
	if _, ok := final.Apps["b"]; !ok {
		t.Error("app 'b' was not saved")
	}
}

// The core loop: approve once with answers, then a second run with NO input
// auto-applies the remembered decisions (allow silently, deny silently) and never
// prompts - the "run twice, silent" behavior.
func TestApproveRemembersAcrossRuns(t *testing.T) {
	s := newTestStore()
	proposal := &policy.Policy{
		Read:    []string{"/data", "/secret"},
		Network: []policy.NetworkRule{{Host: "ok.example", Port: "443"}},
		Exec:    policy.ExecAll,
	}

	// First run: allow /data, deny /secret, allow exec, allow the host.
	first := approve(newPrompter(strings.NewReader("y\nn\ny\ny\n"), &strings.Builder{}), s, "k", "/s", "sh", proposal)
	if len(first.Read) != 1 || first.Read[0] != "/data" {
		t.Fatalf("first run Read = %v, want just /data", first.Read)
	}

	// Second run: no input at all. Every item is remembered, so nothing prompts and
	// the same policy is produced.
	var out strings.Builder
	second := approve(newPrompter(strings.NewReader(""), &out), s, "k", "/s", "sh", proposal)
	if len(second.Read) != 1 || second.Read[0] != "/data" || second.Exec != policy.ExecAll || len(second.Network) != 1 {
		t.Errorf("second run did not reproduce the approved policy from memory: %+v", second)
	}
	if strings.Contains(out.String(), "[y]es") {
		t.Errorf("second run must not prompt; output was %q", out.String())
	}
}
