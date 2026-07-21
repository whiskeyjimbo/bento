package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/backend"
	"github.com/whiskeyjimbo/bento-v2/policy"
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

	got := approve(p, newTestStore(), "k", "/script.sh", "sh", proposal)

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

// The enforced run carries no DenyPaths, so the store shield rests on approve()
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
	if s := newTestStore(); func() bool { s.rememberNetwork("k", "a", "443", allow, false); return s.recordedDeny }() {
		t.Error("an allow must not set recordedDeny")
	}
	for name, record := range map[string]func(*store){
		"network deny": func(s *store) { s.rememberNetwork("k", "a", "443", deny, false) },
		"standing block": func(s *store) { s.rememberNetwork("k", "a", "443", deny, true) },
		"path deny": func(s *store) { s.rememberPath("k", "read", "/x", deny, false) },
		"exec deny": func(s *store) { s.rememberExec("k", deny, false) },
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
