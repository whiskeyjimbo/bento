package main

import (
	"context"
	"io"
	"os"
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

	got := approve(p, "/script.sh", "sh", proposal)

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

// "A" (all) approves the item and everything after it without another prompt.
func TestApproveAllAcceptsRest(t *testing.T) {
	proposal := &policy.Policy{
		Read:    []string{"/a", "/b", "/c"},
		Network: []policy.NetworkRule{{Host: "h", Port: "1"}},
		Exec:    policy.ExecAll,
	}
	// One "A" on the first read, then no more input: everything else is auto-kept.
	p := newPrompter(strings.NewReader("A\n"), &strings.Builder{})
	got := approve(p, "/s", "sh", proposal)

	if len(got.Read) != 3 {
		t.Errorf("Read = %v, want all three kept after A", got.Read)
	}
	if got.Exec != policy.ExecAll || len(got.Network) != 1 {
		t.Errorf("A must carry past reads to exec and network; got exec=%q net=%v", got.Exec, got.Network)
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

// The live gate prompts once per host and remembers the answer for the run, and a
// denial (n or anything not y/A) blocks the connection.
func TestGateRemembersPerHost(t *testing.T) {
	var out strings.Builder
	// example.com=y, then ads.example=n. Repeats must not consume more input.
	p := newPrompter(strings.NewReader("y\nn\n"), &out)
	s := &supervisor{p: p, name: "agent.sh", session: make(map[string]bool)}
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
