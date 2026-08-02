package main

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/whiskeyjimbo/bento/policy"
)

// syncWriter is a prompter output the concurrent gate tests can read while handlers
// are still writing to it.
type syncWriter struct {
	mu sync.Mutex
	b  strings.Builder
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *syncWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

// waitFor blocks until cond holds, failing the test rather than hanging forever.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// The gate used to hold one mutex across the human prompt, so a parked prompt froze
// every other pending connection - including ones whose answer was already known and
// needed no terminal at all. Only the terminal is serialized now.
func TestGateDoesNotBlockAnAnsweredDestWhileAHumanThinks(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	out := &syncWriter{}
	p := newPrompter(pr, out)
	sup := &supervisor{p: p, s: newTestStore(), key: "k", name: "agent",
		session: map[string]bool{"cached.example:443": true}}

	parked := make(chan bool, 1)
	go func() { parked <- sup.gate(t.Context(), "slow.example", "443") }()
	waitFor(t, "the prompt for slow.example", func() bool {
		return strings.Contains(out.String(), "slow.example")
	})

	// Run it in a goroutine: with the old single lock this call blocks forever behind
	// the parked prompt, and the test must report that rather than hang.
	done := make(chan bool, 1)
	go func() { done <- sup.gate(t.Context(), "cached.example", "443") }()
	select {
	case admitted := <-done:
		if !admitted {
			t.Error("the session's admitted dest must stay admitted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a dest already answered for this run blocked behind another connection's human prompt")
	}

	io.WriteString(pw, "y\n")
	if !<-parked {
		t.Error("answering y should admit slow.example")
	}
}

// Two connections to the same host can be gated at once. The second must take the
// first one's answer, not ask the human the same question twice.
func TestGateAsksOnceWhenTwoConnectionsRaceTheSameDest(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	out := &syncWriter{}
	sup := &supervisor{p: newPrompter(pr, out), s: newTestStore(), key: "k", name: "agent",
		session: make(map[string]bool)}

	var wg sync.WaitGroup
	verdicts := make([]bool, 2)
	for i := range verdicts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			verdicts[i] = sup.gate(t.Context(), "example.com", "443")
		}()
	}
	// One "y" for the two racing connections: the loser must not consume an answer.
	waitFor(t, "the first prompt", func() bool { return strings.Contains(out.String(), "example.com") })
	io.WriteString(pw, "y\n")
	wg.Wait()

	for i, admitted := range verdicts {
		if !admitted {
			t.Errorf("connection %d was denied; both must take the single y", i)
		}
	}
	if got := strings.Count(out.String(), "reaching"); got != 1 {
		t.Errorf("prompted %d times, want 1 - the second connection must reuse the answer", got)
	}
}

// A host the store already allows needs the terminal for nothing - it prints no verdict
// and asks no question - so it must not wait behind a human parked at an unrelated
// prompt. This is the first connection to it, so the session cache cannot cover it.
func TestGateAdmitsAStoredAllowWhileAHumanThinks(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	out := &syncWriter{}
	s := newTestStore()
	s.rememberNetwork("k", "known.example", "443", allow, false)
	sup := &supervisor{p: newPrompter(pr, out), s: s, key: "k", name: "agent",
		session: make(map[string]bool)}

	parked := make(chan bool, 1)
	go func() { parked <- sup.gate(t.Context(), "slow.example", "443") }()
	waitFor(t, "the prompt for slow.example", func() bool {
		return strings.Contains(out.String(), "slow.example")
	})

	done := make(chan bool, 1)
	go func() { done <- sup.gate(t.Context(), "known.example", "443") }()
	select {
	case admitted := <-done:
		if !admitted {
			t.Error("a stored allow must admit the connection")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a stored allow, which needs no terminal, blocked behind another connection's human prompt")
	}

	io.WriteString(pw, "y\n")
	<-parked
}

// Two connections to different hosts both need the human, and the prompts share one
// terminal reader: they must be asked one at a time, or the second prompt's question is
// on screen while the first is still waiting and one answer decides the wrong host.
func TestGateSerializesPromptsForDifferentHosts(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	out := &syncWriter{}
	sup := &supervisor{p: newPrompter(pr, out), s: newTestStore(), key: "k", name: "agent",
		session: make(map[string]bool)}

	hosts := []string{"a.example", "b.example"}
	verdicts := make(chan bool, len(hosts))
	for _, host := range hosts {
		go func() { verdicts <- sup.gate(t.Context(), host, "443") }()
	}

	// Whichever host wins the terminal, the other must not be on screen until this one
	// has been answered.
	waitFor(t, "the first prompt", func() bool { return strings.Contains(out.String(), ".example") })
	first, second := hosts[0], hosts[1]
	if !strings.Contains(out.String(), first) {
		first, second = second, first
	}
	time.Sleep(50 * time.Millisecond) // long enough for a lockless second prompt to print
	if strings.Contains(out.String(), second) {
		t.Errorf("%s was prompted while %s was still waiting for an answer; the two share one reader", second, first)
	}

	io.WriteString(pw, "y\n")
	waitFor(t, "the second prompt", func() bool { return strings.Contains(out.String(), second) })
	io.WriteString(pw, "y\n")
	for range hosts {
		if !<-verdicts {
			t.Error("both hosts were answered y and must be admitted")
		}
	}
}

// Ctrl-C during the approval prompts used to kill the process where it stood,
// discarding every answer the human had already given. It now cancels the run, which
// denies the remaining items silently - without printing a prompt it then answers
// itself - and leaves the answers already given in the store for the caller to save.
func TestApproveStopsPromptingOnceCancelled(t *testing.T) {
	s := newTestStore()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var out strings.Builder
	// The reader is empty and never closed by an answer: a prompt that is actually
	// waited on would hang, and one that is printed and self-answered shows up in out.
	p := newPrompter(strings.NewReader("y\n"), &out)
	proposal := &policy.Policy{Read: []string{"/data", "/secret"}, Exec: policy.ExecAll,
		Network: []policy.NetworkRule{{Host: "example.com", Port: "443"}}}

	final := approve(ctx, p, s, "k", "/s", "sh", nil, proposal)

	if len(final.Read) != 0 || final.Exec == policy.ExecAll || len(final.Network) != 0 {
		t.Errorf("a cancelled run granted something nobody answered: %+v", final)
	}
	if strings.Contains(out.String(), "[y]es") {
		t.Errorf("a cancelled run must print no prompts it then answers itself; got %q", out.String())
	}
	if _, ok := s.decidePath("k", "read", "/data"); ok {
		t.Error("a teardown denial must not be remembered as the human's answer")
	}
}
