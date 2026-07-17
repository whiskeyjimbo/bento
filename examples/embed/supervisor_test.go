package main

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

// The supervisor prompts once per undeclared host and remembers the answer for
// the run - the "allow for this session" behavior bento leaves to the wrapper
// (bento re-consults the gate on every connection). A second connection to a
// host already answered must not prompt again.
func TestSupervisorRemembersAnswerPerHost(t *testing.T) {
	// One "y", one "n": the first host is admitted, the second denied. The repeats
	// below must be served from the session cache, not by consuming more input.
	in := strings.NewReader("y\nn\n")
	var out strings.Builder
	s := newSupervisor(nil, in, &out)
	ctx := context.Background()

	if !s.gate(ctx, "a.example", "443") {
		t.Error("answering y should admit a.example")
	}
	if !s.gate(ctx, "a.example", "443") {
		t.Error("a second connection to an admitted host must be served from the session cache")
	}
	if s.gate(ctx, "b.example", "443") {
		t.Error("answering n should deny b.example")
	}
	if s.gate(ctx, "b.example", "443") {
		t.Error("a denied host must stay denied for the run without re-prompting")
	}

	if got := strings.Count(out.String(), "allow egress"); got != 2 {
		t.Errorf("prompted %d times, want 2 (once per unique host)", got)
	}
}

// A pre-approved host is admitted without a prompt at all - the out-of-band
// "already decided" set (BENTO_GATE_ALLOW in the command).
func TestSupervisorPreApprovedSkipsPrompt(t *testing.T) {
	var out strings.Builder
	// Empty input: if a pre-approved host prompted, the read would block/deny.
	s := newSupervisor(map[string]bool{"declared.example": true}, strings.NewReader(""), &out)
	if !s.gate(context.Background(), "declared.example", "443") {
		t.Error("a pre-approved host must be admitted")
	}
	if out.Len() != 0 {
		t.Errorf("a pre-approved host must not prompt; got %q", out.String())
	}
}

// A prompt must return (as a denial) when the run's ctx is cancelled, or a
// blocking human prompt would pin a proxy handler slot and stall run teardown.
func TestSupervisorPromptUnblocksOnCancel(t *testing.T) {
	pr, pw := io.Pipe() // never written to, so the prompt's read blocks
	defer pw.Close()
	s := newSupervisor(nil, pr, io.Discard)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool, 1)
	go func() { done <- s.gate(ctx, "slow.example", "443") }()

	cancel()
	select {
	case admitted := <-done:
		if admitted {
			t.Error("a cancelled prompt must deny, not admit")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("gate did not return after ctx cancel; a blocked prompt wedged teardown")
	}
}
