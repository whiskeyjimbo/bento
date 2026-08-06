package main

import (
	"os"
	"testing"
)

// /dev/null is a character device but not a terminal. profiling's interactive branch
// prompts for consent and mounts real credential content for the answers, so under
// systemd's StandardInput=null, cron, or setsid - where /dev/null is stdin and no
// human is there to answer - it must not be taken.
func TestIsTerminalRejectsDevNull(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isTerminal(f) {
		t.Errorf("%s must not read as a terminal", os.DevNull)
	}
}

func TestIsTerminalAcceptsTTY(t *testing.T) {
	f, err := os.OpenFile("/dev/tty", os.O_RDONLY, 0)
	if err != nil {
		t.Skipf("no controlling terminal: %v", err)
	}
	defer f.Close()
	if !isTerminal(f) {
		t.Error("/dev/tty must read as a terminal")
	}
}
