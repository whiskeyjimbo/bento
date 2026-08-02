package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// runDemoAgent runs demo/agent.sh with a stub curl that exits with the given code, and
// returns what the script printed.
//
// A stub rather than the real thing because the whole point is which hosts the script
// reaches for, and that must not depend on the developer's network - nor touch it. The
// script runs from a copy with its own vault beside it, since it writes out.log next to
// itself and the checked-in demo directory is not a scratch space.
func runDemoAgent(t *testing.T, curlExit int) string {
	t.Helper()
	root := t.TempDir()
	bin, demo, vault := filepath.Join(root, "bin"), filepath.Join(root, "demo"), filepath.Join(root, "vault")
	for _, d := range []string{bin, demo, vault} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	script, err := os.ReadFile("demo/agent.sh")
	if err != nil {
		t.Fatal(err)
	}
	stub := "#!/bin/sh\nprintf 200\nexit " + strconv.Itoa(curlExit) + "\n"
	for _, f := range []struct {
		path, body string
		mode       os.FileMode
	}{
		{filepath.Join(demo, "agent.sh"), string(script), 0o755},
		{filepath.Join(bin, "curl"), stub, 0o755},
		{filepath.Join(vault, "data.csv"), "a,b\n", 0o644},
		{filepath.Join(vault, "secret.txt"), "s\n", 0o644},
	} {
		if err := os.WriteFile(f.path, []byte(f.body), f.mode); err != nil {
			t.Fatal(err)
		}
	}

	cmd := exec.Command("sh", "agent.sh")
	cmd.Dir = demo
	// The stub goes first but the rest of PATH is kept, so cat still resolves.
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("agent.sh: %v\n%s", err, out)
	}
	return string(out)
}

// The demo's live-gate act depends on agent.sh reaching a host the trial never recorded.
// That only holds while the follow-up fetch stays inside the success branch: the trial is
// default-deny, so its example.com fetch fails and the follow-up is never attempted, which
// is the only reason the host is still undeclared when the enforced run gates it. Hoist
// that fetch out of the branch and the README's Act 2 goes back to documenting a prompt
// the demo cannot produce.
func TestDemoLearnsTheGatedHostOnlyFromASuccessfulFetch(t *testing.T) {
	const learned = "example.org"

	denied := runDemoAgent(t, 1)
	if strings.Contains(denied, learned) {
		t.Errorf("with every fetch refused - the trial's case - agent.sh must not reach %s;\ngot:\n%s", learned, denied)
	}

	allowed := runDemoAgent(t, 0)
	if !strings.Contains(allowed, learned) {
		t.Errorf("with fetches succeeding - the enforced run's case - agent.sh must reach %s;\ngot:\n%s", learned, allowed)
	}
}
