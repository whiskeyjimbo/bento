package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

// supervise persists its interpreter guess and exports it into manifests, so a guess
// that differs from `bento profile`'s writes a manifest whose `bento run` is not the run
// the human approved here. The example cannot import the CLI to compare, so this table
// is the copy of its rules that has to be kept in step - it mirrors
// TestGuessInterpreterPrefersTheShebang in cmd/bento.
func TestGuessInterpreterAnswersAsTheCLIDoes(t *testing.T) {
	cases := []struct {
		name     string // file basename (the extension matters)
		body     string
		want     string
		wantArgs []string
	}{
		{"s.sh", "#!/bin/sh\n", "/bin/sh", nil},
		{"s.py", "#!/usr/bin/env -S python3 -u\nprint(1)\n", "python3", []string{"-u"}},
		{"c", "#!/usr/bin/env --split-string python3 -u\n", "python3", []string{"-u"}},
		{"d", "#!/usr/bin/env -S FOO=bar python3\n", "python3", nil},
		{"e", "#!/usr/bin/env python3\n", "python3", nil},

		// env options that take a separate word: without consuming it, the variable name
		// or directory reads as the interpreter.
		{"u1", "#!/usr/bin/env -S -u PATH python3 -u\n", "python3", []string{"-u"}},
		{"u2", "#!/usr/bin/env -S -C /tmp python3\n", "python3", nil},
		{"u3", "#!/usr/bin/env -S -a agent python3\n", "python3", nil},

		// -S can carry its payload attached. Skipping the whole word would drop the
		// interpreter and fall through to the extension, silently running under bash.
		{"S1.sh", "#!/usr/bin/env -Spython3 -u\n", "python3", []string{"-u"}},
		{"S2.sh", "#!/usr/bin/env --split-string=python3 -u\n", "python3", []string{"-u"}},
		{"S3", "#!/usr/bin/env -SFOO=bar python3\n", "python3", nil},
		{"S4.py", "#!/usr/bin/env --split-string=\n", "python3", nil},

		// Linux does not tokenize a shebang: everything after the interpreter is one
		// argument, which is why a multi-arg shebang has to go through `env -S`.
		{"g", "#!/bin/sh -eu\n", "/bin/sh", []string{"-eu"}},
		{"g2", "#!/bin/sh -e -u\n", "/bin/sh", []string{"-e -u"}},

		// No usable shebang: the extension is the fallback. `.sh` maps to bash as the CLI
		// does - the two disagreeing here is the bug this table exists to catch.
		{"h.py", "print(1)\n", "python3", nil},
		{"i.sh", "echo hi\n", "bash", nil},
		{"j.rb", "puts 1\n", "ruby", nil},
		{"k.py", "#!/usr/bin/env\n", "python3", nil},

		// Nothing to go on: a compiled binary is its own interpreter.
		{"bin", "not a script\n", "", nil},
	}
	for _, tc := range cases {
		p := filepath.Join(t.TempDir(), tc.name)
		if err := os.WriteFile(p, []byte(tc.body), 0o755); err != nil {
			t.Fatal(err)
		}
		got, args := guessInterpreter(p)
		if got != tc.want || !slices.Equal(args, tc.wantArgs) {
			t.Errorf("guessInterpreter(%q for %q) = %q %q, want %q %q",
				tc.body, tc.name, got, args, tc.want, tc.wantArgs)
		}
	}
}
