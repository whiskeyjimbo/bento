//go:build linux

package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/manifest"
	"github.com/whiskeyjimbo/bento/policy"
)

// runProfileInteractively drives the profile command through the convergence loop with a
// canned answer stream in place of the terminal, and returns its stdout and stderr. The
// answers repeat forever rather than coming from a fixed list: a stream that runs out
// reads as EOF, which converge takes as [q]uit, so a test that supplied one line too few
// would stop the session early and pass for a reason it never asserted.
//
// Process-wide while it runs - the profilePrompts var and both standard streams - so no
// test in this package may call t.Parallel. Nothing here does; the same holds for the
// homeContainers seam in clamp.go.
func runProfileInteractively(t *testing.T, answer string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	answers := make(chan string)
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		for {
			select {
			case answers <- answer:
			case <-stop:
				return
			}
		}
	}()

	savedPrompts := profilePrompts
	profilePrompts = func() (<-chan string, bool, func()) { return answers, true, func() {} }
	t.Cleanup(func() { profilePrompts = savedPrompts })

	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	// Drained while the command runs: a profiling session writes more than a pipe holds,
	// and reading afterwards would deadlock it mid-round.
	outC, errC := readAll(outR), readAll(errR)

	cmd := newProfileCmd()
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	runErr := func() error {
		savedOut, savedErr := os.Stdout, os.Stderr
		defer func() {
			os.Stdout, os.Stderr = savedOut, savedErr
			outW.Close()
			errW.Close()
		}()
		os.Stdout, os.Stderr = outW, errW
		return cmd.Execute()
	}()
	return <-outC, <-errC, runErr
}

func readAll(r *os.File) <-chan string {
	c := make(chan string, 1)
	go func() {
		defer r.Close()
		b, _ := io.ReadAll(r)
		c <- string(b)
	}()
	return c
}

// A refusal at the prompt has to hold in the artifact, not only in the mount. The merge
// unions in whatever the file at --out granted, approved or not, so a path the user just
// declined comes straight back through it - and the kept lists, whose job is to say what
// the file carries that this run did not show, must not name it either.
//
// End to end against the command rather than the helpers: replaying mergePolicies and
// dropDeclined by hand leaves a regression that stops calling either one green.
func TestProfileHoldsADeclinedPathAgainstTheExistingManifest(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	vault := t.TempDir() // outside the script's own directory, which profiling grants by default
	secret := filepath.Join(vault, "secret.txt")
	if err := os.WriteFile(secret, []byte("hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "run.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ncat "+secret+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// unattempted sits beside the manifest so relocatable rewrites its spelling on the way
	// out. That is what makes the kept-list assertion sharp: narrowing the list against the
	// rewritten policy instead of the absolute one silently drops a grant the file has.
	unattempted := filepath.Join(dir, "reference")
	if err := os.Mkdir(unattempted, 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "bento.yaml")
	existing, err := manifest.Marshal(
		&policy.Policy{Entrypoint: script, Interpreter: "/bin/sh", Read: []string{secret, unattempted}},
		manifest.Provenance{GeneratedBy: "a hand edit"}, // unapproved: the merge takes it anyway
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, existing, 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, _ := runProfileInteractively(t, "n\n", "--json", "--out", out, script)

	written, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(written), secret) {
		t.Errorf("the declined path is back in the written manifest:\n%s\n--- session:\n%s", written, stderr)
	}

	var env struct {
		Merged struct {
			KeptRead []string `json:"kept_read"`
		} `json:"merged"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("--json envelope: %v\n%s", err, stdout)
	}
	if slices.Contains(env.Merged.KeptRead, secret) {
		t.Errorf("merged.kept_read names the declined path, which the manifest has not got: %v", env.Merged.KeptRead)
	}
	// The other half: what the file really does carry beyond this run must still be named,
	// or the merge notice under-reports the half the user is not being shown.
	if !slices.Contains(env.Merged.KeptRead, unattempted) {
		t.Errorf("merged.kept_read = %v, want the grant only the existing file carries (%s)", env.Merged.KeptRead, unattempted)
	}
}

// seedGrants checks the approval before manifest.Resolve for the reason the run does: the
// fingerprint is over the manifest as written, so resolving its relative grants first makes
// a valid stamp read stale and every approved manifest using one stops being resumed from.
// Nothing else fails when the two are swapped - the session just silently starts fresh.
func TestProfileResumesFromAnApprovedManifestWithARelativeGrant(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	script := filepath.Join(dir, "run.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Relative, as writeRunnableManifest's grants are and for the same reason: an absolute
	// grant survives Resolve unchanged, so the swap would leave the fingerprint intact and
	// this test would pass either way.
	p := &policy.Policy{Entrypoint: script, Interpreter: "/bin/sh", Read: []string{"./data"}}
	approved, err := manifest.Marshal(p, manifest.Provenance{Approves: p.Fingerprint()})
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "bento.yaml")
	if err := os.WriteFile(out, approved, 0o644); err != nil {
		t.Fatal(err)
	}

	_, stderr, _ := runProfileInteractively(t, "n\n", "--out", out, script)

	if strings.Contains(stderr, "is not approved") {
		t.Errorf("an approved manifest with a relative grant must be resumed from, not read as stale:\n%s", stderr)
	}
	if want := "mounting approved read " + filepath.Join(dir, "data"); !strings.Contains(stderr, want) {
		t.Errorf("the session must say it resumed from the approved grant (%q):\n%s", want, stderr)
	}
}
