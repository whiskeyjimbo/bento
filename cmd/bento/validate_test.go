package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/gate"
	"github.com/whiskeyjimbo/bento/manifest"
	"github.com/whiskeyjimbo/bento/policy"
)

// validate must surface resource limits in both the human summary and --json, so a
// reviewer (and CI) can see the memory/cpu/pids ceilings before approving.
func TestValidateShowsLimits(t *testing.T) {
	p := &policy.Policy{Entrypoint: "./x", Limits: policy.Limits{Memory: "128M", CPU: "50%", PIDs: 64}}

	var buf bytes.Buffer
	writePolicySummary(&buf, "m.yaml", p, nil, nil, true)
	out := buf.String()
	for _, want := range []string{"limits:", "memory 128M", "cpu 50%", "pids 64"} {
		if !strings.Contains(out, want) {
			t.Errorf("human summary missing %q; got:\n%s", want, out)
		}
	}

	j := toPolicyJSON(p, nil, nil)
	if j.Limits == nil || j.Limits.Memory != "128M" || j.Limits.CPU != "50%" || j.Limits.PIDs != 64 {
		t.Errorf("JSON limits = %+v, want memory/cpu/pids populated", j.Limits)
	}

	// A no-limits policy must omit the limits entirely (no empty struct in JSON).
	if toPolicyJSON(&policy.Policy{Entrypoint: "./x"}, nil, nil).Limits != nil {
		t.Error("a no-limits policy must not emit a limits object in JSON")
	}
}

// runCapturingStdout executes cmd with args while os.Stdout is redirected, and returns
// what the command wrote there. The commands print to os.Stdout directly rather than
// through cobra's writer, so exercising RunE - which is where the --json/--strict
// interaction lives - means capturing the real file.
func runCapturingStdout(t *testing.T, cmd *cobra.Command, args ...string) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	// Deferred because Execute does not always return: a panicking RunE would otherwise
	// leave os.Stdout hijacked for the rest of the package. In its own scope so the read
	// below still runs with the write end closed.
	runErr := func() error {
		saved := os.Stdout
		defer func() {
			os.Stdout = saved
			w.Close()
		}()
		os.Stdout = w
		return cmd.Execute()
	}()

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out), runErr
}

// Pinned because the damage is silent: nothing fails, the output simply stops. The panic
// has to reach the caller too, since recovering it inside the helper would restore stdout
// and hide the crash.
func TestRunCapturingStdoutRestoresOnAPanic(t *testing.T) {
	before := os.Stdout
	cmd := &cobra.Command{Use: "boom", RunE: func(*cobra.Command, []string) error { panic("boom") }}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("the panic must reach the caller; swallowing one hides the crash")
			}
		}()
		_, _ = runCapturingStdout(t, cmd)
	}()
	if os.Stdout != before {
		t.Error("os.Stdout not restored after a panicking RunE")
	}
}

func writeManifest(t *testing.T, p *policy.Policy, prov manifest.Provenance) string {
	t.Helper()
	data, err := manifest.Marshal(p, prov)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "m.yaml")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	// validate now reports whether the host can start what the manifest names, so a
	// fixture whose entrypoint is a bare name nobody created reads as unrunnable and
	// fails --strict for a reason no test here is about. Created beside the manifest,
	// where a relative entrypoint resolves.
	if !filepath.IsAbs(p.Entrypoint) {
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(p.Entrypoint)), nil, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// --strict is the documented CI drift gate, and a machine gate reads --json. The two
// must not disagree: --json --strict on a stale approval has to fail AND still leave a
// parseable envelope naming the state. Executing RunE is the point - the
// bug lived in the early `return writeJSON(...)`, which a direct reportApproval test
// never reached.
func TestValidateJSONHonorsStrict(t *testing.T) {
	cases := map[string]struct {
		approves     string
		approve      bool // stamp it through `bento approve`, as a real current manifest is
		wantApproval string
		wantErr      bool
	}{
		"stale":     {approves: "a-stale-fingerprint", wantApproval: "stale", wantErr: true},
		"unstamped": {wantApproval: "unapproved", wantErr: true},
		"current":   {approve: true, wantApproval: "current"},
	}
	p := &policy.Policy{Entrypoint: "./x", Read: []string{"/data"}}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeManifest(t, p, manifest.Provenance{Approves: tc.approves})
			if tc.approve {
				if _, err := runCapturingStdout(t, newApproveCmd(), path, "--yes"); err != nil {
					t.Fatalf("approve: %v", err)
				}
			}
			out, err := runCapturingStdout(t, newValidateCmd(), "--json", "--strict", path)
			if tc.wantErr && err == nil {
				t.Error("--json --strict must fail on a non-current approval")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("--json --strict must pass on a current approval; got %v", err)
			}
			var got policyJSON
			if err := json.Unmarshal([]byte(out), &got); err != nil {
				t.Fatalf("stdout is not valid JSON (%v); got:\n%s", err, out)
			}
			if got.Approval != tc.wantApproval {
				t.Errorf("approval = %q, want %q", got.Approval, tc.wantApproval)
			}
		})
	}
}

// The summary shows what a grant lands on so a reviewer can see which directory `~`
// or a relative path means - and showing it must not change the verdict. Resolve
// rewrites the slices in place, so resolving through a shallow struct copy would
// write absolute paths into the very policy the approval is then checked against,
// reporting every approved manifest as STALE. The approval assertion is what catches
// that; the display assertion alone passes with the bug present.
func TestValidateShowsResolvedGrantsWithoutDisturbingApproval(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	p := &policy.Policy{Entrypoint: "./x", Read: []string{"~", "./data", "/etc/hosts"}}
	path := writeManifest(t, p, manifest.Provenance{})
	if _, err := runCapturingStdout(t, newApproveCmd(), path, "--yes"); err != nil {
		t.Fatalf("approve: %v", err)
	}

	out, err := runCapturingStdout(t, newValidateCmd(), "--strict", path)
	if err != nil {
		t.Fatalf("validate --strict on a freshly approved manifest: %v\n%s", err, out)
	}
	if !strings.Contains(out, "approval:     current") {
		t.Errorf("approval must stay current when the summary resolves grants; got:\n%s", out)
	}
	// The literal spelling stays, since that is what the fingerprint attests.
	if !strings.Contains(out, "read:         [~ ./data /etc/hosts]") {
		t.Errorf("summary must show the grants as written; got:\n%s", out)
	}
	for _, want := range []string{"on this host: " + strconv.Quote(home), "on this host: " + strconv.Quote(filepath.Join(filepath.Dir(path), "data"))} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q; got:\n%s", want, out)
		}
	}
	// An absolute grant already says where it lands, so it gets no second line.
	if strings.Contains(out, `on this host: "/etc/hosts"`) {
		t.Errorf("an absolute grant must not be repeated; got:\n%s", out)
	}
}

// A symlink answers "what does this grant reach" differently from the name, and the
// reviewer approves from this output. A ~ grant whose .ssh is a link elsewhere reads as
// a harmless path under $HOME unless the link is followed here - the run says so, but by
// then the manifest is approved.
func TestValidateResolvesSymlinkedGrants(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(home, ".ssh")); err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{Entrypoint: "./x", Read: []string{"~/.ssh"}}
	out, err := runCapturingStdout(t, newValidateCmd(), writeManifest(t, p, manifest.Provenance{}))
	if err != nil {
		t.Fatalf("validate: %v\n%s", err, out)
	}
	if !strings.Contains(out, "on this host: "+strconv.Quote(target)) {
		t.Errorf("summary must name what the symlinked grant reaches (%q); got:\n%s", target, out)
	}
}

// Following symlinks means the printed target is a name the filesystem chose, not one the
// manifest did. A directory named with an embedded newline would otherwise print as two
// lines, letting a host path forge what reads like another line of bento's own summary.
func TestValidateQuotesResolvedGrants(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	target := filepath.Join(t.TempDir(), "real\nnetwork:      forged-by-a-directory-name")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Skipf("this filesystem rejects a newline in a directory name: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(home, ".ssh")); err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{Entrypoint: "./x", Read: []string{"~/.ssh"}}
	out, err := runCapturingStdout(t, newValidateCmd(), writeManifest(t, p, manifest.Provenance{}))
	if err != nil {
		t.Fatalf("validate: %v\n%s", err, out)
	}
	if !strings.Contains(out, "on this host: "+strconv.Quote(target)) {
		t.Errorf("summary must name the resolved target, quoted; got:\n%s", out)
	}
	if strings.Contains(out, "\nnetwork:      forged-by-a-directory-name") {
		t.Errorf("a host directory name must not be able to forge a summary line; got:\n%s", out)
	}
}

// The CI gate reads --json, so the envelope has to answer what the human summary does.
// read/write stay literal - that is what the fingerprint attests, and a consumer diffing
// them across hosts must not see them move - so what the grant reaches is a field of its
// own, present only where the two differ.
func TestValidateJSONNamesWhatGrantsReach(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(home, ".ssh")); err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{Entrypoint: "./x", Read: []string{"~/.ssh", "/etc/hosts"}}
	out, err := runCapturingStdout(t, newValidateCmd(), "--json", writeManifest(t, p, manifest.Provenance{}))
	if err != nil {
		t.Fatalf("validate --json: %v\n%s", err, out)
	}
	var got policyJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("stdout is not valid JSON (%v); got:\n%s", err, out)
	}

	if !slices.Equal(got.Read, p.Read) {
		t.Errorf("read = %v, want the manifest's own spelling %v", got.Read, p.Read)
	}
	want := []grantTargetJSON{{Path: "~/.ssh", OnHost: target}}
	if !slices.Equal(got.ResolvedRead, want) {
		t.Errorf("resolved_read = %v, want %v - the absolute grant names its own target and needs no entry", got.ResolvedRead, want)
	}
}

// Passing the script where the manifest belongs is the highest-frequency first-day
// mistake, and the parser's answer quotes the script's own first lines - which reads as
// a problem with the file's contents rather than with which file was named. Every
// command that takes a manifest loads through loadDocument, so the replacement is
// checked there.
func TestLoadDocumentNamesTheManifestForAScript(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "tool.py")
	if err := os.WriteFile(script, []byte("#!/usr/bin/env python3\nprint('hi')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// No sibling manifest yet: the answer has to be how to draft one, not a file that
	// is not there.
	_, _, err := loadDocument(script)
	if err == nil || !strings.Contains(err.Error(), "looks like a script, not a manifest") {
		t.Fatalf("err = %v, want it to say the file is a script", err)
	}
	if !strings.Contains(err.Error(), "bento profile") {
		t.Errorf("err = %v, want the draft command when no manifest sits beside it", err)
	}

	sibling := script + ".manifest.yaml"
	if err := os.WriteFile(sibling, []byte("entrypoint: ./tool.py\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err = loadDocument(script)
	if err == nil || !strings.Contains(err.Error(), sibling) {
		t.Errorf("err = %v, want it to name %s once that manifest exists", err, sibling)
	}

	// A shebang with no extension bento knows is the other signal.
	shell := filepath.Join(dir, "tool")
	if err := os.WriteFile(shell, []byte("#!/bin/sh\nexit 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadDocument(shell); err == nil || !strings.Contains(err.Error(), "looks like a script") {
		t.Errorf("err = %v, want a shebang alone to be enough", err)
	}

	// A manifest that is merely malformed keeps the parser's diagnosis, which says
	// where the YAML went wrong.
	broken := filepath.Join(dir, "m.yaml")
	if err := os.WriteFile(broken, []byte("entrypoint: ./x\n  read: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadDocument(broken); err == nil || strings.Contains(err.Error(), "looks like a script") {
		t.Errorf("err = %v, want the parser's own error for a malformed manifest", err)
	}
}

// A manifest that does not pass HOME through still gets one injected, pointing at the
// sandbox tmpfs rather than the caller's home. Nothing else at the CLI says so, and a
// script using the ordinary ~/... idiom otherwise fails on a path its author never wrote.
func TestValidateStatesTheSandboxHome(t *testing.T) {
	var buf bytes.Buffer
	writePolicySummary(&buf, "m.yaml", &policy.Policy{Entrypoint: "./x", Env: []string{"LANG"}}, nil, nil, true)
	if out := buf.String(); !strings.Contains(out, enforce.SandboxHome) || !strings.Contains(out, "HOME is not passed through") {
		t.Errorf("summary must say what HOME becomes inside the sandbox; got:\n%s", out)
	}

	// Passed through, so ~ means what the author expects and the note would be wrong -
	// but the value still has to be named, since it is what decides whether a ~ the
	// script expands lands on a granted path, and the manifest carries only the name.
	t.Setenv("HOME", "/home/someone")
	buf.Reset()
	writePolicySummary(&buf, "m.yaml", &policy.Policy{Entrypoint: "./x", Env: []string{"HOME"}}, nil, nil, true)
	out := buf.String()
	if strings.Contains(out, "HOME is not passed through") {
		t.Errorf("a manifest allowlisting HOME must not be told it was remapped; got:\n%s", out)
	}
	if !strings.Contains(out, `HOME inside the sandbox: "/home/someone"`) {
		t.Errorf("summary must name the HOME the script will see; got:\n%s", out)
	}

	// An allowlisted name the host never set is passed through as nothing, not as an
	// empty string - so the sandbox lands on the same remapped home an unlisted HOME
	// gets, which an env: list naming HOME gives the reader no reason to expect.
	p := &policy.Policy{Entrypoint: "./x", Env: []string{"HOME"}}
	env, unset, err := enforce.ResolveEnv(p, nil, func(string) (string, bool) { return "", false })
	if err != nil || len(env) != 0 || len(unset) != 1 {
		t.Fatalf("ResolveEnv(unset HOME) = %v, %v, %v; want it reported unset", env, unset, err)
	}
	os.Unsetenv("HOME")
	buf.Reset()
	writePolicySummary(&buf, "m.yaml", p, nil, nil, true)
	if got := buf.String(); !strings.Contains(got, "allowlisted but unset on this host") ||
		!strings.Contains(got, enforce.SandboxHome) {
		t.Errorf("an allowlisted-but-unset HOME must say so and name the remapped home; got:\n%s", got)
	}
}

// The blocked-hosts record is provenance the profiling run wrote, and until now approve
// was its only reader - so profile -> run, and validate's own summary, never said that a
// rule in the manifest names a destination bento itself refuses.
func TestValidateNotesRulesCoveringABlockedHost(t *testing.T) {
	p := &policy.Policy{
		Entrypoint: "./x",
		Network: []policy.NetworkRule{
			{Host: ".internal", Port: "80"},
			{Host: "example.com", Port: "443"},
		},
	}

	var buf bytes.Buffer
	writePolicySummary(&buf, "m.yaml", p, nil, []string{"metadata.internal:80"}, true)
	out := buf.String()
	// Matched through the wildcard, not by spelling: a rule that covers the refusal
	// without naming it is the one the reader is least able to see for themselves.
	if !strings.Contains(out, `".internal" port "80"`) || !strings.Contains(out, "egress guard refused") {
		t.Errorf("the summary must mark the rule covering the refusal; got:\n%s", out)
	}
	if strings.Contains(out, `"example.com"`) && strings.Contains(out, `note: the profiling run reached a destination "example.com"`) {
		t.Errorf("a rule covering no refusal must not be marked; got:\n%s", out)
	}

	// approve prints the same rules through writeApprovalCallouts, where the reader is
	// deciding, so it passes nil rather than saying it twice on one screen.
	var quiet bytes.Buffer
	writePolicySummary(&quiet, "m.yaml", p, nil, nil, true)
	if strings.Contains(quiet.String(), "egress guard refused") {
		t.Errorf("with no blocked hosts recorded the summary must stay silent; got:\n%s", quiet.String())
	}
}

// The summary's closing sentence asserts the credential shields hold over everything
// above it, and it is the last line the approve prompt prints before asking. A grant
// that lifts one has to be named beside the grant AND the footer qualified, or the
// review gate states the opposite of what it is about to stamp.
func TestValidateNamesAnExplicitShieldGrant(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	p := &policy.Policy{Entrypoint: "./x", Read: []string{"~/.ssh"}}
	out, err := runCapturingStdout(t, newValidateCmd(), writeManifest(t, p, manifest.Provenance{}))
	if err != nil {
		t.Fatalf("validate: %v\n%s", err, out)
	}
	for _, want := range []string{"credential store bento shields on every run", "read-only exception", "EXCEPT"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q; got:\n%s", want, out)
		}
	}
	// A shield over a history store is described as one. The note is what a reviewer
	// reads while deciding to approve, and stretching "credential store" over the paths
	// that hold no key material is what drains it for the grants where it is the truth.
	hist, err := runCapturingStdout(t, newValidateCmd(), writeManifest(t, &policy.Policy{Entrypoint: "./x", Read: []string{"~/.local/state/nvim"}}, manifest.Provenance{}))
	if err != nil {
		t.Fatalf("validate: %v\n%s", err, hist)
	}
	if !strings.Contains(hist, "history store bento shields on every run") || strings.Contains(hist, "credential store bento shields") {
		t.Errorf("a history store must be named as one, not as a credential store; got:\n%s", hist)
	}
	if strings.Contains(out, "shielded even if a path above would otherwise expose them") {
		t.Errorf("the unqualified footer contradicts the grant above it; got:\n%s", out)
	}

	// A policy that lifts no shield keeps the plain footer and says nothing extra.
	plain, err := runCapturingStdout(t, newValidateCmd(), writeManifest(t, &policy.Policy{Entrypoint: "./x", Read: []string{"~"}}, manifest.Provenance{}))
	if err != nil {
		t.Fatalf("validate: %v\n%s", err, plain)
	}
	if !strings.Contains(plain, "shielded even if a path above would otherwise expose them") {
		t.Errorf("a policy lifting no shield must keep the plain footer; got:\n%s", plain)
	}
	// Keyed on the part every bucket's note shares, not on the credential spelling: a
	// note about a history store or a host-startup path is the same wrong answer here.
	if strings.Contains(plain, "bento shields on every run") {
		t.Errorf("a grant that merely contains shields is not an opt-in; got:\n%s", plain)
	}
}

// --json --strict is the CI shape, and it was the one reader that saw neither the
// blocked-destination note nor the shield opt-in the human summary prints.
func TestValidateJSONCarriesBlockedHostsAndShieldGrants(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	p := &policy.Policy{
		Entrypoint: "./x",
		Read:       []string{"~/.ssh"},
		Network:    []policy.NetworkRule{{Host: ".internal", Port: "80"}, {Host: "example.com", Port: "443"}},
	}
	prov := manifest.Provenance{BlockedHosts: []string{"metadata.internal:80", "not-a-host-port"}}
	out, err := runCapturingStdout(t, newValidateCmd(), writeManifest(t, p, prov), "--json")
	if err != nil {
		t.Fatalf("validate --json: %v\n%s", err, out)
	}
	var got policyJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, out)
	}
	if !slices.Equal(got.NetworkBlocked, []string{".internal:80"}) {
		t.Errorf("network_blocked = %v, want only the rule covering the refusal", got.NetworkBlocked)
	}
	if !slices.Equal(got.NetworkBlockedUnreadable, []string{"not-a-host-port"}) {
		t.Errorf("network_blocked_unreadable = %v, want the key nothing can be asked about", got.NetworkBlockedUnreadable)
	}
	if !slices.Equal(got.ShieldedGrants, []shieldedGrantJSON{{Path: filepath.Join(home, ".ssh"), Holds: "credentials"}}) {
		t.Errorf("shielded_grants = %v, want the granted shield named as a credential store", got.ShieldedGrants)
	}
}

// validate --strict is the pre-merge gate, and it used to pass a manifest run refuses at
// its first step: an entrypoint that is not there, or an interpreter nobody has. Both
// modes must fail, since a machine gate reads --json and would otherwise see a green
// manifest that cannot execute.
func TestValidateStrictFailsOnAManifestThatCannotRun(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/nope/missing.py", Interpreter: "pythno3"}
	path := writeManifest(t, p, manifest.Provenance{})
	if _, err := runCapturingStdout(t, newApproveCmd(), path, "--yes"); err != nil {
		t.Fatalf("approve: %v", err)
	}

	out, err := runCapturingStdout(t, newValidateCmd(), "--strict", path)
	if err == nil {
		t.Fatalf("--strict must fail on a manifest this host cannot start; got:\n%s", out)
	}
	for _, want := range []string{"runnable:     NO", `entrypoint "/nope/missing.py"`, `interpreter "pythno3" not found`} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q; got:\n%s", want, out)
		}
	}

	jsonOut, err := runCapturingStdout(t, newValidateCmd(), "--json", "--strict", path)
	if err == nil {
		t.Errorf("--json --strict must fail too; got:\n%s", jsonOut)
	}
	var got policyJSON
	if err := json.Unmarshal([]byte(jsonOut), &got); err != nil {
		t.Fatalf("stdout is not valid JSON (%v); got:\n%s", err, jsonOut)
	}
	if got.Runnable == nil || *got.Runnable {
		t.Errorf("runnable = %v, want false", got.Runnable)
	}
	if len(got.RunnableProblems) != 2 {
		t.Errorf("runnable_problems = %v, want the entrypoint and the interpreter", got.RunnableProblems)
	}
}

// A read grant naming nothing here is the softer case: it may name a path the script
// creates, so it is a note rather than a failure - but it must not be silent, because the
// sandbox denies an unmatched grant without saying why.
func TestValidateNotesAReadGrantThatNamesNothingWithoutFailing(t *testing.T) {
	p := &policy.Policy{Entrypoint: "./x", Read: []string{"/nope/nothere"}}
	path := writeManifest(t, p, manifest.Provenance{})
	if _, err := runCapturingStdout(t, newApproveCmd(), path, "--yes"); err != nil {
		t.Fatalf("approve: %v", err)
	}

	out, err := runCapturingStdout(t, newValidateCmd(), "--strict", path)
	if err != nil {
		t.Fatalf("a grant naming nothing must not fail --strict: %v\n%s", err, out)
	}
	if !strings.Contains(out, "runnable:     yes") {
		t.Errorf("an existing entrypoint must still read as runnable; got:\n%s", out)
	}
	if !strings.Contains(out, `"/nope/nothere"`) || !strings.Contains(out, "names nothing on this host") {
		t.Errorf("summary must note the grant that matches nothing; got:\n%s", out)
	}
}

// A write grant that already exists as a file is refused by the backend before the script
// starts, so validate has to say so where the manifest is being reviewed - that is the
// gate's whole point - and --strict has to fail on it.
func TestValidateStrictFailsOnAWriteGrantThatIsAFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "already-a-file")
	if err := os.WriteFile(target, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: "./x", Write: []string{target}}
	path := writeManifest(t, p, manifest.Provenance{})
	assertApproveRefuses(t, path)

	out, err := runCapturingStdout(t, newValidateCmd(), "--strict", path)
	if err == nil {
		t.Fatalf("--strict must fail on a write grant run refuses; got:\n%s", out)
	}
	if !strings.Contains(out, "grants:       NO") || !strings.Contains(out, "grant its parent directory instead") {
		t.Errorf("summary must refuse the file grant in run's words; got:\n%s", out)
	}
	// The entrypoint resolves, so runnable: - "this host cannot start what the manifest
	// names" - is not what is wrong here, and saying so sends the reader hunting for it.
	if !strings.Contains(out, "runnable:     yes") {
		t.Errorf("a refused grant is not an unstartable manifest; got:\n%s", out)
	}
	// Said once. It is a forty-word paragraph naming paths, and the verdict counts it.
	if n := strings.Count(out, "grant its parent directory instead"); n != 1 {
		t.Errorf("the refusal printed %d times, want 1; got:\n%s", n, out)
	}

	jsonOut, err := runCapturingStdout(t, newValidateCmd(), "--json", "--strict", path)
	if err == nil {
		t.Errorf("--json --strict must fail too; got:\n%s", jsonOut)
	}
	var got policyJSON
	if err := json.Unmarshal([]byte(jsonOut), &got); err != nil {
		t.Fatalf("stdout is not valid JSON (%v); got:\n%s", err, jsonOut)
	}
	if got.Runnable == nil || !*got.Runnable {
		t.Errorf("runnable = %v, want true - nothing here is unstartable", got.Runnable)
	}
	if len(got.RefusedGrants) != 1 || !strings.Contains(got.RefusedGrants[0], target) {
		t.Errorf("refused_grants = %v, want the file write grant %q", got.RefusedGrants, target)
	}
}

// A gate reading the envelope has nothing else to tell a host with no runtime shield from
// a healthy one: the rule set, the count and the exit code are all identical. So the note
// the human output carries is a field too, and it is absent on an ordinary host rather
// than empty-stringed.
func TestValidateJSONCarriesAnUnshieldableRuntimeDir(t *testing.T) {
	path := writeManifest(t, &policy.Policy{Entrypoint: "./x"}, manifest.Provenance{})

	t.Setenv("XDG_RUNTIME_DIR", "run/user/1000")
	out, err := runCapturingStdout(t, newValidateCmd(), "--json", path)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	var got policyJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("stdout is not valid JSON (%v); got:\n%s", err, out)
	}
	if got.UnshieldableRuntimeDir != "run/user/1000" {
		t.Errorf("unshieldable_runtime_dir = %q, want the raw relative value", got.UnshieldableRuntimeDir)
	}

	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	out, err = runCapturingStdout(t, newValidateCmd(), "--json", path)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if strings.Contains(out, "unshieldable_runtime_dir") {
		t.Errorf("a shieldable runtime dir must leave the field absent; got:\n%s", out)
	}
}

// The runtime dir's sibling, and the same argument: a relocation the emitters dropped
// leaves the store unshielded while the rule set stays byte-identical to a host that set
// nothing, so a CI gate reading the envelope cannot see it at all. The human output says
// it; --json is how a machine reads doctor.
func TestValidateJSONCarriesTheDroppedRelocations(t *testing.T) {
	path := writeManifest(t, &policy.Policy{Entrypoint: "./x"}, manifest.Provenance{})

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home anchor to make unshieldable: %v", err)
	}
	t.Setenv("GNUPGHOME", home)
	out, err := runCapturingStdout(t, newValidateCmd(), "--json", path)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	var got policyJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("stdout is not valid JSON (%v); got:\n%s", err, out)
	}
	if got.UnshieldableRelocations["GNUPGHOME"] != home {
		t.Errorf("unshieldable_relocations = %v, want GNUPGHOME -> %q", got.UnshieldableRelocations, home)
	}

	t.Setenv("GNUPGHOME", t.TempDir())
	out, err = runCapturingStdout(t, newValidateCmd(), "--json", path)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if strings.Contains(out, "unshieldable_relocations") {
		t.Errorf("a shieldable relocation must leave the field absent; got:\n%s", out)
	}
}

// A write grant naming nothing yet cannot be refused - run creates it, and a directory may
// be exactly what was meant. But run creates a DIRECTORY, so a grant spelled like a file
// silently produces `out.json/` on the host and the script's file never appears. A note,
// like a read grant that names nothing, and never a --strict failure: it is a guess about
// a naming convention.
func TestValidateNotesAWriteGrantSpelledLikeAFileWithoutFailing(t *testing.T) {
	dir := t.TempDir()
	fileish := filepath.Join(dir, "build_output", "file.txt")
	dotfile := filepath.Join(dir, "state", ".env")
	p := &policy.Policy{Entrypoint: "./x", Write: []string{fileish, dotfile}}
	path := writeManifest(t, p, manifest.Provenance{})
	if _, err := runCapturingStdout(t, newApproveCmd(), path, "--yes"); err != nil {
		t.Fatalf("approve: %v", err)
	}

	out, err := runCapturingStdout(t, newValidateCmd(), "--strict", path)
	if err != nil {
		t.Fatalf("a grant spelled like a file must not fail --strict: %v\n%s", err, out)
	}
	if !strings.Contains(out, "runnable:     yes") {
		t.Errorf("a file-ish write grant is a note, not a verdict; got:\n%s", out)
	}
	if !strings.Contains(out, strconv.Quote(fileish)) || !strings.Contains(out, "write grants name") {
		t.Errorf("summary must note the file-ish write grant; got:\n%s", out)
	}
	// A name that is all extension is an ordinary dotfile directory, not a signal.
	if strings.Contains(out, strconv.Quote(dotfile)) {
		t.Errorf("a dotfile-named grant must not be flagged; got:\n%s", out)
	}
	if !strings.Contains(out, "approval:     current") {
		t.Errorf("a note must not disturb the approval; got:\n%s", out)
	}

	jsonOut, err := runCapturingStdout(t, newValidateCmd(), "--json", "--strict", path)
	if err != nil {
		t.Fatalf("--json --strict must not fail either: %v\n%s", err, jsonOut)
	}
	var got policyJSON
	if err := json.Unmarshal([]byte(jsonOut), &got); err != nil {
		t.Fatalf("stdout is not valid JSON (%v); got:\n%s", err, jsonOut)
	}
	if got.Runnable == nil || !*got.Runnable {
		t.Errorf("runnable = %v, want true", got.Runnable)
	}
	if len(got.FileishWriteGrants) != 1 || got.FileishWriteGrants[0] != fileish {
		t.Errorf("fileish_write_grants = %v, want just %q", got.FileishWriteGrants, fileish)
	}
}

// The note is about a grant that names nothing yet. A directory that already exists under
// a version-suffixed name is the host answering the question, and there is nothing left to
// guess at - the heuristic must not talk over it.
func TestValidateDoesNotNoteAWriteGrantThatIsAlreadyADirectory(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "python3.11")
	if err := os.MkdirAll(existing, 0o700); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: "./x", Write: []string{existing}}
	out, err := runCapturingStdout(t, newValidateCmd(), writeManifest(t, p, manifest.Provenance{}))
	if err != nil {
		t.Fatalf("validate: %v\n%s", err, out)
	}
	if strings.Contains(out, "spelled like a file") {
		t.Errorf("an existing directory must not be noted; got:\n%s", out)
	}
}

// `write: [/some/file.txt/]` stats as ENOTDIR rather than as a file or as absent, so it
// fell through both the problem and the note while run refused it all the same - the exact
// gate-passes-what-run-refuses gap this is here to close.
func TestValidateRefusesAWriteGrantNamingAFileWithATrailingSlash(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "already-a-file")
	if err := os.WriteFile(target, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Entrypoint: "./x", Write: []string{target + "/"}}
	path := writeManifest(t, p, manifest.Provenance{})
	assertApproveRefuses(t, path)

	out, err := runCapturingStdout(t, newValidateCmd(), "--strict", path)
	if err == nil {
		t.Fatalf("--strict must fail on a file grant however it is spelled; got:\n%s", out)
	}
	if !strings.Contains(out, "grant its parent directory instead") {
		t.Errorf("summary must refuse the trailing-slash file grant; got:\n%s", out)
	}
}

// A grant whose symlinks loop is refused by the backend for either kind - bwrap tolerates
// a missing bind source, not a looping one - so validate has to predict it for either kind
// too, in the same sentence. Read grants get it as well as writes: a looped read reported
// as a mere note while a looped write failed --strict would be validate disagreeing with
// itself about one host fact.
func TestValidateStrictFailsOnALoopingGrantOfEitherKind(t *testing.T) {
	for _, kind := range []string{"read", "write"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			loop := filepath.Join(dir, "loop")
			if err := os.Symlink(loop, loop); err != nil {
				t.Fatal(err)
			}
			p := &policy.Policy{Entrypoint: "./x"}
			if kind == "read" {
				p.Read = []string{loop}
			} else {
				p.Write = []string{loop}
			}
			path := writeManifest(t, p, manifest.Provenance{})
			assertApproveRefuses(t, path)

			out, err := runCapturingStdout(t, newValidateCmd(), "--strict", path)
			if err == nil {
				t.Fatalf("--strict must fail on a looping %s grant; got:\n%s", kind, out)
			}
			if !strings.Contains(out, "loops through itself on the host") || !strings.Contains(out, strconv.Quote(loop)) {
				t.Errorf("summary must refuse the looping grant by name; got:\n%s", out)
			}
			// A loop is not an absence: reporting it as a grant that names nothing would
			// send the reader looking for a directory that is right where they left it.
			if strings.Contains(out, "names nothing on this host") {
				t.Errorf("a looping grant is a refusal, not a missing-grant note; got:\n%s", out)
			}
		})
	}
}

// The CI gate's promise: it does not pass a manifest run refuses at its first step. A
// write grant naming a credential store used to exit 0 here and 125 at run, on a host
// where the two commands agreed about everything else - and the summary printed the
// shields-hold footer directly beneath the grant that would be refused, which reads as
// confirmation the grant is safe.
func TestValidateFailsOnAGrantTheRunRefuses(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	p := &policy.Policy{Entrypoint: "./job.sh", Interpreter: "sh", Write: []string{"~/.ssh"}}
	path := writeManifest(t, p, manifest.Provenance{Approves: p.Fingerprint()})

	out, err := runCapturingStdout(t, newValidateCmd(), path, "--strict")
	if err == nil {
		t.Errorf("--strict must fail on a grant run refuses; got:\n%s", out)
	}
	if !strings.Contains(out, "REFUSED: write grant") || !strings.Contains(out, "always-shielded") {
		t.Errorf("the summary must name the refusal beside the grant; got:\n%s", out)
	}
	// Once. The reason is a forty-word paragraph naming the same path twice, and the
	// verdict below counts the refusals rather than reprinting them nine lines later.
	if n := strings.Count(out, "always-shielded"); n != 1 {
		t.Errorf("the refusal printed %d times, want 1; got:\n%s", n, out)
	}
	// Both /bin/sh and the entrypoint resolve, so runnable: - "this host cannot start what
	// the manifest names" - would send the reader after a problem that is not there.
	if !strings.Contains(out, "grants:       NO") || strings.Contains(out, "runnable:     NO") {
		t.Errorf("a refused grant belongs under its own verdict, not runnable:; got:\n%s", out)
	}
}

// interpreter_args changes what the interpreter does with the entrypoint, so the
// summary a reviewer reads before approving has to show it - on its own line, so it
// is not skimmed as part of the interpreter's path.
func TestValidateShowsInterpreterArgs(t *testing.T) {
	var buf strings.Builder
	p := &policy.Policy{Entrypoint: "./x.sh", Interpreter: "/bin/sh", InterpreterArgs: []string{"-eu"}}
	writePolicySummary(&buf, "m.yaml", p, nil, nil, true)
	out := buf.String()
	if !strings.Contains(out, "before the entrypoint") || !strings.Contains(out, strconv.Quote("-eu")) {
		t.Errorf("the summary did not show the interpreter's own arguments:\n%s", out)
	}
	// A policy with none says nothing extra: the line exists to flag a real setting.
	var plain strings.Builder
	writePolicySummary(&plain, "m.yaml", &policy.Policy{Entrypoint: "./x.sh", Interpreter: "/bin/sh"}, nil, nil, true)
	if strings.Contains(plain.String(), "before the entrypoint") {
		t.Errorf("an empty interpreter_args must print nothing:\n%s", plain.String())
	}
}

// A fleet approves one manifest per agent class and reuses it in every worktree, which
// holds only while every path anchors to the manifest's own directory. --relocatable is
// what checks it, and the check must read the manifest as written: the resolved policy
// is absolute by construction, so a check fed that one passes nothing.
func TestValidateRelocatable(t *testing.T) {
	cases := map[string]struct {
		policy     *policy.Policy
		wantPinned []string
	}{
		"all relative": {policy: &policy.Policy{Entrypoint: "./x", Read: []string{"./data"}, Write: []string{"out"}}},
		"absolute read grant": {
			policy:     &policy.Policy{Entrypoint: "./x", Read: []string{"./data", "/srv/corpus"}},
			wantPinned: []string{`read grant "/srv/corpus"`},
		},
		"absolute write grant": {
			policy:     &policy.Policy{Entrypoint: "./x", Write: []string{"/var/tmp/out"}},
			wantPinned: []string{`write grant "/var/tmp/out"`},
		},
		"absolute entrypoint": {
			policy:     &policy.Policy{Entrypoint: "/opt/agent/x"},
			wantPinned: []string{`entrypoint "/opt/agent/x"`},
		},
		// A ~ grant anchors to whoever runs it, so it pins harder than an absolute path
		// while looking relative - the case a bare filepath.IsAbs check would pass.
		"tilde read grant": {
			policy:     &policy.Policy{Entrypoint: "./x", Read: []string{"~/.cache/models"}},
			wantPinned: []string{`read grant "~/.cache/models"`},
		},
		// profile writes what the shebang names, so an absolute interpreter is the
		// ordinary case and means the same thing in every checkout.
		"absolute interpreter": {policy: &policy.Policy{Entrypoint: "./x", Interpreter: "/usr/bin/python3"}},
		// A ~ interpreter is not the same case: it resolves through expandHome, so it
		// names a different program per user the way a ~ grant names a different file.
		"tilde interpreter": {
			policy:     &policy.Policy{Entrypoint: "./x", Interpreter: "~/venv/bin/python"},
			wantPinned: []string{`interpreter "~/venv/bin/python"`},
		},
		// An interpreter spelled relative anchors to the manifest like any other path,
		// so the field is not exempt as a whole.
		"relative interpreter": {policy: &policy.Policy{Entrypoint: "./x", Interpreter: "venv/bin/python"}},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeManifest(t, tc.policy, manifest.Provenance{})
			out, err := runCapturingStdout(t, newValidateCmd(), "--relocatable", path)
			if len(tc.wantPinned) == 0 {
				if err != nil {
					t.Fatalf("--relocatable must pass a manifest that anchors: %v\n%s", err, out)
				}
				if !strings.Contains(out, "relocatable:  yes") {
					t.Errorf("the summary must report the verdict; got:\n%s", out)
				}
				return
			}
			if err == nil {
				t.Fatalf("--relocatable must fail on a pinned path; got:\n%s", out)
			}
			for _, want := range tc.wantPinned {
				if !strings.Contains(out, want) || !strings.Contains(err.Error(), want) {
					t.Errorf("both the summary and the error must name %s; got:\n%s\nerr: %v", want, out, err)
				}
			}
		})
	}
}

// The verdict is opt-in: a manifest written for one machine is not wrong, so without the
// flag an absolute grant must neither print a line nor fail - including under --strict,
// whose gate is about approval and gate.Runnability.
func TestValidateRelocatableIsOptIn(t *testing.T) {
	p := &policy.Policy{Entrypoint: "./x", Read: []string{"/srv/corpus"}}
	path := writeManifest(t, p, manifest.Provenance{})
	if _, err := runCapturingStdout(t, newApproveCmd(), path, "--yes"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	out, err := runCapturingStdout(t, newValidateCmd(), "--strict", path)
	if err != nil {
		t.Fatalf("--strict alone must not fail on a pinned path: %v\n%s", err, out)
	}
	if strings.Contains(out, "relocatable:") {
		t.Errorf("the verdict must not be printed unless it was asked for; got:\n%s", out)
	}
}

// A machine gate reads --json, and the two modes must not disagree: the envelope has to
// carry the verdict AND the command has to exit non-zero, with the fields absent
// entirely when the question was never asked.
func TestValidateRelocatableJSON(t *testing.T) {
	p := &policy.Policy{Entrypoint: "./x", Read: []string{"/srv/corpus"}}
	path := writeManifest(t, p, manifest.Provenance{})

	out, err := runCapturingStdout(t, newValidateCmd(), "--json", "--relocatable", path)
	if err == nil {
		t.Errorf("--json --relocatable must fail too; got:\n%s", out)
	}
	var got policyJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("stdout is not valid JSON (%v); got:\n%s", err, out)
	}
	if got.Relocatable == nil || *got.Relocatable {
		t.Errorf("relocatable must be reported false; got %v", got.Relocatable)
	}
	if !slices.Contains(got.PinnedPaths, `read grant "/srv/corpus"`) {
		t.Errorf("pinned_paths must name the grant; got %v", got.PinnedPaths)
	}

	plain, err := runCapturingStdout(t, newValidateCmd(), "--json", path)
	if err != nil {
		t.Fatalf("validate --json: %v\n%s", err, plain)
	}
	var unasked policyJSON
	if err := json.Unmarshal([]byte(plain), &unasked); err != nil {
		t.Fatalf("stdout is not valid JSON (%v); got:\n%s", err, plain)
	}
	if unasked.Relocatable != nil || unasked.PinnedPaths != nil {
		t.Errorf("the fields must be absent when the question was not asked; got %v %v", unasked.Relocatable, unasked.PinnedPaths)
	}
}

// assertApproveRefuses pins the other half of the gate: a grant validate reports as
// refused must not be stampable either, or the CI gate reads an approval over a permission
// the run does not grant. The two verdicts come from one set (gate.Refusals) so that they
// cannot drift, and this is what would catch it if they did.
func assertApproveRefuses(t *testing.T, path string) {
	t.Helper()
	out, err := runCapturingStdout(t, newApproveCmd(), path, "--yes")
	if err == nil {
		t.Fatalf("approve must refuse a grant run refuses; got:\n%s", out)
	}
	if !strings.Contains(err.Error(), "stamp a permission that does not exist") {
		t.Errorf("approve must refuse in the honorable-grants words; got %v", err)
	}
}

// A host that cannot work out where its shields anchor answers half the question: the
// grants are unknown, but whether the entrypoint resolves is a fact about the filesystem
// that the shield set has no part in. Both halves must reach the report - the older shape
// let the unknown one silence the answer this host was sure of.
func TestValidateReportsWhatAnUnanchoredHostStillKnows(t *testing.T) {
	r := gate.Runnability{
		ShieldsUnknown: true,
		Problems:       []string{`entrypoint "/nope/missing.py": no such file or directory`},
		MissingReads:   []string{"/nope/nothere"},
	}

	var out strings.Builder
	writeRunnability(&out, r)
	for _, want := range []string{"runnable:     NO", `entrypoint "/nope/missing.py"`, "grants:       unknown", "names nothing on this host"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("summary missing %q; got:\n%s", want, out.String())
		}
	}

	var o policyJSON
	o.setRunnable(r)
	if o.Runnable == nil || *o.Runnable {
		t.Errorf("runnable = %v, want false", o.Runnable)
	}
	if len(o.RunnableProblems) != 1 || len(o.MissingReadGrants) != 1 {
		t.Errorf("the answered half must reach the envelope; got %v %v", o.RunnableProblems, o.MissingReadGrants)
	}
	if o.RefusedGrants != nil || o.CredentialAliases != nil || !o.ShieldsUnknown {
		t.Errorf("the shield half must stay absent and be marked unknown; got %v %v %v", o.RefusedGrants, o.CredentialAliases, o.ShieldsUnknown)
	}

	// The same host with a resolving entrypoint knows just as much, and the envelope must
	// carry it rather than falling silent because the harder half is missing.
	var healthy policyJSON
	healthy.setRunnable(gate.Runnability{ShieldsUnknown: true, MissingReads: []string{"/nope/nothere"}})
	if healthy.Runnable == nil || !*healthy.Runnable || !healthy.ShieldsUnknown || len(healthy.MissingReadGrants) != 1 {
		t.Errorf("a shield-anchor failure must not silence the half this host answered; got %v %v %v",
			healthy.Runnable, healthy.ShieldsUnknown, healthy.MissingReadGrants)
	}

	// The other flag: a caller that could not resolve the paths at all asked nothing, so
	// the envelope must not answer - runnable is what a CI gate keys on.
	var unasked policyJSON
	unasked.setRunnable(gate.Runnability{Unresolved: true})
	if unasked.Runnable != nil {
		t.Errorf("runnable = %v, want absent on a host that answered nothing", unasked.Runnable)
	}
}

// --strict is the CI gate, and a host that cannot anchor its shields refuses every run
// whatever the manifest says - so a gate reading the exit code alone must not green-light
// a manifest that host will not start. doctor already exits non-zero on this same fact.
func TestStrictFailsOnAHostThatCannotAnchorItsShields(t *testing.T) {
	err := strictRunnableError(gate.Runnability{ShieldsUnknown: true}, true)
	if err == nil {
		t.Fatal("--strict must fail on a host that refuses every run")
	}
	if !strings.Contains(err.Error(), "where its shields anchor") {
		t.Errorf("the failure must name the host fact; got %v", err)
	}

	// The manifest's own problems are still the reader's to fix, so both halves are named
	// rather than the host fact standing in for an entrypoint that does not exist.
	both := strictRunnableError(gate.Runnability{
		ShieldsUnknown: true,
		Problems:       []string{`entrypoint "/nope/missing.py": no such file or directory`},
	}, true)
	if both == nil || !strings.Contains(both.Error(), "/nope/missing.py") || !strings.Contains(both.Error(), "where its shields anchor") {
		t.Errorf("both halves must reach the strict failure; got %v", both)
	}

	// Without --strict it stays a warning, as every other verdict here does.
	if err := strictRunnableError(gate.Runnability{ShieldsUnknown: true}, false); err != nil {
		t.Errorf("without --strict this is a warning; got %v", err)
	}
	// And a host that could not resolve the paths at all still does not fail: the manifest
	// was not shown to be wrong.
	if err := strictRunnableError(gate.Runnability{Unresolved: true}, true); err != nil {
		t.Errorf("an unresolved answer is not a failed manifest; got %v", err)
	}
}

// The alias scan is bounded by an entry budget, because it runs on validate's default
// path. An empty list then means two different things - a tree read whole, or one the walk
// left part way down - and both surfaces have to carry the difference or a reader takes the
// bounded answer for the exhaustive one.
func TestValidateSaysWhenTheAliasScanWasCutShort(t *testing.T) {
	r := gate.Runnability{CredentialAliasesPartial: true}

	var out strings.Builder
	writeRunnability(&out, r)
	if !strings.Contains(out.String(), "did not cover") {
		t.Errorf("the summary must say the trees were not read whole; got:\n%s", out.String())
	}

	var o policyJSON
	o.setRunnable(r)
	if !o.CredentialAliasesPartial {
		t.Error("the envelope must carry the bound, or a gate reads an empty list as exhaustive")
	}

	// A host that could not anchor its shields never ran the scan at all, so the bound is
	// not the thing to say there - shields_unknown already is.
	var unanchored policyJSON
	unanchored.setRunnable(gate.Runnability{ShieldsUnknown: true, CredentialAliasesPartial: true})
	if unanchored.CredentialAliasesPartial {
		t.Error("a scan that never ran is unknown, not partial")
	}
}

// The breadth judgement existed on approve alone, and the edit-run loop spins on
// validate: an author who validates twenty times and approves once meets the sentence
// about `write: /etc` after the loop that would have acted on it. Both commands raise it
// in one sentence (broadGrantNote) so the two cannot come to differ about what is broad.
func TestValidateNotesABroadGrant(t *testing.T) {
	var buf bytes.Buffer
	p := &policy.Policy{Entrypoint: "./x", Read: []string{"/srv/app/data"}, Write: []string{"/etc"}}
	writePolicySummary(&buf, "m.yaml", p, resolvedGrants(p, "m.yaml"), nil, true)

	out := buf.String()
	if !strings.Contains(out, `write: "/etc" is a whole home or top-level directory`) {
		t.Errorf("validate must say a top-level write grant is broader than a script needs; got:\n%s", out)
	}
	if strings.Contains(out, `"/srv/app/data" is a whole home`) {
		t.Errorf("an ordinary grant must not be called broad; got:\n%s", out)
	}
}

// examples/embed reflects over gate.Runnability and fails when a new field goes unprinted;
// the shipping CLI had no equivalent, so a new degradation flag would reach the reference
// embedder's test and not the product's. Both halves are guarded here, because a field can
// be dropped by either: writeRunnability is what a human reads, setRunnable is what a CI
// gate keys on.
//
// What it does NOT cover, so it is not read as more than it is: a field whose CONTENTS are
// incomplete. Refusals mirrors a set the backend owns, and a check the backend adds there
// arrives as a shorter list, which no completeness test over FIELDS can see.
func TestEveryRunnabilityFieldReachesTheUser(t *testing.T) {
	// Unresolved is left false: it is the one field that SUPPRESSES the rest, in both
	// halves, so seeding it would empty the output this scans. Its own arm below asserts
	// what it prints instead.
	printed := gate.Runnability{
		ShieldsUnknown: true,
		Problems:       []string{`entrypoint "/gone/run.sh": no such file or directory`},
		Refusals:       []string{`grant "/home/u/.ssh" is inside the always-shielded path`},
		MissingReads:   []string{"/data/absent"},
		FileishWrites:  []string{"/out/report.json"},
		CredentialAliases: []enforce.CredentialAlias{
			{Path: "/backup/id_rsa", Credential: "/home/u/.ssh/id_rsa"},
		},
		CredentialAliasesPartial: true,
	}
	render := func(r gate.Runnability) string {
		var out strings.Builder
		writeRunnability(&out, r)
		return out.String()
	}

	// The envelope is built from a host that COULD anchor its shields: setRunnable
	// deliberately withholds the grant half under ShieldsUnknown, so seeding both at once
	// would let a field that never reaches --json pass as one that was withheld on purpose.
	// The flag itself is asserted from its own envelope below.
	marshal := func(r gate.Runnability) string {
		t.Helper()
		var envelope policyJSON
		envelope.setRunnable(r)
		encoded, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}
	anchored := printed
	anchored.ShieldsUnknown = false
	human, machine := render(anchored), marshal(anchored)

	for _, f := range reflect.VisibleFields(reflect.TypeFor[gate.Runnability]()) {
		if !f.IsExported() {
			continue
		}
		v := reflect.ValueOf(printed).FieldByIndex(f.Index)
		// Only the shapes the fixture above seeds. A field of another kind is not waved
		// through on a sentence that is in the output for a different reason - which is how
		// a completeness guard passes over the very field it was added for.
		var want, key string
		// The text the key is looked for in: the anchored envelope for every field but the
		// unknown-shields flag, which only a host that could not anchor them emits.
		humanFor, machineFor := human, machine
		switch {
		// Named before the shapes below, because what reaches the reader is not the field's
		// own text: the refusal paragraph is already printed beside the grant it refuses, so
		// this line counts them rather than repeating them forty words later.
		case f.Name == "Refusals" && v.Len() > 0:
			want, key = "cannot be honored", `"refused_grants"`
		case v.Kind() == reflect.Slice && v.Len() > 0 && v.Type().Elem().Kind() == reflect.String:
			want = v.Index(0).String()
		// A slice of a struct is asserted on its first field, the path in every case there
		// is: a finding that does not name the path it is about is not actionable.
		case v.Kind() == reflect.Slice && v.Len() > 0 && v.Type().Elem().Kind() == reflect.Struct:
			want = v.Index(0).Field(0).String()
			key = `"credential_aliases"`
		case f.Name == "ShieldsUnknown" && v.Bool():
			want, key = "where its shields anchor", `"shields_unknown":true`
			humanFor, machineFor = render(printed), marshal(printed)
		case f.Name == "CredentialAliasesPartial" && v.Bool():
			want, key = "the scan for second names", `"credential_aliases_partial":true`
		// The suppressing field, asserted on its own rather than from the fixture: the
		// human half says the host could not answer, and the envelope says nothing at all,
		// because runnable is what a gate keys on and an unasked question must not read as
		// a green one.
		case f.Name == "Unresolved":
			if got := render(gate.Runnability{Unresolved: true}); !strings.Contains(got, "could not answer") {
				t.Errorf("an unresolved host prints no verdict of its own:\n%s", got)
			}
			var suppressed policyJSON
			suppressed.setRunnable(gate.Runnability{Unresolved: true, Problems: []string{"x"}})
			if suppressed.Runnable != nil || suppressed.RunnableProblems != nil {
				t.Errorf("an unresolved host filled the envelope: %+v", suppressed)
			}
			continue
		default:
			t.Errorf("gate.Runnability.%s is new: give it a value in the fixture above and teach this "+
				"switch its shape, then print it in writeRunnability and carry it in setRunnable.", f.Name)
			continue
		}
		// Either spelling counts in the human half: a raw path is quoted on its way out and
		// an already-quoted sentence is not, and which of the two a field is does not change
		// what the guard asks - that it reached the reader at all.
		if !strings.Contains(humanFor, want) && !strings.Contains(humanFor, strconv.Quote(want)) {
			t.Errorf("gate.Runnability.%s is unprinted: print it in writeRunnability. A pre-flight field "+
				"no frontend reads is the silence it exists to close.\ngot:\n%s", f.Name, humanFor)
		}
		if key == "" {
			key = strconv.Quote(want)
		}
		if !strings.Contains(machineFor, key) {
			t.Errorf("gate.Runnability.%s does not reach --json: carry it in setRunnable, so a CI gate "+
				"reads the same answer the summary prints.\ngot:\n%s", f.Name, machineFor)
		}
	}
}

// The judgement that a write grant reaches the entrypoint or the manifest itself is the
// sharpest either review command makes, and it used to arrive only at the stamp - on the
// command the edit-run loop runs least. An iterator who has seen validate warn about a
// whole-home read then reads a clean validate as "no breadth concerns" on a manifest
// approve stops at.
func TestValidateRaisesApproveCallouts(t *testing.T) {
	p := &policy.Policy{Entrypoint: "./tool.py", Write: []string{"."}, Read: []string{"~"}, Exec: policy.ExecAll}
	path := writeManifest(t, p, manifest.Provenance{})

	out, err := runCapturingStdout(t, newValidateCmd(), path)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	for _, want := range []string{"Worth a second look:", "covers the manifest itself", "covers the entrypoint", "exec: all -"} {
		if !strings.Contains(out, want) {
			t.Errorf("validate must raise %q; got:\n%s", want, out)
		}
	}
	// approve's heading asks for a decision that validate is not taking.
	if strings.Contains(out, "before stamping") {
		t.Errorf("validate stamps nothing; got:\n%s", out)
	}
	// The notes the summary already prints beside the grant they are about stay there:
	// one screen saying it twice teaches the reader to skim the block that asks for a
	// decision.
	if n := strings.Count(out, "whole home or top-level directory"); n != 1 {
		t.Errorf("the breadth note belongs beside its grant and nowhere else, got %d copies:\n%s", n, out)
	}
}

// The env: list is what the reviewer stamps, and a name the host does not set carries
// nothing into the sandbox. run says so on stderr, which is after the approval decision;
// validate is where the decision is made.
func TestValidateNamesEveryUnsetAllowlistedEnvVar(t *testing.T) {
	t.Setenv("HOME", "/home/someone")
	t.Setenv("BENTO_TEST_SET", "value")
	os.Unsetenv("BENTO_TEST_UNSET")
	os.Unsetenv("BENTO_TEST_ALSO_UNSET")

	var buf bytes.Buffer
	p := &policy.Policy{Entrypoint: "./x", Env: []string{"HOME", "BENTO_TEST_SET", "BENTO_TEST_UNSET", "BENTO_TEST_ALSO_UNSET"}}
	writePolicySummary(&buf, "m.yaml", p, nil, nil, true)
	out := buf.String()
	for _, name := range []string{"BENTO_TEST_UNSET", "BENTO_TEST_ALSO_UNSET"} {
		if !strings.Contains(out, "note: env "+name+" is allowed by the manifest but not set") {
			t.Errorf("every unset allowlisted name must be reported; %s missing from:\n%s", name, out)
		}
	}
	if strings.Contains(out, "note: env BENTO_TEST_SET") {
		t.Errorf("a name the host sets must not be reported as unset; got:\n%s", out)
	}
	// HOME has its own line saying more than this one could, including where the sandbox
	// lands when nothing is passed through.
	if strings.Contains(out, "note: env HOME") {
		t.Errorf("HOME is writeSandboxHome's to report, not this note's; got:\n%s", out)
	}
}

// The interpreter is resolved against PATH at the moment of `bento run`, and PATH is not
// part of what the approval stamp attests - so the name alone does not say which program
// the policy applies to, the way a bare grant does not say what it reaches.
func TestValidateResolvesTheInterpreter(t *testing.T) {
	dir := t.TempDir()
	interp := filepath.Join(dir, "myinterp")
	if err := os.WriteFile(interp, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	var buf bytes.Buffer
	writePolicySummary(&buf, "m.yaml", &policy.Policy{Entrypoint: "./x", Interpreter: "myinterp"}, nil, nil, true)
	if out := buf.String(); !strings.Contains(out, strconv.Quote(interp)) {
		t.Errorf("summary must say where the interpreter name lands on this host; got:\n%s", out)
	}

	// Nothing to add when the name is already the path, and nothing to add when it does
	// not resolve - runnable: NO reports that, with the lookup's own error.
	buf.Reset()
	writePolicySummary(&buf, "m.yaml", &policy.Policy{Entrypoint: "./x", Interpreter: "nosuchinterp"}, nil, nil, true)
	if out := buf.String(); strings.Contains(out, "on this host: ") {
		t.Errorf("an unresolvable interpreter must not be given a landing place; got:\n%s", out)
	}
}
