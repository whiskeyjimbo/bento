package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/whiskeyjimbo/bento/manifest"
	"github.com/whiskeyjimbo/bento/policy"
)

// validate must surface resource limits in both the human summary and --json, so a
// reviewer (and CI) can see the memory/cpu/pids ceilings before approving (bv2-cyz).
func TestValidateShowsLimits(t *testing.T) {
	p := &policy.Policy{Entrypoint: "./x", Limits: policy.Limits{Memory: "128M", CPU: "50%", PIDs: 64}}

	var buf bytes.Buffer
	writePolicySummary(&buf, "m.yaml", p, nil)
	out := buf.String()
	for _, want := range []string{"limits:", "memory 128M", "cpu 50%", "pids 64"} {
		if !strings.Contains(out, want) {
			t.Errorf("human summary missing %q; got:\n%s", want, out)
		}
	}

	j := toPolicyJSON(p, nil)
	if j.Limits == nil || j.Limits.Memory != "128M" || j.Limits.CPU != "50%" || j.Limits.PIDs != 64 {
		t.Errorf("JSON limits = %+v, want memory/cpu/pids populated", j.Limits)
	}

	// A no-limits policy must omit the limits entirely (no empty struct in JSON).
	if toPolicyJSON(&policy.Policy{Entrypoint: "./x"}, nil).Limits != nil {
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
	saved := os.Stdout
	os.Stdout = w
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	runErr := cmd.Execute()
	os.Stdout = saved
	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	return string(out), runErr
}

func writeManifest(t *testing.T, p *policy.Policy, prov manifest.Provenance) string {
	t.Helper()
	data, err := manifest.Marshal(p, prov)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "m.yaml")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// --strict is the documented CI drift gate, and a machine gate reads --json. The two
// must not disagree: --json --strict on a stale approval has to fail AND still leave a
// parseable envelope naming the state (bv2-fglb). Executing RunE is the point - the
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
				if _, err := runCapturingStdout(t, newApproveCmd(), path); err != nil {
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
	if _, err := runCapturingStdout(t, newApproveCmd(), path); err != nil {
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
	_, _, err := loadDocument(script, io.Discard)
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
	_, _, err = loadDocument(script, io.Discard)
	if err == nil || !strings.Contains(err.Error(), sibling) {
		t.Errorf("err = %v, want it to name %s once that manifest exists", err, sibling)
	}

	// A shebang with no extension bento knows is the other signal.
	shell := filepath.Join(dir, "tool")
	if err := os.WriteFile(shell, []byte("#!/bin/sh\nexit 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadDocument(shell, io.Discard); err == nil || !strings.Contains(err.Error(), "looks like a script") {
		t.Errorf("err = %v, want a shebang alone to be enough", err)
	}

	// A manifest that is merely malformed keeps the parser's diagnosis, which says
	// where the YAML went wrong.
	broken := filepath.Join(dir, "m.yaml")
	if err := os.WriteFile(broken, []byte("entrypoint: ./x\n  read: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadDocument(broken, io.Discard); err == nil || strings.Contains(err.Error(), "looks like a script") {
		t.Errorf("err = %v, want the parser's own error for a malformed manifest", err)
	}
}
