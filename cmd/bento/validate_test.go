package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
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
	writePolicySummary(&buf, "m.yaml", p)
	out := buf.String()
	for _, want := range []string{"limits:", "memory 128M", "cpu 50%", "pids 64"} {
		if !strings.Contains(out, want) {
			t.Errorf("human summary missing %q; got:\n%s", want, out)
		}
	}

	j := toPolicyJSON(p)
	if j.Limits == nil || j.Limits.Memory != "128M" || j.Limits.CPU != "50%" || j.Limits.PIDs != 64 {
		t.Errorf("JSON limits = %+v, want memory/cpu/pids populated", j.Limits)
	}

	// A no-limits policy must omit the limits entirely (no empty struct in JSON).
	if toPolicyJSON(&policy.Policy{Entrypoint: "./x"}).Limits != nil {
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
