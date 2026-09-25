package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/manifest"
	"github.com/whiskeyjimbo/bento/policy"
)

type hookReply struct {
	HookSpecificOutput struct {
		HookEventName            string         `json:"hookEventName"`
		PermissionDecision       string         `json:"permissionDecision"`
		PermissionDecisionReason string         `json:"permissionDecisionReason"`
		UpdatedInput             map[string]any `json:"updatedInput"`
	} `json:"hookSpecificOutput"`
}

// writeAgentManifest writes an approved (or, with stamp false, unapproved) shell manifest.
func writeAgentManifest(t *testing.T, p *policy.Policy, stamp bool) string {
	t.Helper()
	prov := manifest.Provenance{}
	if stamp {
		prov.Approves = p.Fingerprint()
	}
	data, err := manifest.Marshal(p, prov)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func agentPolicy() *policy.Policy {
	return &policy.Policy{Entrypoint: "/bin/sh", Args: []string{"-c"}, ExtraArgs: true, Read: []string{"."}, Write: []string{"."}, Exec: policy.ExecAll}
}

func runHook(t *testing.T, m, payload string, allow bool) (hookReply, string) {
	t.Helper()
	var out strings.Builder
	if err := claudeCodeHook(strings.NewReader(payload), &out, m, "/opt/bin/bento", allow); err != nil {
		t.Fatalf("claudeCodeHook: %v", err)
	}
	if out.Len() == 0 {
		return hookReply{}, ""
	}
	var r hookReply
	if err := json.Unmarshal([]byte(out.String()), &r); err != nil {
		t.Fatalf("hook wrote something that is not a reply: %v\n%s", err, out.String())
	}
	return r, out.String()
}

// The rewritten command must run the original under bento in the agent's cwd, and every
// other tool_input field must survive: updatedInput replaces the input whole.
func TestHookRewritesBashUnderTheManifest(t *testing.T) {
	m := writeAgentManifest(t, agentPolicy(), true)
	r, raw := runHook(t, m, `{"tool_name":"Bash","cwd":"/w/repo","tool_input":{"command":"make test","description":"run tests","timeout":120000}}`, false)
	o := r.HookSpecificOutput
	if o.HookEventName != "PreToolUse" || o.PermissionDecision != "ask" {
		t.Fatalf("want a PreToolUse ask by default, got %s", raw)
	}
	if o.UpdatedInput["description"] != "run tests" || o.UpdatedInput["timeout"] != float64(120000) {
		t.Errorf("updatedInput dropped the other tool_input fields: %s", raw)
	}
	cmd, _ := o.UpdatedInput["command"].(string)
	if want := "'/opt/bin/bento' run '" + m + "' -- "; !strings.HasPrefix(cmd, want) {
		t.Errorf("command = %q, want prefix %q", cmd, want)
	}
}

// Whatever the agent sends must reach sh -c as exactly that string, however it is quoted.
// Checked by letting a real shell unpack the rewritten line, not by eyeballing the escaping.
func TestHookQuotingSurvivesHostileCommands(t *testing.T) {
	m := writeAgentManifest(t, agentPolicy(), true)
	for _, orig := range []string{
		`echo 'single' "double" $HOME $(id) ` + "`id`",
		"printf 'a\\nb'\ncat <<EOF\nheredoc $x\nEOF",
		`it's`,
		`''''`,
	} {
		payload, _ := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": "/w/it's here", "tool_input": map[string]any{"command": orig}})
		r, _ := runHook(t, m, string(payload), false)
		cmd, _ := r.HookSpecificOutput.UpdatedInput["command"].(string)
		// Replace the bento invocation with a printer of its argv, one per NUL.
		out, err := exec.Command("sh", "-c", "set -- "+strings.TrimPrefix(cmd, "'/opt/bin/bento' ")+`; printf '%s\0' "$@"`).Output()
		if err != nil {
			t.Fatalf("sh could not parse the rewritten command %q: %v", cmd, err)
		}
		argv := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
		want := []string{"run", m, "--", "cd '/w/it'\\''s here' && " + orig}
		if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("argv after the shell:\n got %q\nwant %q", argv, want)
		}
	}
}

// Anything other than the Bash tool is not bento's to confine: no output, so Claude Code
// carries on as if no hook existed.
func TestHookPassesNonBashToolsThrough(t *testing.T) {
	m := writeAgentManifest(t, agentPolicy(), true)
	if _, raw := runHook(t, m, `{"tool_name":"Read","cwd":"/w","tool_input":{"file_path":"/etc/passwd"}}`, false); raw != "" {
		t.Errorf("a non-Bash tool got a reply: %s", raw)
	}
}

func TestHookAllowIsOptIn(t *testing.T) {
	m := writeAgentManifest(t, agentPolicy(), true)
	r, raw := runHook(t, m, `{"tool_name":"Bash","cwd":"/w","tool_input":{"command":"ls"}}`, true)
	if r.HookSpecificOutput.PermissionDecision != "allow" {
		t.Errorf("--allow did not answer allow: %s", raw)
	}
}

// Under --allow no prompt shows what the model asked for, so the model must not be able to
// switch Claude Code's own sandbox off along the way. Under ask the user sees it and decides.
func TestHookAllowStripsDisableSandbox(t *testing.T) {
	m := writeAgentManifest(t, agentPolicy(), true)
	payload := `{"tool_name":"Bash","cwd":"/w","tool_input":{"command":"ls","dangerouslyDisableSandbox":true}}`
	if r, raw := runHook(t, m, payload, true); r.HookSpecificOutput.UpdatedInput["dangerouslyDisableSandbox"] != nil {
		t.Errorf("--allow passed dangerouslyDisableSandbox through: %s", raw)
	}
	if r, raw := runHook(t, m, payload, false); r.HookSpecificOutput.UpdatedInput["dangerouslyDisableSandbox"] != true {
		t.Errorf("ask dropped dangerouslyDisableSandbox the user is shown: %s", raw)
	}
}

// Claude Code treats a hook that exits non-zero (other than 2) as a non-blocking error and
// runs the ORIGINAL command, unsandboxed. So every way the hook cannot vouch for a run
// answers deny, with no updatedInput, rather than failing.
func TestHookDeniesWhatItCannotSandbox(t *testing.T) {
	noOptIn := agentPolicy()
	noOptIn.ExtraArgs = false
	wide := agentPolicy()
	wide.Write = []string{".."}
	for name, tc := range map[string]struct {
		manifest, payload, reason string
	}{
		"unapproved manifest":  {writeAgentManifest(t, agentPolicy(), false), `{"tool_name":"Bash","cwd":"/w","tool_input":{"command":"ls"}}`, "approv"},
		"replaceable manifest": {writeAgentManifest(t, wide, true), `{"tool_name":"Bash","cwd":"/w","tool_input":{"command":"ls"}}`, "renamed"},
		"no extra_args":        {writeAgentManifest(t, noOptIn, true), `{"tool_name":"Bash","cwd":"/w","tool_input":{"command":"ls"}}`, "extra_args"},
		"missing manifest":     {filepath.Join(t.TempDir(), "absent.yaml"), `{"tool_name":"Bash","cwd":"/w","tool_input":{"command":"ls"}}`, "absent.yaml"},
		"malformed payload":    {writeAgentManifest(t, agentPolicy(), true), `{"tool_name":`, "payload"},
		"no cwd":               {writeAgentManifest(t, agentPolicy(), true), `{"tool_name":"Bash","tool_input":{"command":"ls"}}`, "cwd"},
		"no command":           {writeAgentManifest(t, agentPolicy(), true), `{"tool_name":"Bash","cwd":"/w","tool_input":{}}`, "command"},
		"NUL in command":       {writeAgentManifest(t, agentPolicy(), true), `{"tool_name":"Bash","cwd":"/w","tool_input":{"command":"echo a\u0000; id"}}`, "NUL"},
		"NUL in cwd":           {writeAgentManifest(t, agentPolicy(), true), `{"tool_name":"Bash","cwd":"/w\u0000x","tool_input":{"command":"ls"}}`, "NUL"},
	} {
		t.Run(name, func(t *testing.T) {
			r, raw := runHook(t, tc.manifest, tc.payload, true)
			o := r.HookSpecificOutput
			if o.PermissionDecision != "deny" || o.UpdatedInput != nil {
				t.Fatalf("want a deny with no updatedInput, got %s", raw)
			}
			if !strings.Contains(o.PermissionDecisionReason, tc.reason) {
				t.Errorf("reason %q does not say why (%q)", o.PermissionDecisionReason, tc.reason)
			}
		})
	}
}

// A hook configured without its manifest must still answer. Failing as a usage error
// exits non-zero, which Claude Code treats as non-blocking - the original command then
// runs unconfined, from a settings file that looks like it sandboxes everything.
func TestHookMisconfiguredStillDenies(t *testing.T) {
	for name, args := range map[string][]string{
		"no manifest":  nil,
		"unknown flag": {"--alow", "m.yaml"},
	} {
		t.Run(name, func(t *testing.T) { hookDeniesWith(t, args) })
	}
}

func hookDeniesWith(t *testing.T, args []string) {
	t.Helper()
	cmd := newClaudeCodeHookCmd()
	cmd.SetArgs(args)
	cmd.SetIn(strings.NewReader(`{"tool_name":"Bash","cwd":"/w","tool_input":{"command":"ls"}}`))
	var out strings.Builder
	cmd.SetOut(&out)
	cmd.SetErr(&strings.Builder{})
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	if err := cmd.Execute(); err != nil {
		t.Fatalf("the hook exited with an error, which Claude Code does not block on: %v", err)
	}
	if !strings.Contains(out.String(), `"permissionDecision":"deny"`) {
		t.Errorf("a hook with no manifest must deny; got %q", out.String())
	}
}
