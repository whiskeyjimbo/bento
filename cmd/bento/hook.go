package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/whiskeyjimbo/bento/gate"
)

func newHookCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Adapters that route an AI agent's commands through bento run",
	}
	cmd.AddCommand(newClaudeCodeHookCmd())
	return cmd
}

func newClaudeCodeHookCmd() *cobra.Command {
	var allow bool
	cmd := &cobra.Command{
		Use:   "claude-code <manifest>",
		Short: "A Claude Code PreToolUse hook that runs each Bash command under a manifest",
		Long: "claude-code reads a PreToolUse hook payload on stdin and rewrites a Bash tool call\n" +
			"into `bento run <manifest> -- <command>`, started in the directory Claude Code is in.\n" +
			"The manifest must be approved and set extra_args: true; see examples/agent for one.\n\n" +
			"By default it answers \"ask\", so Claude Code still prompts, and shows the rewritten\n" +
			"command. --allow answers \"allow\" instead: every Bash call runs without a prompt,\n" +
			"confined by the manifest. Claude Code matches its permission rules against the\n" +
			"rewritten line, which starts with bento, so a rule keyed on a command prefix\n" +
			"such as Bash(git push:*) no longer matches it.\n\n" +
			"Only the Bash tool is rewritten. Claude Code's built-in Read, Edit, Write and WebFetch\n" +
			"tools do not run through a shell and are not confined by this hook.\n\n" +
			"Any payload it cannot turn into a sandboxed command is answered with \"deny\" rather\n" +
			"than an error, because Claude Code runs the original command when a hook fails.",
		// Checked in RunE rather than by an Args validator: every failure here is answered
		// with a deny, because an error exit is one Claude Code does not block on.
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return writeHookDecision(cmd.OutOrStdout(), "deny", fmt.Sprintf("bento hook claude-code is configured with %d arguments; it takes exactly one, the manifest path", len(args)), nil)
			}
			self, err := os.Executable()
			if err != nil {
				return writeHookDecision(cmd.OutOrStdout(), "deny", fmt.Sprintf("bento could not locate its own binary to run the command under: %v", err), nil)
			}
			return claudeCodeHook(cmd.InOrStdin(), cmd.OutOrStdout(), args[0], self, allow)
		},
	}
	// A flag error is answered like every other failure: a deny, not an error exit.
	cmd.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		return writeHookDecision(c.OutOrStdout(), "deny", fmt.Sprintf("bento hook claude-code is misconfigured: %v", err), nil)
	})
	cmd.Flags().BoolVar(&allow, "allow", false, "answer allow rather than ask, so sandboxed Bash calls run without Claude Code's prompt")
	return cmd
}

// claudeCodeHook answers one PreToolUse payload. It returns an error only when it cannot
// write its answer at all; everything else it cannot vouch for is a deny, because a hook
// that fails leaves Claude Code to run the original command unsandboxed.
func claudeCodeHook(in io.Reader, out io.Writer, manifestPath, bentoPath string, allow bool) error {
	var payload struct {
		ToolName  string         `json:"tool_name"`
		Cwd       string         `json:"cwd"`
		ToolInput map[string]any `json:"tool_input"`
	}
	if err := json.NewDecoder(in).Decode(&payload); err != nil {
		return writeHookDecision(out, "deny", fmt.Sprintf("bento could not read the hook payload: %v", err), nil)
	}
	if payload.ToolName != "Bash" {
		return nil
	}
	command, _ := payload.ToolInput["command"].(string)
	if command == "" {
		return writeHookDecision(out, "deny", "bento: the Bash call carried no command", nil)
	}
	if payload.Cwd == "" {
		return writeHookDecision(out, "deny", "bento: the hook payload carried no cwd, so the command's starting directory is unknown", nil)
	}
	abs, err := filepath.Abs(manifestPath)
	if err != nil {
		return writeHookDecision(out, "deny", fmt.Sprintf("bento: %v", err), nil)
	}
	// The run's refusals that depend on the manifest alone, asked here too so the agent
	// reads why at once instead of a run that refuses after the user approved the prompt.
	doc, _, err := loadDocument(abs)
	if err == nil {
		err = requireApproval(doc, false)
	}
	if err == nil && !doc.Policy.ExtraArgs {
		err = errors.New("the manifest does not set extra_args: true, so it cannot run a command it was not written with")
	}
	if err == nil {
		if resolved := resolvedGrants(doc.Policy, abs); resolved == nil {
			err = errors.New("its grants could not be resolved on this host")
		} else if problems := gate.ManifestProblems(abs, resolved); len(problems) > 0 {
			err = errors.New(strings.Join(problems, "; "))
		}
	}
	if err != nil {
		return writeHookDecision(out, "deny", fmt.Sprintf("bento: %s: %v", abs, err), nil)
	}

	updated := make(map[string]any, len(payload.ToolInput))
	for k, v := range payload.ToolInput {
		updated[k] = v
	}
	script := "cd " + shellQuote(payload.Cwd) + " && " + command
	updated["command"] = strings.Join([]string{shellQuote(bentoPath), "run", shellQuote(abs), "--", shellQuote(script)}, " ")
	decision := "ask"
	if allow {
		decision = "allow"
	}
	return writeHookDecision(out, decision, "bento: runs under "+abs, updated)
}

func writeHookDecision(out io.Writer, decision, reason string, updated map[string]any) error {
	type hookOutput struct {
		HookEventName            string         `json:"hookEventName"`
		PermissionDecision       string         `json:"permissionDecision"`
		PermissionDecisionReason string         `json:"permissionDecisionReason"`
		UpdatedInput             map[string]any `json:"updatedInput,omitempty"`
	}
	return json.NewEncoder(out).Encode(struct {
		HookSpecificOutput hookOutput `json:"hookSpecificOutput"`
	}{hookOutput{"PreToolUse", decision, reason, updated}})
}

// shellQuote single-quotes s for a POSIX shell: inside single quotes nothing is special
// but the quote itself, which is closed, escaped and reopened.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
