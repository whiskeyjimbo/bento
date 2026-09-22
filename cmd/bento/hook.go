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
			"confined by the manifest. Claude Code's own deny and ask rules still apply either way.\n\n" +
			"Only the Bash tool is rewritten. Claude Code's built-in Read, Edit, Write and WebFetch\n" +
			"tools do not run through a shell and are not confined by this hook.\n\n" +
			"Any payload it cannot turn into a sandboxed command is answered with \"deny\" rather\n" +
			"than an error, because Claude Code runs the original command when a hook fails.",
		Args: exactArgs(1, "a manifest path"),
		RunE: func(cmd *cobra.Command, args []string) error {
			self, err := os.Executable()
			if err != nil {
				return err
			}
			return claudeCodeHook(cmd.InOrStdin(), cmd.OutOrStdout(), args[0], self, allow)
		},
	}
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
	// Checked here as well as by the run itself, so the agent reads why at once instead of
	// a run that refuses after the user already approved the prompt.
	doc, _, err := loadDocument(abs)
	if err == nil {
		err = requireApproval(doc, false)
	}
	if err == nil && !doc.Policy.ExtraArgs {
		err = errors.New("the manifest does not set extra_args: true, so it cannot run a command it was not written with")
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
