#!/bin/sh
# Drives `bento hook claude-code` the way Claude Code does - a PreToolUse payload on
# stdin - and then executes the command it hands back, so the whole path an agent's
# Bash call takes is exercised without Claude Code itself: approve, rewrite, run.
#
# The checkout is a copy under a temp dir, because the run writes into it.
set -eu
cd "$(dirname "$0")"
root="$(cd ../.. && pwd)"

if ! command -v bwrap >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
	echo "SKIP: the agent example needs bwrap (bubblewrap) and python3" >&2
	exit 0
fi
if ! bwrap --unshare-user --ro-bind / / --proc /proc true 2>/dev/null; then
	echo "SKIP: the agent example needs a host bubblewrap can build its sandbox on" >&2
	exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
bin="$work/bento"
repo="$work/repo"
mkdir -p "$repo/.claude"
cp agent.manifest.yaml "$repo/"
echo '{}' >"$repo/.claude/settings.json"

GOWORK=off go build -o "$bin" "$root/cmd/bento"
"$bin" approve --yes "$repo/agent.manifest.yaml" </dev/null >/dev/null 2>&1

# hook <command> prints the decision JSON for a Bash call of <command> made from $repo.
hook() {
	python3 -c 'import json,sys; print(json.dumps({"tool_name":"Bash","cwd":sys.argv[1],"tool_input":{"command":sys.argv[2],"description":"x"}}))' "$repo" "$1" |
		"$bin" hook claude-code "$repo/agent.manifest.yaml"
}
field() {
	python3 -c 'import json,sys; o=json.load(sys.stdin)["hookSpecificOutput"]; print(eval(sys.argv[1], {}, o))' "$1"
}
# agent <command> runs <command> the way Claude Code would after the hook: the rewritten
# line, through a shell.
agent() {
	cmd="$(hook "$1" | field 'updatedInput["command"]')"
	sh -c "$cmd" </dev/null
}

if [ "$(hook 'true' | field 'permissionDecision')" != "ask" ]; then
	echo "FAIL: the hook did not answer ask by default" >&2
	exit 1
fi

agent 'echo built > out.txt' 2>/dev/null
if [ "$(cat "$repo/out.txt" 2>/dev/null)" != "built" ]; then
	echo "FAIL: a command under the write grant did not write the checkout" >&2
	exit 1
fi

before="$(cat "$repo/agent.manifest.yaml")"
agent 'echo "write: [/]" >> agent.manifest.yaml' 2>/dev/null || true
if [ "$(cat "$repo/agent.manifest.yaml")" != "$before" ]; then
	echo "FAIL: a sandboxed command rewrote the manifest it runs under" >&2
	exit 1
fi

agent 'echo planted > .claude/settings.json' 2>/dev/null || true
if [ "$(cat "$repo/.claude/settings.json")" != "{}" ]; then
	echo "FAIL: a sandboxed command rewrote the checkout's Claude Code settings" >&2
	exit 1
fi

# An unapproved manifest is a deny, never a pass-through: Claude Code runs the original
# command when a hook fails, so failing would run it unsandboxed.
echo "env: [HOME]" >>"$repo/agent.manifest.yaml"
if [ "$(hook 'true' | field 'permissionDecision')" != "deny" ]; then
	echo "FAIL: the hook did not deny under an edited, unapproved manifest" >&2
	exit 1
fi

echo "ok: agent example"
