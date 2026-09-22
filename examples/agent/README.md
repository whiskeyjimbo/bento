# agent - running an AI agent's shell commands under bento

An agent that runs shell commands runs them as you: your SSH keys, your cloud
credentials, every repository on the disk. This example puts each command an agent
runs under one approved manifest instead, so it reaches the checkout it is working
in and nothing else.

It is two files:

- `agent.manifest.yaml` - a shell (`/bin/sh -c`) that may read and write the
  checkout and spawn subprocesses, with no network. `extra_args: true` is what lets
  each run supply its own command.
- `claude-settings.json` - a Claude Code `PreToolUse` hook that rewrites every Bash
  tool call into `bento run agent.manifest.yaml -- '<command>'`.

## Setup

```sh
cp examples/agent/agent.manifest.yaml ~/src/myproject/
bento approve ~/src/myproject/agent.manifest.yaml
```

Then merge `claude-settings.json` into `~/src/myproject/.claude/settings.json`. In your
user settings it would apply to every project, and in a project with no
`agent.manifest.yaml` the hook denies every Bash call - by design, since it never lets
a command through unconfined. Widen the manifest the way you would any other - `network:` for a package
registry, `read:` for a toolchain outside the system directories - and approve it
again.

The project's `.claude/` and your `~/.claude` are both read-only to a sandboxed
command, so the agent cannot switch the hook off from inside. The manifest is
read-only to its own run too: approval is a stamp inside it, and a command that could
rewrite it could re-stamp a wider policy. Keep it at the top of its write grant, as
here - `bento run` refuses a manifest under a wider write grant, because the directory
holding it could be renamed away.

## What the hook answers

By default the hook answers `ask`: Claude Code still prompts before each command, and
the prompt shows the rewritten `bento run ...` line. `bento hook claude-code --allow`
answers `allow`, so sandboxed commands run without a prompt.

Claude Code matches its permission rules against the rewritten line, and every
rewritten line starts with `bento run`. A rule keyed on a command prefix, such as
`Bash(git push:*)`, stops matching - so under `--allow` such a deny rule no longer
stops the command. Keep `ask` if you rely on those rules.

Anything the hook cannot turn into a sandboxed command - an unapproved or edited
manifest, one without `extra_args`, a payload it cannot read - is answered `deny`
with the reason. It never fails open: Claude Code runs the original command when a
hook errors, and that would run it unconfined.

## What this does not cover

- **Only the Bash tool.** Claude Code's built-in Read, Edit, Write and WebFetch tools
  do not run through a shell and are not confined by this hook. Use Claude Code's
  permission rules for those.
- **Prompt injection.** `CLAUDE.md`, `AGENTS.md` and files the agent reads are inside
  the write grant. bento keeps an agent from planting code that runs on the host
  later; it does not keep one from writing text a later session will read.
- **Claude Code's own sandbox.** If Claude Code's Bash sandbox is on, `bento run`
  happens inside it and bubblewrap may not get a user namespace. bento then refuses
  rather than running unconfined; turn one of the two off.

## Other agents

The hook is a convenience for Claude Code. Any agent that lets you wrap its shell
command can use the manifest directly:

```sh
bento run agent.manifest.yaml -- "$COMMAND"
```

Each command pays bento's startup cost (probing the host and building the sandbox).

`verify.sh` drives the hook with canned payloads and runs what it returns.
