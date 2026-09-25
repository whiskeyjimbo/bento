# Threat model: the Claude Code PreToolUse hook adapter

Scope: `cmd/bento/hook.go` (`newClaudeCodeHookCmd`, `claudeCodeHook`, `writeHookDecision`,
`shellQuote`) and the manifest checks it calls (`loadDocument`, `requireApproval`,
`resolvedGrants`, `gate.ManifestProblems`). Date: 2026-09-25. Complements
[threat-model.md](threat-model.md), which covers what happens once `bento run` starts; this
document covers only whether a model-proposed Bash call reliably becomes one.

- **Adversary (proposed, not confirmed by the owner):** `model` - the model, or a prompt
  injected into it, which chooses every value inside `tool_input` of a Bash call and can
  also use Claude Code's other tools. It does not control the top-level payload fields
  (`tool_name`, `cwd`), which Claude Code fills in, nor the hook's argv, stdout pipe or the
  settings file that installs the hook.
- **Spikes:** no consent gate was satisfied (run as a subagent). One in-process spike ran
  under the contained-spike carve-out: `claudeCodeHook` called with crafted payloads against
  a manifest planted in `t.TempDir()`, the rewritten line then unpacked by `sh -c 'set -- ...;
  printf'` (the technique `TestHookQuotingSurvivesHostileCommands` uses). Nothing ran under a
  real Claude Code or a real `bento run`.
- **Rows:** 14. Stamps: VERIFIED BY SPIKE 7, VERIFIED BY EXECUTION (existing tests) 4,
  VERIFIED BY READING 2, UNVERIFIED 1.

## Findings (by effect)

1. **Hook hang falls through to the unsandboxed command (UNVERIFIED, medium if real).**
   `claudeCodeHook` has no deadline of its own. `loadDocument` does a blocking `os.Open` of
   the manifest (`cmd/bento/validate.go:158`) and `gate.ManifestProblems` stats every
   ancestor (`gate/manifest.go:41-65`). If the manifest name can be made to resolve to a FIFO
   or a hung mount, the hook blocks until Claude Code's hook timeout. Whether Claude Code then
   runs the original command is not established here; if a timeout is treated like any other
   non-blocking hook error (the behaviour `hook.go:42-44` and `hook_test.go:123-125` already
   defend against), this is a fail-open. Reaching it needs the manifest path's entry
   replaced, which `ManifestProblems` refuses for write grants (`gate/manifest.go:50-61`), so
   the likely trigger is a misconfiguration (manifest on a network mount) rather than the
   model. Nothing in the hook stops it. Detection: SILENT. Hand-off: `failure-modes`.
2. **`--allow` auto-approves every other `tool_input` field unread (VERIFIED BY SPIKE, low).**
   `hook.go:116-119` copies all keys through. A payload with
   `"dangerouslyDisableSandbox": true` came back `allow` with that key intact. Effect: under
   `--allow` the model turns off Claude Code's own sandbox layer for the call without the
   prompt Claude Code would otherwise show. The bento sandbox still wraps the command, so the
   gain is lost defence in depth, not an escape. The copy is deliberate (`hook_test.go:63`,
   "updatedInput replaces the input whole"), but nothing weighs it against `--allow`.
   Detection: SILENT. FIXED: under `--allow` the hook drops `dangerouslyDisableSandbox`
   (`TestHookAllowStripsDisableSandbox`); under ask it still passes through, shown in the prompt.
3. **NUL bytes reach the emitted line (VERIFIED BY SPIKE for emission, BY READING for effect,
   informational).** `"command":"echo a\u0000; id"` and a NUL in `cwd` both yield `allow`
   with the NUL inside the quoted script; exec of the line fails (`fork/exec ... invalid
   argument`). By reading, every downstream handling (reject, truncate at NUL, drop NUL)
   either errors or leaves the remainder inside the single-quoted region or unterminated, so
   nothing reaches the host shell outside `bento run`. Held only by `shellQuote`
   (`hook.go:146-148`) placing the NUL inside quotes; nothing rejects it. Denying on NUL would
   be cheaper to reason about. FIXED: a NUL in `command` or `cwd` is now denied
   (`TestHookDeniesWhatItCannotSandbox/NUL_in_*`).

No crossing observed: every Bash payload tried came back deny, or with the entire
model-controlled text as one argv element after `--`.

## Boundaries and flows (proposed)

| slug | outside -> inside | crossing | receiving side assumes |
|---|---|---|---|
| `claudecodehook` stdin | Claude Code payload, `tool_input` model-chosen | `hook.go:73` Decode | `tool_name`/`cwd` are Claude Code's; `command` is arbitrary text |
| `claudecodehook` stdout | hook -> Claude Code | `hook.go:129-138` | Claude Code runs `updatedInput.command` in a host bash |
| `claudecodehook` exit status | hook -> Claude Code | `cmd/bento/main.go:95-101` | non-zero non-2 exit = run original command |
| manifest file | disk -> hook | `validate.go:158` | path is a regular file, not swapped |

Dropped attackers: `local-other-uid` (can already edit what it can reach; covered by
`ManifestProblems` and the system model); `settings-editor` (can remove the hook outright;
the model doing so via the unconfined Write tool is disclosed at `hook.go:39-40`).

## Matrix

| id | enforcement | effect if crossed | detection | stamp / evidence |
|---|---|---|---|---|
| `claudecodehook/shell-injection` (command) | ENFORCED `hook.go:120-121,146-148` whole script single-quoted | host shell runs model text outside bento | n/a | EXECUTION `TestHookQuotingSurvivesHostileCommands`; SPIKE (newline, surrogate) |
| `claudecodehook/shell-injection` (cwd) | ENFORCED `hook.go:120` | same | n/a | SPIKE: `cwd="/w\n; id #"` stays one argv |
| `claudecodehook/input-unvalidated` (NUL) | ENFORCED: denied in `claudeCodeHook` | none found | reason | EXECUTION `TestHookDeniesWhatItCannotSandbox/NUL_in_*`, finding 3 |
| `claudecodehook/input-unvalidated` (non-string/null `command`, null `tool_input`) | ENFORCED `hook.go:79-82` -> deny | line with no command | reason | SPIKE |
| `claudecodehook/input-unvalidated` (lone surrogate) | decoder maps to U+FFFD, still quoted | none | n/a | SPIKE |
| `claudecodehook/input-unvalidated` (extra keys) | BY-DESIGN `hook_test.go:63`; `dangerouslyDisableSandbox` dropped under `--allow` | finding 2 | SILENT | EXECUTION `TestHookAllowStripsDisableSandbox` |
| `claudecodehook/input-unvalidated` (`Command` casing twin) | ENFORCED: exact map lookup `hook.go:79`, only `command` rewritten | none; twin passed through (Claude Code ignoring it is inferred) | n/a | SPIKE |
| `claudecodehook/authz-bypass` (non-Bash, `bash` casing) | BY-DESIGN `hook.go:39-40,76-78` no output | Read/Write/WebFetch unconfined | SILENT | EXECUTION `TestHookPassesNonBashToolsThrough`; SPIKE (`bash` -> no output) |
| `claudecodehook/fail-open` (malformed JSON) | ENFORCED `hook.go:73-75` deny | original runs | reason | EXECUTION `TestHookDeniesWhatItCannotSandbox/malformed_payload` |
| `claudecodehook/fail-open` (bad args/flags) | ENFORCED `hook.go:46-48,56-58` | original runs | reason | EXECUTION `TestHookMisconfiguredStillDenies` |
| `claudecodehook/fail-open` (manifest unapproved/no extra_args/replaceable/missing) | ENFORCED `hook.go:96-111` | allow of a swappable or refusing run | reason | EXECUTION `TestHookDeniesWhatItCannotSandbox` |
| `claudecodehook/fail-open` (stdout write error) | UNENFORCED: error -> exit 125 `main.go:101` | original runs | stderr | READING; not reachable by `model` |
| `claudecodehook/resource-unbounded` (hang) | UNENFORCED | finding 1 | SILENT | UNVERIFIED |
| `claudecodehook/input-unvalidated` (trailing bytes after JSON) | first value used `hook.go:73` | none: bytes are Claude Code's | n/a | SPIKE; no attacker |

## Not spiked

- Covered by existing tests: quoting, deny paths, non-Bash passthrough, `--allow` opt-in
  (all in `cmd/bento/hook_test.go`).
- Not reachable without consent: end-to-end under real Claude Code (timeout behaviour, how it
  hands a NUL-bearing command to bash) and a real `bento run` whose manifest entrypoint is not
  `sh -c` (by reading, the script becomes a plain argv and the run fails closed).

## Dropped rows

Top-level spoofing (`TOOL_NAME` is accepted by Go's case-insensitive decode - spike
confirmed - but the model cannot set top-level keys); duplicate JSON keys (Claude Code
serialises an already-parsed object); bento binary / manifest argv tampering (installer's);
repudiation and info-disclosure (nothing attributed; reasons name only the manifest path).

## Handoffs

- Finding 1 -> `failure-modes`.

## Teardown

Spike `cmd/bento/zz_hookspike_test.go` lived in the agent worktree only and was deleted.
