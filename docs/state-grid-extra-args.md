# State grid: extra_args and argv screening

Reviewed 2026-09-25 against 7e4adda. Area: manifest `args` / `interpreter_args` / `extra_args`,
CLI trailing args after `--`, the Claude Code hook adapter, and where they are screened and joined
into the target argv (`internal/linux/args.go:807 command`, shared by both tiers:
`args.go:483`, `degraded.go:228`).

## Phase 0 - fit

Weak-to-moderate fit. One mirror pair (validate's screen `policy.Problems` vs what reaches
`command()`), five entry paths, 12 cells. Gridded, but close to "an ordinary review suffices";
most cells resolve by one read.

**Invariant as proposed:** any argv element that reaches exec passed the screen `bento validate`
applies. **This is false by design for extra args** and is restated below. `validate` never sees
extra args (they are not in the manifest), and `FirstUnsafeRune` (policy/policy.go:174-181) exists
to stop a manifest *misleading the operator reading it*. Extra args are not reviewed text; run
echoes them `strconv.Quote`d (cmd/bento/run.go:120-124) and approve discloses the opt-in
(approve.go:321). `enforce/run_test.go:1957` pins that a newline-bearing extra arg is admitted.

**Invariant used (one-sided):** screening may refuse argv exec would accept; but (a) every
manifest-sourced argv element passes `policy.Problems` on every exec path, and (b) an extra arg
reaches exec only when the policy sets `extra_args: true` and carries no NUL, on every exec path.

## Grid - source x path

Paths: V = `bento validate`/approve, R = `bento run` -> `enforce.Run` -> backend, P = `bento profile`
(discovery run via `Enforcer.Profile`), H = `bento hook` (rewrites the Bash call into `bento run`),
E = Go embedder calling the exported backend `Enforcer.Run` directly (`backend.New()`).

| # | Source | Path | Verdict | Where | Stamp |
|---|---|---|---|---|---|
| 1 | manifest args / interpreter_args | V | HANDLED | `manifest.Parse` -> `p.Problems()` screens Args+InterpreterArgs (policy.go:174-181) | READING |
| 2 | manifest args | R | HANDLED | loadDocument parse, then `enforce.Run` `p.Validate()` (enforce/run.go:123) | READING |
| 3 | manifest args | P | HANDLED | `Enforcer.Profile` `p.Validate()` (internal/linux/profile.go:48); mergePolicies keeps base.Args (cmd/bento/profile.go:1858) | READING |
| 4 | manifest args | H | HANDLED | hook loads the doc (hook.go:92) and hands off to `bento run` = cell 2 | READING |
| 5 | manifest args | E | HANDLED | `Enforcer.Run` re-validates (internal/linux/linux.go:58) | READING |
| 6 | CLI trailing | V | IMPOSSIBLE | validate takes no trailing args; nothing to screen | READING |
| 7 | CLI trailing | R | HANDLED (restated invariant) | opt-in refused at run.go:117 and enforce/run.go:141; NUL at enforce/run.go:144; rune screen deliberately not applied | EXECUTION (`TestRunAdmitsExtraArgsOnlyWhenThePolicyOptsIn`, `TestRunRefusesExtraArgsWithoutTheOptIn`) |
| 8 | CLI trailing (profile script args) | P | HANDLED | profile puts trailing args into policy.Args (profile.go:188, 1450), so they pass `Validate` at internal/linux/profile.go:48; Profile never appends proc.ExtraArgs | READING |
| 9 | Process.ExtraArgs | E | **WRONG (forbidden direction)** | `Enforcer.Run` re-checks Validate/RequireExpanded/RunID "because this is an exported entry point an embedder can call directly" (linux.go:56-66) but not the extra_args opt-in or NUL. `command()` (args.go:814) appends `proc.ExtraArgs` unconditionally | SPIKE (argv half); READING (Run lacks the check) |
| 10 | hook adapter command | H | HANDLED | refuses a manifest without extra_args (hook.go:96); command becomes one shell-quoted extra arg of `bento run` (hook.go:113-114), so cell 7 applies | EXECUTION (`go test ./cmd/bento -run 'ExtraArgs\|TestHook'`) |
| 11 | hook adapter command | V/P/E | IMPOSSIBLE | the adapter emits only a `bento run` command line (hook.go:114) | READING |
| 12 | any source | degraded tier | HANDLED | same `command()` (degraded.go:228) behind the same `enforce.Run` checks; the E-path gap of cell 9 applies equally | READING |

Counts: 8 HANDLED, 3 IMPOSSIBLE, 1 WRONG, 0 UNHANDLED.

## Findings

**F1 (cell 9, forbidden direction).** The extra_args gate lives only in the frontend
(cmd/bento/run.go:117) and `enforce.Run` (enforce/run.go:141-149), not at the backend entry that
declares itself embedder-callable and re-runs the other policy checks (linux.go:56-66). An
embedder's `Process.ExtraArgs` reaches exec on a policy that never opted in, whose fingerprint and
approval cover only its own args. Fix: repeat the opt-in + NUL check in `linux.Enforcer.Run`
(shared helper with enforce.Run, per the one-source rule), regression test at that entry.
Severity bounded: an embedder calling the backend directly also skips layer admission, so this is
a coupling gap more than an attack, but linux.go:56-57 is the repo's own stated contract.
VERIFIED BY SPIKE that `command()` appends ExtraArgs with `p.ExtraArgs=false`; VERIFIED BY READING
that `Enforcer.Run` has no opt-in check before `compile`/`runDegraded`.

Spike (deleted; the regression test belongs at `Enforcer.Run` once fixed):

```go
func TestSpikeCommandIgnoresOptIn(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/bin/true"}
	got := command(p, enforce.Process{ExtraArgs: []string{"injected\x1b[2J"}}, sandbox{entrypoint: "/bin/true"})
	for _, a := range got {
		if a == "injected\x1b[2J" {
			t.Fatalf("extra arg reached argv with p.ExtraArgs=false: %q", got)
		}
	}
}
```
Output: `extra arg reached argv with p.ExtraArgs=false: ["/bin/true" "injected\x1b[2J"]`.

## Rejected

- **Extra args skip `FirstUnsafeRune` (cells 7, 10).** Not a defect: the screen protects reviewed
  manifest text; extra args are echoed quoted and disclosed as unapproved by approve. Pinned by
  `enforce/run_test.go:1957`. VERIFIED BY EXECUTION.
- **`--json` `extra_args` carries a bidi/zero-width rune raw.** encoding/json escapes C0 controls
  but not U+202E etc. Minor: JSON is a machine contract; the human echo is `strconv.Quote`d.
  VERIFIED BY READING; UNVERIFIED that no human-facing renderer prints the field raw.
- **Hook command with NUL.** Travels as a shell word; a NUL cannot reach a real argv, and
  enforce/run.go:144 refuses it anyway. VERIFIED BY READING.

## Re-open pass

`git log 265a790..HEAD`: 76b7f82 (add extra_args), 1ab5721 (hook adapter), 3d8685e (pass extra
args outside the policy). 3d8685e moved extra args onto `Process` and added the opt-in + NUL check
to `enforce.Run` only (cells 7, 10), and did not carry the row to the backend entry that already
repeats enforce.Run's other policy checks (cell 9). No open bead covers it (`bd list --status open`
grep for extra/argv/embedder: none).
