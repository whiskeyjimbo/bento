# State grid: enforce.Result return arms vs the consumers that read them

Area: `enforce/enforce.go` (`Result`), `enforce/run.go` (`Run`'s overlay, err arm, silent-stage
refusal, `postRunShortfall`), `internal/linux/linux.go` (`Run`, `runCmd` arms),
`internal/linux/degraded.go` (`runDegraded` arms), and the readers: `cmd/bento/run.go`
(`writeRunResult`, `failJSON`), `cmd/bento/render.go`, `examples/embed/main.go`,
`examples/supervise/main.go`.

## Phase 0 - fit

Good fit. Enum-x-call-sites: Result has 19 fields, the backend has ~30 `return` statements that
yield one, and four consumers each pick which fields to read per arm. The backend comments
already argue the invariant arm by arm ("dropping the list here reports a cancelled run as
having exposed nothing"), which is the repeated one-at-a-time fix signal.

Invariant (one-sided): on every arm, every Result field a consumer reads is either populated or
its zero value is distinguishable to that consumer from "clean". Forbidden direction: a field
empty because nothing was asked / nothing was built reads the same as a clean run.

`internal/launcher/degraded.go` produces no Result (it is the in-sandbox stage; it reaches the
host only through the applied report that `reconcile` reads), so it enters the grid only via
the `Setup` and `Report` columns of the degraded arms.

## Phase 1 - dimensions (from the code)

Backend arms (collapsed by what they return):

- A1 pre-dispatch error: `return enforce.Result{}, err` - linux.go:54-224 (validate, run id,
  degraded-tier refusals, bwrap lookup, newSandbox, preflightGrants, checkLauncher, bridge pipe);
  degraded.go:42-218.
- A2 full tier cancel: linux.go:297.
- A3 full tier success (exit 0): linux.go:314.
- A4 full tier exit error / signal / limits kill: linux.go:334.
- A5 full tier other wait error (`runCmd` default): linux.go:368.
- A6 degraded cancel: degraded.go:270.
- A7 degraded launcher never started (nil ProcessState): degraded.go:284.
- A8 degraded completed (exit, signal, WaitDelay): degraded.go:291.
- A9 degraded other wait error: degraded.go:301.
- enforce.Run then rewrites every arm: `res.Report = required` (run.go:239) unconditionally;
  err arm returns res with err or a Shortfall wrapping it (run.go:258-262); a nil-err SetupSilent
  becomes a Refusal (run.go:277).

Field groups (collapsed; each group is populated or dropped together on every arm):

- F-exit: ExitCode, Signaled, Signal
- F-setup: Setup
- F-report: Report
- F-rec: ExecRecord
- F-net: EgressConnections, GateAdmitted, GuardBlocked, GuardBlockedMetadata, Denied, GateDenied, Untunneled
- F-shield: Shields, Exposed, ShieldedGrants, AcceptedAliases
- F-hooks: ChangedAutoExec, RedirectedHooks, UnresolvedHooks

Consumers and their err-arm vs success-arm read sets:

- C1 cmd/bento success/Shortfall (run.go:554 verdict, render chain run.go:560-630): all groups.
- C2 cmd/bento failed (run.go:435-468, failJSON run.go:379): F-report, F-shield, F-hooks only.
- C3 embed success (`writeResult`, main.go:345): all groups. Error arm (main.go:250-270):
  Report degradations, ChangedAutoExec, RedirectedHooks only.
- C4 supervise success (`writeSummary`, main.go:325): all groups. Interrupt/error arms
  (main.go:295-308): ChangedAutoExec, RedirectedHooks, UnresolvedHooks only.

Grid A: backend arm x field group, 27 rows (the full-tier arms A2-A5 and degraded completing
arms A8-A9 are identical per group, so they share rows).
Grid B: consumer err arm x field group, 16 cells the arm can actually carry non-empty.
Total 43 cells.

## Grid A - backend arm populates the field

| # | Arm | Group | Verdict |
|---|---|---|---|
| A1.exit | pre-dispatch | F-exit | HANDLED: zero with non-nil err; every consumer branches on err first (run.go:423, embed main.go:250, supervise main.go:302) |
| A1.setup | pre-dispatch | F-setup | HANDLED: SetupSilent zero, documented "read the error first" (enforce.go:347-351) |
| A1.report | pre-dispatch | F-report | FIXED in ed7ead3/b88ee14 (was **WRONG**, forbidden). Backend returns a zero Report; run.go:239 replaces it with the pre-run probe, so the returned report claims every required layer Enforced for a run whose stage never existed. Finding 1 |
| A1.rec | pre-dispatch | F-rec | HANDLED: nil, and no consumer err arm reads it (Grid B), so nil is never rendered as "unasked" |
| A1.net | pre-dispatch | F-net | HANDLED: nothing dialed, no proxy started |
| A1.shield | pre-dispatch | F-shield | HANDLED: nothing mounted or exposed, target never started |
| A1.hooks | pre-dispatch | F-hooks | HANDLED: target never started, nothing to have changed |
| A2-5.exit | full cancel/success/exit/other | F-exit | HANDLED: success/exit arms carry the code (linux.go:314, 334); cancel and other arms leave it zero with non-nil err (linux.go:297, 368) |
| A2-5.setup | same | F-setup | HANDLED: `reconcile` on every arm (linux.go:280, 304, 322, 358) |
| A2-5.report | same | F-report | HANDLED: reconcile plus every `note*` on every arm; run.go overlay only worsens (run.go:222) |
| A2-5.rec | same | F-rec | HANDLED: `a.execRecord(opts.RecordExec)` on every arm, non-nil when asked (applied.go:361) |
| A2-5.net | same | F-net | HANDLED: collector read after `stopProxy` on all four arms |
| A2-5.shield | same | F-shield | HANDLED: Shields/ShieldedGrants/AcceptedAliases on all four; Exposed empty by design on this tier (enforce.go:486) |
| A2-5.hooks | same | F-hooks | HANDLED: `changed` computed once above the cancel check (linux.go:258) |
| A6.exit | degraded cancel | F-exit | HANDLED: zero with err |
| A6.setup/report | degraded cancel | F-setup, F-report | HANDLED: reconcile (degraded.go:265) |
| A6.rec | degraded cancel | F-rec | HANDLED: `degradedExecRecord` non-nil when asked |
| A6.shield/hooks | degraded cancel | F-shield, F-hooks | HANDLED: Exposed, ShieldedGrants, AcceptedAliases, hooks all carried |
| A7.setup/report | degraded never started | F-setup, F-report | HANDLED: reconcile with -1 (degraded.go:283) lowers every layer |
| A7.rec | degraded never started | F-rec | HANDLED: stamped |
| A7.shield | degraded never started | F-shield | HANDLED: launcher never started, nothing exposed (degraded.go:279-281) |
| A7.hooks | degraded never started | F-hooks | HANDLED: nothing ran |
| A8-9.all | degraded completed/other | all but F-net | HANDLED: degraded.go:291, 301 carry every group this tier has |
| A6-9.net | degraded any | F-net | IMPOSSIBLE non-empty: degraded tier refuses network rules and gates (run.go:201-213, linux.go:71-81), and the launcher blocks egress |
| A6-9.Shields | degraded any | Shields | HANDLED: empty by design, documented as not proof (enforce.go:473-476); Exposed carries it |
| run.silent | Run, nil err + SetupSilent | all | HANDLED: Refusal (run.go:277) |
| run.err | Run, err arm | posture | HANDLED: Shortfall wraps err (run.go:258); report inherits A1.report |

## Grid B - consumer error arms read what the backend carries

Only cells where the backend arm can carry a non-empty value (A2, A5, A6, A9).

| # | Consumer err arm | Group | Verdict |
|---|---|---|---|
| B1 | cmd/bento failed | F-hooks | HANDLED: human run.go:442-443 (UnresolvedHooks inside writeRedirectedHooksNotice, render.go:1634), JSON run.go:379 |
| B2 | cmd/bento failed | F-shield | HANDLED: human run.go:437-439, JSON run.go:379; Shields JSON only, deliberately (run.go:436) |
| B3 | cmd/bento failed | F-report | FIXED in ed7ead3/b88ee14 (was WRONG via A1.report (JSON reports `fully_enforced: true`)). Finding 1 |
| B4 | cmd/bento failed | Denied, GuardBlocked, Untunneled, EgressConnections | FIXED in 0eacfd5 (was **UNHANDLED**: dropped in both modes). Finding 2 |
| B5 | cmd/bento failed | ExecRecord | FIXED in 0eacfd5 (was **UNHANDLED**: dropped in both modes). Finding 2 |
| B6 | cmd/bento failed | GateAdmitted, GateDenied | IMPOSSIBLE non-empty: cmd/bento passes no NetworkGate (no `NetworkGate` anywhere in cmd/bento) |
| B7 | embed error | ChangedAutoExec, RedirectedHooks | HANDLED: main.go:263-268 |
| B8 | embed error | UnresolvedHooks | FIXED in 6731896 (was **WRONG**, forbidden: not read, so an empty hook list on an unanswered grant reads like the clean one). Finding 3 |
| B9 | embed error | Exposed, ShieldedGrants, AcceptedAliases | FIXED in 6731896 (was **WRONG**, forbidden: not read; embed sets no DenyPaths, so the degraded tier is reachable and A6/A9 carry Exposed). Finding 3 |
| B10 | embed error | F-net | FIXED in 6731896 (was **UNHANDLED**: not read). Finding 3 |
| B11 | embed error | F-report | HANDLED for degradations (main.go:256); inherits A1.report |
| B12 | supervise interrupt/error | F-hooks | HANDLED: main.go:298-306, UnresolvedHooks inside writeRedirectedHooks (main.go:498) |
| B13 | supervise interrupt/error | Exposed | IMPOSSIBLE: DenyPaths set (main.go:294), so the degraded tier is refused (run.go:193) |
| B14 | supervise interrupt/error | AcceptedAliases | IMPOSSIBLE: Options carries no AcceptAliasesUnder (main.go:294) |
| B15 | supervise interrupt/error | ShieldedGrants | FIXED in 638befc/15dae72 (was **UNHANDLED**: not read; an approved manifest granting ~/.ssh reaches A2/A5). Finding 4 |
| B16 | supervise interrupt/error | F-net | FIXED in 638befc/15dae72 (was **UNHANDLED**: GateAdmitted is carried on cancel precisely for a supervised run that timed out (linux.go:283-288) and supervise does not read it). Finding 4 |

Adversarial re-check of HANDLED cells: A2-5.hooks re-read (computed before the cancel branch,
so every arm sees it). A7.shield re-read: `ProcessState == nil` is only Start failing, and a
cancel before start is caught by the cancel arm first (degraded.go:246), so nothing ran. B1
confirmed UnresolvedHooks is printed inside the notice, not a separate unread call. B6 confirmed
by grep that cmd/bento never sets a gate. No cell left without a verdict.

## Findings, forbidden direction first

1. **FIXED in ed7ead3/b88ee14. A1.report / B3: a backend setup error before any stage returns a fully Enforced report.**
   The Linux backend's pre-dispatch arms return `enforce.Result{}`. `enforce.Run` then sets
   `res.Report = required` unconditionally (run.go:239), which is the probe's claim of what the
   host CAN enforce, and returns it beside the error. The backend's own post-dispatch arms
   reconcile to avoid exactly this ("Returning the probe raw attests the tier's fences to a run
   whose in-sandbox stage may never have installed one", linux.go:346-351), but a zero Report
   bypasses that. `bento run --json` then emits `{"event":"failed", ..., "report":{...,
   "fully_enforced":true}}`, and the failed event carries no setup field to qualify it; embed's
   error arm prints no degradation. The overlay cannot tell "no report" from "nothing to add".
   VERIFIED BY SPIKE, three levels: a fake enforcer through `enforce.Run` (filesystem and
   exec-block Enforced, Setup silent, plain error); the same fake through `writeRunResult` in
   --json (`fully_enforced:true` in the failed event); the real Linux backend under the sandbox
   with the `launchGuard` seam failing checkLauncher (linux.go:207), through `enforce.Run`
   (filesystem Enforced). `launchGuard` is nil in production, so the spike stands in for the other
   pre-dispatch arms (newSandbox, preflightGrants, bridge pipe), which return the same zero
   Result; their reachability on a probe-Enforced host is VERIFIED BY READING.

2. **FIXED in 0eacfd5. B4/B5: `bento run` drops the network refusal lists and the exec record on the failed path.**
   A run cancelled by Ctrl-C (main.go:66 NotifyContext) or dying in teardown carries Denied,
   GuardBlocked, Untunneled, EgressConnections and ExecRecord out of the backend (linux.go:297,
   368), and neither the human path (run.go:435-446) nor `streamRefusalJSON` (run.go:329) has
   them. Allowed direction: the JSON fields are absent from the event schema rather than
   present-and-empty, and the human path prints an error, so no clean claim is made. But a run
   hung retrying a denied host and then interrupted is the one where Denied explains it, and
   `--record-exec` asked for a record the operator never sees.
   VERIFIED BY SPIKE: `writeRunResult` with all four populated and a cancel error, both modes;
   none of the hosts nor the exec marker reached stdout or stderr.

3. **FIXED in 6731896. B8/B9/B10: examples/embed error arm reads four fields of the ones it reads on success.**
   main.go:250-270 prints the error, degradations, ChangedAutoExec and RedirectedHooks. It drops
   UnresolvedHooks (forbidden: enforce.go:557 says only this separates an empty hook report from
   an unanswered one), Exposed/ShieldedGrants/AcceptedAliases (forbidden: embed runs with no
   DenyPaths and may be admitted degraded, and A9 carries Exposed out; cmd/bento carries these
   on its own failed path for this reason, run.go:344-347), and the network lists (allowed
   direction, information loss). embed is the copy-me template for embedders (result_test.go:53),
   and result_test.go holds only `writeResult` to every field, not the error arm.
   VERIFIED BY READING. UNSPIKEABLE HERE without refactoring: the arm is inline in `run()` behind
   a real backend; settling it needs the arm extracted into a writer, or a sandbox run with an
   injected backend wait error reachable from outside the linux package.

4. **FIXED in 638befc/15dae72. B15/B16: examples/supervise interrupt and error arms drop ShieldedGrants and the network lists.**
   main.go:295-308 read only the hook group. The backend's cancel arm carries GateAdmitted for "a
   supervised run timed out after a human admitted a host" (linux.go:283-288), and supervise is
   that consumer. Allowed direction on balance: the human is told the run was interrupted or
   failed, GateAdmitted hosts are ones they approved at the prompt, and ShieldedGrants is a
   manifest opt-in they also approved. Information loss, not a clean claim. VERIFIED BY READING
   (same inline-arm limit as finding 3).

## Rejected findings

- Degraded never-started arm drops Exposed (degraded.go:284). The launcher never started, so
  nothing was exposed (degraded.go:279-281), and a pre-start cancel is caught by the cancel arm.
- ExitCode zero on cancel and other-error arms. Always paired with a non-nil error, and every
  consumer branches on the error before reading the code.
- Shields empty on the degraded tier. Documented as not evidence (enforce.go:473-476); Exposed
  carries the disclosure.
- Setup zero on pre-dispatch arms. Documented as meaningful only with nil or a Shortfall
  (enforce.go:347-351), and cmd/bento's failed event omits setup accordingly. The report is the
  defect (finding 1), not Setup.
- F-net zero on every degraded arm. IMPOSSIBLE to be non-empty: network and gate are refused
  before dispatch.

Dismissals verified by execution: `go test ./internal/linux -run 'TestRunFailing|Cancel'` under
the sandbox passed (full-tier cancel carries observations, degraded cancel carries the exposure
audit and exec record before and after dispatch, the default wait-error arm carries the record
and reconciles to no layer).

## Proposed exhaustive test

In enforce: a table over {backend returns Result{} + err, reconciled report + err, report + nil}
with a fully Enforced probe, asserting a zero backend Report never comes back with a required
layer Enforced. In cmd/bento, examples/embed and examples/supervise: extract each error arm into
a writer and hold it to the same reflect walk over Result fields that
`TestWriteResultSurfacesEveryHonestyField` applies to the success writer, with an explicit
exclusion list naming why each skipped field is impossible for that consumer.

## Re-open pass, against 5a98897

The worktree was cut at 924e291. Between that and 5a98897, only f45da41 (postRunShortfall under
--allow-degraded with a run id) and 0085cec touch enforce/run.go or enforce/enforce.go.

- New field `Result.Degraded` (0085cec). `enforce.Run` sets it straight after the backend returns
  (run.go:220), so it is set on every backend arm, the error arm included; no backend return
  statement has to set it. Refusals raised before the backend runs return `Result{}` with
  Degraded false, and no consumer reads Result on the refusal path. The one reader is
  cmd/bento/render.go:778 (the seccomp legend), on the success path only. New cell A*.degraded:
  HANDLED. Grid is now 44 cells.
- A1/B3 re-checked on 5a98897: `res.Report = required` is still unconditional (run.go:258), and
  neither commit touches the overlay. Finding 1 stands unchanged. Its line reference moves from
  run.go:239 to run.go:258.

Prior grid (2026-08-13) mapped onto these cells:

| Prior site / fix | Cell here | Carried to the grid B consumers? |
|---|---|---|
| linux.go 292 cancel, shield set (83f212e) | A2.shield, A2.net | cmd/bento: shield set yes (B2), egress set yes since 0eacfd5 (B4). embed: yes since 6731896 (B9, B10). supervise: shield and egress sets yes since 638befc (B15, B16; Exposed and AcceptedAliases are impossible there) |
| linux.go 321 default-err, shield and egress sets | A5.shield, A5.net | Same as the row above: B2 yes; B4, B9, B10, B15, B16 yes since their fixes |
| degraded.go 238 cancel, ShieldedGrants/Exposed/AcceptedAliases | A6.shield | cmd/bento yes (B2). embed yes since 6731896 (B9). supervise: Exposed impossible (B13), ShieldedGrants yes since 638befc (B15) |
| degraded.go 255 default-err, same fields | A9.shield | Same as the row above |
| bv2-h9g6 degraded cancel reconcile (closed) | A6.setup/report | HANDLED here, and the Report reaches every consumer |
| linux.go 303 exit0 / 317 exited, degraded.go 243 / 250 | A3, A4, A7, A8 | Success paths read every field (C1, and the success writers in C3 and C4) |

What the pattern says: every prior fix closed the backend arm, and none carried the fields into the
consumers' error paths. The recurring defect of one arm getting a field its siblings do not has
moved up a layer. Findings 2 to 4 are that defect, one per consumer.
