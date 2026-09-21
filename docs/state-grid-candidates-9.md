# State grid candidates - ninth sweep

Phase A, 2026-09-21, against `main` at 265a790 (52 commits past `deadd82`, the eighth
sweep's file). Same filter as the eighth round: what POST-DATES the grids on disk. Every
row the eighth sweep nominated (39-42) has a grid now, so the cold-sweep candidates are
all taken and this round is only about code that landed since.

Signals used: fix scopes since `deadd82`, new functions and enum constants in that diff,
ordinal comparisons against `enforce.State`, and the recorded gaps of the four
eighth-round grids.

## New candidates

| # | Candidate | Signals | Invariant (one-sided) | Shape | Fit | Route |
|---|---|---|---|---|---|---|
| 43 | **`enforce.State`'s `Unsampled` x every ordinal and fold site.** `be1a6da` put a fourth value in the MIDDLE of a severity-ordered enum (report.go:72: "admission checks compare against that order"). Sites: `enforce/run.go` admit bars, `limitsBar`, `postRunShortfall`, strict, `StateOf`/`forLayers` folds, `run.go:764`, `doctor.go:163`, `render.go:1881`, `degraded.go:420,425`, `applied.go:466,515`, validate's host-shortfall note | New constant in an ordered enum; its own doc admits the placement is "a deliberate exemption for exactly one" bar. `be1a6da` touched only `state-grid-platform-stubs.md`, so `state-grid-admission.md`, `-layer-consumers.md` and `-host-shortfall.md` carry verdicts over a three-value enum. `d154b01`, `2b2442b`, `fa78083` keep taking exec-strict one at a time | A state may read worse than the host is, never better: no site may treat `Unsampled` as at least as good as a state it did not deliberately rank it against | state (4) x site (~12), collapse sites that share a bar ~30 | **Strong**. Re-open trigger is mechanical: the question is whether each `< Degraded` / `< Unavailable` site sorts `Unsampled` on purpose or by integer accident | grid, as a re-open of the admission and layer-consumers grids |
| 44 | **`screenRemedies` (enforce/run.go:643-700) x the remedies frontends print (`cmd/bento/render.go`)** | Function under a week old, four one-at-a-time fixes (`715ec11`, `4490bd7`, `fa78083`, and `a5d251f` on the render side). Mirror pair: the remedy a frontend names vs the composed admission that would judge it. Its own doc names the gap as generic ("any check Run composes after admit inherits the same gap"), and `composedAdmission` composes only `admit` + `admitRunID`. `remed` appears in 10 grids, none owns it | A remedy may be withheld where it would have worked; it must never be offered where composed admission, under the posture it implies, still refuses | refusal source (admit core, admit hardening, strict, `admitRunID` no-limits, `admitRunID` limits short, `undeliverableExecBlock`, `admitEnv`, `ValidateRunID`) x remedy (`--allow-degraded`, drop `limits:`, drop run id, `NoRemedy`) x frontend (run human, run --json, profile) ~30 after IMPOSSIBLE folds | **Strong** | grid |
| 45 | **Shield-record provenance (`internal/linux/shields.go:922-1099`: `recordCreatedShields`, `reclaimStrandedShields`, `parseShieldRecord`, `openOwnRecord`)** | New mechanism (`470317c`, `286e705` "trust only our own shield records"), both after `state-grid-teardown.md` and `-during-run.md` | Reclaim may leave a stranded shield behind; it must never remove or alter a path a record does not prove this user's bento created | record state (absent, ours-live, another live run's, dead run's, malformed, truncated, not ours by owner/mode, lost to reboot) x reclaim action ~16-24 | **Good, scoped tight**: the record-trust axis only. Artifact classes and termination modes belong to the teardown and during-run grids | grid for the state axis; the shared-`/tmp` attacker half routes to `threat-model` |

## Routed elsewhere, or not a row

| Area | Why | Route |
|---|---|---|
| Gate's derived carve half (`ab80ec0`, `15347ac`, `71631bf`) | A new flag, `ShieldCarveUnknown`'s derived half, landing after `state-grid-gate-unknowns.md`; open beads bv2-rj5ow, bv2-wbrff already name its two live cells | re-open of `state-grid-gate-unknowns.md` if picked; small |
| `internal/credhunt` (4 fixes since) | They are the fix batch from `state-grid-credhunt-coverage.md` itself | nothing owed |
| Folding re-open cells E8, F2c/F3c | Recorded as uncarried in `state-grid-folding-reopen.md` | cells, not a row: check they are filed |
| Shield-record trust against a hostile `/tmp` | attacker capability, not a distinction the code makes | `threat-model` |
| `internal/observe`, `internal/proxy` | unchanged from sweeps 1-8 | `concurrency-audit`, `failure-modes` (both spent) |

## Not re-gridded

All 29 grids on disk. Rows 43 and the carve row are re-open passes, which is the cheaper
shape when a fix lands after a grid was written.

## Outcome, 2026-09-21

All four picks were gridded, and every cell got a verdict: `state-grid-unsampled.md` (41),
`state-grid-remedies.md` (23), `state-grid-shield-record.md` (21), and a re-open section
in `state-grid-gate-unknowns.md` (12 new, 6 re-verdicted).

Filed: bv2-xjwnp, bv2-zlqjy, bv2-l1dtz, bv2-vrnur (shield record: P6, P3, R10, P4);
bv2-szx4c, bv2-68uqa, bv2-0686z (remedies: C15/C16, C20, C18); bv2-ujyy2 (Unsampled
U-GAP). Noted on bv2-rj5ow (gate E6).

**The same shape again.** Every forbidden-direction finding is a fix that covered one
cell and stopped. The remedy screen was applied to admit's refusal and not to
admitRunID's, two lines below. ca5d099 raised one core bar and not its `--allow-degraded`
sibling. 470317c reused same-run teardown checks across runs, where the window is
open-ended.

**Process note for the next round.** A clean worktree is deleted at a staged
"GRID WRITTEN" handback, and the reviewer's shell stays pinned to the dead path. The
Unsampled reviewer lost its spike pass this way, and the orchestrator finished its re-open
pass by reading. Either skip the staged pause, or have the reviewer keep an untracked file
in its worktree until the final return.

Not filed, with reasons:
- Unsampled U8b: the default posture not faulting an unread limit is deliberate
  (report.go:91-94).
- Gate A6: `--strict` green on unresolved paths is the owner decision bv2-c80hv.
- Gate E3: `--strict` green on the carve unknown alone. Failing it would invent refusals.
- Shield record R10-kind, R13, P5, R12, R2: allowed direction, by design, documented, or
  a teardown residual.
- Remedies C3: a withheld flag that would have worked is the allowed direction.
