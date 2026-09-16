# State grid: run admission vs post-run shortfall vs doctor readiness

Area: `enforce/run.go` (`Options.admit`, `requiredLayers`, `admitRunID`, the degraded-tier
refusals in `Run`, `postRunShortfall`, `judgedLayers`), `enforce/report.go` (`Tier`,
`shortfall`, `forLayers`), `cmd/bento/doctor.go` (`gatedShortfall`, `BaselineLayers`).

## Phase 0 - fit

Good fit. Two strong signals: a mirror pair (admit and postRunShortfall answer the same
question at two lifecycle points; doctor answers it for a baseline manifest) and an enum
cross call-site (Layer x State x posture branch). Invariant is one-sided:

- For a judged state S under posture P: admit refuses S => postRunShortfall faults S.
  (Post-run may be stricter, never more lenient.)
- doctor ready => a baseline policy is admitted under every posture (doctor may be stricter
  than `--allow-degraded`, never more lenient than any posture).
- A report-only layer never refuses, never faults, never gates doctor.

## Phase 1 - dimensions (from the code)

- Posture: default, strict, allow-degraded (`admit` switch, run.go:442; mirrored at run.go:364).
- Layer: collapses to 4 classes, because both predicates key only on `Tier()` plus the
  limits special case (`unenforcedRequestedLimits`, run.go:572):
  - core (filesystem, network)
  - hardening non-limit (exec-block, exec-strict)
  - hardening requested limit (limits-memory/pids/cpu)
  - report-only (auto-exec-report; `ReportOnly`, run.go:393)
- State: enforced, degraded, unavailable.
- Side conditions only admission checks (not in the proposed grid, found in code):
  RunID set (`admitRunID`), degraded tier + DenyPaths/NetworkGate/network rules
  (run.go:192-210), network Unavailable outside the degraded tier (run.go:162).

Grid A: posture x layer class x state = 3 x 4 x 3 = 36 cells (spike ran the uncollapsed
3 x 8 layers x 3 = 72).
Grid B: doctor, baseline layer (filesystem) state x posture = 9 cells.
Grid C: admission-only side conditions x post-run = 4 cells.
Total 49 cells.

## Grid A - admit vs postRunShortfall

Refuse / fault per cell. All HANDLED: both sides use the identical predicate per branch
(strict: `Degradations`; allow: `shortfall(TierCore, Unavailable)`; default:
`shortfall(TierCore, Degraded)` + `unenforcedRequestedLimits`), and post-run judges exactly
the required set (`forLayers` synthesizes missing required layers, run.go:125; overlay only
worsens, run.go:239; `judgedLayers` strips report-only, run.go:363).

| Posture | Layer class | enforced | degraded | unavailable |
|---|---|---|---|---|
| default | core | pass/pass | refuse/fault | refuse/fault |
| default | hardening | pass/pass | pass/pass | pass/pass |
| default | limit (requested) | pass/pass | refuse/fault | refuse/fault |
| default | report-only | pass/pass | pass/pass | pass/pass |
| strict | core | pass/pass | refuse/fault | refuse/fault |
| strict | hardening | pass/pass | refuse/fault | refuse/fault |
| strict | limit | pass/pass | refuse/fault | refuse/fault |
| strict | report-only | pass/pass | pass/pass | pass/pass |
| allow | core | pass/pass | pass/pass | refuse/fault |
| allow | hardening | pass/pass | pass/pass | pass/pass |
| allow | limit | pass/pass | pass/pass | pass/pass |
| allow | report-only | pass/pass | pass/pass | pass/pass |

Zero mismatches. VERIFIED BY SPIKE (72-cell loop calling `admit` and `postRunShortfall` on
a single-layer report). Report-only at admit is IMPOSSIBLE: `requiredLayers` never yields it
and `forLayers` drops it (run.go:125, run.go:393).

Coupling notes (not defects):
- Report-only is defined negatively as "not in `requiredLayers` of a maximal policy"
  (run.go:393). A new policy field that makes `requiredLayers` add a layer without updating
  that maximal policy would classify a required layer as report-only and strip it from
  post-run judgment. Nothing fails to compile. VERIFIED BY READING.
- Existing coverage is one cell (run_test.go:1399, default x report-only). No table test
  walks the grid.

## Grid B - doctor ready vs baseline admission

`BaselineLayers()` = [filesystem]. `gatedShortfall` = any non-enforced filesystem entry.

| fs state | doctor ready | default | strict | allow |
|---|---|---|---|---|
| enforced | yes | admit | admit | admit |
| degraded | no | refuse | refuse | admit (doctor stricter: allowed direction, stated in doctor.go:98) |
| unavailable | no | refuse | refuse | refuse |

All 9 HANDLED at the `admit` level. VERIFIED BY SPIKE.

Caveat on "ready => admitted": `Run` also refuses a non-degraded run when network is
Unavailable (run.go:162) regardless of manifest. Doctor does not gate on network; it relies
on the Linux probe tying network Unavailable to filesystem non-enforced (doctor.go:63-72,
pinned by internal/linux TestAnUnavailableNetworkLayerNeverLeavesFilesystemEnforced).
HANDLED by cross-package coupling. VERIFIED BY READING (that test not executed here).

## Grid C - admission-only side conditions vs post-run

| # | Condition | Admission | Post-run | Verdict |
|---|---|---|---|---|
| C1 | allow-degraded + RunID + requested limit not enforced | refuses (`admitRunID`, run.go:560) | does NOT fault when the backend finds the controller undelegated mid-run (allow branch waives limits, run.go:370) | WRONG against the stated invariant (forbidden direction). VERIFIED BY SPIKE at unit level: `admitRunID` refused and `postRunShortfall` returned `[]` for the same report. Severity is a judgment call: admission's reason is "nothing to reap through", and a late discovery means the scope was created, so reaping may still work. Either mirror the RunID check into post-run or document the asymmetry. Strict and default already fault it. |
| C2 | non-degraded run, network Unavailable, policy without network rules | refuses (run.go:162) | network not in `wanted`, so a mid-run network downgrade is neither overlaid nor judged | UNHANDLED, but the refused fact is a host precondition (no netns) that cannot newly appear for a run already inside one. VERIFIED BY READING; backend side UNSPIKEABLE HERE. |
| C3 | degraded tier + DenyPaths / NetworkGate / network rules | refuses (run.go:192-210) | `degraded` is fixed pre-run; if the probe said Enforced and the backend reports filesystem Degraded mid-run under allow-degraded, post-run does not fault | Allowed direction in practice: the backend ran the full tier with shields/proxy, so the refusal reason does not apply. VERIFIED BY READING. |
| C4 | SetupSilent | n/a | refuses under every posture on `judgedDegradations` (run.go:295) | HANDLED, stricter post-run. VERIFIED BY READING. |

## Phase 2 re-open pass

Relevant fixes: be9a958 (every posture held post-run), 0e7eaaf (requested limits faulted
post-run, default only), 2e674a8 (run ids screened on required limits at admission),
2a34f9d (err arm held to posture bar), 641a83b / e90e2dd (report-only kept out of judgment),
1fb7ae3 / bcdce90 (doctor vs network refusal).

- 2e674a8 added the RunID row at admission; neither 0e7eaaf nor be9a958 carried it to
  post-run under allow-degraded. That is cell C1.
- 641a83b / e90e2dd: re-walked; report-only cells hold across all postures (Grid A).
- 2a34f9d: the err arm calls the same `postRunShortfall` (run.go:275), so Grid A covers it.
- `bd list --status=open` matched nothing for admi/doctor/shortfall/posture.

## Proposed exhaustive test

One table test in enforce: loop posture x every Layer constant x State, build a single-layer
report, assert `(!l.ReportOnly() && o.admit(r) != nil) == (len(postRunShortfall(o, r)) > 0)`,
and assert report-only never faults. A second loop over filesystem state x posture asserts
`len(r.forLayers(BaselineLayers()).Degradations()) == 0` implies `o.admit(...) == nil`.
Keep the Layer list in the test next to a guard that fails when a constant is missing, so a
new layer forces an edit. C1 gets its own case once its intended behavior is decided.
