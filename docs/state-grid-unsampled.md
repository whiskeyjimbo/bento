# State grid: `enforce.Unsampled` x every State comparison

Area: the `Unsampled` constant (enforce/report.go:102), inserted between Enforced and
Degraded, crossed with every ordinal comparison, equality test, and max-fold that reads a
`State`. Base: 265a790.

## Phase 0 - fit

Good fit. One strong signal (an enum times its call sites: 4 constants, ~25 comparison
sites across enforce, cmd/bento, internal/linux) plus a degradation dimension (Unsampled is
literally "could not tell"). Invariant, one-sided:

- A state may read WORSE than the host is, never better. No site may treat Unsampled as at
  least as good as a state it did not deliberately rank it against.

Allowed direction: a site treating Unsampled as Degraded/Unavailable (over-refusal,
over-disclosure). Forbidden direction: a site admitting, not faulting, or reporting clean
on Unsampled where it would not on Degraded, without a comment choosing that.

## Phase 1 - dimensions (from the code)

- **Producer reach.** Exactly one writer of Unsampled in the tree:
  `noteScopeLimits` (internal/linux/scopeattest.go:189), iterating `limitControllers`
  (scopeattest.go:164-173), i.e. only the three limits layers, only post-run, only
  replacing an Enforced entry (guard at :185). The probe never emits it (probe.go:102-257
  emits only Enforced/Degraded/Unavailable). So the layer dimension collapses to
  {limits layer, any other layer} and the WHEN dimension to {probe/pre-run report,
  post-run report}.
- **Site kind.** threshold (`>= X`, `< X`), equality (`== X`, `!= Enforced`), fold (max).
- **Posture** (only for the postRunShortfall rows): default, allow-degraded, strict,
  x run id set / unset.

Cells = site x reachable (layer, WHEN) combination. Unreachable combinations are listed
once per site as IMPOSSIBLE with the producer cite; the coupling gap is recorded
separately (U-GAP).

## Phase 2 - grid

| Cell | Site | Reads | Unsampled reach | Verdict |
|------|------|-------|-----------------|---------|
| U1 | `shortfall` report.go:322 (`>= atLeast`) | any, bar param | via callers | HANDLED: generic; correctness is per bar passed (U2-U4, U8) |
| U2 | `admit` default run.go:552 `shortfall(TierCore, Unsampled)` | core, probe | IMPOSSIBLE at probe (no producer); bar deliberately Unsampled so a future core Unsampled refuses | HANDLED (deliberate, comment report.go:93-98) |
| U3 | `admit` allow-degraded, core bar Unavailable (run.go:~520) | core, probe | IMPOSSIBLE (probe never emits it) | IMPOSSIBLE - probe.go only producer of pre-run states; latent: a core Unsampled would be admitted under --allow-degraded while Degraded also is, so same rank; not forbidden |
| U4 | `admit` strict run.go:529 `Degradations()` (`!= Enforced`) | all | n/a | HANDLED: != Enforced catches it |
| U5 | `admit` default limits bar, literal Degraded | limits, probe | IMPOSSIBLE (probe) | IMPOSSIBLE - pre-run; composition with admitRunID documented at run.go:422-433 |
| U6 | `admitRunID` run.go:743 `limitsBar(opts)`=Unsampled | limits, probe | IMPOSSIBLE (probe) | HANDLED: bar deliberately Unsampled |
| U7 | `postRunShortfall` strict run.go:402 | all post-run | limits Unsampled reachable | HANDLED: Degradations() faults it |
| U8a | `postRunShortfall` default, core bar Unsampled run.go:414 | core post-run | no producer | HANDLED (deliberate bar) |
| U8b | `postRunShortfall` default, limits, no run id, bar Degraded | limits post-run | REACHABLE | HANDLED - deliberate exemption, argued at report.go:91-94 and run.go:774-779: a could-not-tell does not fault a completed run. Ranked on purpose, not by accident |
| U8c | `postRunShortfall` default, limits, run id, bar Unsampled | limits post-run | REACHABLE | HANDLED: faults (limitsBar run.go:434) |
| U9a | `postRunShortfall` allow-degraded, core bar Unavailable run.go:409 | core post-run | no producer | IMPOSSIBLE today; see U-GAP |
| U9b | `postRunShortfall` allow-degraded, limits, no run id | limits post-run | REACHABLE | HANDLED: limits waived entirely under --allow-degraded (run.go:405-408), Unsampled treated same as Degraded/Unavailable |
| U9c | `postRunShortfall` allow-degraded, limits, run id | limits post-run | REACHABLE | HANDLED: limitsBar -> Unsampled, faults |
| U10 | `undeliverableExecBlock` run.go:764 `>= Unavailable` | exec layers post-run and probe | no producer for exec | IMPOSSIBLE today (scopeattest.go:164 table has no exec row); integer-accident placement: an exec Unsampled would read as "not undeliverable". See U-GAP |
| U11 | `unenforcedRequestedLimits` run.go:783 `>= atLeast` | limits | REACHABLE | HANDLED: bar is the parameter, both callers choose it (U8b/U8c/U6) |
| U12 | overlay run.go:242 `l.State > required.StateOf` | required layers post-run | REACHABLE (limits) | HANDLED: Unsampled > Enforced so it is adopted; noteScopeLimits only writes over Enforced (scopeattest.go:185), so Unsampled never meets a probe Degraded here |
| U13 | report-only overlay run.go:276 | report-only | no producer | IMPOSSIBLE (limitControllers has no report-only layer) |
| U14 | run.go:140 `StateOf(Filesystem) == Degraded` | filesystem, probe | no producer | IMPOSSIBLE |
| U15 | run.go:163 `probed.StateOf(Network) == Unavailable` | network, probe | no producer | IMPOSSIBLE |
| U16 | `StatusOf`/`probedState`/`StateOf` report.go:254 max-fold | any | REACHABLE (limits) | HANDLED: only one entry per layer after Set (report.go:194-213); a duplicate Unsampled+Degraded would fold to Degraded, both faulted by every bar that faults Unsampled except U8b which faults Degraded - so folding toward Degraded reads worse, allowed |
| U17 | `HasDegradation`/`Degradations` report.go:264/275 | any | REACHABLE | HANDLED: != Enforced |
| U18 | `forLayers` report.go:313 synthesis | required | n/a (writes Unavailable for absent) | HANDLED: absence folds to most severe, not to Unsampled (report.go:85-89 argues it) |
| U19 | doctor.go:163 `>= Unavailable` hardening in zero-policy set | exec layers, probe | IMPOSSIBLE (probe; limits not in zero-policy set) | IMPOSSIBLE - doctor reads the probe only; see U-GAP |
| U20 | doctor.go:176 `gatedShortfall` via Degradations | baseline, probe | n/a | HANDLED: != Enforced |
| U21 | render.go:141 `!= Enforced` FullyEnforced | any post-run | REACHABLE | HANDLED: a run with an Unsampled limit is not fully enforced |
| U22 | render.go:111 `!HasDegradation()` | any | REACHABLE | HANDLED |
| U23 | render.go:116/580 `State.String()` | any | REACHABLE | HANDLED: "unsampled" case in String (report.go:113); JSON carries the string, not the int, so the renumbering of Degraded/Unavailable did not change any serialized form |
| U24 | render.go:687 exec `!= Enforced` | exec post-run | no producer | HANDLED either way (!= Enforced) |
| U25 | render.go:755 filesystem `== Enforced` | filesystem | no producer | HANDLED either way (Unsampled would read as not confined - worse) |
| U26 | render.go:778 filesystem `== Degraded` | filesystem | no producer | IMPOSSIBLE |
| U27 | render.go:1880-1881 host banner, limits unconditional, exec `>= Unavailable` | probe | IMPOSSIBLE (probe) | IMPOSSIBLE - host banner renders a probe report |
| U28 | render.go:2195 Degradations | any | REACHABLE | HANDLED |
| U29 | validate.go:416 `== Enforced` hostPosture | probe | IMPOSSIBLE (probe) | HANDLED either way (!= Enforced is listed) |
| U30 | degraded.go:420 `StateOf(Filesystem) < Degraded` | filesystem, probe | IMPOSSIBLE | IMPOSSIBLE; were it reachable, Unsampled would be rebuilt to the degraded tier verdict - worse, allowed |
| U31 | degraded.go:425 `StateOf(Network) < Unavailable` | network, probe | IMPOSSIBLE | IMPOSSIBLE; would be set Unavailable - allowed |
| U32 | applied.go:466 exec-strict `< Unavailable` then Set Degraded | exec-strict, applied reconcile | no producer; order: applied reconcile precedes noteScopeLimits and never touches limits | IMPOSSIBLE; were it reachable, Unsampled -> Degraded is worse, allowed |
| U33 | applied.go:515 filesystem `< Unavailable` then Set Degraded | filesystem | IMPOSSIBLE | IMPOSSIBLE; same as U32 |
| U34 | linux.go:661 `networkState` max-fold | network | IMPOSSIBLE | IMPOSSIBLE |
| U35 | scopeattest.go:185 `StateOf(limit) != Enforced` skip | limits | self | HANDLED: Unsampled only replaces Enforced, so it can never upgrade a Degraded/Unavailable probe verdict - the one place a mid-enum insert could have read better |
| U36 | profile.go:94/99 `!= Enforced` | limits, profiling probe | n/a | HANDLED; profiling uses unattestedScopeCaps (scopeattest.go:208-212), which refuses an unsampled scope outright - stricter than run's U8b, allowed |
| U-GAP | coupling: "Unsampled only on limits layers" | - | - | UNHANDLED (coupling gap, not a live defect): U3, U9a, U10, U19, U27 are IMPOSSIBLE only because limitControllers has no core/exec row. At U10/U19/U27 the `>= Unavailable` bar would rank an exec Unsampled as "delivered" by integer accident, and at U3/U9a allow-degraded would admit a core Unsampled. Nothing fails to compile if a second producer appears |

Tally (first pass): 41 cells (U1-U36 with U8/U9 split, plus U-GAP). HANDLED 25, IMPOSSIBLE
15, UNHANDLED 1 (U-GAP, latent), WRONG 0.

## Inherited verdicts

- state-grid-admission.md: its State axis is {enforced, degraded, unavailable}. Every cell
  on the limits x post-run rows is reopened by Unsampled; U7-U9c re-walk them. Its one-sided
  invariant (admit refuses S => post-run faults S) still holds for Unsampled because admit
  never sees it (U5, U6).
- state-grid-layer-consumers.md / state-grid-host-shortfall.md: probe-only consumers
  (host note, doctor, validate) inherit IMPOSSIBLE for Unsampled; post-run renderers
  (U21-U28) re-walked above.

## Re-open pass, 2026-09-21 (orchestrator, read only)

The reviewer's worktree was removed at its staged handback, so the orchestrator did this pass
by reading, and nothing was spiked.

- **The IMPOSSIBLE verdicts hold.** A tree-wide grep for `Unsampled` outside `enforce/`
  finds one writer, `internal/linux/scopeattest.go:189`. There is none in
  `internal/launcher` and none in `degradedProbe`. VERIFIED BY EXECUTION (grep at 265a790).
- **ca5d099 closed half of U-GAP defensively.** It raised the default-posture core bar
  from Degraded to Unsampled in both `admit` (run.go:552) and `postRunShortfall`
  (run.go:414), so a future core Unsampled writer is refused under the default posture. It
  did not carry the row: the `--allow-degraded` core bar (run.go:409,
  `shortfall(TierCore, Unavailable)`) and the exec `>= Unavailable` bars (run.go:764,
  doctor.go:163, render.go:1881) would still read a core or exec Unsampled as good enough.
  That is latent today and in the forbidden direction the day a second writer lands.
  VERIFIED BY READING.
- The planned spikes U8b, U8c, U9b and U35 did not run. Their HANDLED verdicts stay
  VERIFIED BY READING.

Filed: one item for U-GAP. Acceptance is either a test pinning that no layer outside
`limitControllers` is ever set Unsampled, or every bar routed through one predicate that
ranks Unsampled explicitly.
