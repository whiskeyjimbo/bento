# State grid: refusal remedies vs composed admission

Area: `enforce/run.go` (`screenRemedies`, `composedAdmission`, `Run` and every Refusal it
returns), crossed with the remedies the frontends print: `cmd/bento/render.go`
(`writeRefusalRemedy`), `cmd/bento/run.go` (`writeRunResult`, human and `--json`
`allow_degraded_would_admit`), `cmd/bento/profile.go` (`preflightHost`). Base: 265a790.

## Phase 0 - fit

Good fit. Mirror pair: the remedy a frontend derives from a Refusal (Waivable, Short,
NoRemedy) against the composed admission that would judge the run the reader gets by
taking it. Enum x call sites: Refusal producers x the three remedy fields. Invariant is
one-sided:

- A remedy may be withheld where it would have worked (allowed direction).
- A remedy must never be offered where composed admission, under the posture the remedy
  implies, still refuses (forbidden).
- A remedy must never be worded against the lever the refusal itself names (forbidden).

## Phase 1 - dimensions (from the code)

- Producer: every Refusal `Run` can return (run.go:117-131, 162, 190-210, 328) plus
  `preflightHost` (profile.go:474).
- Remedy the frontend derives: flag (Waivable, render.go:1076-1093), manifest edit
  (`limits:` drop, render.go:1068-1074 and 1090), JSON `allow_degraded_would_admit`
  (run.go:484), none.
- Run id set / unset, where the producer's remedy depends on it.

Remedy fields are only read where the producer sets them, so the grid is one row per
(producer, run id) with the remedy that renders, not a full cross product.

## Grid

| # | Producer (posture) | run id | Refusal fields | Remedy rendered | Composed admission of the remedy | Verdict |
|---|---|---|---|---|---|---|
| C1 | `ValidateRunID` (any) | bad | no Short, not Waivable | none | n/a | HANDLED - withheld, render.go:1068 |
| C2 | `admitEnv` (any) | any | no Short | none | n/a | HANDLED - withheld |
| C3 | admit default, core Unsampled/Degraded | any | Short=core | none | flag would admit (Unavailable bar) | HANDLED - allowed-direction withholding |
| C4 | admit default, core Unavailable | any | Short=core | none | flag refuses | HANDLED |
| C5 | admit default, undeliverable exec block | unset | Waivable, Short=exec | flag | admit(allow) passes, admitRunID nil | HANDLED - run.go:668 |
| C6 | admit default, undeliverable exec block | set, limits Enforced | Waivable, Short=exec | flag | admitRunID passes | HANDLED |
| C7 | admit default, undeliverable exec block | set, no limits | Waivable | NoRemedy | admitRunID arm 1 refuses | HANDLED - run.go:668-671 |
| C8 | admit default, requested limits Degraded/Unavailable | unset | Waivable, Short=limits | flag + edit | flag: passes. edit: admitRunID nil, admit default passes | HANDLED |
| C9 | admit default, requested limits short | set | Waivable, Short=limits | NoRemedy | flag: admitRunID arm 2 refuses (bar Unsampled) | HANDLED - both withdrawn together, run.go:670 |
| C10 | admit strict, limits whole shortfall | unset | Short=limits | edit | admit strict on the rest passes | HANDLED - render.go:1069 |
| C11 | admit strict, limits whole shortfall | set | Short=limits | NoRemedy | edit: admitRunID arm 1 refuses | HANDLED - run.go:684-690 |
| C12 | admit strict, mixed shortfall | any | Short=mixed | none | edit leaves the rest | HANDLED - render.go:1069 |
| C13 | admit allow-degraded, core Unavailable | any | Short=core | none | n/a | HANDLED |
| C14 | `admitRunID` arm 1 (no limits) | set | no Short | none | n/a | HANDLED - reason names "set a limit or drop the run id" |
| C15 | `admitRunID` arm 2, default posture, limits Unsampled | set | Short=limits, not Waivable, NOT screened (run.go:130) | edit ("drop `limits:`") | edit: admitRunID arm 1 refuses; reason says drop the run id | WRONG - forbidden direction, both halves |
| C16 | `admitRunID` arm 2, allow-degraded, limits Degraded/Unavailable/Unsampled | set | same as C15 | edit | same | WRONG - same as C15 |
| C17 | `admitRunID` arm 2, strict | set | unreachable: strict admit refuses first on the same layer | - | - | IMPOSSIBLE - run.go:444 `Degradations` covers Unsampled limits |
| C18 | netns Unavailable, not degraded (run.go:162) after a Waivable admit | any | runs only after admit | flag offered on the earlier refusal | flag: composedAdmission passes, Run then refuses at run.go:162 | WRONG for a generic Enforcer (probe with fs Enforced, network Unavailable on a zero-rule manifest); IMPOSSIBLE on Linux (probe ties the two, per run.go:152) |
| C19 | degraded-tier refusals (DenyPaths/gate/rules, run.go:190-210) after a Waivable admit | any | - | flag | waived run's tier is the same probe; Waivable needs core Enforced (run.go:552), so `degraded` stays false | IMPOSSIBLE - run.go:133 + run.go:552 |
| C20 | SetupSilent (run.go:328) | any | Short=`judgedDegradations`, not Waivable | edit when Short is all limits (allow-degraded, limits Degraded) | admission would admit the edit, but the refusal is about the stage never attesting | WRONG - wording contradicts the lever (stage/DispatchReexec) |
| C21 | Policy `Validate`/`RequireExpanded` | any | plain error | none | n/a | HANDLED - not a Refusal |
| C22 | `--json` refusal, any producer | any | `allow_degraded_would_admit`=Waivable post-screen | flag bit only | same as the human flag rows | HANDLED except where C18 holds |
| C23 | `preflightHost` (profile) | n/a | Short=core | none (no `writeRefusalRemedy`, profile.go:128) | n/a | HANDLED - withheld |

23 cells: 17 HANDLED, 4 WRONG (C15, C16, C18, C20), 2 IMPOSSIBLE (C17, C19), 0 UNHANDLED.

Coupling note on C19: IMPOSSIBLE rests on admit's default core bar (run.go:552) and the
single `degraded` computation (run.go:133); nothing in `screenRemedies` states it.
Also note the doc's claim "any check Run composes after admit inherits the same gap" is
answered only for `admitRunID`; C18 is the concrete check it leaves out.

## Phase 2 re-open pass (closed work on this row)

- 715ec11 / 4490bd7 (withdraw a remedy admission refuses; screen the edit too): fixed C9
  and C11, the refusals that reach `screenRemedies` from `admit`. The row was not carried:
  `admitRunID` arm 2 returns at run.go:130 without screening, so C15/C16 keep the edit.
- fa78083 / bv2-mhfja (name the live lever): fixed the C11 wording. The same contradiction
  (edit says drop `limits:`, reason says drop the run id) is live at C15/C16, where no
  screening happens at all.
- a5d251f / bv2-4xviy (flag on any waivable refusal): C5/C6. Carried. Its doc paragraph
  on the non-waivable branch assumes only strict reaches it with limits-only Short;
  C15, C16 and C20 reach it too.
- bv2-2eirs (JSON would_admit): C22. Carried, except C18.
- bv2-no8ru, be1a6da / bv2-dnda5 (Unsampled state, run-id bar): introduced the Unsampled
  limits state that makes C15 reachable under the default posture. admit keeps the
  Degraded bar and hands Unsampled to admitRunID by design (run.go:427), which is
  exactly the unscreened path.
- bv2-f628 (strict + allow-degraded rejected): why strict never names the flag. Carried.
- bv2-3h4 (allow-degraded waives limits): design, sets C8. No cell change.

## Phase 3 - verification

Spike: `cmd/bento` test driving `enforce.Run` with a fake Enforcer and rendering
`writeRefusalRemedy` on the refusal (throwaway worktree, deleted).

- C15 VERIFIED BY SPIKE: default, run id, limits-memory Unsampled -> Waivable=false,
  NoRemedy=false, remedy printed "drop `limits:`". The same run with limits dropped refuses
  ("sets no resource limits ... drop the run id").
- C16 VERIFIED BY SPIKE: allow-degraded, run id, limits Degraded -> same output.
- C20 VERIFIED BY SPIKE: allow-degraded, limits Degraded, silent stage -> the stage-death
  reason followed by "drop `limits:`".
- C18 VERIFIED BY SPIKE (fake Enforcer): fs Enforced, network Unavailable, zero-rule
  manifest, limits Degraded -> Waivable=true, both flag and edit printed. With
  --allow-degraded the run refuses at run.go:162. JSON would say allow_degraded_would_admit
  true. Not reachable on Linux (VERIFIED BY READING, run.go:152 comment + probe).
- Inverted dismissals, VERIFIED BY SPIKE: C9, C11, C17 (NoRemedy set, no remedy printed),
  C8 (flag + edit both admit: edited run admitted), C19 (allow-degraded + DenyPaths with
  fs Enforced admits), C3 (withheld, allowed direction). Rest VERIFIED BY READING.

## Findings

1. C15/C16 (forbidden, both halves): run.go:130 skips screenRemedies; render.go:1068-1074
   offers the dead-end edit against a reason naming the run id.
   Bead: "enforce: screen the remedy on admitRunID's limits refusal".
2. C20 (forbidden, wording): run.go:328-335 Short=judgedDegradations lets
   render.go:1068 offer "drop `limits:`" on a stage-death refusal.
   Bead: "run: a silent-stage refusal offers the limits edit".
3. C18 (forbidden, generic Enforcer only): composedAdmission omits run.go:162.
   Bead: "enforce: composedAdmission omits the netns refusal".

Rejections: C3 withholds a flag that would work - allowed direction, the documented core
bar. C19 IMPOSSIBLE holds by run.go:133 + run.go:552 only; no test ties it to screening
(coupling note, not a defect).
