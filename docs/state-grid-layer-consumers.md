# State grid: enforce.Layer x its user-facing consumers

## Phase 0 - fit

Signals: an enum times its call sites (Layer x State consumed in cmd/bento and internal/linux),
plus a lot of fix history in internal/linux around report reconciliation. The invariant is one-sided:
a consumer may say too little about an Enforced layer, but must never show a Degraded or Unavailable
layer as fine, drop it, or give it a legend or remedy that belongs to another layer or tier. Human and JSON.
Fit: good, but narrow. Most consumers loop over the layers generically, so most of the grid
collapses into a single row per consumer.

Correction to the brief: the enum has **8** layers, not 10 (enforce/report.go:9-33): filesystem,
network, exec-block, exec-strict, limits-memory, limits-pids, limits-cpu, auto-exec-report.

Out of scope: admission and post-run agreement (TestAdmissionAndPostRunShortfallAgree).

## What each producer can emit (source of reachable cells)

| layer | probe.go | applied.go reconcile | degraded.go | scopeattest.go | linux.go worsenNetwork |
|---|---|---|---|---|---|
| filesystem | E / D (Landlock-only tier, with Consequences) / U | U (silent, unreached), D (bwrap + backstop failed, applied.go:482), U (no-ns tier + Landlock failed) | D or U rebuilt via filesystemLayer (:390) | - | - |
| network | E / U | - | U (:395) | - | D / U mid-run |
| exec-block | E (with Consequences) / U | U | - | - | - |
| exec-strict | E / U | U, D (basic filter where strict wanted, only if not already U) | - | - | - |
| limits-* (x3) | E / D / U per controller | - | - | U when a cap did not bind (:176) | - |
| auto-exec-report | E / U (with Consequences) | - | - | - | - |

## Grid 1 - generic consumers (one loop covers every layer x state)

Every consumer below iterates `r.Layers` or `r.Degradations()` with no per-layer branch except
`ReportOnly()`. That makes each one HANDLED for all 24 layer/state cells at once, which I checked by
running all 8 x 3 cells through each consumer.

| # | consumer | verdict | stamp |
|---|---|---|---|
| G1 | toReportJSON (render.go:103) - doctor JSON, refusal envelope (run.go:319, :421) | HANDLED: one entry per layer, state and tier from the enum, detail + consequences whole; fully_enforced = !HasDegradation; empty report -> noReport | VERIFIED BY SPIKE (24 cells) |
| G2 | toRunReportJSON (render.go:130) - run verdict/failed JSON | HANDLED: listed like G1; fully_enforced ignores ReportOnly layers only (auto-exec-report). The layer's own state is still shown unavailable, so nothing is hidden | VERIFIED BY SPIKE |
| G3 | writeReportTable (render.go:567) - doctor human | HANDLED: every row with state; long/consequence detail relocated to a note via Disclosure() | VERIFIED BY SPIKE |
| G4 | writeDegradations (render.go:2015) - run human | HANDLED: every non-Enforced layer printed with Disclosure(); ReportOnly split into its own header | VERIFIED BY SPIKE |
| G5 | writeRefusal (render.go:977) - run/profile human | HANDLED: each Short layer with state + Reason. The "fallback tier" doctor pointer fires on any short layer that has Consequences. Only filesystem-Degraded (probe.go:279) and auto-exec-report-Unavailable (probe.go:137) carry Consequences while short, and auto-exec-report never reaches Short (forLayers drops it; judgedLayers at run.go:327). So the tier-worded line never lands on the wrong layer | VERIFIED BY SPIKE (render) + READING (Consequences producers) |
| G6 | gatedShortfall / Ready / exit code (doctor.go:127, :150) | HANDLED: derived from enforce.BaselineLayers, so it never drifts from admission | VERIFIED BY READING |

## Grid 2 - per-layer branches

### 2a writeDegradedSummary (render.go:1784, doctor human; only reached when no baseline shortfall and no anchor error, doctor.go:95-103)

| layer | D | U |
|---|---|---|
| filesystem | IMPOSSIBLE: baseline layer, so doctor.go:95 returns before the summary. Text would read "manifests run by default ... filesystem refused", which contradicts itself, but it can't be reached | same |
| network | IMPOSSIBLE in doctor: the probe emits only E/U (probe.go:242) | IMPOSSIBLE: U is coupled to a short filesystem layer, so gated first. The coupling lives in another package and is pinned by TestAnUnavailableNetworkLayerNeverLeavesFilesystemEnforced (passes, VERIFIED BY EXECUTION) |
| exec-block | IMPOSSIBLE (probe E/U only) | HANDLED "runs with the gap reported". Matches admit (hardening) |
| exec-strict | IMPOSSIBLE in probe | HANDLED "reported" |
| limits-memory/pids/cpu | HANDLED "refused by default". Matches unenforcedRequestedLimits | HANDLED |
| auto-exec-report | IMPOSSIBLE (probe E/U) | HANDLED as host-only, no refusal claim |

Stamp: all texts VERIFIED BY SPIKE (rendered every cell); reachability VERIFIED BY READING.

### 2b writeRefusalRemedy (render.go:1055, run refusal)

| Short contains | verdict |
|---|---|
| no limits layer, strict | HANDLED: silent |
| limits only, Waivable | HANDLED: offers --allow-degraded or dropping `limits:` |
| limits only, strict | HANDLED: offers dropping `limits:` only |
| limits + other layer, strict | HANDLED: silent, so it doesn't send the reader back to the same refusal |
| undeliverable exec block, Waivable | HANDLED: offers --allow-degraded, naming what running without the block costs |
| any other layer, Waivable | HANDLED: offers --allow-degraded with an unspecific consequence, so a third Waivable producer inherits a hint rather than silence |
| limits + exec, Waivable | UNREACHABLE today: admit returns one refusal at a time (exec before limits), but the writer names both rather than resting on that |

VERIFIED BY READING.

### 2c Denial legend + exec hint (render.go:687 blockedExecMode, :740 writeDenialLegend), run human, post-run report

Rows are the filesystem layer state on a zero-network-rule manifest, split by which tier produced that state.

| filesystem state / tier | legend output | verdict |
|---|---|---|
| E / bwrap | EROFS + ENOENT + ENETUNREACH lines | HANDLED |
| D / Landlock-only tier (probe) | EPERM-on-socket line | HANDLED |
| **D / bwrap tier, Landlock backstop failed in-sandbox (applied.go:482)** | **prints `"Operation not permitted" on a socket or connection`**. That is the seccomp tier's errno. This run has a netns and answers ENETUNREACH | **WRONG**, forbidden direction (a legend that belongs to another tier). The comment at render.go:771-777 says the zero-rule test separates the two Degraded states, but both states have zero rules, so the test tells them apart only when the manifest has rules. The report carries nothing but the Reason text to distinguish them. VERIFIED BY SPIKE (render); reachability VERIFIED BY READING (applied.go:480-484 sets D when mountConfined; the legend runs on a clean exit, run.go:615) |
| U (any) | silent on fs/net | HANDLED (says too little, which the invariant allows) |

| exec-block / exec-strict | blockedExecMode | verdict |
|---|---|---|
| exec E, strict E | mode named | HANDLED |
| exec E, strict D (basic filter where none-strict was asked) | still names "exec: none-strict" with "Operation not permitted on a command" / 126 hint | HANDLED: execve is still blocked, so the line is true. It just doesn't mention fork (allowed direction). writeDegradations names the strict gap. READING |
| exec D/U | "" -> silent | HANDLED (render.go:687) |

## Phase 2 re-open pass

- 930d8fc (exec fallback upgrading exec-strict): I checked the same row for the filesystem Set at applied.go:482. enforce.Run's overlay propagates only a state that got worse (comment at applied.go:475), and noteScopeLimits acts only on an Enforced layer. The row is carried. READING.
- 1fb7ae3 (doctor promising a refusal no manifest can trigger): the ReportOnly split carries into writeDegradations (G4) and toRunReportJSON (G2). The row is carried. SPIKE.
- 66f7558 (failed run shortfall wrapping): G4/G5 wrap. Carried.
- bd open list: no matches for legend/render/doctor/layer.

## Findings

1. **WRONG, forbidden direction** - writeDenialLegend on a bwrap-tier run whose Landlock backstop failed, zero network rules: it prints the Landlock-only tier's EPERM-on-socket shape for a netns run. VERIFIED BY SPIKE (render), READING (reachability). Possible fix: key the seccomp line on a tier fact the Result carries instead of on filesystem==Degraded.
2. Coupling note (not a defect): doctor's summary is only correct because of a probe fact in internal/linux (network U implies filesystem short). It is pinned by a test there, and that test passes. VERIFIED BY EXECUTION.

## Cells not walked

- Profile's use of writeRefusal was treated as identical to run's and not traced separately.
- JSON has no legend counterpart, so 2c has no JSON cells.

## Status, 2026-09-17

Row D fixed: the seccomp egress legend line is keyed on enforce.Result.Degraded, set in
enforce.Run, not on zero rules plus filesystem Degraded (0085cec).
