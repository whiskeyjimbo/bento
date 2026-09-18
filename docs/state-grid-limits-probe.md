# State grid: cgroup limits probe internals vs the reported enforce.State

Area: `internal/linux/limits.go` (`cacheProbe`, `measureScope`, `measureDelegatedControllers`,
`hostSafetyDelegationState`, `cpuDelegationState`, `unifiedCgroupReadable`,
`abandonedProbeReason`, `scopeProbeTimeout`, `probeWaitDelay`) against the consuming end:
`internal/linux/probe.go:96-118` + `limitsLayers` (:199), `internal/linux/scopeattest.go`
(`attestScopeLimits`, `noteScopeLimits`), and the four report-assembly arms in
`internal/linux/linux.go` and `internal/linux/degraded.go`, plus `internal/linux/profile.go:75-100`.

Inherited, not re-walked: posture x requested-limit admission is `docs/state-grid-admission.md`
(Grid A "limit (requested)" rows, cell C1); layer x consumer rendering is
`docs/state-grid-layer-consumers.md`. This grid stays below that boundary.

## Phase 0 - fit

Accepted. Signals: a mirror pair (the pre-run probe and the post-run scope attestation answer
the same question at two lifecycle points, on three tiers that must agree), plus a degradation
axis - every helper here returns `(T, bool)` where the bool is "did the probe answer at all",
the classic empty-because-clean vs empty-because-unasked shape.

Invariant, one-sided:

> A limit may be reported UNENFORCED when it was in fact enforced (conservative miss, allowed).
> It must NEVER be reported Enforced when the probe was unknown, timed out, the unified cgroup
> was unreadable, or the controller was undelegated.

## Phase 1 - dimensions (from the code)

Limit kind is a weak axis: memory and pids both route through `hostSafetyDelegationState` and
cpu through the near-identical `cpuDelegationState`, so it is kept only as the cheap baseline
grid. The axis that actually partitions behaviour is **which consumer reads the probe's answer**.

- Grid A (18 cells): limit kind {memory, pids, cpu} x probe outcome {delegated, undelegated,
  controllers unknown, unified cgroup unreadable, scope probe timed out / abandoned, answer
  served from `cacheProbe`}.
- Grid B (12 cells): consumer {Probe report assembly, bwrap run, degraded run, profile gate}
  x post-probe reality {cap bound, cap accepted but absent, no scope sampled}.

30 cells. All 30 walked.

## Grid A - probe outcome -> reported State

Driven through the real `Probe` with `scopeProbe` / `delegatedControllers` /
`unifiedCgroupReadable` swapped per row (spike, see Phase 3). Rows are uniform across the three
limit kinds except where noted.

| # | probe outcome | memory | pids | cpu | verdict |
|---|---|---|---|---|---|
| A1 | delegated | Enforced | Enforced | Enforced | HANDLED - limits.go:159 / :247, gated on a creatable scope at probe.go:108 |
| A2 | controller undelegated (per controller) | Unavailable | Unavailable | Unavailable | HANDLED - limits.go:156-158, :244-246. Partial delegation is per controller, so a cpu-only gap does not fault memory/pids (spike row "cpu undelegated") |
| A3 | controllers unknown (`measureDelegatedControllers` errored, or the marker was absent) | Unavailable | Unavailable | Unavailable | HANDLED - `known==false` fails closed at limits.go:153-155 and :241-243; not memoized (limits.go:71) |
| A4 | unified cgroup unreadable (cgroup-v1-only, or v2 mounted off `/sys/fs/cgroup`) | Unavailable | Unavailable | Unavailable | HANDLED - screened at limits.go:269 before any scope is created; returns `(nil,false)` into A3 |
| A5 | scope probe timed out / caller abandoned it | Unavailable | Unavailable | Unavailable | HANDLED - `measureScope` returns `answered=false` (limits.go:116, :129, :136); `canCreateScope` maps a non-answer to `false` (limits.go:88-90); probe.go:100-106 defaults the three layers Unavailable and only fills them inside `if scopeOK` |
| A6 | answer served from `cacheProbe` (earlier call) | as cached | as cached | as cached | HANDLED at the cache level - only an answered measurement is memoized (limits.go:71-73), so a transient failure is re-probed. See finding 3 for what a *stale* cached yes means downstream |

`limitsLayers` (probe.go:199-208) overwrites all three with the scope reason whenever
`scopeOK` is false, so no A5/A4 row can leak an Enforced default. Zero forbidden-direction
cells in Grid A. VERIFIED BY SPIKE (A1-A5), BY EXECUTION (A6:
`TestCacheProbeMemoizesOnlyAnsweredMeasurements`, passes).

## Grid B - consumer x what the run actually got

| # | consumer | cap bound | cap accepted but absent | no scope sampled |
|---|---|---|---|---|
| B1 | `Probe` report assembly (probe.go:96-118) | HANDLED | n/a - the probe runs before any run; delegation is its proxy for this (limits.go:309-331) | n/a |
| B2 | bwrap run (linux.go:190-236, `noteScopeLimits` at :285/:305/:325/:359) | HANDLED - layer left Enforced | HANDLED - worsened to Unavailable, scopeattest.go:172-176 | **UNHANDLED (finding 2)** - `a.caps` empty, loop does nothing, the probe's Enforced stands |
| B3 | degraded run (degraded.go:172-186, arms at :270 / :283 / :291 / :300) | HANDLED (vacuously) | **UNHANDLED (finding 1, forbidden direction)** - no arm calls `attestScopeLimits` or `noteScopeLimits`; the probe's Enforced is returned raw | UNHANDLED - same absent channel |
| B4 | profile gate (profile.go:75-100) | HANDLED - refuses unless every requested controller reads Enforced | **UNHANDLED (finding 3)** - gate consults only the cached delegation reading; there is no Report and no attestation, so a scope that silently dropped the cap profiles untrusted code unbounded | UNHANDLED - same |

No cell is marked IMPOSSIBLE anywhere in this grid: every "cannot happen" I considered rested
on a guarantee in another file that I could not pin to a line, so it was downgraded.

## Findings (forbidden direction first)

**1. The degraded tier never reconciles the limits layers against the scope it got.**
FORBIDDEN DIRECTION. `runDegraded` wraps the launcher in a systemd scope (degraded.go:172-186)
but none of its four return arms calls `attestScopeLimits` / `noteScopeLimits`, which the bwrap
tier calls on all four of its arms (linux.go:285, :305, :325, :359). systemd-run accepts a
`MemoryMax` for an undelegated controller and silently does not apply it - the exact failure the
attestation exists for - so a degraded run can report `limits-memory: enforced` for a target that
ran unbounded. Reachable whenever the probe's cached delegation reading is right at probe time and
wrong at run time (manager restarted, `Delegate=` changed, container re-parented).
*Why it survived:* `TestEveryLayerIsAnsweredForByTheInRunCorrections` (layergrid_test.go:85)
proves the *function* moves the limits layers; nothing proves each tier *calls* it, so the test
passes vacuously for the degraded tier.
**VERIFIED BY SPIKE** - `attestScopeLimits` overridden to record its call and return
`{memory.max: false}`; a real `runDegraded` with `Limits{Memory:"256M"}` never invoked it and
returned `limits-memory = enforced`.

**2. An attestation that sampled no scope leaves the probe's Enforced standing (bwrap tier).**
FORBIDDEN DIRECTION, narrow. `noteScopeLimits` (scopeattest.go:169-177) only worsens on
`known && !bound`; an empty `scopeLimits{}` - `attestScopeLimits` gave up after
`scopeSampleTimeout` (2s), or the wrapper was `gone` - worsens nothing. scopeattest.go:47-56
argues this is deliberate and measures the fast-target case at 0/100, but the residue it names
("a host whose manager never creates the scope at all") is not distinguishable from it, and the
`default:` arm at linux.go:325 reconciles *failed* runs through the same empty reading. The
report cannot tell "the cap was verified present" from "nothing was verifiable".
**VERIFIED BY SPIKE** - `noteScopeLimits` with `scopeLimits{}` on a requested memory limit left
the layer Enforced.

**3. The profile gate has no attestation channel, so it rests on a possibly stale cache.**
FORBIDDEN DIRECTION in effect, though there is no Report to be wrong. profile.go:86-100 refuses a
requested limit whose controller is not delegated, citing "profiling untrusted code unbounded
could exhaust host resources". The reading comes from `cachedDelegatedControllers`, memoized for
the process lifetime (limits.go:62-76, :275), and profiling never re-checks or attests. In a
long-lived embedder whose manager changed delegation after the first probe, the gate passes on a
stale fact and the profiled target runs unbounded - the one thing that comment says must not
happen. **VERIFIED BY READING** (no attestation call exists on the profile path; grep of
`attestScopeLimits` / `noteScopeLimits` finds no profile.go site). A spike would need a host whose
delegation changes mid-process: **UNSPIKEABLE HERE**.

**4. Coupling note, not a defect.** `limitsLayers` is the only thing preventing an A4/A5 row from
reporting the zero-value `Enforced`: probe.go:100-106 seeds the slice Unavailable and :199-208
overwrites it. Both are one line each in a file separate from the helpers that decide `known`, and
nothing fails to compile if either is dropped. VERIFIED BY READING.

## Dismissals, inverted and checked

- **`canCreateScope` collapsing "definitive no" and "unknown" into `false`** - allowed direction.
  The unknown case is uncached, so the run-path re-probe at linux.go:190 can only add enforcement
  under a report that claimed none. Inverted assertion (all three layers Unavailable on an
  unanswered `scopeProbe`) **VERIFIED BY SPIKE** (Grid A row A5).
- **Unreadable unified cgroup** - inverted assertion (`delegatedControllers` returns `nil,false`
  and the three layers read Unavailable with `unifiedCgroupReadable` forced false)
  **VERIFIED BY SPIKE** (row A4).
- **`cacheProbe` memoizing a non-answer** - it does not. **VERIFIED BY EXECUTION**
  (`TestCacheProbeMemoizesOnlyAnsweredMeasurements`).
- **`measureScope`'s canary branch misattributing a caller cancellation** - re-read of `ctx.Err()`
  at limits.go:128 covers it. VERIFIED BY READING.
- **The bwrap run path wrapping limits on an undelegated host** - allowed direction: systemd
  ignores the property and the report already claims nothing. VERIFIED BY READING.

## Cells not walked

None in Grids A and B; all 30 have a verdict. Deliberately out of scope and NOT walked:
posture x requested-limit admission (inherited from `docs/state-grid-admission.md`), the
rendering of these states (inherited from `docs/state-grid-layer-consumers.md`), and
`probeDeadlines` accounting (`deadlines.go`) as an observability surface rather than a state
this grid's invariant ranges over.

## Suggested tests (spikes were deleted)

1. A tier-parity test asserting that every launch path which wraps a scope also samples it -
   the same override used in the spike, run against `Run` and `runDegraded`, so
   layergrid_test.go:85 stops passing vacuously.
2. An explicit assertion for cell B2: decide whether "no scope sampled" should worsen the layer
   or be surfaced as its own state, then pin whichever.

## Re-open pass (Phase 2, second half)

Run after the grid, against the shipped fixes in this area and the open board items handed
over afterwards. The question per row: which cell did the fix cover, and was the rest of its
row carried?

### Shipped fixes, cell by cell

| fix | cell it fixed | rest of the row | stamp |
|---|---|---|---|
| c4111fa "attest the limits layers against the run's scope" | B2, cap-absent | **NOT carried.** It touched linux.go, probe.go, scopeattest.go - never degraded.go. That is finding 1 | SPIKE |
| a045e6f "read the scope caps before --collect reaps them" | B2, cap-absent (timing) | Same row, same gap: a tier with no sample has nothing to reap-race | READING |
| 7a93d42 "test(degraded): prove the scoped memory cap binds" | degraded tier, cap-bound | **NOT carried.** It pins that the cap *binds* on a healthy host; nothing pins what the degraded report says when it does not. The one test that looks like it covers this (layergrid_test.go:85) tests the function, not the call site | EXECUTION (both tests pass, and pass with the gap present) |
| f8fb86d "bound the systemd-run probes with WaitDelay" + be6cb85 "bound and count the two missed probe sites" | the two scope probes (limits.go:204, :360) and the bwrap namespace probe (probe.go:499) | **NOT carried to the canary run at limits.go:124** - the one probe subprocess in the package with neither its own deadline nor a `WaitDelay`. See finding 5 | SPIKE |
| bf00401 "bound the limits probes by the caller's context" | both scope probes layered under the caller's ctx | Carried within limits.go. The sibling with no ctx at all is `attestScopeLimits` (scopeattest.go:77, pid only, 2s poll loop); in practice a cancel kills the wrapper and `gone` breaks the loop early, so it is bounded by accident rather than by the fix | READING |
| f2f3202 / a6b0091 / 137937e (per-controller gating, per-controller reasons, layer split) | A2 | Carried: probe.go:111-113, profile.go:88-99 and scopeattest.go:165-167 all key per controller | READING |
| 9a1d343 "report an unanswered host probe as unknown" + 14815bd (canary/scope split) + 6973ba4 (misattributions) | A5 | Carried across both `measureScope` exits and the delegation read | SPIKE (row A5) |
| 89d64be "cache an unreadable cgroup layout verdict" | A4 | Carried; `measureScope` deliberately does not share the screen, and its verdict is cached either way | READING |
| ee1296f "give the controller read its own oracle" (the marker) | A3 | Carried; `measureScope` needs no marker because its question *is* the exit status | READING |

### Finding 5 (new, from this pass)

**The canary run inside `measureScope` is bounded by nothing.** limits.go:124 runs
`exec.CommandContext(ctx, canary).Run()` with the caller's context and no `WaitDelay` and no
`scopeProbeTimeout` of its own - unlike `runScopeProbe` (:194, :204),
`measureDelegatedControllers` (:334, :360) and the bwrap namespace probe (probe.go:499), each of
which f8fb86d and be6cb85 bounded. A caller without a deadline (the CLI's `Probe` on the hot path
of every run) is held for as long as the canary takes. It is the failure path, so it is reached
exactly on the host that is already unhealthy, and the expiry is invisible: with no bound there is
nothing for `noteProbeDeadline` to count either.
**VERIFIED BY SPIKE** - PATH stubbed with a `systemd-run` that exits 1 and a `true` that sleeps 5s;
`measureScope(context.Background())` returned after 5.0s.
Direction: this is fail-closed as to the *verdict* (`answered=false`, layers Unavailable), so it
does not violate the grid's invariant - it violates the bound the file's own two constants exist to
provide, and it is the last site of a row the two bounding fixes otherwise completed.

### Open board items

- **bv2-03sfk** ("state-grid the cgroup delegation probe against reported limit state"):
  **discharged** by this document. One correction to its text: the grid it proposes (limit kind x
  probe outcome) is Grid A, and Grid A came back HANDLED in all 18 cells - the probe-to-report
  mapping is sound. Every defect is on the axis that item does not name, which is *which consumer*
  reads the answer (Grid B): the degraded tier and the profile gate, not the helpers. If the item
  is closed on this grid, the follow-ups are findings 1, 2, 3 and 5, not a re-run of its own shape.
- **bv2-mfvki** (profile --help promises convergence a missing exec dependency prevents) and
  **bv2-f0ikq** (clampProposal bounds neither grant count nor path length): finding 3 is
  **genuinely distinct** from both. Those two are about the profiler's *proposal output* - what it
  promises and how large a proposal it emits. Finding 3 is about the *refusal that gates profiling
  at all* (profile.go:75-100): a limits precondition read from a process-lifetime cache with no
  attestation channel behind it, which is the same mechanism as findings 1 and 2 and belongs with
  them, not with the two profile items. They share a file and nothing else.

Nothing in the pass changed a Grid A or Grid B verdict.

## Base correction (grid re-checked against docs/state-grids @ 0a45ddb)

The grid and the re-open pass above were walked on a worktree based on `main` @ 924e291, 89
commits behind the branch this lands on. Everything below is re-checked against the main
checkout at 0a45ddb. Twelve commits touch `internal/linux/` in that gap; one of them lands
squarely on this grid.

### Cites that still match byte for byte

`internal/linux/limits.go` and `internal/linux/scopeattest.go` are **unchanged** between
924e291 and 0a45ddb (`git diff` empty). Every cite into them holds exactly: the `cacheProbe`
contract (:62-76), `hostSafetyDelegationState` (:152-160), `cpuDelegationState` (:240-248),
`unifiedCgroupReadable` (:291), `delegatedControllers` (:265-273), the canary run (:124),
`noteScopeLimits` (:158-178) and `controllerBound` (:184-201). So **all of Grid A and findings
2 and 5 rest on unchanged code**. The finding 5 spike was already run in the main checkout at
0a45ddb, not in the stale worktree. VERIFIED BY EXECUTION (`git diff 924e291..HEAD --`) and, for
finding 5, BY SPIKE on this tree.

`internal/linux/linux.go`: the four `noteScopeLimits` arms are still :285 / :305 / :325 / :359
and the sample is still :236; the only change in the gap is `resolveBwrap` at :97. Cites hold
byte for byte.

### Cites that moved but hold

| doc cite | at 0a45ddb | note |
|---|---|---|
| probe.go:96-118 (limits assembly) | :97-117 | +1 line, same code |
| probe.go:199-208 (`limitsLayers`) | :200-209 | +1 |
| probe.go:499 (namespace probe `WaitDelay`) | :599 | probe.go grew 151 lines elsewhere; the WaitDelay is unchanged, so finding 5's "every other probe site is bounded" still holds |
| profile.go:75-100 (the limits gate) | :78-103 | +3, the gate's logic is untouched (the diff is only `resolveBwrap`) |

### Findings that do not survive the newer tree

**Finding 1 is FIXED at 0a45ddb by 3cc71f9 "fix(linux): attest degraded tier's scope limits".**
`runDegraded` now runs through `runCmd` with a sampling callback (degraded.go:240-246) and calls
`noteScopeLimits(&report, p.Limits, attested)` at :247, ahead of every return arm - so all four
arms are covered by one call rather than four. Cell B3 "cap accepted but absent" and "no scope
sampled" both move from UNHANDLED to **HANDLED (degraded.go:247)**.
**VERIFIED BY SPIKE on this tree** - the same spike that failed on the stale base (recording
override on `attestScopeLimits` returning `{memory.max: false}` through a real `runDegraded`)
now passes: the hook is reached and the report reads Unavailable.
The re-open row for 7a93d42 is also superseded: 3cc71f9 added
`TestDegradedRunReconcilesTheLimitsLayersItGot` (degraded_limits_test.go:151), the degraded twin
of `TestRunReconcilesTheLimitsLayersItGot`, which pins exactly the cell that was open. The
vacuity observation about layergrid_test.go:85 stays true as a statement about that test, but it
is no longer load-bearing: the call site now has its own test on both tiers.

### Findings that survive unchanged

- **Finding 2** (an attestation that sampled no scope leaves Enforced standing). scopeattest.go
  is unchanged; the same spike fails the same way on this tree. **VERIFIED BY SPIKE @ 0a45ddb.**
  It now applies to *both* tiers, since the degraded tier reconciles through the same
  `noteScopeLimits` and therefore inherits the empty-reading gap.
- **Finding 3** (the profile gate has no attestation channel and rests on a process-lifetime
  cache). profile.go's gate is unchanged; nothing in the 89 commits adds an attestation to the
  profile path (`grep attestScopeLimits` finds only linux.go:236 and degraded.go:243).
  **VERIFIED BY READING @ 0a45ddb**; still UNSPIKEABLE HERE. It is now the only consumer that
  wraps a scope (or gates on one) without sampling it.
- **Finding 5** (the canary run in `measureScope` is bounded by nothing). Unchanged code, and the
  spike was run on this tree. **VERIFIED BY SPIKE @ 0a45ddb.**

### Dismissals re-checked

All five dismissals rest on limits.go / scopeattest.go / probe.go's limits assembly, none of
which changed in the gap; the Grid A spike rows were driven through helpers that are byte
identical. No dismissal is withdrawn. VERIFIED BY READING (diff) for the cites, BY SPIKE for
rows A4 and A5.

### Net effect on the tracker

File findings 2, 3 and 5. **Do not file finding 1** - it is already fixed and tested at 0a45ddb.
