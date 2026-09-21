# State grid: post-run corrections to the enforcement report x enforce.Layer

Worked from commit `09ddde4f6f41bfbc14799888a2fcb8e231c3ca1f` (`docs/state-grids`, detached
in a worktree). Phases 0-3 only; tracker filing is the orchestrator's.

Neighbours inherited, not re-walked: `docs/state-grid-layer-consumers.md` (layer x who
renders it) and `docs/state-grid-admission.md` (posture x layer state at admission).

## Phase 0 - fit

**Accepted.** Two strong signals:

- **A mirror pair with a direction.** The pre-run probe and the mid/post-run corrections
  answer the same question ("what did this run enforce?") at two lifecycle points, and the
  contract between them is stated in four separate comments in the code
  (`applied.go:411`, `scopeattest.go:176`, `linux.go:580`, `run.go:231`): a correction may
  only WORSEN. That is the one-sided invariant, already written down by the authors and
  nowhere enforced in one place.
- **An enum times its call sites.** 8 `enforce.Layer` constants against ~8 correction
  sites, plus a `State` order (`Enforced < Unsampled < Degraded < Unavailable`) that makes
  each cell a numeric comparison rather than a taste argument. (`Unsampled` was added after
  this grid was taken, by bv2-dnda5; the cells below were walked on the three-state order.)

Invariant used per cell, stated mechanically:

> **I1 (direction).** A correction site that writes state S onto a layer currently at
> state C must not produce a report where that layer is better than C. Formally: it
> checks C before writing, or it can only ever write `Unavailable`.
>
> **I2 (reach).** A worsening severe enough to refuse the run must reach the report, the
> shortfall and the operator's channel alike. A layer worsened in one and not the others
> is the forbidden direction.

Not declined. Phase 3 is fully runnable here (`GOWORK=off go test`), so nothing degenerates
to reading.

## Phase 1 - dimensions, derived from the code

Correction sites (rows), each read first-hand:

| id | site | file:line | writes via |
|---|---|---|---|
| S1 | pre-run probe seeding | `internal/linux/probe.go:63-119` | `AddStatus` onto a fresh `Report` |
| S2 | degraded-tier rewrite | `internal/linux/degraded.go:393-406` | `SetStatus` / `Set`, guarded by `StateOf` |
| S3 | in-run attestation (`applied.reconcile`) | `internal/linux/applied.go:424-517` | `Set` x 9 |
| S4 | scope attestation (`noteScopeLimits`) | `internal/linux/scopeattest.go:178` | `Set`, guarded by `StateOf == Enforced` |
| S5 | mid-run egress notes (8 callers, one funnel) | `internal/linux/linux.go:594` `worsenNetwork` | `Set`, guarded by `StateOf` |
| S6 | `enforce.Run` judged overlay | `enforce/run.go:240-244` | `SetStatus`, guarded by `l.State > StateOf` |
| S7 | `enforce.Run` report-only overlay | `enforce/run.go:253-257` | `SetStatus`, **unguarded** |
| S8 | operator stderr channel (`warnResidue`) | `internal/linux/linux.go:732` | no layer at all, by design |

Layer classes (collapsed where the correction path is shared): **filesystem**, **network**,
**exec pair** (exec-block + exec-strict, always written together), **limits triple**
(memory/pids/cpu, one loop over `limitControllers`), **report-only** (auto-exec-report).

Grid 1 = site x layer class, sparse (only cells a site can actually write): **17 cells**.
Grid 2 = I2 reach, the sites that can produce a refusing worsening x {report, shortfall,
operator channel}: **12 cells**. Total **29 cells**, every one verdicted below.

The two grids do not interact (direction is a property of the write; reach is a property of
what happens downstream of it), which is why they are separate.

## Grid 1 - direction (I1): can this site make a layer read BETTER?

| # | site | layer | can write | guard | verdict |
|---|---|---|---|---|---|
| 1.1 | S1 probe | filesystem | E/D/U | n/a - fresh report | IMPOSSIBLE: `probe.go:64` declares `var r enforce.Report`, so there is no prior state to improve. |
| 1.2 | S1 probe | network | E/U | n/a | IMPOSSIBLE, same line. |
| 1.3 | S1 probe | exec pair | E/D/U | n/a | IMPOSSIBLE, same line. |
| 1.4 | S1 probe | limits triple | E/D/U | n/a | IMPOSSIBLE, same line. `probe.go:98-103` defaults each to Unavailable rather than the zero value, so an unmeasured controller fails safe. |
| 1.5 | S1 probe | report-only | E/U | n/a | IMPOSSIBLE, same line. |
| 1.6 | S2 degradedProbe | filesystem | D/U | `if r.StateOf(fs) < Degraded` (`degraded.go:397`) | HANDLED. And the rebuilt status is never Enforced: `filesystemLayer` is called with `namespacesBlocked`, which cannot reach either Enforced arm (`probe.go:255-258`). VERIFIED BY SPIKE (4 combinations of landlock x fences). |
| 1.7 | S2 degradedProbe | network | U only | `if r.StateOf(net) < Unavailable` (`degraded.go:403`) | HANDLED - and vacuously safe, since `Unavailable` is the maximum. |
| 1.8 | S2 degradedProbe | exec pair / limits | - | - | IMPOSSIBLE: the function touches only two layers (`degraded.go:387-389` states why). |
| 1.9 | S3 reconcile | exec pair, silent/unreached arms | U only | none needed | HANDLED (`applied.go:433-435`, `:449-451`, `:461-462`): `Unavailable` is the maximum, so an unguarded write cannot improve. |
| 1.10 | S3 reconcile | filesystem, silent/unreached arms | U only | none needed | HANDLED (`applied.go:435`, `:451`). |
| 1.11 | S3 reconcile | exec-strict, architecture fallback | D | `r.StateOf(execStrict) < Unavailable` (`applied.go:466`; the probe now reports the same fallback D, so the guard covers the no-seccomp and tampered-report cases) | HANDLED. Pinned by `TestTheArchitectureFallbackDoesNotSoftenAnUnavailableExecStrict` (`applied_test.go:1402`). |
| 1.12 | **S3 reconcile** | **filesystem, Landlock-failure arm, `mountConfined` true** | **D** | **none** | **WRONG - forbidden direction.** `applied.go:507` writes `Degraded` unconditionally over whatever the layer holds. A report seeded `Unavailable` comes back `Degraded`: the run asserts a mount namespace confined it when the backend's own probe said nothing could. Finding **F1**. VERIFIED BY SPIKE. |
| 1.13 | S3 reconcile | filesystem, Landlock-failure arm, `mountConfined` false (degraded tier, `degraded.go:273-308`) | U only | none needed | HANDLED (`applied.go:511`). |
| 1.14 | S4 noteScopeLimits | limits triple | U only | `r.StateOf(c.layer) != Enforced → continue` (`scopeattest.go:181`) | HANDLED, doubly: the guard, and `Unavailable` is the maximum. VERIFIED BY SPIKE (inverted: fed a Degraded and an Unavailable baseline, both survive). |
| 1.15 | S5 worsenNetwork | network | D (all 8 callers) | `if state < current { return }` (`linux.go:595`) | HANDLED. Equal-state notes join reasons rather than replace (`linux.go:598-601`), so a second note does not erase the first. VERIFIED BY SPIKE (inverted: a dead-listener note onto an Unavailable layer leaves both state and reason intact). |
| 1.16 | S6 enforce.Run judged overlay | filesystem / network / exec / limits | any | `l.State > required.StateOf(l.Layer)` (`run.go:241`) | HANDLED. Pinned by `TestRunRefinementOnlyWorsens` (`run_test.go:331`). |
| 1.17 | **S7 enforce.Run report-only overlay** | **report-only** | **E/U** | **none** (`run.go:255`) | **WRONG - forbidden direction**, with a narrow blast radius. The PRE-RUN probe's status unconditionally replaces whatever the backend reported, so a backend that learned mid-run the hint is short has that erased and the operator is shown `enforced`. Finding **F2**. VERIFIED BY SPIKE. |

`S8` (`warnResidue`) writes no layer at all and appears only in Grid 2.

### Second pass over the HANDLED cells

- 1.15's guard reads `StateOf`, which returns `Unavailable` for an **absent** layer
  (`report.go:196-201`). So a `worsenNetwork` call on a report with no network entry is
  silently discarded rather than recorded. Finding **F3** (drop, not improvement).
- 1.11 and 1.12 are the same row. The guard at `applied.go:471` was added for exec-strict
  (the consumers grid names 930d8fc) and the filesystem sibling twelve lines below was not
  carried along. See the re-open pass.
- 1.14: `controllerBound` (`scopeattest.go:219-235`) returns `known=false` on any read error
  other than ENOENT, and the caller then leaves the layer alone. Correct direction (says
  too little), and deliberate per the comment at `:216`.

## Grid 2 - reach (I2): does a refusing worsening land in all three channels?

"Refusing" = the state would have been refused at admission under the posture that admitted
this run. Channels: the returned `Result.Report`, `postRunShortfall` (which sets the
process's own verdict), and the operator's stderr.

| # | site x layer | report | shortfall | operator channel | verdict |
|---|---|---|---|---|---|
| 2.1 | S3/S6 filesystem Degraded, default posture | yes | yes | yes (`writeDegradations`) | HANDLED. VERIFIED BY SPIKE (report and shortfall observed together; the stderr leg is the consumers grid's cell G4). |
| 2.2 | same, strict | yes | yes | yes | HANDLED. VERIFIED BY SPIKE. |
| 2.3 | same, --allow-degraded | yes | **no** | yes | HANDLED, allowed direction: `admit` would also have admitted Degraded core under that flag (`run.go:466-471`), so nothing that refuses went missing. VERIFIED BY SPIKE (shortfall empty, `err == nil`, report still carries Degraded). |
| 2.4 | S5 network Degraded, manifest with rules | yes | yes (core tier) | yes | HANDLED - `LayerNetwork` is in `wanted` whenever a note can fire, because a proxy exists only when `sb.proxySocket != ""` (`linux.go:157`), which needs rules or a gate, which is exactly `requiredLayers`' predicate (`run.go:433`). VERIFIED BY READING. |
| 2.5 | S5 network Degraded, zero-rule gateless manifest | dropped by `forLayers` | dropped | dropped | IMPOSSIBLE: no proxy and no bridge liveness pipe exist on such a run (`linux.go:157`, `:274`), so no note can fire. Enforcing lines cited; not merely "unreachable". |
| 2.6 | S4 limits Unavailable, default posture | yes | yes (`unenforcedRequestedLimits`, `run.go:390`) | yes | HANDLED. Inherited from `docs/state-grid-admission.md` Grid A. |
| 2.7 | S4 limits Unavailable, --allow-degraded, RunID set | yes | yes (`run.go:385-387`) | yes | HANDLED - this is admission-grid cell C1, since fixed (f45da41). Re-checked: the branch is present at `run.go:385`. VERIFIED BY READING. |
| 2.8 | S4 limits Unavailable, --allow-degraded, no RunID | yes | no | yes | HANDLED, allowed direction: admission waives it too (`run.go:472-476`). |
| 2.9 | S3 exec pair Unavailable, default posture | yes | no (hardening tier) | yes | HANDLED, allowed: admission does not refuse a hardening layer either, so nothing refusing went missing. Inherited from the admission grid. |
| 2.10 | **S7 report-only Unavailable from the backend** | **no** | n/a (never judged) | **no** | **WRONG for the disclosure channel.** F2's downstream half: the fact is erased before any channel sees it. It never refuses, so I2's "refusing" clause is not violated - but the operator is shown the opposite of what the run found. VERIFIED BY SPIKE. |
| 2.11 | **S5 network note onto an absent layer** | **no** | no | no | **UNHANDLED**, defended one line away. `probe.go:91` adds `networkLayer` unconditionally on every `Probe`, and every path that can call a note starts its report from `Probe` (`linux.go:98`, `degraded.go` via `degradedProbe`). So the drop is not reachable today. Nothing fails to compile if that `AddStatus` moves. Finding **F3**. VERIFIED BY SPIKE (the drop itself) + READING (the defence). |
| 2.12 | S8 `warnResidue` (unreclaimed write-grant dirs / shield mount points) | no layer, by design | no | yes, stderr only | HANDLED by its own stated contract (`linux.go:725-731`): the teardown invariant is one-sided and worsening a confinement layer would fault a run whose confinement held. It never refuses, so I2 does not bite. Boundary note: it is invisible to a `--json` consumer - that is the consumers grid's axis, inherited, not re-walked here. |

## Phase 2 re-open pass (known-open brief received after the grid was written)

- **930d8fc** (the exec-strict upgrade fix) produced the guard at `applied.go:471`. Cell
  1.12 is the same row, twelve lines below, and was not carried. This is the "fix covered
  one cell and stopped" shape, and it refutes a recorded decision: the consumers grid's
  Phase 2 re-open pass dismissed this exact site (it cites it as `applied.go:482`)
  VERIFIED BY READING, on the grounds that "enforce.Run's overlay propagates only a state
  that got worse". That is true of `enforce.Run` callers and says nothing about the
  missing guard at the site itself.
- **`FuzzParseAppliedNeverOverClaims`** (`applied_fuzz_test.go`) asserts exactly I1 over
  `reconcile` - and cannot catch F1, because `reportStates` (`applied_fuzz_test.go:50-57`)
  seeds every layer `Enforced` before reconciling. The oracle is blind to any non-Enforced
  baseline. That is the fuzz blind spot, not a fuzzer bug: the seed set is the gap.
- **f45da41 / 0d0cde5** (admission grid C1 and its table test): re-checked at `run.go:385`,
  carried. Cell 2.7.
- **641a83b / e90e2dd** (report-only kept out of judgment): carried for judgment, which is
  what they were about. Neither touches the overlay's direction, which is F2.

## Findings, forbidden direction first

**F1 - `applied.reconcile` upgrades an Unavailable filesystem layer to Degraded.**
`internal/linux/applied.go:507`. The Landlock-failure arm writes `Degraded` with no
`StateOf` check, unlike its exec-strict twin at `:471-473` and unlike `degradedProbe`'s
`:397`. A report carrying filesystem `Unavailable` (which the probe emits for
`namespacesUnknown` - `probe.go:259-260`, reached when `canUnshare`'s own bound expires,
`probe.go:848-851`) comes back claiming "bubblewrap's mount namespace still confines the
filesystem". **VERIFIED BY SPIKE**: `reconcile` on `applied{complete, landlock=no}` with
`mountConfined=true` over an Unavailable baseline returned `degraded`.

Severity, stated honestly on both sides:
- Via `enforce.Run`, it is largely masked: `opts.admit` refuses a core-Unavailable layer
  under every posture (`run.go:126`, admission grid Grid A), and the overlay at `run.go:241`
  compares against the *first* probe. But **`Probe` is not memoized** - `usableNamespaces`
  re-runs `canUnshare` on every call (`probe.go:549-574`), and there are two probes per run
  (`run.go:124`, `linux.go:98`). A first probe saying `namespacesUsable` (admitted) and a
  second timing out to `namespacesUnknown` is a live disagreement on a loaded host; the
  final report then reads `Degraded` for a run whose own backend probe said `Unavailable`.
- `linux.Enforcer.Run` is exported and has no in-tree caller besides `enforce.Run`
  (grepped), so the direct-embedder path is a real but unexercised surface. Same reasoning
  the code itself gives at `degraded.go:384-386` for re-screening what admission checked.

Fix: the three-line guard already used twice in this file -
`if r.StateOf(enforce.LayerFilesystem) < enforce.Unavailable`. Regression test: the spike,
plus a non-Enforced baseline in `fuzzAppliedBases`/`reportStates`.

**F2 - the report-only overlay erases a backend's worse verdict.**
`enforce/run.go:253-257` copies `probed`'s report-only statuses over the result
unconditionally, and `want` never contains a report-only layer so `run.go:241` skips it.
A backend reporting `auto-exec-report` Unavailable mid-run has that replaced by the
pre-run probe's `Enforced`. **VERIFIED BY SPIKE.**

Not an oversight in intent - `run.go:245-252` states the single-source design ("keeps one
source for the fact (the probe) rather than having the run path consult a second one") -
but the consequence is a disclosure that reads the opposite of what the run found. The
Linux backend never produces one (`probe.go:119` is the sole producer of that layer, and
nothing in `internal/linux` corrects it), so this is **UNHANDLED rather than IMPOSSIBLE**:
`enforce` takes any `Enforcer`, and the interface doc at `enforce.go:29-48` does not forbid
a backend from reporting it. Cheapest honest fix: the same `>` comparison the judged
overlay uses.

**F3 - `worsenNetwork` silently drops a note when the network layer is absent.**
`internal/linux/linux.go:595` reads `StateOf`, which reports an absent layer as
`Unavailable` (`enforce/report.go:196-201`), so the `state < current` guard discards the
write rather than recording it. **VERIFIED BY SPIKE** (a proxy-fault note onto an empty
report left the report empty). Not reachable today: `probe.go:91` adds the network layer on
every probe and every note-firing path seeds from a probe - **VERIFIED BY READING**. It is
the coupling gap Phase 2 asks to report on its own: one line in another file makes it safe,
and nothing fails to compile if that line moves. `probedState` (`report.go:207`) is the
existing helper that tells "absent" from "asserted Unavailable" and is what a fix would use.

## Dismissals, verified inverted

- `noteScopeLimits` never improves - **VERIFIED BY SPIKE** (Degraded and Unavailable
  baselines both survive a "cap bound" attestation).
- `worsenNetwork` never improves an already-Unavailable layer, and does not rewrite its
  reason - **VERIFIED BY SPIKE**.
- The degraded tier's rebuilt filesystem layer is never `Enforced` - **VERIFIED BY SPIKE**
  (all four landlock x fences combinations).
- A worsening that refuses reaches report and shortfall together under every posture -
  **VERIFIED BY SPIKE** (three postures; `--allow-degraded` correctly does not fault, which
  matches admission).
- `warnResidue` is the allowed direction by its own contract - **VERIFIED BY READING**.

## Cells not walked

- The **operator stderr leg of Grid 2** was inherited from `docs/state-grid-layer-consumers.md`
  (cells G4/G5) rather than re-rendered. Only cell 2.12's stderr leg was read first-hand.
- `internal/linux/degraded.go`'s four `reconcile` arms were verdicted as one cell (1.13):
  all four pass `mountConfined=false` (grepped), so they share a path.
- The **eight `worsenNetwork` callers** were verdicted through the funnel (1.15), not
  individually. They differ only in state (all `Degraded`) and reason text.
- **Reason-text correctness** of any correction is out of scope; this axis is state
  direction only. Reason text belongs to the consumers grid.
- `probe.go`'s own internal seam-timeout handling (`boundedSeam`, `bounded`) was read only
  far enough to establish that `Probe` re-measures. Whether two probes can *in practice*
  disagree on a given host is **UNSPIKEABLE HERE** - it needs a host whose `canUnshare`
  intermittently exceeds its bound.

## Handoff to fuzzing

`fuzzAppliedBases`/`reportStates` (`applied_fuzz_test.go`) already carries I1 as its oracle.
Widening `reportStates` to take the baseline report as a fuzzed dimension (each layer drawn
from the three states) turns F1 into something the existing fuzzer finds, and every cell in
Grid 1 into a corpus seed.

**Superseded by the re-open pass below (RO-2): a widened seed alone does NOT catch F1.**
The oracle compares corrupted-vs-intact from the *same* baseline, so both sides land on
Degraded and it never fires. One extra assertion is needed. See RO-2.

---

# Re-open pass

Same commit, `09ddde4f6f41bfbc14799888a2fcb8e231c3ca1f`. Run after the known-open board list
was handed over. Hunting the "fix closed one cell of a row and stopped" shape rather than
re-walking verdicts.

## RO-1 - F1 is LIVE, not latent. VERIFIED BY SPIKE.

The coordinator asked whether the two `Probe` call sites can actually disagree. They can,
and I no longer need to argue it. Two spikes, both run on this host:

```
probe 1 (healthy ctx): filesystem = enforced    ("Landlock backstop active")
probe 2 (expired ctx): filesystem = unavailable ("the user-namespace probe did not finish
                                                  (context deadline exceeded), ...")
```

`Probe` re-measures. Feeding that **real second probe's report** straight into
`reconcile` with a Landlock failure:

```
after reconcile: filesystem = degraded
  ("the Landlock backstop could not be applied inside the sandbox (ruleset creation
    failed); bubblewrap's mount namespace still confines the filesystem, ...")
```

So the full chain is observed end to end on real output, with no hand-built report: probe 1
Enforced admits the run (`run.go:126`), probe 2 says Unavailable (`linux.go:98`),
`applied.go:507` upgrades it to Degraded, and `run.go:241` propagates Degraded because it
compares against probe 1's Enforced. The operator is handed a sentence asserting a mount
namespace confined the run, on a run whose own backend probe said it could not establish
one. **F1 is reachable through the ordinary CLI path**; the earlier "largely masked behind
admission" framing was too generous and is withdrawn.

Honesty about the injection: I drove `ctxErr` through the **caller's** context, not the
internal 5s bound in `canUnshare` (`probe.go:588`). `classifyUnshare` cannot tell the two
apart - it branches on `ue.ctxErr != nil` alone (`probe.go:848`) - so the state transition
and the non-memoization are settled. **There is no fault-injection seam for `canUnshare`
itself**: it is a plain function, not a var, and `resolveBwrap` does a fresh `exec.LookPath`
every call. (`attestScopeLimits` at `scopeattest.go:82` *is* a var seam; the namespace probe
has no equivalent.) That the internal 5s bound fires independently of the caller on a loaded
host stays **UNSPIKEABLE HERE**, and F1 does not rest on it any more.

## RO-1b - the memoization claim in the interface doc is wrong. VERIFIED BY EXECUTION.

`enforce/enforce.go:25-28`, the `Enforcer` type doc, tells embedders:

> "the expensive host probes are memoized per PROCESS, not per Enforcer. A long-lived
> process amortizes them however many Enforcers it builds"

That is true of the scope and delegation probes (`cacheProbe`, `limits.go:50`;
`unifiedCgroupReadable`, `limits.go:301`) and **false of the namespace probe**, which is the
one both reported layers rest on: `usableNamespaces` (`probe.go:549`) calls `resolveBwrap`
and `canUnshare` unconditionally, and `canUnshare` execs bwrap. Measured: the two-probe
spike takes 0.04s, which is two real bwrap execs.

This matters beyond accuracy. It is the sentence a reader uses to conclude the two probes
agree, which is the unstated premise under the layer-consumers grid's dismissal of
`applied.go:507`. Fixing the doc is half of F1's fix. New finding **F4**.

## RO-2 - the fuzz handoff, corrected. VERIFIED BY READING.

I asked for a one-line seed change and the honest answer is that a seed change alone does
not work, so this supersedes my own "Handoff to fuzzing" paragraph above.

`FuzzParseAppliedNeverOverClaims`' oracle is *corrupted must be no better than intact, from
the same baseline* (`applied_fuzz_test.go:105-113`). With the baseline set to Unavailable,
intact reconciles to Degraded and corrupted reconciles to Degraded too - equal, no fire. The
blindness is not only the seed; it is that the oracle never compares the result against the
**baseline it started from**, which is what I1 actually says.

The fix the bead should carry, three edits, one of which is the load-bearing line:

1. `func reportStates(t *testing.T, body string, base enforce.State)` - seed the loop at
   `applied_fuzz_test.go:57` with `base` instead of `enforce.Enforced`.
2. `f.Fuzz(func(t *testing.T, baseIdx, at, baseState int, junk []byte)`, mapping `baseState`
   onto one of the three `enforce.State` values, and pass it to both `reportStates` calls.
3. **The assertion that catches F1** - one line, next to the existing floor check:

   ```go
   if got[layer] < base { t.Fatalf("reconcile improved %v from the %v baseline to %v", layer, base, got[layer]) }
   ```

All three are needed. Edit 3 is the one that encodes I1, but at an Enforced-only baseline it
can never fire - every state is `>= Enforced` trivially - so edits 1 and 2 are what give it
something to catch.

## RO-3 - F2's UNHANDLED-not-IMPOSSIBLE call, re-checked at HEAD. VERIFIED BY READING.

The coordinator is right that the whole cell turns on this sentence, so here is the doc
verbatim. `enforce/enforce.go:30-37`, the **`Probe`** method, imposes an explicit obligation
and names the fail-safe:

> "It must report every core layer, LayerNetwork included, whatever the manifest asks for.
> A layer left out is read as Unavailable, which is the only reading that fails safe: Run
> cannot tell 'this host has no netns' from 'the probe was not written to say so', and the
> second must not be the shape that runs unfenced."

`enforce/enforce.go:39-46`, the **`Run`** method, in full:

> "Run enforces p around proc, runs it to completion, and reports what was actually
> enforced. A non-zero process exit is returned in Result, not as err; err is reserved for
> a failure to set up or run the sandbox itself.
>
> Everything the core decided about this particular invocation travels in RunOptions rather
> than as positional arguments, so a new decision does not change this signature and a
> backend cannot mistake one flag for another."

"reports what was actually enforced" is an affirmative instruction to report the run's own
verdict, with **no** carve-out for report-only layers and no statement that the core will
ignore them. A backend author reading this has every reason to report `auto-exec-report`
Unavailable when git vanished mid-run, and `run.go:255` silently discards it. **F2 stands
as UNHANDLED**, not IMPOSSIBLE: the contract invites the write that is then dropped.

## RO-4 - board items against the grid

### bv2-dnda5 (limits: an unsampled scope refuses a completed default-posture run)

This is my Grid 2 cell 2.6. **The refusal is correct under I2 and under I1.** VERIFIED BY
SPIKE:

```
limits-memory after an unsampled scope = unavailable
  ("no scope was found to read for this run, so the memory cap the manifest asked for
    could not be confirmed to have been applied: ...")
```

The worsening reaches the report, and the default posture faults it through
`unenforcedRequestedLimits` (`run.go:390`), so report and shortfall agree - which is exactly
what the invariant demands. The bead's complaint is about *blast radius*, not direction: a
run whose scope simply could not be sampled in time loses its exit code even though the cap
may well have been applied. That is the **allowed** direction of a one-sided invariant
(over-strict, never under-strict), and `scopeattest.go:186-188` argues it deliberately -
"an unverifiable run is reported unenforced rather than claimed enforced". My grid has no
verdict that says this is a defect. If it is to be softened, the softening is the forbidden
direction and needs a reason outside this grid.

**Row check on bv2-tdwfx (the fix that added `sampled`): the row WAS carried.** `scopeLimits`
has exactly three consumers - `linux.go:248`, `degraded.go:240`, `profile.go:207` - and both
readers of the field handle it: `noteScopeLimits` (`scopeattest.go:183`) and
`unattestedScopeCaps` (`scopeattest.go:207`, `!a.sampled || ...`), which is profiling's
refusal path and matches bv2-3ka8n. Nothing stopped here.

### bv2-0hy3m and bv2-dhj3o - my cell 2.12 was over-collapsed. Correcting it.

I gave `warnResidue` a single HANDLED cell. That was wrong: I verdicted the *function's
contract* and not its *call sites*, and the call sites are a three-tier row with two tiers
missing. `warnResidue` has exactly two callers, both on the full bwrap tier
(`linux.go:120`, `linux.go:144`). Splitting cell 2.12:

| # | tier x residue | verdict |
|---|---|---|
| 2.12a | full bwrap tier, write-grant dirs on a run that did not start | HANDLED (`linux.go:118-121`) |
| 2.12b | full bwrap tier, unreclaimed shield mount points | HANDLED (`linux.go:142-145`) |
| 2.12c | **degraded tier, write-grant dirs on a setup failure** | **UNHANDLED.** `degraded.go:118` calls `prepareWriteDirs` and registers no residue defer; `warnResidue` does not appear in the file. = bv2-dhj3o. VERIFIED BY READING (grep: two call sites, both `linux.go`). |
| 2.12d | **profile, shield reclaim residue** | **UNHANDLED.** `profile.go:136` is `defer removeCreatedShields(shieldDirs, shieldFiles)` - the return value, which is the list of paths it could not reclaim, is discarded at the `defer`. = bv2-0hy3m. VERIFIED BY READING. |

**This is the stopped row the pass was looking for.** bv2-t41ij and bv2-obrnf created
`warnResidue` and wired it on the full tier; the degraded tier and the profile path both
create host state by the same helpers and report none of it. Two of four cells in a row that
reads closed. Both are already filed, which is the good outcome - my grid should have found
them and did not, because I collapsed a row on the strength of a function's doc comment
instead of walking its callers.

### bv2-ofg48

Belongs to `docs/state-grid-layer-consumers.md`'s axis (who renders a layer), which this
grid inherits rather than re-walks. Not verdicted here.

## Re-open pass findings, forbidden direction first

- **F1 (upgraded), `internal/linux/applied.go:507`** - now **live through the ordinary CLI
  path**, not latent behind admission. VERIFIED BY SPIKE on real `Probe` output. Fix is the
  guard at the site *plus* F4's doc correction.
- **F4 (new), `enforce/enforce.go:25-28`** - the `Enforcer` doc states host probes are
  memoized per process; the namespace probe is not, and it is the one both core layers rest
  on. VERIFIED BY EXECUTION. This is the belief that made the consumers grid's dismissal of
  `applied.go:507` look safe.
- **2.12c / 2.12d (new cells, both already on the board)** - `warnResidue`'s row stops at the
  full bwrap tier. VERIFIED BY READING. Correction to my own cell 2.12.
- **F2 stands UNHANDLED** - the `Enforcer.Run` doc says "reports what was actually enforced"
  with no carve-out, so a backend is invited to write the report-only verdict that
  `run.go:255` discards. VERIFIED BY READING, doc quoted above.
- **F3 unchanged** - coupling gap, defended one line away at `probe.go:91`.
- **bv2-dnda5 is not a defect by this grid's invariant** - correct direction, correct reach,
  VERIFIED BY SPIKE. Its cost is over-strictness, which the invariant permits.

## Cells still not walked, after the re-open pass

- The independent firing of `canUnshare`'s internal 5s bound: **UNSPIKEABLE HERE**, no seam,
  and F1 no longer depends on it.
- bv2-ofg48 (the layer-consumers axis).
- The stderr rendering of the two newly-split residue cells (2.12c/2.12d) - I verdicted that
  nothing is *reported*, not how it would render if it were.

