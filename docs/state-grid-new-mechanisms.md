# State grid: the six mechanisms that landed 2026-09-18

Worked from commit `09ddde4f6f41bfbc14799888a2fcb8e231c3ca1f` (`docs/state-grids`),
covering `57267c8..09ddde4`.

## Phase 0 - fit call: ACCEPT, and no, it should not have waited

Signals present, two of them strong:

1. **Mirror pair**, the best signal the skill lists. The bwrap tier and the degraded tier
   answer the same questions two ways: `verifyEmptyCapBound`
   (`internal/launcher/verify.go:212`) against `restrictCapabilityBound`
   (`internal/launcher/degraded.go:141`); `--new-session` (`internal/linux/args.go:533`)
   against `seccomp.BlockTerminalInjection`; `Run`'s residue disclosure
   (`internal/linux/linux.go:120`, `:144`) against the same teardown on `Profile` and
   `runDegraded`.
2. **Repeated one-at-a-time fixes.** Fourteen tracked defects closed in one day, all of
   them in the same class: a state that exists on one path and is not disclosed on a
   sibling.
3. Weaker, and used as the second axis: **degradation / partial-answer states.**
   `scopeLimits.sampled` is precisely the "empty-because-clean vs empty-because-unasked"
   distinction the skill names.

**Invariant (one-sided):** every state the new code introduces is disclosed on every entry
path that can reach it. A path may over-disclose; no path may silently discard a residue,
an unsampled reading, or a refusal reason that another path reports.

**On the churn caveat.** The skill says decline an area that is churning, because verdicts
rot. That rule is aimed at logic being rewritten. What this grid actually found is a
different shape: **omissions at the seams of a just-landed mechanism** - a call site that
discards a return value, an entry path that never adopted the new helper at all. Those do
not rot with age, they calcify: waiting a week does not grow a `warnResidue` call at
`internal/linux/profile.go:136`, it only widens the window in which the asymmetry reads as
intentional. The code is gated (`make check` passed), merged, and not mid-refactor. Grid
now. The verdicts most at risk of staling are the HANDLED ones, which are the cheap half.

**Second caveat honoured.** Two fixes self-reported blast radius (the degraded terminal
fence being narrower than `--new-session`, `internal/linux/args.go:528-534`; the profiling
mkdir not being reclaimed, `internal/linux/profile.go:120-127`). Neither is reported here
as a finding. F2 below does touch the second one, and says explicitly why it is a
different claim.

## Phase 1 - dimensions, derived from the code

**Axis A - mechanism (6),** each as it now stands:

| # | Mechanism | Where |
|---|---|---|
| M1 | `restrictCapabilityBound` + the `capBoundingNow`/`dropCapBound`/`heldCaps` seams | `internal/launcher/degraded.go:141`, called `:327` |
| M2 | `TestTierDifferential` - 4 rows against the launcher grid's 13 restrictions | `internal/launcher/tierdiff_test.go` |
| M3 | `warnResidue` + `removeCreatedShields` returning what it could not reclaim | `internal/linux/linux.go:732`, `internal/linux/shields.go:597` |
| M4 | `scopeLimits.sampled` and the refusal it drives | `internal/linux/scopeattest.go:62`, `internal/linux/profile.go:227` |
| M5 | `absentWrites` + the setup-failure directory reporting | `internal/linux/linux.go:699`, `:120` |
| M6 | `terminalResidual` / `capBoundResidual` in the degraded Consequences | `internal/linux/probe.go:447`, `:460` |

**Axis B - entry path (5),** collapsed where a path cannot reach a mechanism. Two of the
five collapse wholesale, with cites, as required:

- **P1 `Run` (bwrap tier)** - `internal/linux/linux.go:51`, the arm past the degraded
  dispatch at `:96`.
- **P2 `runDegraded`** - `internal/linux/degraded.go:34` (host side) and
  `launcher.RunDegraded` `internal/launcher/degraded.go:222` (in-sandbox stage). Treated as
  one path: the host side is the only caller and the stage has no other entry.
- **P3 `Profile`** - `internal/linux/profile.go:47`.
- **P4 `embed`** - an SDK caller invoking `Enforcer.Run` / `Enforcer.Profile` directly.
  **Collapses into P1/P3 on every axis but one.** The code makes exactly one distinction
  for an embedder: `enforce.Process.Stderr` may be nil, documented at
  `enforce/enforce.go:161-167` as "no stream (e.g. /dev/null), not inherit". That is the
  only cell it gets, C3.4. Everywhere else `Run` cannot tell an embedder from the CLI, so
  a separate row would invent cells the code has no opinion about.
- **P5 `supervise`** - a gate-supervised run. **Collapses into P1 entirely.** It is the
  same `Enforcer.Run` body; the gate changes what the proxy admits, not what any of M1-M6
  does. It also cannot reach P2 at all: `enforce/run.go:185` records that a supervising
  gate requires `LayerNetwork`, which is `Unavailable` without a netns, so admission
  refuses the degraded tier for it - stated again at `internal/linux/degraded.go:21-26`
  ("the caller (enforce.admit) has already refused anything that needs egress - a network
  manifest or a supervising gate").

**Grid shape:** the mechanisms do not all partition the same way, so the cross product is
uneven rather than a clean rectangle. Substantive verdicts per mechanism: M1=3, M2=2, M3=4,
M4=4, M5=3, M6=4, i.e. `3+2+4+4+3+4 = 20 substantive verdicts across 27 table rows, of
which 7 are collapse-pointers`. **All 20 walked.**

## Phase 2 - every cell, one verdict

### M1 - `restrictCapabilityBound`

| Cell | Path | Verdict |
|---|---|---|
| C1.1 | Run (bwrap) | **IMPOSSIBLE.** `restrictCapabilityBound` is called only from `RunDegraded` (`internal/launcher/degraded.go:327`); this tier passes `--cap-drop ALL` (`internal/linux/args.go:502`) and the launcher verifies it at `internal/launcher/launcher.go:167` calling `verifyEmptyCapBound` (`internal/launcher/verify.go:212`). The state is covered by a different mechanism, not undisclosed. |
| C1.2 | runDegraded | **HANDLED.** `internal/launcher/degraded.go:141`. Re-reads `CapBnd` after the drop rather than assuming it (`:150`), and refuses when the set is non-empty *and* `heldCapabilities` is non-zero (`:161`). `heldCapabilities` reads PERMITTED ∪ EFFECTIVE (`:191`), which is the correct set under no-new-privs. Ordered after the seccomp installs (`:325-327`) so the no-new-privs premise holds. |
| C1.3 | Profile | **IMPOSSIBLE.** Profile launches bwrap (`internal/linux/profile.go:181`) into `launcher.Run`, which reaches `verifyEmptyCapBound` at `internal/launcher/launcher.go:167` - the same check as C1.1. There is no degraded profiling tier: `internal/linux/profile.go:56-61` refuses outright rather than degrading. |
| C1.4 | embed | Collapses to C1.1/C1.2/C1.3 - no stream is consulted. |
| C1.5 | supervise | Collapses to C1.1 - `enforce/run.go:185`. |

### M2 - `TestTierDifferential`

| Cell | Path | Verdict |
|---|---|---|
| C2.1 | coverage of the tier differential | **UNHANDLED (partial), see FINDING F4.** 4 rows covering 3 of the launcher grid's 13 restrictions, and 2 of the 4 skip without a controlling terminal. |
| C2.2 | the bwrap arm's fidelity | **WRONG (narrow), see FINDING F5.** `internal/launcher/tierdiff_test.go:155-159` omits `--unshare-cgroup` from the `namespaceFlags` set (`internal/linux/args.go:500-503`) its own comment promises to reproduce. |

M2 is not crossed with the entry paths: it is a test, not a runtime state, and crossing it
manufactures cells the code has no opinion about.

### M3 - `warnResidue` / `removeCreatedShields`

| Cell | Path | Verdict |
|---|---|---|
| C3.1 | Run (bwrap) | **HANDLED.** `internal/linux/linux.go:144` wraps the call and reports what came back. `removeCreatedShields` now distinguishes absent (clean) from still-standing (`internal/linux/shields.go:604-606`) and returns every input path on an expiry (`:626`) rather than racing the abandoned closure. |
| C3.2 | runDegraded | **IMPOSSIBLE.** The degraded tier creates no bwrap mount points to reclaim: it runs the target as a direct child with no mount namespace and no binds at all (`internal/linux/degraded.go:20-32`), and `preflight.createdShields` - the only producer of the dirs/files lists - is never called there. *Flagged as the thinnest IMPOSSIBLE in this grid:* the enforcing fact is the absence of a call, and the comment at `internal/linux/shields.go:565` ("both bwrap entry paths") is prose, not an enforced line. Nothing fails to compile if the degraded tier grows a shield. |
| C3.3 | Profile | **UNHANDLED - FINDING F1.** `internal/linux/profile.go:136` is `defer removeCreatedShields(shieldDirs, shieldFiles)`. The return value - the whole point of the change - is discarded. |
| C3.4 | embed (nil Stderr) | **UNHANDLED - FINDING F3.** `internal/linux/linux.go:733` returns early on `w == nil`. There is no second channel. |
| C3.5 | supervise | Collapses to C3.1. |

### M4 - `scopeLimits.sampled`

| Cell | Path | Verdict |
|---|---|---|
| C4.1 | Run (bwrap) | **HANDLED.** `noteScopeLimits` worsens every requested layer on `!a.sampled` (`internal/linux/scopeattest.go:185-189`), and it is called on **all four** report-bearing arms of `Run` - `internal/linux/linux.go:304` (cancel), `:324` (success), `:344` (exit error), `:378` (default). I enumerated every return in `Run` that carries a `report`; there is no fifth. Earlier returns carry `enforce.Result{}` with no report, so there is no reading to discard. |
| C4.2 | the `exe != bwrap` guard | **HANDLED (conservative).** `internal/linux/linux.go:254` only samples when the run was wrapped. Unwrapped with non-zero `Limits` leaves `scopeLimits{sampled:false}`, which worsens - the allowed direction. `noteScopeLimits` is additionally gated on `r.StateOf(layer) == Enforced` (`scopeattest.go:180`), so an unwrapped run on a host the probe already called unavailable is not double-reported. |
| C4.3 | runDegraded | **HANDLED.** `internal/linux/degraded.go:243` samples, `:247` reconciles, on the single report-bearing path. |
| C4.4 | Profile | **HANDLED.** `internal/linux/profile.go:203-212` samples while the target is alive; `unattestedScopeCaps` (`internal/linux/scopeattest.go:201`) turns an unsampled or unbound reading into a refusal at `profile.go:227`, since Profile has no Report to worsen. The `cancelled` guard (`:226`) matches Run's, and `limitControllers` (`scopeattest.go:161`) is shared by both readers so they cannot drift on which controller answers for which layer. |
| C4.5 | embed / supervise | Collapse to C4.1 - no stream is consulted and the gate does not touch limits. |

### M5 - `absentWrites` / setup-failure directory reporting

| Cell | Path | Verdict |
|---|---|---|
| C5.1 | Run (bwrap) | **HANDLED.** `absentWrites` recorded before the `MkdirAll` (`internal/linux/linux.go:698-700`), carried out on `preflightGrants`' own error path (`:705`), and the `Run` defer is registered *before* the call (`:118-122`) so it survives that path. `launched` (`:255`) correctly separates a setup failure from a run whose target started. A stat that could not answer is deliberately not counted (`:701`) - the safe direction. |
| C5.2 | runDegraded | **UNHANDLED - FINDING F2a.** `internal/linux/degraded.go:118` calls `prepareWriteDirs` directly. This path never constructs a `preflighted`, never calls `absentWrites`, and never calls `warnResidue`. Every setup failure after that mkdir - `checkLauncher`, `preflightLimits`, the launcher failing to start, a cancel before start - leaves the directory on the host with nothing said. Whole entry path, zero participation. |
| C5.3 | Profile | **UNHANDLED - FINDING F2b.** `internal/linux/profile.go:129` takes `preflight` and drops `createdWrites`. At least eight failure points follow it before the target runs (`CreateTemp` `:139`, `startRecordingProxy` `:163`, `compile` `:172`, `preflightLimits` `:184`, `checkLauncher` `:191`, `runCmd` `:213`, the `unattestedScopeCaps` refusal `:227`, `parseObservations` `:232`), each returning with the directory on the host and silent. |
| C5.4 | embed (nil Stderr) | Same cell as C3.4 / F3. |
| C5.5 | supervise | Collapses to C5.1. |

### M6 - `terminalResidual` / `capBoundResidual`

| Cell | Path | Verdict |
|---|---|---|
| C6.1 | Run (bwrap) | **IMPOSSIBLE, and correctly so - this was the cell most likely to come back WRONG.** Both constants are appended only inside the `case landlockAvail:` arm of `filesystemLayer` (`internal/linux/probe.go:294-295`). The two bwrap arms (`ns == namespacesUsable`, `probe.go:255-258`) return early with an empty `Consequences`. A bwrap run is therefore never told it has no session fence - which would be false, `--new-session` is in `sessionFlags` at `internal/linux/args.go:533`. Verified by spike, inverted. |
| C6.2 | runDegraded (Degraded verdict) | **HANDLED.** `internal/linux/degraded.go:399` rebuilds the layer through the same `filesystemLayer`, so the tier's disclosure is the same text a userns-blocked host gets rather than a second account that can drift. The `< enforce.Degraded` guard at `:398` is correct: `Enforced=0 < Degraded=1 < Unavailable=2` (verified), so the rebuild fires exactly when the probe's verdict is better than the tier deserves. |
| C6.3 | runDegraded (Unavailable verdict) | **HANDLED by worsening - the allowed direction, noted not filed.** If the probe already returned `Unavailable` (`namespacesUnknown` `probe.go:259`, fences unavailable `:261`, no Landlock `:298`), `degradedProbe` leaves it alone and the report carries an empty `Consequences` - no `terminalResidual`, no `capBoundResidual`. The state that replaces them is strictly worse than `Degraded`, so the operator is not told the run is better than it is. Allowed by the one-sided invariant. Confirmed by spike: all three arms return `state=unavailable, Consequences=""`. |
| C6.4 | Profile | **IMPOSSIBLE.** Profile produces a `profile.Observation`, not an `enforce.Report` - stated at `internal/linux/profile.go:41-46` - so there is no Consequences field to carry either constant, and no degraded profiling tier exists to need one (`profile.go:56-61`). |
| C6.5 | embed / supervise | Collapse to C6.1/C6.2. |

### Coupling gap (reported on its own, as the skill requires)

`restrictCapabilityBound`'s decision to let an inert residual pass without refusing
(`internal/launcher/degraded.go:146-148`, and the doc comment at `:130-137`) rests
**entirely** on `capBoundResidual` being disclosed to the operator. That disclosure is one
`const` in another package (`internal/linux/probe.go:460`), reachable only through one
string concatenation at `probe.go:295`. Nothing fails to compile if it is removed, and no
test ties the launcher's decision to the probe's text. The silent-drop guarantee of the
degraded tier is held together by a string literal in a different module directory.

## Phase 3 - findings, forbidden direction first

### F1. `Profile` discards the shield residue `Run` reports - **VERIFIED BY SPIKE**

`internal/linux/profile.go:136` - `defer removeCreatedShields(shieldDirs, shieldFiles)`.
`Run` wraps the identical call in `warnResidue` (`internal/linux/linux.go:144`). Profile
applies the same deny-list shields (its own comment, `profile.go:134-135`) and so leaves
the same artifacts; a mount point left standing inside the user's checkout is named on one
path and not the other. Forbidden direction: a residue silently discarded on a sibling
path.

Spike (deleted): one policy whose write grant is a checkout with a `.git`, run through
**both** paths with the same forced residue - `shieldLstat` (the seam at
`internal/linux/shields.go:631`) held past an expired walk bound, so
`removeCreatedShields` returns every path it was handed (`shields.go:626`). Side by side:

```
Run stderr:     "bento: shield mount points it could not reclaim:
                   .../work/.git/config
                   .../work/.git/config.worktree
                   .../work/.cargo/config.toml
                   .../work/.cargo/config
                   .../work/.git/hooks
                   .../work/.vscode
                   .../work/.cargo
                   .../work/.idea"
Profile stderr: ""
--- FAIL: TestSpikeProfileNamesTheShieldItCouldNotReclaim (1.35s)
```

Eight shield mount points inside the user's checkout, named on one entry path and silent on
the other, from one policy and one seam. The regression test is this spike with the `Run`
half kept as the premise check.

### F2a. `runDegraded` never participates in the write-residue mechanism at all - **VERIFIED BY SPIKE**

`internal/linux/degraded.go:118` calls `prepareWriteDirs` directly, bypassing
`preflightGrants` entirely. No `absentWrites`, no `preflighted.createdWrites`, no
`warnResidue`. This is the strongest cell in the grid: not a call site that dropped a
value, an entire entry path that the mechanism never reached.

Spike (deleted): a degraded run with `Write: [a-created, b-refused]` where `b-refused` is a
regular file, asserting stderr names `a-created` exactly as `Run` does.

```
--- FAIL: TestSpikeDegradedNamesTheWriteDirItAlreadyCreated (0.14s)
    runDegraded must name the directory it already created; stderr was "",
    want a line naming .../a-created
```

Polarity is right: the spike asserts the residue line **is** present, mirroring
`internal/linux/reclaim_test.go:205`, and fails.

### F2b. `Profile` discards `createdWrites` on every one of its setup-failure paths - **VERIFIED BY SPIKE**

`internal/linux/profile.go:129` takes `preflight` and never reads `createdWrites`. Eight
subsequent failure points (enumerated in C5.3) return with the directory on the host and
nothing said.

```
--- FAIL: TestSpikeProfileNamesTheWriteDirItAlreadyCreated (1.94s)
    Profile must name the directory it already created; stderr was "",
    want a line naming .../a-created
```

**Pre-empting the recorded-decision rebuttal.** The comment at
`internal/linux/profile.go:120-127` already says profiling's mkdir is one host artifact
"nothing removes", and calls it the right trade. That is a claim about **reclaiming**, and
it predates `warnResidue` by fourteen commits. This finding is about **disclosing**, which
is the mechanism that landed today and which `Run` adopted and `Profile` did not. The
recorded decision is not refuted; it is orthogonal, and the fix is compatible with it -
name the directory, still do not remove it.

### F3. A nil `Stderr` swallows every residue with no alternative channel - **VERIFIED BY SPIKE**

`internal/linux/linux.go:733` - `if w == nil || len(paths) == 0 { return }`.
`enforce/enforce.go:161-167` documents nil as "no stream (e.g. /dev/null), not inherit", so
an embedder that captures nothing - a CI runner, a server embedding bento - is a supported
and likely caller. For that caller the entire teardown-hygiene mechanism is a no-op, and
unlike F1/F2 this **cannot be fixed by wiring `warnResidue` in**: there is no channel to
wire it to. `enforce.Result` carries no field for it (stated at `linux.go:728-731`), which
is the design decision this cell puts pressure on.

```
with a writer: "bento: what:\n  /x\n"; with nil: no channel exists
```

Its own cell rather than folded into F1/F2, because the remedy is different in kind: a
`Result` field or a callback seam, not a call site.

A second-order note on the same line: the residue goes to the **target's** stderr writer,
so an embedder that captures target output into a buffer gets bento's own diagnostics mixed
into the program's captured output. Over-disclosure, the allowed direction - noted, not
filed.

### F4. `TestTierDifferential` measures 4 of 13 restrictions, and 2 of the 4 skip in CI - **VERIFIED BY EXECUTION**

```
--- PASS: TestTierDifferential/sysv-ipc
--- PASS: TestTierDifferential/cap-bounding-set
--- SKIP: TestTierDifferential/controlling-terminal
        needs a controlling terminal, and this run was not started from one
--- SKIP: TestTierDifferential/tty-inject-ioctl
        needs a controlling terminal, and this run was not started from one
```

The two rows that skip are exactly the two that measure **today's** terminal fence. In any
non-tty run - CI, `make test`, `make check` - the new mechanism's differential is
unmeasured, and the table reports PASS while having asserted nothing about it.

The 13 is counted independently, not taken on the orchestrator's word:
`docs/state-grid-launcher-order.md:52` declares "Grid A - restriction x state (13 x 4 = 52
cells)" and its table carries rows 1-13. The 4 differential rows map onto **3** of those
restrictions - row 11 (SysV IPC), row 10 (capability bounding set), row 6 (terminal detach,
twice). So 10 of 13 restrictions have no differential row at all, and on a non-tty host the
table measures 2.

Coverage, not a correctness defect; filed as a cell because the invariant it is supposed to
guard is currently held by nobody in CI.

### F5. The differential's bwrap arm is not the bwrap tier's flag set - **VERIFIED BY READING**

`internal/launcher/tierdiff_test.go:155-159` builds the reference arm with
`--unshare-user --unshare-ipc --unshare-pid --unshare-uts --cap-drop ALL --new-session`,
under a comment promising it is "the bwrap tier's own restriction set for the cells this
table covers (internal/linux/args.go namespaceFlags and sessionFlags)". `namespaceFlags`
(`internal/linux/args.go:500-503`) is user/ipc/pid/uts/**cgroup** + `--cap-drop ALL`. The
drift is exactly one flag: `--unshare-cgroup` is missing.

Narrow deliberately - `--unshare-net` is **not** in `namespaceFlags` (it is added
elsewhere), so its absence here is not a drift from the list the comment promises to
reproduce, and claiming it would be wrong. No current row depends on `--unshare-cgroup`, so
this is latent rather than live; it is filed because it is the kind of drift the table was
written to prevent, pointed at itself.

### Dismissals, verified inverted

- **"The two new residuals are pasted into the *filesystem* layer's Consequences, so the
  bwrap probe mis-discloses a fence it actually has."** Dismissed. **VERIFIED BY SPIKE**,
  inverted - asserted the safe behaviour (`TestSpikeBwrapArmsCarryNoDegradedResiduals`
  PASSED): both `namespacesUsable` arms return before the append at `probe.go:294`.
- **"`degradedProbe`'s `< enforce.Degraded` guard leaves an Enforced verdict standing for
  an embedder running degraded on a healthy host."** Dismissed. **VERIFIED BY SPIKE**:
  `Enforced=0 Degraded=1 Unavailable=2`, so `Enforced < Degraded` is true and the rebuild
  fires. My first reading of the comparison was inverted; the code is right.
- **"A fifth report-bearing arm in `Run` misses `noteScopeLimits`."** Dismissed.
  **VERIFIED BY READING** - all four enumerated (`linux.go:304, 324, 344, 378`), no fifth
  return in `Run` carries a `report`.
- **"`restrictCapabilityBound` reads the wrong capability set."** Dismissed.
  **VERIFIED BY EXECUTION** - `TestRestrictCapabilityBound`'s five subtests all PASS,
  including "undroppable but the caller holds nothing" and "undroppable and the caller
  holds capabilities", which are the two cells the fence exists for.

### Cells not walked

None. All 20 cells carry a verdict. The two collapsed paths (P4 embed, P5 supervise) are
collapsed with cites rather than skipped, and the one place embed genuinely differs from
Run got its own cell (C3.4 / F3).

## Handoff

- F2a and F2b are the same missing call in two places and should be one change with two
  regression tests, one per entry path.
- The cell F4 names has no owner in CI. Either the two terminal rows get a pty so they
  stop skipping, or the missing coverage is filed against the cell it guards.
- The coupling gap under Phase 2 is not a WRONG or UNHANDLED cell and is not filed as one,
  but it is the single most fragile thing this grid touched.

## Re-open pass

Run after the grid was written, against the known-open list held back during Phase 1 so it
could not bias the dimensions. One verdict per bead: **same cell**, **strictly worse
sibling**, or **distinct**.

### bv2-0hy3m - "Profile discards the shield reclaim residue" - **SAME CELL as F1**

Cell C3.3. Do not file again. The bead and the finding name the same line
(`internal/linux/profile.go:136`) and the same remedy (wrap the call in `warnResidue` as
`linux.go:144` does).

What should be appended to the bead is the evidence, which is stronger than a reading:
one policy, one forced-residue seam (`shieldLstat`, `internal/linux/shields.go:631`, held
past an expired walk bound so `removeCreatedShields` returns every path it was handed at
`shields.go:626`), both entry paths side by side in one test. Run named eight shield mount
points inside the user's checkout; Profile's stderr was `""`. That spike is also the
regression test the bead's acceptance needs, with the Run half kept as its premise check.
**VERIFIED BY SPIKE.**

### bv2-dhj3o - "the degraded tier reports no write-grant directory" - **STRICTLY WORSE SIBLING of F2a**

Not the same cell. The bead is filed as a *reporting* gap - as though `runDegraded`
computes the list and fails to print it. It does not compute it. `runDegraded` calls
`prepareWriteDirs` directly (`internal/linux/degraded.go:118`), bypassing `preflightGrants`
entirely; it never constructs a `preflighted`, never calls `absentWrites`, never calls
`warnResidue`. The entry path has zero participation in the mechanism, not a missing print.
The bead should be re-scoped to say so, because the two descriptions imply different fixes -
one adds a call, the other has to decide where the list comes from on a path that has no
`preflighted` to carry it.

**And yes, F2a settles the design question the bead records as an unpaid cost.** The bead
notes `absentWrites` doubling the bounded stat per write grant, with the clean shape being
`prepareWriteDirs` returning what it created, in one signature change serving both tiers.
That is no longer just a tidier shape - it is the *only* shape that fixes both beads at
once:

- `prepareWriteDirs` is the single function both tiers already share for this
  (`internal/linux/linux.go:710`, called from `preflightGrants:704` and
  `degraded.go:118`). It is the one place all callers route through.
- Returning what it created from there removes the second stat pass **and** hands
  `runDegraded` the list it currently has no way to obtain, without `runDegraded` having to
  adopt `preflightGrants`.
- `absentWrites` (`linux.go:699`) then deletes outright rather than being optimised.

So bv2-dhj3o and the cost note collapse into one fix: change `prepareWriteDirs`' signature,
delete `absentWrites`, wire the return through both tiers. That is also the root-cause shape
rather than the per-caller one - a guard in the shared function instead of one in each
caller. **VERIFIED BY SPIKE** (the gap), **BY READING** (the shared-function claim: both
call sites cited above).

### bv2-ciz11 - "the tier differential's terminal rows never assert in CI" - **SAME CELL as half of F4; the other half is confirmed unfiled**

The skip half is the bead's. **VERIFIED BY EXECUTION**: `controlling-terminal` and
`tty-inject-ioctl` both SKIP with "needs a controlling terminal, and this run was not
started from one", while the table still reports PASS.

The coverage half is **distinct and, as far as I can tell, unfiled**. I counted it
independently rather than taking it on report: `docs/state-grid-launcher-order.md:52`
declares "Grid A - restriction x state (13 x 4 = 52 cells)" and its table carries rows 1-13.
The 4 differential rows map onto **3** of those restrictions - row 11 (SysV IPC), row 10
(capability bounding set), row 6 (terminal detach, twice). Ten of thirteen restrictions have
no differential row at all; on a non-tty host the table measures two. That is a separate
item from "these two rows skip", and fixing the skip does not touch it. **VERIFIED BY
READING.**

F5 (`--unshare-cgroup` missing from the differential's reference arm,
`internal/launcher/tierdiff_test.go:155-159`) is a third distinct item and belongs on
neither bead.

### bv2-3mxlo - SysV IPC failing on the degraded tier with nothing saying why - **DISTINCT, not a cell of this grid**

Adjacent to the disclosure axis but pointed the other way, and the distinction is worth
stating because it decides whether this grid can speak for it.

My invariant is one-sided about **residue**: a restriction the degraded tier does *not*
apply must be disclosed. bv2-3mxlo is about a restriction it *does* apply - the SysV IPC
denials added to `BlockProcessReach` - and a target that needs one getting EPERM with no
explanation. That is the opposite direction, and my invariant explicitly permits it: it is
over-restriction, not under-disclosure of a gap.

Confirming the factual claim anyway, since it is cheap: the degraded Consequences text has
`signalClause` (`internal/linux/probe.go:407`) for signals and `unixSocketClause` (`:387`)
for unix sockets, and **neither mentions `shmget`/`msgget`/`semget`**. So the tier now
denies twelve syscalls that no probe text names. The bead is correct and is not duplicated
by anything here. **VERIFIED BY READING.**

Worth noting for whoever takes it: this is a second, opposite-direction invariant over the
same Consequences string ("every restriction this tier applies that a target might need is
named"), which is a grid of its own and not one I walked.

### bv2-dnda5 - an unsampled scope refusing a completed run - **DISTINCT: the recorded cost of a cell I verdicted HANDLED**

Cell C4.4. Not a finding of mine and not a duplicate - it is the price of the fix, and the
grid corroborates that the price is real and confined to one path.

The asymmetry is deliberate and I verified it end to end. On `Run`, an unsampled reading
**worsens** a layer (`noteScopeLimits`, `internal/linux/scopeattest.go:185-189`) and refuses
nothing: admission happens before the run, against `e.Probe` (`enforce/run.go:124-127`), and
nothing downstream re-admits on the post-run report. On `Profile` it **refuses**
(`internal/linux/profile.go:227`), because Profile has no Report to worsen - stated at
`scopeattest.go:197-200`. So the bead's "refuses a completed run" can only be the profiling
path, and only with limits requested.

That narrows the bead usefully: the blast radius is profiling runs with a `Limits` block on
a host whose manager is slow enough to miss the sample, measured at 0 of 100 in the sampler's
own note (`scopeattest.go:53-56`). The `cancelled` guard at `profile.go:226` already carves
out the one case that was certain to be wrong. **VERIFIED BY READING.**

### Dedup summary

| Bead | Verdict | Action |
|---|---|---|
| bv2-0hy3m | same cell as F1 | append spike evidence, do not file |
| bv2-dhj3o | strictly worse sibling of F2a | re-scope; collapses with its own cost note into one `prepareWriteDirs` signature change |
| bv2-ciz11 | same cell as half of F4 | the 3-of-13 coverage half is unfiled and needs its own item; F5 a third |
| bv2-3mxlo | distinct, opposite direction | not this grid's; correct as filed |
| bv2-dnda5 | distinct, recorded cost of C4.4 | narrow to the profiling path with limits |
| F2b (Profile's `createdWrites`) | **unfiled** | needs its own item; see below |
| F3 (nil `Stderr`) | **unfiled** | design item; see below |

F2b is the one finding with no bead at all: `Profile` drops `createdWrites`
(`internal/linux/profile.go:129`) across eight subsequent failure points. It is F2a's twin
but a different entry path, and the `prepareWriteDirs` signature change above gives it its
list too - so all three land in one change with three regression tests.

## Job 1 - F3: what the channel should be

**Recommendation: one `Residue []string` field on `enforce.Result`. Not an error, not a
seam.**

The reason it is not over-reach is that the field already has three siblings of exactly this
shape in exactly this struct - `ChangedAutoExec`, `RedirectedHooks`, `UnresolvedHooks`
(`enforce/enforce.go`, the `Result` type). Those are post-run host facts that are not layer
states and not failures, carried out on every arm including the error ones. Teardown residue
is the same kind of thing, so this adds a field to an established pattern rather than a new
concept. The comment at `internal/linux/linux.go:728-731` argues against putting hygiene in a
*confinement layer*, and that argument stands - a `Result` field is not a layer, which is
precisely why those three siblings are not layers either.

Rejected alternatives, briefly:

- **A returned error.** Wrong direction. Residue is not a failure - a clean run that left a
  mount point standing succeeded. Returning an error would turn every such run into a failed
  one, and callers would start ignoring the error to get their exit code, which is worse than
  the silence it replaces.
- **A callback / reporter seam.** Speculative generality for one consumer. There is no second
  caller asking for this, and a seam defined now would be defined against the wrong shape.

**Cost, honestly:** the field is one line; wiring it is not. `Result` is constructed on four
arms of `Run` (`linux.go:304, 324, 344, 378`) plus `runDegraded`'s arms, and the residue is
only known at defer time, which is *after* those returns are built. So the field has to be
populated from the deferred closure through the named return - the same mechanism
`linux.go:118-122` already uses for `err`, so the pattern is in place, but it is genuinely
fiddlier than adding a struct field usually is, and it is the part a reviewer should look at.

**One gap the field does not close, and the bead must say so:** `Profile` returns a
`profile.Observation`, not a `Result`. So a `Result.Residue` fixes F3 for `Run` and
`runDegraded` and does nothing for F1/F2b's embed case. The peer field belongs on
`profile.Observation`. `warnResidue` stays either way - it is the right channel for the CLI,
and the field is for the caller that has no terminal.

Stamp: **VERIFIED BY READING** (the three sibling fields and the four construction sites were
read first-hand). The recommendation itself is a design judgement, not a verified fact.

## Job 2 - the coupling gap: is there a cheap test?

**Yes, and the answer is close to the one you guessed - but it cannot live in the launcher's
own test, and that limitation is the interesting part.**

`internal/launcher` **cannot** import `internal/linux`: the dependency runs the other way
(`internal/linux/args.go:18`, `applied.go:15` both import the launcher), so the assertion
would be an import cycle. Every reference the launcher makes to `internal/linux` today is a
prose comment, `internal/launcher/degraded.go:313` among them - which is itself part of why
this coupling is only held together by comments.

So the test lives in `internal/linux`, next to the const it guards:

```go
// restrictCapabilityBound (internal/launcher/degraded.go:141) deliberately lets an
// undroppable bounding set pass on an unprivileged host, on the sole ground that the
// degraded tier's Consequences disclose it. That is this const, in another package,
// reached through one concatenation - so the launcher's decision is only sound while
// this text says so.
func TestDegradedConsequencesDiscloseTheCapabilityBound(t *testing.T) {
	c := filesystemLayer(namespacesBlocked, "r", true, true, true, true, true, true, true).Consequences
	for _, want := range []string{"capability bounding set", "PR_CAPBSET_DROP", "refused"} {
		if !strings.Contains(c, want) {
			t.Errorf("the degraded disclosure no longer mentions %q, so restrictCapabilityBound's inert-residual decision is now undisclosed", want)
		}
	}
}
```

Cheap - one call, no host state, runs everywhere. **Run, not just proposed:** it PASSES
against the degraded arm as written, and inverted against a disclosure-free arm
(`namespacesUsable`, whose `Consequences` is empty) it FAILS on all three strings - so the
assertion has teeth rather than matching some other sentence in the text.

**Be honest about what it buys, because it is less than it looks.** It is a one-directional
tie: it stops the const being deleted or gutted, which is the likely failure. It does **not**
notice if `restrictCapabilityBound` changes its decision and the text goes stale in the other
direction, and no test in either package can, because the two cannot see each other. Closing
that properly means the disclosure text and the launcher's decision sharing a source - the
same shape `limitControllers` (`internal/linux/scopeattest.go:161`) already uses to stop its
two readers drifting, and the precedent worth citing on the bead.

Take the cheap test now; it turns a silent rot into a failing build for the common case. Note
the residual on the bead rather than pretending the test closes it.

Stamp: **VERIFIED BY SPIKE** for the test body (run both ways, output above). **VERIFIED BY
READING** for the import direction - no `internal/linux` import exists anywhere in
`internal/launcher`; every reference is a comment. The claim that a shared source would close
the remaining direction is a design judgement, not a verified fact.
