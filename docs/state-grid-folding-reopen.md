# State grid: shield folding, Phase 2 re-open pass

> **Status, 2026-09-20 (fleet run).** One claim of this document is RETRACTED: the corpus
> could already express checkout-derived cases, and two of the three differential harnesses
> already derived and passed the workspace rules (`internal/linux` and `cmd/bento`; `gate`
> passes nil by documented divergence). What was genuinely uncovered was the derived half at
> a FOLDED spelling, now landed as a real corpus case (af2e925, cd3cd10). The retraction is
> recorded on bv2-k2g1h, which owns the decision. **E8 remains OPEN and is not a coding
> task**: it needs a refuse-or-disclose call from a human. One cost now known - if the answer
> is DISCLOSE, `shieldcorpus.Verdict` models refusals only and has no member for a
> disclosure-only outcome. The F2c/F3c comment drift is fixed (233ed86).

Reviewed 2026-09-20 at 9a90f6a. This is not a fresh enumeration. It re-opens the two
existing grids - `docs/state-grid-shield-verdict.md` (verdict x kind x consumer, written at
924e291 / 5a98897) and `docs/state-grid-profile-clamp.md` (proposal vs run refusals) -
against the eight folding commits that landed after them, and asks of each one the single
question the skill names as highest-yield: **not "is this fix correct" but "was the rest of
the row carried along".**

## Phase 0 - fit

**Fit: ACCEPTED, narrowly.** Declining was live and is argued below, because the existing
grids are unusually complete and the named tests are real.

Signals, all three present:

1. **Mirror set, the strongest kind.** `shield.Set.Contains` is one source of truth read by
   nine call sites across four packages (`internal/linux/grants.go` x4,
   `cmd/bento/clamp.go` x3, `gate/gate.go` x2, `internal/linux/linux.go:992`), each
   switching or equality-testing on the verdict. `internal/shieldcorpus` exists precisely
   because they diverged.
2. **An enum times its call sites.** Seven verdicts x nine sites.
3. **Eight one-at-a-time fixes in one day**, all on the same noun. That is the tell.

**Invariant, restated unchanged and verified in Phase 0:**

> A refusal may be NARROWER than the backend's; it may never be WIDER. A frontend that
> refuses what the backend accepts is a documented narrowing; a frontend that accepts what
> the backend refuses is always a bug.

**Which contract I judged against.** `gate/gate.go:12-17` states its own direction: the
package doc rules out refusing what a run accepts - the gate may MISS a refusal, never
invent one. It is restated at gate.go:464-470 and again at `writeShieldProblem`'s
AboveWriteShield arm (gate.go:691-696). That is the same one-sidedness worded from the
gate's side, so the two agree and every cell below is judged against the invariant as
stated. VERIFIED BY READING.

One correction to how the invariant was applied in the older grid: it is stated
frontend-vs-backend, so a cell where **neither** side refuses falls outside it. Those are
still grid cells and still findings - see Grid E - but they are UNHANDLED rather than
forbidden-direction.

### Why I did not decline

Read the bodies, not the names, as instructed:

- `FuzzShieldCoversReachableSecrets` (`internal/linux/shield_fuzz_test.go:242`) and
  `TestShieldInvariantsExhaustive` (:266) share one body, `checkShieldInvariants` (:174).
  Read in full: it builds `testSandbox(existing...)` - the real host FS seam, which folds
  nothing - asks `explicitShieldOptIns` and `checkReadNotShielded` for a **READ** grant
  only, and passes no `workspace` argument anywhere. The fuzz corpus does seed the folded
  spelling `/home/u/.SSH`, so the `covers` fold is exercised in the INSIDE direction, but
  the `SameFile` seam is never varied and no write grant is ever asked. So the target
  cannot reach cell E8 - a WRITE grant above workspace-derived shields on a folding mount -
  nor any above-direction folding cell. Strong oracle, smaller space.
  VERIFIED BY READING (the body, not the name).
- `TestShieldGroundTruthMatchesTheWrittenMenu` (:279) asks `shieldGroundTruth(sb, g)` over
  `fuzzGrants` and compares against the hand-written `fuzzOptInable` / `fuzzRefusedGrant`
  tables. It is about which grants are opt-in-able and which one is refused, over the same
  non-folding `testSandbox`; it never reaches a verdict-x-fold cell. VERIFIED BY READING.
- The corpus differentials (`*shield_differential_test.go`) DO carry `Case.Folding`, and
  that is where the folding property is genuinely asserted - but `shieldcorpus.Case` has no
  field for workspace-derived rules, so the corpus cannot express Grid E's open cell either.

So the whole folding property is not asserted today. The grid earns its keep.

## Phase 1 - dimensions

Derived from the code, not from history. Four small grids beat one cross product; the
dimensions below do not interact.

- **Grid D** - the NEW verdict arm (FoldedShield raised over a DenyWrite shield, write
  grants only) x every consumer of `Contains`. 9 cells.
- **Grid E** - shield ORIGIN x containment direction x fold. This is the row 0418cea walked
  half of. 11 cells.
- **Grid F** - truncation CAUSE x consumer of `TruncatedStores`. The fe7769a row. 9 cells.
- **Grid G** - refusal SENTENCE x "can this sentence now be raised over a DenyWrite
  shield". The a3f81c8 row. 7 cells.

36 cells. Every one has a verdict below.

## Commit-to-cell map

| Commit | Cell it fixed | Rest of the row |
|---|---|---|
| `0418cea fix(shield): refuse a folding write shield on both tiers` | Grid E cell E7: built-in DenyWrite x above x folding. New `FoldedShield` arm, verdict.go:180-210 | **NOT carried: cell E8**, workspace-derived DenyWrite x above x folding |
| `c0305d9 fix(shield): fold only the spelling inside the grant` | Narrowed E7's loop to `covers(grant, a.Resolved)` alone, verdict.go:203 | Carried - the DenyAll fold loop (verdict.go:134) already had the identical narrowing |
| `dae2b38 fix(clamp): drop a write grant above a folding shield` | Grid D cell D6, via a second WRITE ask in `clampShieldedGrants` | Superseded by 75c0087 |
| `75c0087 fix(clamp): pin the folding write's withholding channel` | Reverted dae2b38 and moved D6 to `withholdRunRefused` | Carried, with a test; the test's own narrowing is stated in it. The commit also carries a `gate/gate.go` prose narrowing about a profiling run's HOME tmpfs and a `gate/workdir_test.go` assertion fix - both outside the folding scope, checked and not re-graded here |
| `a3f81c8 fix(grantrefusal): kind-neutral noun for FoldedShield` | Grid G cell G1 | Carried - G2..G7 checked, no other sentence is now kind-ambiguous |
| `fe7769a fix(shield): disclose a store read only in part` | Grid F: a second truncation cause reaches `truncatedStores` | Half carried by a SIBLING commit, `905d683` (16:52, 43 minutes later), which rewrote `render.go`'s prose and emitted line for both causes. **Still uncarried: cells F2c/F3c**, the doctor JSON field's prose and `truncatedStores()`'s own |
| `052f651 test(shield): pin the workspace and caller-deny arms` | Pins the workspace INSIDE direction (`TestEveryWorkspaceRuleRefusesAWriteAtItself`) | The ABOVE direction is unpinned - the same gap as E8 |
| `17bef85 style: gofmt shieldcorpus` | none (formatting) | n/a |

## Grid D - FoldedShield over a DenyWrite shield x consumer

The arm sits AFTER `Contains`' `kind == Read` early return (verdict.go:139), so it is a
write-only verdict. "Refuses" below means the grant does not reach the host.

| # | Consumer | Ask | Verdict | Stamp |
|---|---|---|---|---|
| D1 | `checkNotShielded` full tier (grants.go:92, arm :101) | Write | HANDLED: refuses with `grantrefusal.FoldedShield` | EXECUTION (corpus case "write containing a write shield on a case-folding mount") |
| D2 | same, degraded tier (degraded.go:56 -> `checkGrants`) | Write | HANDLED: shared function, refuses | READING (one function, both tiers) |
| D3 | `checkWriteNotAboveWriteShield` (grants.go:279) | Write, `== AboveWriteShield` | HANDLED by omission: the fold loop returns first so this returns nil - but D1/D2 already refused, and `runDegraded` calls `checkGrants` (degraded.go:56) before this (degraded.go:61). Coupling note: nothing ties the ordering | READING |
| D4 | `checkWriteNotUnderReadOnlyShield` (grants.go:176) | Write + workspace, `== UnderWriteShield` | IMPOSSIBLE to matter: the fold arm is the ABOVE direction; the inside direction is answered by `covers`, which folds in both directions (verdict.go:239-266) | EXECUTION (`TestWriteUnderAReadOnlyShieldIsRefusedThroughAFoldedSpelling`) |
| D5 | `writeShieldProblem` (gate.go:673, arm :687) | Write | HANDLED: refuses in the same sentence. Not a widening - the full tier refuses too now, which is exactly what 0418cea changed | READING |
| D6 | `clampShieldedGrants` (clamp.go:56) | **Read** | HANDLED by design: keeps. The verdict is write-only so a read ask cannot see it; `withholdRunRefused` -> `gate.Refusals` -> `ShieldedWriteProblems` withholds it in the refusal's own sentence (clamp.go:45-52, gate.go:224/233) | EXECUTION (`TestShieldCorpusClampDrops`' folding arm asserts `ShieldedWriteProblems` non-empty) |
| D7 | `clampWriteShieldedGrants` (clamp.go:99) | Write, `== UnderWriteShield` | HANDLED: not its verdict, no action needed | READING |
| D8 | `aboveWriteShieldGrants` (clamp.go:131) | Write, `== AboveWriteShield` | HANDLED: correctly silent. The fold makes the refusal tier-independent, so the degraded-tier *report* is the wrong channel and D6 is the right one | READING |
| D9 | `linux.go:992` entrypoint/interpreter | Read, `v != Honored` | IMPOSSIBLE: a write-only verdict under a Read ask, pinned by `TestAReadGrantEarnsNoWriteOnlyVerdict` | EXECUTION |

**Grid D result: the row WAS carried.** 0418cea/75c0087 walked every consumer. This is the
main dismissal of the pass and it was verified inverted - D6's channel was traced end to end
rather than taken from its comment: `Refusals` (gate.go:224) calls `refusals`, which appends
`ShieldedWriteProblems` (gate.go:233), whose FoldedShield arm is gate.go:687.

## Grid E - shield origin x direction x fold

This is where 0418cea stopped. "Above" = the grant CONTAINS the shield.

| # | Shield origin | Direction | Fold | Verdict | Stamp |
|---|---|---|---|---|---|
| E1 | built-in DenyAll (`~/.ssh`) | inside | no | HANDLED: `InsideShield`, verdict.go:110 | EXECUTION |
| E2 | built-in DenyAll | inside | yes | HANDLED: `covers` folds, same arm | EXECUTION (fold_test.go) |
| E3 | built-in DenyAll | above | no | HANDLED: `AboveShield` for a write, Honored for a read (correct - the bind holds) | EXECUTION |
| E4 | built-in DenyAll | above | yes | HANDLED: `FoldedShield` for both kinds, verdict.go:130-137 | EXECUTION (`TestGrantContainingAShieldIsRefusedWhereTheMountFoldsCase`) |
| E5 | built-in DenyWrite (`~/.pyenv/shims`) | inside | yes | HANDLED: `UnderWriteShield` through `covers` | EXECUTION |
| E6 | built-in DenyWrite | above | no | HANDLED: `AboveWriteShield`, degraded tier only, documented tier split | EXECUTION |
| E7 | built-in DenyWrite | above | yes | HANDLED: `FoldedShield`, both tiers - **this is what 0418cea fixed** | SPIKE (control arm returned verdict 6 = FoldedShield naming `.pyenv/shims`) |
| E8 | **workspace-derived DenyWrite** (`<checkout>/.git/hooks`, `.vscode`, `config.worktree`) | **above** | **yes** | **UNHANDLED** - see below | **SPIKE** |
| E9 | workspace-derived DenyWrite | inside | either | HANDLED: workspace loop, verdict.go:153-158, pinned by 052f651's `TestEveryWorkspaceRuleRefusesAWriteAtItself` | EXECUTION |
| E10 | caller deny (always DenyAll) | inside | either | HANDLED: `InsideCallerShield`, verdict.go:116 | EXECUTION |
| E11 | caller deny | above | yes | HANDLED: caller denies are DenyAll and live in `s.applied`, so E4's loop covers them | READING |

### E8 - the cell the row stopped short of

**UNHANDLED. VERIFIED BY SPIKE.**

`internal/shield/verdict.go:180-210` - the folding loop iterates `s.applied` only. It never
looks at the `workspace` argument. The workspace loop that does
(`internal/shield/verdict.go:153-158`) is the INSIDE direction alone.

Spike (`internal/shield/zzspike_test.go`, since deleted), `write: <home>/proj` with the
workspace rules the REAL emitters produce - `denylist.Workspace(checkout)` plus
`denylist.WorkspaceGitfile(checkout)`, the same pair 052f651's test uses, 12 rules, every
one `DenyWrite`, covering `.git/hooks`, `.git/config`, `.git/config.worktree`, `.vscode`,
`.idea`, `.cargo/config.toml`, `.cargo/config` and `.git` itself:

```
fold=false write:.../proj   -> verdict=0 (Honored)          rule=""
fold=true  write:.../proj   -> verdict=0 (Honored)          rule=""
CONTROL fold=false write:.pyenv -> verdict=5 (AboveWriteShield) rule=".pyenv/bin"
CONTROL fold=true  write:.pyenv -> verdict=6 (FoldedShield)     rule=".pyenv/shims"
```

The control shows the escalation working for a built-in. The workspace rule gets none.

**Why it matters, and it is 0418cea's own argument.** Grid C1 of
`state-grid-shield-verdict.md` records the byte-exact case and says the **full tier holds**,
because `denyArgs` ro-binds each derived shield after the grant's bind and bwrap is
last-wins. 0418cea's finding is that a bind covers the one spelling it names, so where the
mount presents the shield's directory under a second entry, that entry sits inside the
grant's read-WRITE bind. Carrying the corpus's own hedge, which `c0305d9` added and which
this cell must not drop: that was *measured on a mount presenting two dentries for one
directory*, where the write reached the host. A mount that folds in the dentry layer may
instead hit the bind under either spelling. The verdict cannot tell the two apart, which is
why 0418cea refuses both - and the same inability is why this cell cannot be graded safe.

Applied to `<checkout>/.git/hooks`, on the two-dentry shape, `.git/HOOKS/pre-commit` is
plantable on the host through a full-tier run of `write: <checkout>` - the ordinary project
grant - and nothing refuses it on either tier.

Direction: **not** a forbidden-direction violation of the stated invariant, because no
frontend accepts what a backend refuses - no side refuses.

**Reconciled against the prior pass, which rejected the byte-exact version of this shape.**
`state-grid-shield-verdict.md`'s F3 was moved to Rejected because degraded-grid F4 x A1
marks derived write shields inside a write grant HANDLED-disclosed, through
`exposedShields`. That disposition does not transfer here, and the reason is precisely the
tier split: the byte-exact case is an exposure of the **degraded tier alone**, a tier a
caller opts into with `--allow-degraded` and whose documented cost it is, while the full
tier holds. Under a fold the full tier's hold is what goes away, on the tier every run lands
on unless the caller opts out - and nothing records that. So this is a live cell rather than
a duplicate of a settled one.

What it is NOT is an argument for the symmetric fix. `Contains`' own doc (verdict.go:80-88)
says workspace shields are consulted inside-only because a self-derived shield sits strictly
under its own grant, so the above direction is structurally always true - adding the missing
loop would refuse **every** `write: <checkout>` on **every** folding mount, which is a much
larger proposition than refusing `write: ~/.pyenv`. The likely right answer is the
disclosure channel the degraded tier already uses, extended to the full tier where the mount
folds, rather than a refusal. Graded UNHANDLED because no side does either today; the fix's
shape is a decision for whoever takes the item, not something this grid settles.

Partial mitigation, checked rather than assumed: `ChangedAutoExec` is carried on BOTH tiers
(`internal/linux/linux.go:318,335,355,389` and `internal/linux/degraded.go:300,321,331`), so
a plant is disclosed after the run. Detected, not prevented, and not disclosed as a
shield-coverage shortfall the way `Exposed` discloses the degraded tier's. VERIFIED BY
READING.

**"Nothing else asks the fold question of workspace rules", checked rather than assumed.**
`grep -rn 'foldsCase|SameFile'` over non-test Go returns exactly two `foldsCase` call sites,
`internal/shield/verdict.go:134` (DenyAll) and `:211` (DenyWrite), both iterating `s.applied`
alone; the only other `SameFile` uses are the seam's own definition
(`internal/shield/shield.go:57,76,90`), the backend's seam (`internal/linux/shields.go:96`),
the corpus's folding seam, and an unrelated one in `trust/trust.go:216`. No other site -
`denyArgs`, `shieldRules`, `checkWorkspaceShieldNotRedirected` - asks it at all. VERIFIED BY
EXECUTION.

Why a corpus row is not the cheap fix here, though the brief prefers one:
`shieldcorpus.Case` has no field for a workspace-derived rule, and the three differential
harnesses never pass a `workspace` argument to `Contains`. The cheap landing is a test in
`internal/shield` beside `TestWriteAboveAReadOnlyShieldThatFoldsCaseIsRefusedOnBothTiers` -
but it must assert the FIXED behaviour, so it belongs to the fix, not to this grid. I did
not land a test pinning the gap as correct.

## Grid F - truncation cause x consumer

fe7769a added a second cause to one channel.

| # | Cause | a. `Set.TruncatedStores` | b. `render.writeTruncatedStores` | c. `doctor.TruncatedStores` | Stamp |
|---|---|---|---|---|---|
| F1 | depth bound reached | HANDLED (rules.go:183) | HANDLED, prose names it | HANDLED | READING |
| F2 | `ListDir` failed having returned entries | HANDLED: `truncated := !ok`, rules.go:334 | HANDLED by sibling `905d683`, not by fe7769a: render.go:2046-2055 names both causes and the emitted line says "or a directory inside it could not be read" (VERIFIED BY EXECUTION: `git log -S` names that commit, dated after fe7769a) | **WRONG prose**: `cmd/bento/doctor.go:159-160` still says "walked only as far as the walk bound" | EXECUTION (`TestAStoreTheWalkCouldNotReadWholeIsReported`, both arms) for the behaviour; READING for the prose |
| F3 | `ListDir` failed having returned nothing | HANDLED: rules.go:311 now returns `true` | HANDLED (same channel) | same stale prose | EXECUTION |

**F2c/F3c: WRONG, VERIFIED BY READING.** `cmd/bento/doctor.go:159-160`, and the same
one-cause sentence at `cmd/bento/render.go:2077` on `truncatedStores()`'s own doc comment -
the latter sitting thirty lines below the exported prose `905d683` did update, which is what
makes it a missed half of a row rather than an oversight nobody could have seen.
Both are one-cause sentences on a two-cause field, which is the exact shape a3f81c8 was
raised for on the other side of the tree. Low blast radius - a JSON field comment and an
unexported helper's comment - but it is the half of the row that was not carried, and this
repo's convention makes cross-file prose load-bearing.

Not edited here: the brief reserves filing to the orchestrator, and a prose correction is
one item rather than a grid change.

## Grid G - refusal sentence x reachable over a DenyWrite shield

a3f81c8's row. Per cell: can `Contains` now hand this sentence a DenyWrite rule, and does
the sentence stay true if it does?

| # | Sentence | Reachable over DenyWrite? | Verdict | Stamp |
|---|---|---|---|---|
| G1 | `grantrefusal.FoldedShield` | YES, since 0418cea | HANDLED: noun made kind-neutral, pinned by `TestFoldedShieldDoesNotClaimTheShieldHidesItsContent` | EXECUTION |
| G2 | `WriteAboveShield` | No - `AboveShield` is raised in the DenyAll loop only (verdict.go:159-178) | HANDLED: keeps denylist's "always-shielded" noun, asserted in the same test | EXECUTION |
| G3 | `WriteAboveWriteShield` | YES by construction | HANDLED: already worded for DenyWrite | READING |
| G4 | `WriteUnderReadOnlyShield` | YES by construction | HANDLED | READING |
| G5 | `InsideShield` / `WriteInsideShield` | No - DenyAll loop only | HANDLED | READING |
| G6 | `InsideCallerShield` | No - caller denies are DenyAll | HANDLED | READING |
| G7 | `ShieldNotCarvable` | Names a mount point, not a verdict | HANDLED, outside the fold row | READING |

**Grid G result: the row WAS carried.** G1 was the only sentence the new arm made
kind-ambiguous, and the test deliberately checks G2 alongside it so a kind-neutral sweep
cannot take a true sentence away with the false one.

## Cell count by verdict

| Verdict | Count |
|---|---|
| HANDLED | 31 |
| WRONG | 2 (F2c and F3c - one defect, two sites) |
| UNHANDLED | 1 (E8) |
| IMPOSSIBLE | 2 (D4, D9) |

All 36 walked. None skipped.

## Findings, forbidden direction first

**Forbidden direction (a frontend accepting what a backend refuses): none.** Every consumer
in Grid D agrees with both backends on the new arm. That was the headline risk of 0418cea -
adding a verdict the frontends do not know - and it did not happen.

1. **E8 - UNHANDLED. `internal/shield/verdict.go:180-210`.** The folding escalation 0418cea
   added for built-in DenyWrite shields was not carried to workspace-derived ones, so
   `write: <checkout>` on a case-folding mount leaves `.git/HOOKS` (and `.VSCODE`, and the
   gitdir-scan shields) writable through to the host on BOTH tiers, where the byte-exact
   case is held by the full tier's ro-bind. Disclosed after the fact by `ChangedAutoExec`,
   not prevented. VERIFIED BY SPIKE. Acceptance for the fix must include the regression
   test: `internal/shield` can express it, the corpus cannot.
2. **F2c/F3c - WRONG prose. `cmd/bento/doctor.go:159-160` and `cmd/bento/render.go:2077`.**
   Both describe `TruncatedStores` as the depth bound alone; fe7769a gave the field a second
   cause and updated `internal/shield/rules.go:176-183` and `cmd/bento/render.go:2046` but
   not these two. VERIFIED BY READING.

## Dismissals, each verified inverted

- **"c0305d9's narrowing dropped a reachable case."** Dismissed. The loop now tests
  `covers(grant, a.Resolved)` alone where the `AboveWriteShield` loop below it tests three
  spellings. The two dropped spellings are `loc` (parent resolved, base literal) and the
  literal rule path, both describing a shield whose NAME is inside the grant while its
  TARGET is elsewhere. A fold at the name level sends both spellings through the same
  symlink to the same shielded target, so nothing is walked around - which is what the
  comment claims and what the mechanism does. The DenyAll fold loop (verdict.go:134) has had
  the identical narrowing all along, so the two halves agree. VERIFIED BY READING.
- **"D6 rests on a comment."** Dismissed by tracing the channel end to end: gate.go:224 ->
  gate.go:233 -> gate.go:687. VERIFIED BY READING, plus the corpus test's own arm.
- **"The existing tests already cover the folding property, so decline."** Dismissed with
  the inverted check done: neither `FuzzShieldCoversReachableSecrets` nor
  `TestShieldInvariantsExhaustive` passes a `workspace` argument or varies the `SameFile`
  seam, so neither can reach E8 or any folding cell. VERIFIED BY READING of both bodies.
- **"E8 is the same cell the prior pass rejected as F3."** Dismissed, with the reason
  stated in full at E8: the byte-exact disposition rests on the full tier holding, and the
  fold is what removes that hold, on the default tier rather than the opt-in one.
- **"Some other site asks the fold question of workspace rules, so E8 is covered."**
  Dismissed by grep over non-test Go: two `foldsCase` call sites, both over `s.applied`.
  VERIFIED BY EXECUTION.
- **"D3's ordering is a latent bug."** Dismissed: `runDegraded` calls `checkGrants`
  (degraded.go:56) before `checkWriteNotAboveWriteShield` (degraded.go:61), so the fold is
  refused first and in the right sentence. Recorded as a coupling note, not a finding -
  nothing would fail to compile if the order moved.

## Corrections made to the existing grid files

- `docs/state-grid-shield-verdict.md` cell **A12** - the full-tier "HANDLED (holds rather
  than refuses)" cell now carries the fold split 0418cea introduced.
- `docs/state-grid-shield-verdict.md` cell **C1** - "Full: holds: ro-bind of each derived
  shield" was written unconditionally and does not hold on a case-folding mount. Corrected
  and cross-referenced to E8, carrying the corpus's own two-dentry hedge rather than
  asserting the leak flatly.
- `docs/state-grid-shield-verdict.md` finding **F4** - the corpus-coverage note now records
  that the corpus cannot express a workspace-derived case at all.
- `docs/state-grid-profile-clamp.md` cell **A20** - "clampShieldedGrants drops any
  non-Honored read verdict, including FoldedShield" is still true but is no longer the whole
  story for a write: corrected to name `withholdRunRefused` as the channel for the DenyWrite
  fold (dae2b38, then 75c0087).

## Phase 4

- Spike `internal/shield/zzspike_test.go` deleted; tree clean.
- Gates run on the touched packages (`internal/shield`, `internal/linux`, `gate`,
  `cmd/bento`, `internal/grantrefusal`) plus `make vet`. This grid changed no source, so
  that run is a baseline rather than a verification of an edit.
- Permanent corpus seed candidate: E8 (folding mount x `write: <checkout>` with a derived
  `.git/hooks` shield). Not landable as a `shieldcorpus.Case` today - see Grid E.

## Phase 2 re-open, second half: the known-open list (2026-09-20)

Handed over after the grid was written, as the skill requires, so none of it biased Phase 1.

### E8 vs bv2-kxv8p - one defect or two?

**Two, and the distinction is the whole point.** They are the same *symptom* - built-in
shields get something checkout-derived shields do not - with different root causes, and they
cannot be fixed by one change.

- **bv2-kxv8p is a LAYERING gap.** `gate.ShieldCarveProblems` (gate.go:562) iterates
  `set.Mount(set.Rules())` - built-ins only - while the backend's `checkShieldsCarvable`
  (internal/linux/shields.go:367) iterates `shieldRules(sb, writes)`, which appends
  `workspaceShields` at shields.go:141. The gate cannot reach the derived half because
  deriving it needs `sb.isDir` / `sb.listDir` / `checkoutRoot`, host facts a cross-platform
  package has no access to. The bead says so itself and records it as a boundary decision
  `scripts/layering.sh` names an exception for. The derived rules **exist** on one side and
  are **unreachable** on the other.
- **E8 is a DIRECTIONALITY gap inside one function.** `Contains` is *handed* the derived
  rules - the caller passes them - and consults them in the inside direction
  (verdict.go:153-158) and not the above direction (the fold loop at :196-212 and the
  `AboveShield` loop at :159-178 both iterate `s.applied` alone). Nothing is unreachable;
  one direction is deliberately not asked. Fixing kxv8p - having the gate derive workspace
  shields - changes nothing about E8, and vice versa.

**The sweep the coordinator asked for, and its result.** Every non-test site that derives or
takes the workspace half:

| Site | Derived half consulted? | Verdict |
|---|---|---|
| `shield.Contains`, inside loop (verdict.go:153) | YES | HANDLED, pinned by 052f651 |
| `shield.Contains`, `AboveShield` loop (verdict.go:159) | no | IMPOSSIBLE to matter: that loop guards on `Deny == DenyAll` and every rule `denylist.Workspace` / `WorkspaceGitfile` emits is `DenyWrite` - verified by the spike (12 rules, all DenyWrite) and pinned forward by 052f651's `TestEveryWorkspaceRuleRefusesAWriteAtItself` |
| `shield.Contains`, fold loop (verdict.go:196) | **no** | **UNHANDLED - E8** |
| `checkWriteNotUnderReadOnlyShield` (grants.go:161-176) | YES | HANDLED |
| `checkWorkspaceShieldNotRedirected` (grants.go:215) | YES - it is the derived half's own check | HANDLED |
| `checkWriteNotAboveShield` (grants.go:252) | no, passes nil | IMPOSSIBLE, same DenyAll guard as above |
| `checkWriteNotAboveWriteShield` (grants.go:279) | no, passes nil | The byte-exact sibling of E8. Already on the books as grid C1 / rejected finding F3, disclosed through `Exposed` |
| `shieldRules` -> `denyArgs`, `createdShields` (shields.go:116,141,504) | YES | HANDLED - the enforcement side has always had it |
| `checkShieldsCarvable` (shields.go:367) | YES | HANDLED |
| `gate.ShieldCarveProblems` (gate.go:562) | **no** | **bv2-kxv8p** |
| `clampWriteShieldedGrants` (clamp.go:94) | YES | HANDLED |
| `aboveWriteShieldGrants` (clamp.go:131) | no, passes nil | Mirrors grants.go:279 deliberately |
| `redirectedWorkspaceProblem` (clamp.go:501) | YES | HANDLED - the clamp's mirror of grants.go:215 |
| credential-alias scan, both sides (`internal/linux/alias.go:793`, `gate/alias_unix.go:159`) | no, both | IMPOSSIBLE: both filter `r.Deny == denylist.DenyAll` (alias.go:794), and no workspace rule is DenyAll. Symmetric, so no mirror gap |

**No third or fourth undiscovered site.** That is the sweep's real result, and it is worth
stating as a negative: the above-direction exclusion of derived shields is not scattered
neglect, it is **one decision applied at four call sites** (verdict.go:159, verdict.go:196,
grants.go:279, clamp.go:131), documented at `Contains`' own doc (verdict.go:80-88) - a
self-derived shield sits strictly under its own grant, so refusing a grant that contains one
would refuse every project write there is. E8 is the single cell where that decision was
made before the fold existed and was not revisited when 0418cea showed the fold removes the
full tier's hold. VERIFIED BY EXECUTION (the grep) plus READING of each site.

### Does kxv8p's disposition constrain E8's?

**No, and E8 should NOT follow it.** kxv8p's recorded direction is "closing it means the
gate deriving workspace shields, which is the layering exception scripts/layering.sh names -
so it is a boundary decision, not a patch", carried forward by the 2026-09-18 groom as
HAS-A-BAR. That bar is about *who may compute* the derived set. E8 has no such bar: the
derived set is already in the function's hands.

What E8 does inherit from kxv8p is the shape of its own bar, which is different and worth
stating so the filing does not copy the wrong one: E8's open question is not "may this code
see the rules" but "**refuse or disclose**". The symmetric fix - adding the derived half to
the fold loop - refuses every `write: <checkout>` on every folding mount, because the above
relation is structurally always true for a self-derived shield. That is a far larger
proposition than 0418cea's `write: ~/.pyenv`. The narrower answer is the channel the
degraded tier already uses for the byte-exact sibling (`Exposed` / `exposedShields`),
extended to the full tier where the mount folds. I am not deciding it here; I am recording
that kxv8p's bar does not transfer and E8's is its own.

### bv2-g7tno - absent DenyAll shield x folding

**IMPOSSIBLE, and here is the mechanism rather than the assertion.** An absent shield cannot
fold because the fold question is answered by an `Lstat` of both spellings:

- `shield.hostSameFile` (`internal/shield/shield.go:90-99`) lstats `a`, returns false on
  error, then lstats `b`, returns false on error. A path that is not there fails the first
  call.
- `foldsCase` (`internal/shield/verdict.go:310-321`) asks `s.fs.SameFile(path, flipped)` and
  nothing else, so both fold loops (verdict.go:134, :211) decline for an absent rule.
- The corpus's folding seam makes the same guarantee independently and says why:
  `shieldcorpus.sameFolded` (`internal/shieldcorpus/shieldcorpus.go:361-368`) lstats the
  folded path, with the comment "A name with nothing behind it still reaches nothing, which
  is what keeps a shield that does not exist from being reported as folding."

So g7tno's axis (absent DenyAll shield needs a write grant to be worth a tmpfs) and this
grid's fold axis do not interact: the absent case exits both fold loops before the
containment question is even reached. Note the coupling, since it is one `Lstat` in another
package holding it: `17e3c01`'s test pins the absent-shield need, and the corpus comment
pins the fold half, but no single test asserts the pair. VERIFIED BY READING.

### bv2-ntncf - stranded artifacts x folding

A SIGKILL strands materialized shield artifacts inside the checkout; E8 is about a derived
shield being plantable under the ordinary project grant on a folding mount. They compound in
one direction only: a stranded `.git/hooks` artifact is a real directory where the run
expected a mount point, so on a folding mount it is reachable under a second spelling by the
*next* run's grant as well - but that next run's exposure is E8's, not ntncf's, and neither
makes the other's fix harder. Worth no more than this line.

### New item: the corpus cannot express a workspace-derived case at all

Recorded as its own finding rather than as E8's obstacle, because
`internal/shieldcorpus` is this repo's designated "two sides share one source" precedent
(named in CLAUDE.md alongside `limitControllers`), and a class of cases it structurally
cannot carry is invisible by construction - nothing fails when a site diverges there.

What is missing, concretely:

- `shieldcorpus.Case` has fields for `Grant`, `Write`, `OptInRead`, `Folding`,
  `WorkspaceDerived` (a *comment* field about the clamp's derivation, not a rule set),
  `ClampKeeps` and `Verdict`. There is no field carrying checkout-derived rules.
- None of the three `*shield_differential_test.go` harnesses passes a `workspace` argument to
  `Contains`. They call it with `nil`.
- So every cell in the above table whose answer depends on the derived half - E8, the
  byte-exact sibling at grants.go:279, and kxv8p's cell - is unreachable from the corpus, and
  each has had to be settled by a spike or by unit tests in one package, which is exactly the
  per-site divergence the corpus exists to prevent.

What it would take: a `Case.Workspace bool` that `Build` honours by creating a checkout
layout (`.git/hooks`, `.vscode`) under the staged home, plus each harness deriving its own
side's rules from that layout - `denylist.Workspace(checkout)` in the corpus-facing helper,
`workspaceShields(sb, w)` in the backend harness, `workspaceShields([]string{w})` in the
clamp harness - and passing them through. That is the same three-seam shape `Case.Folding`
already has, so the precedent for doing it exists. It is a test-infrastructure item, not a
behaviour fix, and it gates how cheaply the next sweep can settle this family.

### Net after the known-open pass

- No grid cell changed verdict. E8 stays UNHANDLED; the F2c/F3c prose cells stay WRONG.
- E8 and bv2-kxv8p are **two defects, one symptom family**; the shared fact is that the
  derived shield set is threaded into some checks and not others, but the *reasons* differ
  (layering vs directionality) and so do the fixes.
- Two items beyond the two already reported: the corpus-expressiveness gap above, and the
  coupling note under g7tno.
