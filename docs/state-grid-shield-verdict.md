# State grid: shield.Verdict x grant kind x consumer

Reviewed 2026-09-17 in a worktree at 924e291; cites re-checked against 5a98897 in the re-open pass below. Area: `internal/shield/verdict.go` (`Set.Contains`) and its
consumers: `gate/gate.go` (pre-run gate), `internal/linux/grants.go` (`checkGrants`, both tiers),
`internal/linux/degraded.go` + `internal/launcher/degraded.go` + `internal/landlock` (degraded
Landlock-only tier), `internal/linux/linux.go:878` (entrypoint/interpreter), `cmd/bento/clamp.go`
(profiler clamp). Corpus: `internal/shieldcorpus`, driven by the three `*shield_differential_test.go`.

## Phase 0 - fit

Good fit. One enum (seven verdicts) times one kind times five call sites, each switching on the
verdict, plus a mirror triple (gate and clamp predicting the backend) held together by a shared corpus.

**Invariant (one-sided):** every backend applying the run refuses or holds at least what the Verdict
says; the gate never refuses what both backends admit; the clamp never proposes a grant the gate or
a backend refuses.

"Holds" is judged against the verdict `Contains` returns, not against every shield the full tier
binds. Grid C records where the degraded tier admits a grant `Contains` calls Honored but cannot hold
a shield the full tier holds. Those sit outside the invariant as stated and are listed separately.

## Grid A - verdict x kind, backend (both tiers)

Full = `checkGrants` via `preflightGrants` (linux.go:642) and args.go:264. Degraded = `runDegraded`
(degraded.go:56 `checkGrants`, then degraded.go:61 `checkWriteNotAboveWriteShield`).

| # | Verdict | Kind | Full tier | Degraded tier | Stamp |
|---|---|---|---|---|---|
| A1 | Honored | R | HANDLED: admits (grants.go:106) | HANDLED: admits. A read containing a DenyAll shield is exposed and reported in `Exposed` (degraded.go:139), documented cost (C2) | EXECUTION (corpus) |
| A2 | Honored | W | HANDLED: admits | HANDLED: admits, but see C1 | EXECUTION (corpus) |
| A3 | InsideShield | R | HANDLED: `checkReadNotShielded`, opt-in sentence (grants.go:99) | HANDLED: same function | EXECUTION (corpus) |
| A4 | InsideShield | W | HANDLED: `checkWriteNotShielded`, write sentence | HANDLED: same function | EXECUTION (corpus) |
| A5 | InsideCallerShield | R | HANDLED: grants.go:94, caller sentence | IMPOSSIBLE: linux.go:87 refuses any degraded run with `DenyPaths` | EXECUTION (TestRunDenyPathsShieldsCallerStore, TestACallerDeniedReadIsNotOfferedTheBuiltInOptIn); no corpus row |
| A6 | InsideCallerShield | W | HANDLED: grants.go:94, returned before any write-only verdict (first loop in `Contains`) | IMPOSSIBLE: linux.go:87 | EXECUTION (TestACallerDeniedWriteIsRefusedInTheCallersWords); no corpus row |
| A7 | UnderWriteShield | R | IMPOSSIBLE: `kind == Read` early return in `Contains` precedes every write loop; pinned by TestAReadGrantEarnsNoWriteOnlyVerdict | same | EXECUTION |
| A8 | UnderWriteShield | W | HANDLED: `checkWriteNotUnderReadOnlyShield` (grants.go:176), with the workspace union | HANDLED: same function | EXECUTION (corpus, incl. folded and workspace rows) |
| A9 | AboveShield | R | IMPOSSIBLE: as A7 | same | EXECUTION |
| A10 | AboveShield | W | HANDLED: `checkWriteNotAboveShield` (grants.go:252) | HANDLED: same function (TestDegradedRefusesWriteAboveShield) | EXECUTION |
| A11 | AboveWriteShield | R | IMPOSSIBLE: as A7 | same | EXECUTION |
| A12 | AboveWriteShield | W | HANDLED (holds rather than refuses): shield ro-bind after the grant, last wins (grants.go:259-271; TestWriteGrantDoesNotLeavePyenvInterpreterWritable). CORRECTED 2026-09-20: byte-exact only - where the shield's own directory folds case, Contains answers FoldedShield instead (verdict.go:180-210, 0418cea) and BOTH tiers refuse | HANDLED: refused at degraded.go:61 (TestDegradedRefusesWriteAboveWriteShield) | EXECUTION (corpus drives `checkWriteNotAboveWriteShield`) |
| A13 | FoldedShield | R | HANDLED: grants.go:101 | HANDLED: same function | EXECUTION (corpus) |
| A14 | FoldedShield | W | HANDLED: grants.go:101, ahead of the write-only verdicts | HANDLED: same function | EXECUTION (corpus) |
| A15 | any non-Honored | R, entrypoint/interpreter | HANDLED: linux.go:878 refuses on `v != Honored`, so no verdict is admitted by omission | HANDLED: `newSandbox` is shared (degraded.go:40) | READING |

## Grid B - verdict x kind, gate and clamp

Gate = `ShieldedReadProblems` / `writeShieldProblem` over `gate.ShieldSet` (no caller denies, no
workspace shields). Clamp = `clampShieldedGrants`, `clampWriteShieldedGrants`,
`withholdRunRefused`, `aboveWriteShieldGrants`, all reached from `clampProposal` (clamp.go:401).

| # | Verdict | Kind | Gate (vs both backends) | Clamp (vs gate and backends) | Stamp |
|---|---|---|---|---|---|
| B1 | Honored | R/W | HANDLED: silent | HANDLED: keeps (subject to the broad-dir partition) | EXECUTION (corpus) |
| B2 | InsideShield | R | HANDLED: refuses, both backends refuse | HANDLED: drops; also drops the opt-in read the run honors (narrower, allowed) | EXECUTION (corpus) |
| B3 | InsideShield | W | HANDLED | HANDLED: drops (asked as Read, both spellings) | EXECUTION (corpus) |
| B4 | InsideCallerShield | R/W | IMPOSSIBLE on the CLI: `ShieldSet` passes nil caller denies (gate.go:327). The arm is live only for a caller passing its own set; wording matches the backend | IMPOSSIBLE: `commandShieldSet` is `gate.ShieldSet` (render.go:406) | READING |
| B5 | UnderWriteShield | W, built-in | HANDLED | HANDLED: drops, both spellings | EXECUTION (corpus) |
| B6 | UnderWriteShield | W, workspace-derived | Silent: no workspace passed. Allowed direction, documented gate.go:374 | HANDLED for the corpus shapes: clamp derives its own workspace set (clamp.go:85) including the gitdir scan (clamp.go:165). Was F2, fixed at 21dc076 | EXECUTION (corpus) |
| B7 | AboveShield | W | HANDLED: refuses | HANDLED: `clampShieldedGrants` keeps it (`ClampKeeps`), `withholdRunRefused` then removes it via `gate.Refusals` (clamp.go:410) | SPIKE (the corpus differential stops at `clampShieldedGrants`; the spike drove `clampProposal`) |
| B8 | AboveWriteShield | W | Silent by design (gate.go:592), refusing would refuse every full-tier run. Allowed direction | Keeps and reports via `aboveWriteShieldGrants` (clamp.go:417). **FORBIDDEN (documented narrowing)** against the degraded tier | EXECUTION (corpus) |
| B9 | FoldedShield | R/W | HANDLED | HANDLED: drops | EXECUTION (corpus) |
| B10 | UnderWriteShield / AboveShield / AboveWriteShield | R | IMPOSSIBLE: early return in `Contains`; gate arm is a documented no-op (gate.go:412) | IMPOSSIBLE: same | EXECUTION |

## Grid C - holds the Verdict does not name (degraded tier)

| # | Shape | Full | Degraded | Verdict | Stamp |
|---|---|---|---|---|---|
| C1 | Write containing a workspace-derived shield (`write: ~/proj` over `~/proj/.git/hooks`, `.git/config`, `.vscode`, `.cargo/config.toml`) | holds: ro-bind of each derived shield - CORRECTED 2026-09-20: on a case-FOLDING mount it does not hold unconditionally. A bind covers the one spelling it names, so on a mount presenting a second dentry for the shield's directory `.git/HOOKS` is inside the grant's read-write bind - the shape 0418cea measured; a mount folding in the dentry layer may hit the bind under either spelling, and the verdict cannot tell them apart. The built-in half of that row was escalated to FoldedShield at 0418cea and the workspace half was not. See docs/state-grid-folding-reopen.md cell E8 (UNHANDLED, VERIFIED BY SPIKE) | admits; those paths are writable on the host. `Contains` consults workspace shields in the INSIDE direction only, and `checkWriteNotAboveWriteShield` passes nil workspace (grants.go:279). Detected after the fact by the auto-exec baseline (`ChangedAutoExec`) and listed in `Exposed` | HANDLED (disclosed), per degraded-tier grid F4 x A1 | SPIKE |
| C2 | Read containing a DenyAll shield (`read: ~`) | holds: bind over the store | exposed, reported in `Exposed` | Documented cost (degraded.go:106-110), outside the invariant | READING |
| C3 | Caller deny on the degraded tier | n/a | run refused (linux.go:87) | HANDLED | READING |

## Findings

Sorted by whether they break the forbidden direction of the invariant.

**Forbidden direction:** none beyond documented narrowings.

- **F1 (B8), the clamp proposes AboveWriteShield grants the degraded tier refuses.** Documented at
  clamp.go:101-112 and on `shieldcorpus.AboveWriteShield`; the reviewer gets a note. Recorded so the
  orchestrator can decide whether the clamp clause of the invariant excludes the degraded tier.
  VERIFIED BY EXECUTION (TestShieldCorpusClampDrops, TestClampReportsAWriteGrantContainingAWriteShield).
- **F2 (B6), WITHDRAWN in the re-open pass (fixed at 21dc076), the clamp's workspace derivation is shallower than the backend's.** Stated on
  `shieldcorpus.Case.WorkspaceDerived`: the clamp skips the recursive `.git/modules` / linked-worktree
  gitdir scan, so a write at a submodule gitdir's hooks is kept by the clamp and refused by both
  backends. The gate misses it too, so `withholdRunRefused` cannot catch it. VERIFIED BY READING.
  UNVERIFIED by execution: settled by a corpus case with a `.git/modules/<name>/hooks` layout run
  through TestShieldCorpusClampDrops.

**Not forbidden, but gaps:**

- **F3 (C1), REJECTED in the re-open pass (duplicates degraded-tier grid F4 x A1), the degraded tier leaves a checkout's derived shields writable under a write grant
  that contains them.** It is the mechanism `AboveWriteShield` exists for (Landlock takes the union
  of matching rules), applied only to built-in DenyWrite rules, so on this tier a planted
  `.git/hooks/pre-commit` is detected after the run rather than prevented. Documented as the tier's
  cost. Refusing it would refuse every project write on the degraded tier, so the likely answer is
  "accepted", but it is the one place the degraded tier holds less than the full tier for a grant both
  admit. VERIFIED BY SPIKE: `corpusVerdict` (every shield check of both tiers) returned Honored for
  `write: <home>/checkout` while `workspaceShields` derived hooks, config, config.worktree, .vscode,
  .idea and .cargo/config rules for it.
- **F4, corpus coverage.** No `InsideCallerShield` row: `shieldcorpus.Verdict` has no such member and
  `Case` cannot carry caller denies, so gate/backend wording agreement for it rests on unit tests
  (callerdeny_test.go, gate problems_test.go, linux caller-deny tests), which pass. The clamp
  differential never reaches `withholdRunRefused` (B7 was verified by spike only). The "no degraded
  differential" suspicion is half true: `corpusVerdict` does run `checkWriteNotAboveWriteShield`, so
  the degraded tier's refusal set is corpus-tested; what no corpus test reaches is Landlock
  enforcement itself (C1, C2). VERIFIED BY READING.
  CORRECTED 2026-09-20: nor can the corpus express a WORKSPACE-derived case at all -
  `shieldcorpus.Case` has no field for one and no differential harness passes a `workspace`
  argument to `Contains` - which is why grid-folding-reopen cell E8 could only be spiked.

## Rejected

- **Gate over-refusing on spelling.** The gate asks `Contains` of where `pathresolve.Existing` says the grant lands, the backend
  asks it of `resolveGrants` output. The corpus includes dangling-link and symlinked-store rows and
  the sites agree. VERIFIED BY EXECUTION (gate and backend corpus tests).
- **A write containing a caller deny gets the built-in AboveShield sentence.** `callerDenied` is
  consulted only in the inside loop. Both tiers still refuse, the gate cannot see caller denies, so
  this is wording only (TestExtraDenyWriteAboveShieldRefused covers the refusal).
- **WorkspaceRedirected kept by the clamp.** Not a `shield.Verdict` (the check bypasses `Contains`),
  host-symlink attributable, stated on `shieldcorpus.WorkspaceRedirected`. Out of area.

## Spikes

Both deleted; worktree `git status` clean.

- `cmd/bento`: `clampProposal` with `HOME` at a temp dir holding `.config/hub` and
  `.config/gcloud`, `write: $HOME/.config`. Passed: the grant was withheld with the gate's
  WriteAboveShield sentence.
- `internal/linux`: `corpusVerdict` on a synthetic `Case{Grant: "checkout", Write: true}` over the
  corpus layout. Passed: Honored, with seven derived workspace shields.

## Re-open pass, 2026-09-17

Checked against open work (bv2-h7k3b, 76tn4, nm49f, ntncf, 4cyeg, k1gnk, kxv8p, rw0ae, 6m6yl),
docs/state-grid-profile-clamp.md, docs/state-grid-degraded-tier.md, docs/state-grid-candidates.md,
and 5a98897.

- **F2 is withdrawn, not bv2-kxv8p.** It was reviewed on a stale clamp.go (924e291). The gitdir-scan
  gap is profile-grid A10, fixed at 21dc076 (clamp.go:165 `gitDirShields`), with a corpus case. The
  `Case.WorkspaceDerived` comment cited for it predates the fix. bv2-kxv8p is a different cell: the
  gate's missing workspace half of ShieldNotCarvable (profile A12), which this grid does not reach
  because carvability is not a `shield.Verdict`.
- **F1 is profile-grid A8, already recorded and deliberately not filed.** state-grid-candidates.md
  rejects it as "reported, not silent" (validate F2b, profile A8). No new work.
- **F3 duplicates a prior verdict and does not refute it.** degraded-tier grid cell F4 x A1 marks
  derived write shields inside a write grant HANDLED (disclosed through `exposedShields`). The spike
  confirms the documented behavior: admitted, disclosed, not prevented. Moved to Rejected.
- **Cites changed between 924e291 and 5a98897:** only cmd/bento/clamp.go (21dc076, 4817490):
  `clampProposal` 311 -> 401, `withholdRunRefused(p)` 321 -> 410, `aboveWriteShieldGrants` call
  326 -> 417, `aboveWriteShieldGrants` def 113. gate.go, grants.go, degraded.go and linux.go cites
  are unchanged. Updated in the tables above. B7's spike ran on the old clamp; the withhold step it
  exercised is unchanged in shape.
- None of the open beads is a verdict x kind x consumer cell here. bv2-6m6yl (extraDeny) is nearest
  to A5/A6/B4 and does not change their verdicts.

**Net after re-open:** no new findings to file. F4 (corpus has no InsideCallerShield row, clamp
differential does not reach `withholdRunRefused`) is the only remaining item, a test-coverage note.
