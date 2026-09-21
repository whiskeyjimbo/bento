# State grid: derived-shield carve half x frontend x placement

Reviewed 2026-09-21 in a worktree at 44ab8df. Area: the carve half of the grant check for the
checkout-derived ("workspace") shields. Frontends: `gate/gate.go` (`Refusals`, `derivesWorkspaceShields`,
`ShieldCarveProblems`, `Runnability.ShieldCarveUnknown`), `cmd/bento/validate.go` (human, `--json`,
`--strict`), `cmd/bento/approve.go` (`requireHonorableGrants`), `cmd/bento/clamp.go`
(`withholdGateRefused`, `workspaceShieldSet`, `workspaceShields`, `gitDirShields`), `examples/embed`
(`writeRunnability`). Counterpart: the run's `checkShieldsCarvable` (internal/linux/shields.go:588) over
`createdShields` (shields.go:546), whose rules come from `shieldRules` (shields.go:160: built-ins from
`internal/shield` plus `workspaceShields` per write grant that `isDir`).

## Phase 0 - fit

Good fit. Two implementations of one predicate (gate/clamp vs backend), a coarse flag standing in for
the half the gate cannot compute, and five readers of that flag. Recent history (ab80ec0, 15347ac,
a777525) is exactly one-row-at-a-time carriage of the flag.

**Invariant (one-sided):** a frontend may call the carve half unknown, or refuse a grant the run would
carve; it must never report clean a grant whose carve the run's derived set refuses.

## Dimensions (from the code)

- Frontend: G = gate `Check`/`Refusals` (feeds validate human + JSON, embed); S = `validate --strict`
  exit code; A = approve stamp; C = clamp proposal.
- Derived state: D0 no directory write grant (nothing derived; shields.go:169 and gate.go:195 share the
  `isDir` gate); D1 dir grant, every derived mount point creatable; D2 `.git` present, hooks absent,
  `.git` not writable; D3 editor task dir (`.vscode`) present, not writable, `tasks.json` absent;
  D4 unanchored host.
- Placement: at (grant is the checkout), beneath (grant inside checkout, off the shield), on
  (grant is `.git`, the shield's parent), above (grant holds a nested checkout), sibling.

Degraded tier: skips `checkShieldsCarvable` entirely, so every gate refusal there is the allowed
direction (gate.go:696-704). One row, H1.

## Grid

| # | State | Placement | G (gate/validate/embed) | S (--strict) | A (approve) | C (clamp) | Run | Stamp |
|---|---|---|---|---|---|---|---|---|
| 1 | D0 | any | HANDLED: no flag, built-in answer is whole (gate.go:195, 368) | HANDLED | HANDLED | HANDLED: no derived ask (clamp.go:521) | derives nothing (shields.go:169) | READING |
| 2 | D0, grant absent inside a checkout | beneath | HANDLED: absent grant derives nothing on both sides; prepareWriteDirs runs after the carve check (linux.go:743-747) | HANDLED | HANDLED | HANDLED: clamp derives ungated (superset, clamp.go:148), allowed direction | carves clean | READING |
| 3 | D1 | at / beneath / on | HANDLED: flag raised, no refusal (unknown, allowed) | HANDLED | HANDLED | HANDLED | carves clean | READING |
| 4 | D2 | at | HANDLED: Refusals empty, ShieldCarveUnknown true, note at validate.go:320, embed main.go:297, JSON validate.go:817 | WRONG (documented): `strictRunnableError` (validate.go:482) ignores the flag, so exit 0 on a manifest the run refuses | WRONG (documented): stamps with a note (approve.go:216) | HANDLED: withheld | refuses `.git/hooks` | SPIKE (run refuses; gate empty+flag; strict error omits carve; clamp kept=[]) |
| 5 | D2 | on (`write: repo/.git`) | as #4 | WRONG (documented), as #4 | WRONG (documented), as #4 | HANDLED: withheld | refuses | SPIKE |
| 6 | D2 | beneath (`repo/src`) | HANDLED: flag raised though run is clean (coarse, allowed, gate.go:188-194) | HANDLED | HANDLED | HANDLED: kept | carves clean (hooks not reachable, shields.go:778) | SPIKE |
| 7 | D2 | above (grant holds nested checkout) | HANDLED: flag raised | HANDLED | HANDLED | HANDLED | anchors on the grant, not the nested repo (shields.go:229), so the nested `.git` is never a mount point; carves clean | READING |
| 8 | D2 | sibling | IMPOSSIBLE as a carve: not reachable (gate.go:743 `reachableFrom`, shields.go:778 `reachable`) | - | - | - | - | READING |
| 9 | D3 | at | as #4 | WRONG (documented), as #4 | WRONG (documented), as #4 | HANDLED: same `denylist.Workspace` rules (clamp.go:180 vs shields.go:220) | refuses `tasks.json` | READING |
| 10 | D2/D3 via submodule / worktree gitdir | at | as #4 | as #4 | as #4 | HANDLED: `gitDirShields` mirrors shields.go:318 line for line; same seams (Lstat exists, Stat isDir, ReadDir split) | refuses | READING (TestClampProposalWithholdsWalkDerivedRefusals covers the rule set) |
| 11 | D4 | any | HANDLED: flag suppressed, ShieldsUnknown is the verdict (gate.go:367) | HANDLED: strict fails on ShieldsUnknown (validate.go:487) | HANDLED: note, and run refuses anyway | IMPOSSIBLE as a carve pass: run refuses every grant for anchoring before any carve (the clamp skips, clamp.go:510) | refuses all | READING |
| H1 | any | any, degraded tier | HANDLED: gate over-refuses, allowed (gate.go:696) | HANDLED | HANDLED | HANDLED | no carve check | READING |

Counts: HANDLED 36 cells, IMPOSSIBLE 2, WRONG 6 (one finding, two frontends x three rows), UNHANDLED 0.

## Adversarial re-review of HANDLED

- Clamp parity with the run's rule derivation: `checkoutRoot` (clamp.go:284, Lstat) vs shields.go:229
  (`sb.exists` = Lstat, args.go:777); gitfile test identical; `listDir` identical to `hostListDir`;
  depth bound shared (`shield.MaxWalkDepth`). The clamp's `redirected` compares `pathresolve.Existing`
  against the spelling, so an unresolved grant spelling only adds rules (allowed).
- `ShieldCarveProblems` vs `checkShieldsCarvable`: the gate's existence test is `os.Stat` (follows)
  where the run's is Lstat. Hypothesis: a looping symlink ancestor makes the run refuse (Lstat exists,
  access ELOOP) while the gate walks past it and passes. REJECTED by spike: `write: repo` with
  `repo/.vscode -> repo/.vscode`; run preflight returned nil, gate and clamp also clean. Mount paths are
  resolved by `pathresolve.Existing`, so a surviving symlink ancestor is not reached in practice.
- Clamp per-grant probe asks with no reads, so no opt-in skip applies: stricter than the run (allowed).
- Validate's summary block (validate.go:982) answers built-ins only with no flag of its own, but the same
  output always carries `writeRunnability` (validate.go:115); approve's summary is followed by
  `requireHonorableGrants`. Carried.

## Re-open pass

`git log -20 -- gate/ cmd/bento/clamp.go cmd/bento/validate.go`: ab80ec0 added the flag (G rows, validate
text/JSON, embed); 15347ac carried it into `RefusalSet` so approve reads it (A column); a777525 made the
clamp answer it (C column). Every reader of the flag has a row and each was carried. The one column never
carried is S: `strictRunnableError` still reads only Problems, Refusals and ShieldsUnknown. The prose at
validate.go:316-319 and approve.go:209-215 says this is deliberate.
`bd list --status open`: no open bead on this area.

## Findings, ranked

1. **F1 - strict and approve collapse the carve unknown to a pass** (rows 4, 5, 9, 10; S and A). WRONG
   (documented). VERIFIED BY SPIKE: gate.Check on a checkout whose `.git` is 0500 returns no refusals and
   `ShieldCarveUnknown`, `strictRunnableError(r, true)` names only the (test-empty) entrypoint, and the
   run's `preflightGrants` refuses the same grant with ShieldNotCarvable. Blast radius: a CI gate on
   `validate --strict`, or an approve stamp, goes green for a manifest dead at its first step on that
   host. Cheap fix available: validate and approve live in `cmd/bento` beside `workspaceShieldSet`, so
   they can answer the half exactly as the clamp does instead of flagging it. Decision for the owner:
   the current prose rejects refusing on the unknown; answering it is a different option it does not
   address.

No UNHANDLED cells. Cells not walked: run-to-run drift (a grant absent on run 1 derives shields on run 2,
after prepareWriteDirs created it) is outside a single-run grid; the built-in half's parity is
state-grid-shield-verdict.md's.
