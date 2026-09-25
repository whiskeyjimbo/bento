# State grid candidates - tenth sweep

Phase A, 2026-09-25, against `main` at 7e4adda (121 commits past `265a790`, the ninth
sweep's file). Same filter as rounds eight and nine: only what POST-DATES the grids on disk.

Signals used: fix scopes since `265a790`, files those fixes touched, and a grep of the 41
grids on disk for the new mechanisms' names (`hooksPath`, `extra_args`, `PreToolUse`,
`--out`, agent config). None of the last four appears in any grid.

## New candidates

| # | Candidate | Signals | Invariant (one-sided) | Shape | Fit | Route |
|---|---|---|---|---|---|---|
| 46 | **Grant-derived shields (`internal/linux/autoexec.go`, the derived half of `shields.go`) against where git, editors and agents actually load executable config** | About 15 one-at-a-time fixes since `265a790`: `14b3ca8`, `30181ff`, `80f0799` (nested checkouts), `9ee1014`, `7bfdace`, `2bb374f` (hooksPath), `bd32a86`, `0538bc7` (editor and agent config below a grant), `5ce8070`, `029b770`, `74beff9`, `8190884`, `732669f`. Mirror pair: bento's derivation vs git's own `core.hooksPath` / discovery resolution. `state-grid-workdir.md` mentions hooksPath but predates all of these | A derived shield may cover a path nothing would execute from; it must never leave writable a path git, an editor or an agent would load and run | config source (hooks dir, `core.hooksPath` rel/abs/unset, worktree/`.git` file, bare/no work tree, editor tasks, agent config) x location (grant root, nested below grant, above grant, via symlink, under an existing shield) ~30 after folds | **Strong**: repeat fixes plus a mirror pair with an outside oracle (ask git) | grid |
| 47 | **Run-input self-protection: the files a run reads back vs its own write grants** (`1ad8a6f`, `26ae603`, `1cb6954`, `5148209`, `5a76121`) | Five fixes each covering one input: the manifest, a symlinked dir in its name, `profile --out`, agent links. Same question asked per file, never mapped | A run may refuse an input its grants could not replace; it must never launch with, or later trust, an input its own write grants can replace or redirect | input (manifest, manifest parent chain, `--out`, agent links, extra_args sources) x reach (direct grant, parent grant, symlinked component, hardlink, created after launch) ~20-25 | **Good**. One-sided and small | grid |
| 48 | **`extra_args` (`76b7f82`, `3d8685e`) x argv screening in `internal/linux/args.go`** | New manifest field plus an immediate fix ("pass extra args outside the policy"). Mirror: args screened at validate vs args exec'd | Screening may refuse argv exec would have accepted; argv that reaches exec must have passed the same screen | arg source (manifest `args`, `extra_args`, CLI trailing) x path (validate, run, profile, hook adapter) ~12 | **Moderate**, small grid; could fold into 47 | grid, or cells in 47 |

## Routed elsewhere, or not a row

| Area | Why | Route |
|---|---|---|
| Claude Code PreToolUse adapter (`cmd/bento/hook.go`, `1ab5721`) | New, 139 lines, question is whether a model-controlled command can escape the rewrite (`shellQuote`, `updatedInput`) - attacker capability, not a distinction the code makes | `threat-model` |
| Gate credential-alias anchor walk bound (`76d98c5`) | A hang on a dead or deep tree | `failure-modes` |
| Remedy screen follow-ups (`7ca549e`, `61ebf22`, `a8b754e`) | The fix batch from `state-grid-remedies.md` itself | re-verdict cells there only if picked |
| Launcher bridge perf (`daa4856`, `0c0252c`) | perf, not state | nothing owed |

## Not re-gridded

All 41 grids on disk. `state-grid-workdir.md` gets its hooksPath cells superseded by 46 if picked.

## Outcome, 2026-09-25

All four picks returned: `state-grid-derived-shields.md` (32 cells), `state-grid-run-inputs.md`
(30), `state-grid-extra-args.md` (12), `threat-model-hook-adapter.md`. Every cell has a verdict.

Filed: bv2-fzujr, bv2-mhiqa, bv2-w7o5l (derived shields H14, H15, H16); bv2-q1rmx, bv2-xlbhd
(run inputs M8, M11 with M16); bv2-fie6v (extra_args cell 9); bv2-i3vhf, bv2-k1s9n (hook
--allow passthrough, NUL); bv2-n6icw (hook hang, routed to failure-modes).

**The same shape a third time.** 30181ff carried shields to nested checkouts but not the
report; 26ae603 put the hard-link check behind the under-a-grant test; 3d8685e put the
extra_args check in enforce.Run and not the backend entry.

Not filed, with reasons: derived-shields E4, E5, E10-subdir (documented residuals); run-inputs
O4/O5 (caught downstream), A3 (disclosed); extra_args unsafe-rune skip (by design, tested).

**Process note.** Worktree-isolated reviewers could not write the main checkout; two of four
wrote into their worktree and the orchestrator copied the file out. Next round, name a
worktree-relative output and copy on return.
