# State grid candidates - ninth sweep

Phase A, 2026-09-21, against `main` at `44ab8df` (70 commits past `deadd82`, the eighth
sweep's file). All four of the eighth sweep's picks landed (`workdir`, `folding-reopen`,
`host-shortfall`, `credhunt-coverage`), and six more grids were written on 2026-09-21. The
filter is the same as last round: which fix clusters POST-DATE the grid that would own them,
and which mechanisms have no grid at all.

Most of the 70 commits are fixes filed out of the 2026-09-21 grids themselves (teardown,
layer-consumers, platform-stubs, report-corrections). Those are a grid's own output, not
sampling, and are not candidates. Three clusters are not.

## New candidates

| # | Candidate | Signals | Invariant (one-sided) | Shape | Fit | Route |
|---|---|---|---|---|---|---|
| 43 | **Remedy screening x admission** - `enforce/run.go` `screenRemedies` (:581), `composedAdmission`, `NoRemedy` (:840); frontends `cmd/bento/render.go` `writeRefusalRemedy`, `run.go` | Four one-at-a-time fixes in four hours, all after `layer-consumers` (which gridded the remedy's wording, not whether it works): `715ec11` withdraw a remedy admission refuses, `4490bd7` screen the manifest-edit remedy too, `7ca549e` screen over all of admission, `fa78083` name the live lever in a withdrawn edit, plus `a5d251f` name `--allow-degraded` on any waivable refusal. Signal 3 at full volume; mirror pair (the remedy text vs what admission does once it is taken) | A refusal may withhold a remedy that would have worked; it must never print a remedy that, once taken, admission still refuses | remedy (waiver `--allow-degraded` / manifest edit / live lever / none) x refusal cause (layer shortfall per tier, unsampled state, exec-block refusal, silent stage, grant refusal) x whether a second cause stands behind the first ~ 4x6x2 = 48, collapses toward ~25 | **Strong** | grid |
| 44 | **Derived-shield carve half** - `gate/gate.go` `CarveUnknown`/`ShieldCarveUnknown` (:119-134, :362-388), `cmd/bento/clamp.go` (:512-559), `cmd/bento/validate.go`, against the run's real derived set in `internal/linux` (git hooks, editor task files) | New mechanism with no grid: `ab80ec0` (feature) then `a777525` clamp answers it, `15347ac` gate carries the qualifications, `71631bf` doc names the coarseness. "carve half" appears in no existing grid. Mirror triple: gate, clamp, run | A frontend may call the carve half unknown or refuse a grant the run would carve cleanly; it must never pass a grant whose carve the run's derived shield set refuses | frontend (gate/validate, clamp, embed `Result`, run) x derived-shield state (no workspace write / write, no hooks / hooks present / editor task files / unanchored host) x grant placement (at root / beneath / above) ~ 4x5x3 = 60, collapses to ~20 since gate is deliberately coarse | **Good**; the one-sidedness is written into the gate's own comment | grid |
| 45 | **Stranded shield reclaim** - `internal/linux/shields.go` `recordCreatedShields` (:976), `reclaimStrandedShields` (:1049), `parseShieldRecord`, `openOwnRecord` (:1158), `reclaimShieldPaths` (:692) | Brand-new mechanism with four fixes on landing day: `470317c`, `286e705` trust only our own records, `a9a550c` keep reclaim inside the checkout, `65fef8e` retry a path whose parent errs. Two open beads already name cells: `bv2-zlqjy` (own empty artifact vs a user's later one), `bv2-eq5cw` (record under /tmp lost on reboot) | Reclaim may leave a stranded shield artifact behind; it must never remove a path this tool did not create | WHEN the run died (before record written / after record, before anchor / mid-run / clean exit) x record state (own / foreign owner / malformed / missing / names path outside checkout) x path state now (our empty artifact / replaced by user content / parent errs / gone) ~ 4x5x4, split into two grids of ~15-20 | **Good**, but it is a deletion decision on a trust boundary: pair with `threat-model` for "who can write the record" | grid, and `threat-model` for the record's trust |

## Routed elsewhere, not dropped

| Area | Why not a grid | Route |
|---|---|---|
| Unsampled state / exec-block refusal (`be1a6da`, `ca5d099`, doctor `58a9544`/`3517c4f`, probe `d154b01`) | `layer-consumers` (03:40) post-dates every commit in the cluster, and `8b94d45` put the degraded tier on one source. `bv2-ujyy2` is the live remainder | the bead |
| credhunt fixes `c22d7aa`..`9554ff4` | output of `state-grid-credhunt-coverage.md`, filed from it | nothing owed |
| `bv2-7kdkj` doctor with one Docker flag lifted | a single host-posture bug | ordinary fix |
| `bv2-gr44i` `CoversResolved` relative/relative | one cell, already named | ordinary fix; worth a fuzz oracle on `CoversResolved` (`fuzz-oracle`) |
| `internal/observe`, `internal/proxy` | orderings and external faults | `concurrency-audit` (done), `failure-modes` |
| `bv2-cr6cs`, `bv2-gsxl5`, `bv2-quje6` | carried from the eighth sweep, unchanged | beads |

## Not re-gridded, deliberately

Every file named `docs/state-grid-*.md` has verdicts on disk. None of the three candidates
above is a re-open: `screenRemedies`, the carve half, and the reclaim record each landed
after every grid that could have owned them, and none of those grids names them as a
dimension.
