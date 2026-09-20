# State grid candidates - eighth sweep

Phase A, 2026-09-20, against `main` (172 commits past `a808872`, the seventh sweep's file).
Signals: fix-commit scopes over the last year, `mirror`/`parity`/`counterpart` prose,
degradation fields, fuzz-oracle strength, and - new to this round - which surfaces
POST-DATE every one of the 24 grids already in `docs/`.

That last filter is the whole story of this round. The obvious candidates a cold sweep
produces (degraded tier, `enforce.Layer` x consumers, gate's unknown flags, shield verdict
x kind) are all gridded already. What is left is (a) one mechanism that landed after the
last grid was written, (b) two classes taking repeat one-at-a-time fixes since, and (c)
one grid an open bead has already asked for.

## New candidates

| # | Candidate | Signals | Invariant (one-sided) | Shape | Fit | Route |
|---|---|---|---|---|---|---|
| 39 | **`workdir` x its answerers** - `manifest.Resolve`(:372-376), `policy.Validate`(:214,:293), `policy/fingerprint.go:49-52`, `gate.workdirProblems`(gate.go:153-207), `cmd/bento/profile.go` (47 sites), `validate.go`, `approve.go:275`, `render.go:172`, `internal/linux/linux.go:880`, `args.go:399-402` | Key added `d2cad92` (2026-09-18), then SIX one-at-a-time fixes in nine days: not-a-directory, host-has-not, relocatable, carry-the-manifest-workdir, profile-quiet-on-carried, profile-names-ungranted. Signal 3 firing at full volume. Mentioned only incidentally in two existing grids | A frontend may disclose or refuse a workdir a run would accept; it must never pass a workdir a run on the same host refuses | workdir state (absent / relative / absolute-exists-dir / exists-not-a-dir / absent-but-write-granted at or beneath / absent-and-ungranted / under a home not on this host / inside a DenyAll shield / at a grant's own root) x answerer (gate, validate, validate --strict, profile proposal, approve stamp+fingerprint, run) ~ 9x6 = 54, collapses to ~30 once the IMPOSSIBLE rows fold | **Strong** | grid |
| 40 | **Shield folding re-open** - `internal/shield/verdict.go`, `shieldcorpus`, `internal/grantrefusal`, `cmd/bento/clamp.go`, `gate/gate.go`, both tiers' `checkGrants` | Eight fixes since the shield-verdict grid was written: `c0305d9` fold only the spelling inside the grant, `0418cea` refuse a folding write shield on both tiers, `dae2b38`+`75c0087` clamp drops/pins the folding write, `a3f81c8` kind-neutral noun, `fe7769a` disclose a store read only in part. Every one is a single cell of a row nobody carried along | unchanged from `state-grid-shield-verdict.md`: a refusal may be narrower than the backend's; it may never be wider | Phase 2 re-open of the folding ROW of two existing grids (shield-verdict, profile-clamp), not a fresh grid. `shieldcorpus` is already the shared source, so cells are cheap | **Strong, but as a re-open** | re-open pass on the two existing grids |
| 41 | **Host-shortfall disclosure x layer** - `cmd/bento/validate.go` + `enforce/run.go` (`b5dbe59`), against `enforce/run.go` admit and `cmd/bento/doctor.go` `BaselineLayers` | A third answerer of "which layers will this host fall short on" landed after `state-grid-admission.md` gridded the other two. Mirror triple, one of whose corners is new and unwalked | validate's note may name a layer the run then enforces; it must never stay silent on a layer the run refuses to start without | layer (8 `enforce.Layer` values) x answerer (validate note, admit, doctor baseline) x host posture (enforced / degraded / unavailable) ~ 24-40 | **Good**; narrower than 39 but the new corner is genuinely unwalked | grid, or fold in as a third column on a re-open of `state-grid-admission.md` |
| 42 | **credhunt shape signals x denylist coverage** | `bv2-agqg4` (open, P4) asks for exactly this. Row 29 of the seventh sweep declined credhunt as one-dimension-and-linear; the bead's second axis (denylist coverage) is what that decline was missing | the hunt may report a store the denylist already shields; it must never stay silent on a secret-bearing store the denylist does not cover | shape signal x coverage state (covered by a DenyAll dir rule / covered by a file rule / uncovered) ~ 15-24 | **Medium.** Verify in Phase 0 that `FuzzHuntNeverReportsAShieldedFile` does not already assert the whole property | grid, after checking that fuzz oracle |

## Routed elsewhere, not dropped

| Area | Why not a grid | Route |
|---|---|---|
| `internal/observe` ptrace stop parity | interleavings, not states | already done: `docs/concurrency-audit-observe.md`. `bv2-quje6` is the live remainder |
| `internal/proxy` fault reporting, cross-connection verdicts | external misbehaviour + orderings | `docs/failure-modes/`; `make race` is the load-bearing gate per CLAUDE.md |
| `internal/denylist` | **the three-sweep deferral is over.** `bv2-h7k3b` closed 2026-09-18 (answered by `bv2-5y7c0`), and `state-grid-denylist.md` landed. The seventh sweep's row 38 - "deciding this is worth more than a fourth grid" - was acted on | closed; nothing owed |
| `internal/pathresolve` `Unreadable` arm | one open bead, an ordinary fix | `bv2-cr6cs` |
| `internal/landlock` ABI floor build-tag pair | gridded (`state-grid-landlock-abi.md`); `bv2-gsxl5` is the open decision | ordinary review |
| Open board, 19 issues | not a grid | `bead-groom` |

## Not re-gridded, deliberately

`degraded-tier`, `layer-consumers`, `gate-unknowns`, `shield-verdict`, `result-arms`,
`admission`, `output-parity`, `platform-stubs`, `teardown`, `limits-probe`,
`manifest-fields`, `approval`, `group-reach`, `launcher-order`, `profile-clamp`,
`during-run`, `report-corrections`, `exec-record`, `trust-flaws`, `new-mechanisms`,
`validate-run`, `denylist`, `landlock-abi` - all have verdicts on disk. Rows 40 and 41
above are re-open passes on three of them rather than fresh enumerations, which is the
cheaper shape and the one the skill asks for when a fix landed after a grid was written.
