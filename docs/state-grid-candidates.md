# State grid candidates

Phase A sweep, 2026-09-16. Signals: fix-commit counts per scope over the last year,
`mirror`/`parity`/`counterpart` prose, degradation fields, and fuzz oracle strength.
Prior grids (bd memories `gate-state-grid`, `cancel-result-field-grid`,
`state-grid-result-arms`) date from 2026-08-13. The file the last one names,
`docs/state-grid-result-arms.md`, is no longer in the tree.

| # | Candidate | Signals | Invariant (one-sided where possible) | Grid shape | Fit | Route |
|---|-----------|---------|--------------------------------------|------------|-----|-------|
| 1 | Full tier (`internal/linux`) vs degraded tier (`internal/launcher/degraded.go`, `internal/landlock`) | Mirror pair; ~11 `fix(degraded)` plus launcher fixes of the shape "do X like the full tier" | The degraded tier may enforce less only where its Report/Exposed fields say so; it must never grant silently what the full tier denies | fence (read shields, write shields, egress, limits, seccomp, env/HOME, hooks) x arm (success, setup failure, cancel) ~ 21 cells, x2 tiers for parity | Strong | grid |
| 2 | `validate`/`approve` vs the run path (`gate`, `enforce` admit) | Mirror pair ("mirror the grant checks the gate skipped"); 17 `fix(validate)`, 19 `fix(approve)` | `validate --strict` may refuse what a run admits, never admit what a strict run refuses for a manifest reason | refusal kind (gate problems, root write, shield collisions, unanchorable host, approval state, HOME/env) x frontend (validate, validate --strict, approve, run) ~ 24-30 cells | Strong | grid |
| 3 | Profiler clamp (`cmd/bento/clamp.go`, `profile/`) vs gate/backend refusals | Mirror pair (`shieldcorpus.ClampKeeps`); 79 `fix(profile)`; `FuzzProfileSynthesize` only asserts non-nil | A synthesized profile may propose less than was observed, never a grant the gate or backend refuses | observed access class (read, write, exec, egress) x landing (shield, above shield, system tree, root, home container, unresolvable) ~ 24 cells | Strong | grid, then `fuzz-oracle` for the Synthesize target |
| 4 | Admission (`enforce/run.go` admit) vs `postRunShortfall` vs doctor `BaselineLayers` | Mirror triple named in comments; 24 `fix(enforce)` | A layer state that refuses at admission under a posture must fault post-run under the same posture; doctor ready implies admit for a baseline policy | posture (strict, allow-degraded, default) x layer state (enforced, degraded, unavailable, report-only, requested limit) ~ 15 cells | Good, small | grid (or an exhaustive table test directly) |
| 5 | `policy.Validate` vs `policy/match.go` (proxy runtime) | Mirror pair named in `match.go`; 23 `fix(policy)` | Validate must never accept a rule the matcher cannot match as written | rule field x spelling | Weak here: `FuzzPolicyValidation`/`FuzzPortMatches` exist | `fuzz-oracle` (check they assert Validate-vs-Match agreement, not only Validate-vs-Problems) |
| 6 | `gate/` vs backend `checkNotShielded` | Mirror pair | Gate refuses a subset of backend refusals, never one the backend admits | four grids, already walked 2026-08-13 | Re-grid only | 21 gate commits since the last grid; re-open pass on that grid, not a fresh one |
| 7 | `internal/observe` ptrace lifecycle | 66 `fix(observe)`; lost-answer counting | Every undecodable or lost stop is counted, never silently dropped | interleavings of thread exec/exit | Bad for a grid | `concurrency-audit`, `failure-modes` |
| 8 | `internal/proxy` fault reporting | 57 fixes; observer vs handler faults, dial failures, NAT64 | An egress outcome the run lost is disclosed | external upstream misbehaviour | Bad for a grid | `failure-modes`; `make race` covers cross-connection verdicts |
| 9 | `internal/launcher` "verify rather than assume" namespace checks | Repeat fix shape (pidns, netns, /tmp, capabilities) | Each fence is verified, not assumed | fence x verification | Enforcement point | `threat-model` |
| 10 | `internal/denylist` | 89 fixes | Coverage of credential stores | open-ended path space | Parity audit plus `FuzzCoversAgreesWithIndex` already walk it | `fuzz-oracle` if anything |

## Outcome, 2026-09-16

Rows 1-4 were gridded: `state-grid-degraded-tier.md`, `state-grid-admission.md`,
`state-grid-profile-clamp.md`, `state-grid-validate-run.md`. Validate findings were judged
against gate.go's contract (a gate inventing a refusal is the worse mistake), not the
invariant proposed above, which pointed the other way.

Filed: bv2-8mp4n, bv2-84o51 (degraded tier); bv2-no8ru, bv2-1gude (admission);
bv2-99ypm, bv2-e694c, bv2-ls0jp, bv2-7pt8k (profiler); bv2-iap38, bv2-0ivu6, bv2-rw0ae,
bv2-oq59k (validate). Profile cell A12 was noted on bv2-kxv8p rather than filed apart.

Not filed, with reasons:
- Workspace-shield second grant passing `validate --strict` (validate F1): a documented
  gate narrowing (gate.go:374-378), the tolerated direction.
- Write above a write-protected shield on the degraded tier (validate F2b, profile A8):
  the frontends cannot know the tier, and the grant is reported, not silent.
- Credential alias refused by run without `--accept-alias` (validate F2b): a run flag, posture.
- `~` grant under an unusable `$HOME` passing strict: a host fault, not the manifest's.
- Network Unavailable refused at admission but not judged post-run (admission C2): a
  missing network namespace cannot appear mid-run.
- File-write collapse to its directory and `exec: all` (profile C): documented widenings.
