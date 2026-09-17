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

## Second sweep, 2026-09-17

Signals added over the first sweep: enum declarations counted against their switch and
reference sites, build-tag and platform splits of the same file, and the human vs JSON
output pairs that the validate grid's F4 exposed.

| # | Candidate | Signals | Invariant | Grid shape | Fit | Route |
|---|-----------|---------|-----------|------------|-----|-------|
| 11 | Landlock ABI x right x disclosure (`internal/landlock`, `internal/linux/probe.go` Consequences) | Repeated one-at-a-time disclosures: truncate (<3), ioctl_dev (<5), TCP (<4), abstract unix (<6), resolve_unix (<9), metadata (any); ABI levels are an ordered enum | For every right the running ABI cannot restrict, the degraded filesystem or network layer's Consequences names it; nothing is claimed that the ABI lacks | ABI floor..9 x Landlock right family (fs access, truncate, ioctl, net bind/connect, scope signal/abstract, resolve_unix, metadata) ~ 30-40, collapse on ABI thresholds | Strong | grid |
| 12 | `enforce.Layer` x its consumers (probe, applied, scopeattest, degraded, render legend, doctor) | Enum x call sites: 10 layers referenced 28x in probe.go, 12x applied.go, 10x render.go, 2x doctor.go; `fix(run)` 46 incl. legend gaps | Every layer a backend can report in a non-Enforced state has a probe arm, an applied arm and a legend/remedy line in both human and JSON; no layer renders as fine when not Enforced | layer (10) x consumer (5-6), collapse consumers that iterate generically | Strong | grid |
| 13 | Non-amd64 and off-Linux stubs (`internal/seccomp/*_other.go`, `gate/{alias,carve}_other.go`, `trust_other.go`, `landlock` stub) | Build-tag mirror pairs; the degraded-tier grid left non-amd64 unwalked | A stub never lets a fence or check read as held: its Supported is false AND the consuming probe reports the layer not Enforced, or the gate marks the answer Unknown/Partial | stubbed function (~14) x consumer verdict | Good | grid (cross-compile `GOARCH=arm64`/`GOOS=darwin` vet to spike) |
| 14 | `trust.ApprovalState` x consumers (validate 9 switch arms, run 3, approve) | Enum x call sites; `fix(approve)` 19, `fix(trust)` 15 | Run never proceeds on a state validate or approve reports unapproved; every state has an arm in each frontend | state (~5) x frontend (validate human, validate JSON, approve, run) ~ 20 | Good | grid |
| 15 | Result arms re-grid (`enforce.Result` x backend return arms) | Prior grid file `state-grid-result-arms.md` is gone; `runDegraded` was restructured through `runCmd` (3cc71f9) | Every return arm carries every Result field a consumer reads | arm (8+) x field | Re-grid | grid, re-open against the 2026-08-13 memory |
| 16 | Human vs JSON output parity across `validate`, `doctor`, `run` | validate F4 (three callouts missing from JSON); `5c3676f` guards Runnability fields only | Every fact the human output states is present in JSON | fact x frontend x format | Medium, overlaps 12 and 14 | fold into 12/14 as a consumer column, or a reflection guard test |
| 17 | `internal/denylist` Deny/Holds switches (18 arms in one file) | Enum x call sites, but one file | | | Weak for a grid | `fuzz-oracle` (existing FuzzCoversAgreesWithIndex) |

## Second outcome, 2026-09-17

Rows 11, 12 and 14 were gridded: `state-grid-landlock-abi.md`, `state-grid-layer-consumers.md`,
`state-grid-approval.md`. The reviewers' worktrees were based on 924e291, before the
2026-09-16 fix batch; findings touching that batch were re-read on `docs/state-grids`.

Filed: bv2-vnic2, bv2-ivg7h, bv2-688em (Landlock ABI); bv2-ofg48 (layer consumers);
bv2-65id6, bv2-mxvq6, bv2-7o2mm (approval).

Not filed, with reasons:
- `landlocktsync` on an ABI 1-7 kernel says "this kernel has no Landlock": wording only, the run refuses.
- `ioctlDevResidual` says "the host's whole /dev": over-disclosure, the allowed direction.
- Entrypoint content, `blocked-hosts` edits, reformatting and relocation keep a stamp current: by
  design per fingerprint.go:29-32 and manifest.go:82-88.
- `run --allow-unapproved` on a stale or unstamped manifest names no state: the flag is the
  consent and its help mentions stale. Left for the owner to decide; the unrecorded-stamp note
  under the same flag does print.
- Layer x consumers left profile's writeRefusal path untraced, assumed to match run's.
