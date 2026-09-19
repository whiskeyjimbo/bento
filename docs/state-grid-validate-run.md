# State grid: validate / approve vs run

Reviewed 2026-09-16 against 924e291. Area: `cmd/bento/validate.go` (human, `--json`, `--strict`),
`cmd/bento/approve.go`, compared with `cmd/bento/run.go` -> `enforce.Run` (admit) ->
`internal/linux` grant refusals (`checkGrants`, `preflightGrants`, `runDegraded`).

## Phase 0 - fit

Good fit. A mirror pair (validate/approve predicting run's refusals), an enum times call sites
(the grant-refusal kinds, each answered in `internal/linux/grants.go` and mirrored in `gate/gate.go`),
and a stated one-sided invariant.

**Invariant as given (one-sided):** `validate --strict` may refuse a manifest a run admits, but
must never pass a manifest that a run on the same host and posture refuses for a
manifest-attributable reason. The callouts approve records must be the ones validate raises.

**Conflict to decide before filing anything.** `gate/gate.go:12-17` states the OPPOSITE
one-sidedness: "a gate that refuses what a run accepts is worse than one that passes something the
run then stops". Every narrowing gate.go documents as safe is a forbidden-direction cell under the
invariant above. The cells below are judged against the invariant as given. Cells that are
forbidden under it but are deliberate, documented gate narrowings are marked **FORBIDDEN (documented
narrowing)** so the orchestrator can decide which contract wins. The gate itself was gridded on
2026-08-13 (`bd memories gate-state-grid`); those verdicts were taken as given and not redone.

**Manifest-attributable**, as used here: editing the manifest text alone, on this host and
posture, removes the refusal. Run flags (`--accept-alias`, `--allow-degraded`, `--strict`) are
posture.

## Grid A - refusal kind x frontend

Columns: S = validate --strict exit (human and --json share `strictApprovalError` and
`strictRunnableError`; plain validate reports the same verdicts as warnings), A = approve --yes,
R = run.

| # | Refusal kind (run source) | Attributable | S vs R verdict | A | Stamp |
|---|---|---|---|---|---|
| 1 | Malformed policy, `p.Validate` (enforce/run.go:108) | manifest | IMPOSSIBLE: `manifest.Parse` runs `p.Problems()` (manifest/manifest.go:186-196), so every frontend fails at `loadDocument` | same | READING |
| 2 | `~` left unexpanded, `RequireExpanded` (enforce/run.go:111) | manifest | IMPOSSIBLE: run.go:571 `manifest.Resolve` expands every `~` or returns an error first | n/a | READING |
| 3 | `~other/` home spelling (manifest.go:441) | manifest | IMPOSSIBLE: refused at parse by `screenTilde` (policy/policy.go:321) | same | READING |
| 4 | `manifest.Resolve` fails: `~` grant under relative/empty/unsafe `$HOME` (manifest.go:435-460) | host (the manifest supplies the `~`) | S PASSES, R refuses. `gate.Check(nil)` sets only `Unresolved`, which `strictRunnableError` (validate.go:332-344) doesn't block on, by design. Allowed if host-attributable. Borderline, because removing the `~` removes the refusal | A stamps (approve.go:193, callout says unresolved) | SPIKE |
| 5 | Approval stale/unstamped, `requireApproval` (run.go:1135) | manifest | HANDLED: `strictApprovalError` (validate.go:228) mirrors every arm, including the unknown-enum default | approve is the fix | READING (+ existing TestValidateJSONHonorsStrict) |
| 6 | Entrypoint missing / interpreter off PATH | manifest | HANDLED: `gate.Check` Problems (gate.go:122-132), strict blocks | A doesn't check Problems and stamps an unrunnable manifest. Allowed: approve isn't the gate | READING |
| 7 | Write of `/`, `WriteIsRoot` (grants.go:231) | manifest | HANDLED: `RootWriteProblems` | A refuses (`gate.Refusals`) | READING |
| 8 | Read inside DenyAll shield, `InsideShield` | manifest | HANDLED: `ShieldedReadProblems` | A refuses | READING |
| 9 | Caller-supplied deny, `InsideCallerShield` | embedder | IMPOSSIBLE on the CLI: run.go:613 passes no `DenyPaths` | n/a | READING |
| 10 | `FoldedShield` | manifest | HANDLED: both Shielded*Problems arms | A refuses | READING |
| 11 | Write inside shield, `WriteInsideShield` | manifest | HANDLED (existing TestValidateFailsOnAGrantTheRunRefuses, not re-run) | A refuses | READING |
| 12 | Write above DenyAll shield, `WriteAboveShield` | manifest | HANDLED: `writeShieldProblem` AboveShield arm | A refuses | READING |
| 13 | **Second write grant at/inside a workspace shield** (`write: w` + `write: w/.git/hooks`), `checkWriteNotUnderReadOnlyShield` (grants.go:155) | manifest | **FORBIDDEN (documented narrowing).** S exits 0 and A stamps, but the backend refuses. gate.go:374-378 names this exact case | A stamps | **SPIKE** |
| 14 | Workspace shield redirected by symlink, `checkWorkspaceShieldNotRedirected` (grants.go:210) | host symlink under a granted tree (borderline) | S passes (the gate passes no workspace shields), R refuses. Treated as host-attributable: the manifest line is fine and the checkout's link is not | A stamps | READING |
| 15 | Write above DenyWrite shield, `AboveWriteShield`, degraded tier only (degraded.go:61) | manifest, posture `--allow-degraded` on a userns-less host | **FORBIDDEN (documented narrowing).** With `~/.pyenv/shims` present, S passes `write: ~/.pyenv` and the degraded run refuses | A stamps | SPIKE (S side); READING (degraded refusal) |
| 16 | Host `/proc/<pid>` grant, `GrantIsProcess` | manifest | HANDLED: `MountGrantProblems` | A refuses | READING |
| 17 | Managed mount, `GrantIsManagedMount` | manifest | HANDLED: `MountGrantProblems` | A refuses | READING |
| 18 | Symlink loop, `Looped` | manifest+fs | HANDLED (existing TestValidateStrictFailsOnALoopingGrantOfEitherKind) | A refuses | READING |
| 19 | Write grant is a file / unstattable (linux.go:714-731) | manifest+fs | HANDLED: `FileWriteGrantProblems` | A refuses | READING |
| 20 | Shield mount point not carvable, `checkShieldsCarvable` (shields.go:517) | manifest+fs | Built-in shields: S HANDLED and exits non-zero (spike), but see F3 for the human output. Workspace-shield half: FORBIDDEN (documented narrowing), already open as bv2-kxv8p | A refuses the built-in half | SPIKE (built-in); READING (workspace) |
| 21 | Credential alias, `checkAliasedCredentials` (linux.go:655) | manifest grant tree + posture (`--accept-alias`) | **FORBIDDEN (documented narrowing)** when run has no `--accept-alias`: S never fails on `CredentialAliases` (validate.go:490-493). Bind aliases and budget-truncated scans are missed too | A stamps (approve.go:186-192 says so) | READING |
| 22 | Shields can't anchor (`HomeAnchors` error), so every run is refused | host | S HANDLED and fails (validate.go:337). A prints a note and STAMPS (approve.go:202-204). Allowed: host-attributable, documented | A stamps | UNSPIKEABLE HERE (HomeAnchors falls back to the passwd home, and no test seam blanks it) |
| 23 | Env passthrough / `--env`, `ResolveEnv`/`admitEnv` | invocation | IMPOSSIBLE for a manifest-only cause: ResolveEnv errors only on an override missing from `env:` (enforce/env.go:115-118), and admitEnv's map comes from ResolveEnv (run.go:574) | n/a | READING |
| 24 | Posture admit: core layer degraded, default posture (enforce/run.go:459) | host | S passes, R refuses. Host-attributable, allowed | n/a | READING |
| 25 | **Requested limits the host can't enforce** (enforce/run.go:470, default posture) | manifest (`limits:`) x host | **FORBIDDEN, UNHANDLED.** S passes, R refuses. Removing `limits:` removes the refusal, and nothing in validate probes cgroup delegation | A stamps | READING; UNSPIKEABLE HERE (this host delegates) |
| 26 | **Network rules on the degraded tier** (enforce/run.go:206, `--allow-degraded`) | manifest (`network:`) x host | **FORBIDDEN, UNHANDLED.** Same shape as A25 | A stamps | READING; UNSPIKEABLE HERE (needs a userns-less host) |
| 27 | **`exec: none-strict` without the arch seccomp filter**, under `run --strict` | manifest x host | **FORBIDDEN, UNHANDLED.** Same shape. The summary prints a note (validate.go:730-732), but S doesn't fail | A stamps | READING |
| 28 | `--run-id` with no limits (admitRunID) | invocation | Out of scope: dropping the flag removes it | n/a | READING |

## Grid B - callouts: validate vs approve

`writeApprovalCallouts` is shared. validate passes `notedBeside=true`, approve passes `false`.

| Callout | validate human | validate --json | approve | Verdict | Stamp |
|---|---|---|---|---|---|
| network rule covers a blocked host | beside the rule (unsplittable key reported as unreadable) | `network_blocked`, `network_blocked_unreadable` | callout (unsplittable key counted as covered) | HANDLED, wording differs by design (profile.go:785-792) | READING |
| grants under /tmp | callout | **absent** | callout | F4 | READING |
| interpreter_args | callout + summary line | raw `interpreter_args` | callout | HANDLED | READING |
| exec: all | callout | raw `exec` | callout | HANDLED | READING |
| grants unresolvable ($HOME) | callout + "unknown" | resolved_read and runnable absent | callout | HANDLED | READING |
| write covers the manifest / entrypoint | callout | **absent** | callout | **F4** | READING |
| shielded read opt-in | beside the grant | `shielded_grants` | callout | HANDLED | READING |
| broad grant (home / top-level) | beside the grant | **absent** | callout | F4 | READING |
| approve's already-approved shortcut (approve.go:87) | always printed | n/a | callouts skipped; `requireHonorableGrants` still runs first | Allowed: the stamp was reviewed with callouts on this host (journal match). Only validate re-raises a callout that later host state creates (for example a new symlink) | READING |

## Findings (forbidden direction first)

- **F1 - workspace-shield second grant (A13).** `write: w` + `write: w/.git/hooks` in a checkout:
  `validate --strict` exits 0 and `approve --yes` stamps, but the backend's
  `checkWriteNotUnderReadOnlyShield` refuses ("is at or inside the write-shielded path").
  Documented narrowing, manifest-attributable. VERIFIED BY SPIKE (cmd/bento: approve err=nil,
  strict err=nil; internal/linux: backend refusal observed on the same shape).
- **F2 - host-capability x manifest refusals the gate never asks (A25, A26, A27).** `limits:` on a
  host without delegated controllers, `network:` under `--allow-degraded` on a userns-less host,
  and `exec: none-strict` under `run --strict` without the seccomp filter. Each goes away when the
  manifest is edited, and `validate --strict` passes each. validate's help says strict fails on "a
  manifest this host cannot start". VERIFIED BY READING; UNSPIKEABLE HERE.
- **F2b - AboveWriteShield (A15) and credential alias (A21).** Documented narrowings, forbidden
  under the invariant as given. The A15 strict pass is VERIFIED BY SPIKE, and the degraded refusal
  is VERIFIED BY READING (degraded.go:61). A21 is VERIFIED BY READING.
- **F3 - carve refusal has no REFUSED line (A20, human output). WRONG, now FIXED.** `writePolicySummary`
  (validate.go:686, 693) calls each problem function by name and leaves out `ShieldCarveProblems`.
  So `validate --strict` prints `grants: NO - the grants marked REFUSED above` with no REFUSED line
  anywhere. The exit code is right. validate.go:788-791 says the "marked above" claim has to hold
  for every kind. VERIFIED BY SPIKE. FIXED: the summary now marks it beside the write grant.
- **F4 - `validate --json` doesn't carry the self-write, /tmp or broad-grant callouts (Grid B).
  UNHANDLED, now FIXED.** approve and human validate raise them, but `policyJSON` (validate.go:424-517) has
  no field for any of them. A CI gate reading the envelope can't see "write covers the manifest
  itself". VERIFIED BY READING. FIXED: `writes_covering_manifest`, `writes_covering_entrypoint`,
  `tmp_grants`, `broad_read_grants` and `broad_write_grants`.
- **F5 - carve on the degraded tier. NOT A DEFECT; the original verdict was wrong.** `runDegraded`
  doesn't call `checkShieldsCarvable` (degraded.go:40-75) and the gate refuses the carve on any
  tier. `validate --strict` then `run --allow-degraded` does reach the divergence, but it is a
  cross-posture cell in the allowed direction (A24): validate carries no degraded posture of its
  own - no flag, no env var, no manifest field - so strict judges the default tier, which does
  refuse the carve, and the degrading is a run-side choice made after. The gate tracking the
  default tier is
  also what `clamp_refusal_test.go:151` and approve's stamp (`approve.go:205`) rest on: demoting
  the carve to a note would let the clamp propose a grant the default run dies on. Re-checked
  2026-09-19.
- **A4 - Unresolved passes strict.** Deliberate and host-attributable. The dismissal was checked
  inverted: with `HOME=relative/home` and `read: ~/data`, strict returned err=nil and run-side
  `Resolve` errored. VERIFIED BY SPIKE. Accepted, unless the `~` counts as manifest-attributable.

## Cells not walked

Every cell has a verdict. A11, A18 and A19 rest on existing tests that weren't re-run, and A14 and
the A20 workspace half weren't spiked.

## Phase 2 re-open pass (done after the verdicts above)

- `a78b4eb fix(validate): point at the REFUSED marks instead of counting them` (2026-08-05) made
  every refusal kind print beside its grant. `46c315f feat(gate): mirror the uncarvable-shield
  write refusal` (2026-08-17) added a seventh kind to `refusals` and didn't carry the summary row
  along. That is F3: the fix covered the kinds that existed then and stopped.
- `af6d3c1 fix(validate): raise the callouts approve holds to the stamp` fixed human validate only
  (validate.go:96). The `--json` row of Grid B was not carried along. That is F4.
- `ed61d8e fix(gate): keep the degraded-only write verdict out of the gate` is the recorded
  decision behind A15. It picks gate.go's direction, which contradicts the invariant under review.
- `c2a491b fix(validate): fail --strict on an unanchorable host` and `107e992 fix(approve): say the
  unanchored-shields note on every path` are A22. Validate fails there and approve only notes.
  Consistent with "approve's verdict must not depend on the host".
- `3e123ca`, `8af02d0` and `4f1e3d1` cover A7-A19. No gaps found beyond A13, A20 and F3.
- Open tracker items: bv2-kxv8p already covers the A20 workspace half. bv2-nm49f (isCheckout
  trusts a .git name) touches A13/A14 anchoring but is not the same cell. Nothing open covers F1,
  F2, F3 or F4.
