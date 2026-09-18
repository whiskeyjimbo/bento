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

## Third sweep, 2026-09-17

Signals added: which rows the first two sweeps nominated and nobody picked, `shield.Verdict`
against the shared corpus that drives its differential tests, and fix scopes since 2026-09-01
(`linux`, `validate`, `clamp` lead, all already gridded).

| # | Candidate | Signals | Invariant | Grid shape | Fit | Route |
|---|-----------|---------|-----------|------------|-----|-------|
| 13 | Non-amd64 and off-Linux stubs | Carried from the second sweep, unpicked; the degraded-tier grid left non-amd64 unwalked | A stub never lets a fence or check read as held | stubbed function (~14) x consumer verdict | Good | grid; spike by cross-compiled vet and a `GOARCH=arm64` test build |
| 15 | Result arms re-grid | Carried; the earlier grid file is gone and `runDegraded` was restructured | Every return arm carries every Result field a consumer reads | arm (8+) x field, ~40 before collapsing | Good | grid |
| 18 | `shield.Verdict` x tier x `shieldcorpus` | 7 verdicts; the corpus has 21 rows driving gate, linux and clamp differentials, but no `InsideCallerShield` row and no degraded-tier (`internal/launcher`) differential; `AboveWriteShield` is documented as tier-specific | For every verdict, each consumer (gate, full-tier backend, degraded tier, clamp) refuses at least what the corpus says; the gate never refuses what both backends admit | verdict (7) x kind (2) x consumer (4), collapsed on kind where the verdict is kind-bound, ~30 | Good; differentials already walk most full-tier cells, so the yield is the degraded column and the empty rows | grid, then add the missing corpus rows as the exhaustive test |
| 6 | `gate/` vs backend `checkNotShielded` re-open | Carried; 21 gate commits since the 2026-08-13 grid | as row 6 | re-open pass | Overlaps 18 heavily | fold into 18 |
| 16 | Human vs JSON parity | Carried | as row 16 | | Medium | a reflection guard test, not a grid |
| 19 | `examples/embed` mirroring the backend's shield and grant sets (main.go:296, :442) | Mirror prose in library-consumer example | The example never claims a fence the backend does not apply | small | Weak: example code, `make examples` verifies it | ordinary review |

## Third outcome, 2026-09-17

Rows 13, 15, 16 and 18 were gridded: `state-grid-platform-stubs.md`, `state-grid-result-arms.md`,
`state-grid-output-parity.md`, `state-grid-shield-verdict.md`. Reviewer worktrees started on
924e291; each re-checked its cites against 5a98897 in a re-open pass.

Filed: bv2-5v0pf, bv2-xzkku, bv2-dkdwd, bv2-i73jf (result arms); bv2-9rus4, bv2-097pd, bv2-hqqlp,
bv2-9xt55, bv2-2eirs, bv2-9jlzo, bv2-qmlok, bv2-4cy9j (output parity, several cells per bead where
one fix covers the row); bv2-2pbxh, bv2-whloj, bv2-9rqim (platform stubs); bv2-kdp1e (shield verdict).

The result-arms re-open pass found the recurring defect moved up a layer: every prior fix closed
the backend arm, none carried the fields into a consumer's error path.

Not filed, with reasons:
- Shield verdict F1, clamp keeping an AboveWriteShield grant the degraded tier refuses: profile A8,
  already rejected on 2026-09-16.
- Shield verdict F2, clamp skipping the gitdir scan: fixed at 21dc076, read on a stale base.
- Shield verdict F3, checkout-derived write shields writable on the degraded tier: disclosed in
  Exposed, degraded-tier grid F4 x A1.
- Run's hedged signal inference (R16) and file-ish write note on stderr (R26): documented choices.
- Run's hints and denial legend absent from JSON (R17/R18): rebuildable from JSON fields.
- `seccomp_other.go` lacking `TerminalInjectionSupported`: a compile failure, the safe direction.

## Fourth sweep, 2026-09-17

Signals added: degradation flags counted by consuming file (`ShieldsUnknown` 31 uses,
`CredentialAliasesPartial` 21, `ArgvTruncated` 15, `HoldsUnknown` 11, `ErrLocationUnknown` 7),
the remaining iota enums against the grids already done, and the gaps the output parity guard
exposed when widened (bv2-ati60, bv2-uzlc2).

| # | Candidate | Signals | Invariant | Grid shape | Fit | Route |
|---|-----------|---------|-----------|------------|-----|-------|
| 20 | Gate's "could not tell" flags (`gate.Check`: `ShieldsUnknown`, `CredentialAliasesPartial`, and the answers they qualify) x consumers (validate human, validate --json, examples/embed) | Degradation flags in 4 files each; bv2-hqqlp was this shape (refusals dropped under `ShieldsUnknown`); `alias_other.go` vs `alias_unix.go` platform split | A consumer never presents an answer computed under an unknown or partial flag as complete: empty-because-unasked is always distinguishable from empty-because-clean | flag (2-4) x qualified answer (refusals, aliases, shielded grants, runnability) x consumer (3), collapse unrelated pairs, ~25 | Strong | grid |
| 21 | Manifest trust flaws x frontend (`trust.LocationFlaws`, `stampFlaws`, `ErrLocationUnknown` x run, validate, approve, profile x human, --json x linux, other) | Two gaps filed from one guard widening (bv2-ati60, bv2-uzlc2; both fixed in f2d50d2); `trust_other.go` returns `ErrLocationUnknown`; four frontends each call the flaw functions differently | Every frontend that acts on or stamps a manifest surfaces every flaw it computes in each output form, and none reads `ErrLocationUnknown` as no flaws | flaw source (3) x frontend (4) x form (2), platform only for the unknown row, ~24 | Good | grid |
| 22 | Exec record states (`ArgvTruncated`, marked vs unmarked, absent, partial) x consumers (render human and --json, applied in both tiers, embed, supervise) | ADR 0011; `ArgvTruncated` in 4 files; render_test pins five record states for render only | No consumer reads a truncated, partial or absent record as a complete one | state (5) x consumer (5) ~25 | Medium: render is already table-tested, the yield is the example consumers | grid, small |
| 23 | `enforce.SetupState` x consumers | 3 states in 5 files | | | Weak: walked as a field in the result-arms grid | skip |
| 24 | `denylist.Holds` (`HoldsUnknown`) x shield rules x clamp | 11 uses; open P1 bv2-h7k3b disputes what Holds decides | | | Decline: the semantics are under an open decision | revisit after bv2-h7k3b |
| 25 | `internal/observe` | 66 fixes; this session saw an uncommitted change time it out | | | Bad for a grid | `concurrency-audit` |
| 26 | Open board, 47 beads | Several beads this session were stale on arrival (cites moved, fixed on another base) | | | Not a grid | `bead-groom` |

## Fourth outcome, 2026-09-17

Rows 20, 21 and 22 were gridded: `state-grid-gate-unknowns.md`, `state-grid-trust-flaws.md`,
`state-grid-exec-record.md`, each reviewed at 7bc186f with a re-open pass. Row 26 was groomed
separately (one bead closed, twenty descriptions corrected, no blocker edges broken).

Reopened: bv2-pf2n. Its fix, 3b14c98, marked the recorder on a lost trace but left
`execRecordComplete` keyed on a non-empty recorder line, so a partial record still reads complete.

Filed: bv2-chp2i, bv2-ncpur (exec record); bv2-t7nrj, bv2-c1pca, bv2-k95b0, bv2-c80hv
(gate unknowns, the last an owner decision); bv2-cr963, bv2-pt74y (trust flaws). Trust-flaws
findings 1 and 3 are bv2-ati60 and bv2-uzlc2, which f2d50d2 addresses from another session.

Not filed, with reasons:
- run --json refusal events dropping stamp_at_risk before enforce.Run: nothing ran, and approve
  refuses on the same fatal flaws and warns on the rest (approve.go:65, :412-421).
- Human "nothing was watching" when a failed recorder left runs: under-claiming, the allowed direction.
- Exec record in embed, supervise and profile: nothing but run.go:163 sets RecordExec.
- Degraded-tier exec record states beyond unavailable: degraded.go:334 returns a fixed record.
- Profile's clamp skipping the shield clamp silently when the shield set fails (gate unknowns D3):
  the profiling run's own sandbox fails on the same anchor error first; reachable only if the
  anchors break between the run and the clamp. Read only, not spiked.
- run and validate exiting 0 on a fatal location flaw: advisory by design, trustwarn.go:33-36.

## Fifth sweep, 2026-09-17

Thin by design: four rounds have taken the strong mirror pairs and the enums with many call
sites. This sweep looked at what is left, which is mostly areas the fit check sends elsewhere.
Signals added: fuzz targets read for which fields their oracle actually varies, and the
parse/serialize pair in `manifest`.

| # | Candidate | Signals | Invariant | Grid shape | Fit | Route |
|---|-----------|---------|-----------|------------|-----|-------|
| 27 | `manifest.Marshal`/`Parse` field coverage (manifest.go `fromPolicy`, `toPolicy`, `quoteUnlessItReadsBack`, `screenSource`, `screenProvenance`) | Parser/serializer mirror pair; `FuzzManifestRoundTrip` has a real DeepEqual oracle but its literal varies only 8 of 10 `policy.Policy` fields (not InterpreterArgs, not Args), passes `Provenance{}` always, and uses single-element lists | Marshal may refuse what Validate accepts, but must never write a manifest that Parse reads back as a different policy or provenance | field (10 policy + 4 provenance) x concern (fromPolicy, toPolicy, quoting, screen, fuzz-covered) ~28, collapsible | Good: the fuzzer's oracle is strong and its input list is a hand-list, which is exactly where a grid adds coverage | grid, then widen the fuzz target for the fields the grid finds unvaried |
| 28 | `policy.Validate` vs `policy/match.go` | Mirror pair named at match.go:7 ("the runtime counterpart to the rule validation in Validate"); 33 fix commits | Validate must never accept a rule the matcher cannot match as written | rule field x spelling | Weak here: two fuzz targets exist, but `FuzzPolicyValidation` only fuzzes Validate and `FuzzPortMatches` only PortMatches, so neither asserts the pair agrees | `fuzz-oracle`: the missing target is a cross-assertion, not a grid |
| 29 | `internal/credhunt`, `internal/pathresolve` | 8 and 4 fixes, small surfaces | | | Decline: one dimension, linear flow | ordinary review if anything |
| 30 | `internal/denylist` Deny/Holds | 89 fixes, but `HoldsUnknown` semantics sit under open P1 bv2-h7k3b | | | Decline, unchanged from row 24 | revisit after bv2-h7k3b |

## Fifth outcome, 2026-09-17

Row 27 was gridded (`state-grid-manifest-fields.md`, 44 cells, one UNHANDLED, no WRONG). The three
routed runs were spent too, each reviewed at 0abf849: `fuzz-oracle-audit.md`,
`concurrency-audit-observe.md`, `threat-model-launcher.md`.

Correction to row 28: `FuzzPortMatches` already cross-asserts the port half of Validate against the
matcher. Only the host half is unasserted, and the property holds by construction, so the item is a
missing assertion rather than a defect.

Correction to row 25 and to this session's brief: `make race` runs `internal/observe` whole under the
detector (Makefile:137), not `internal/proxy` alone.

Filed: bv2-jql08, bv2-kt3um, bv2-wzvsx (manifest); bv2-ehvnz, bv2-f29et (fuzz targets, plus a note on
bv2-nul45); bv2-waaqd, bv2-w07fb, bv2-utgv8 (observe concurrency, plus a note on bv2-8updn);
bv2-v09t5, bv2-b4wdp, bv2-7x1es, bv2-466p5 (launcher threat model). A warning went on bv2-zkyyz: its
closing instruction cites fuzz seeds that cannot prove the YAML workaround is safe to drop, because
the target never varies the fields the workaround protects.

What the routed skills reached that a grid could not:
- The terminal-detachment asymmetry (bv2-b4wdp) is a check on one tier and not its sibling, which the
  degraded-tier grid had no cell for: nothing branches on `--new-session`, so there was no cell to be
  wrong in.
- The unauthenticated applied report (bv2-v09t5) comes from attacker capability, not from a
  distinction the code makes.
- The concurrent-opens docstring (bv2-utgv8) is a test that cannot fail the way it claims, which only
  removing the protection reveals.

Not filed, with reasons:
- Manifest empty-slice and `Exec: ""` normalizations, list order and duplicates, quoting in the
  unvaried fields: all checked inverted and holding.
- `networkRule.UnmarshalYAML`'s scalar branch: unreachable from Marshal output.
- Observe's `seen`, `drops`, `held`, `lastOp`, `execSpawn`, `tracees`, `res`: single-goroutine.
- `stopProxy()` before `rec.into()` (profile.go:205-213): an ordering invariant held by comment; a
  WHEN-axis candidate for a later grid, not a concurrency finding.
- Fuzz targets for landlock, seccomp, i386, backend and cmd/*: no cheap in-process oracle.
- Both exec dispatch paths already refuse a relative argv[0] (launcher.go:1040, seccomp_linux.go:157).

## Sixth sweep, 2026-09-18

Five rounds have taken the strong mirror pairs and the enums with many call sites, so this
sweep went after axes the earlier ones did not use: teardown and termination as a WHEN axis,
the two board items that ask for a grid by name and nobody has picked, a tree-wide `= iota`
count (earlier sweeps counted enums in `internal/` and the frontends, not everywhere), and
cross-package degradation flags in `trust`.

| # | Candidate | Signals | Invariant (one-sided) | Grid shape | Fit | Route |
|---|-----------|---------|----------------------|------------|-----|-------|
| 31 | Teardown and reclaim x termination mode x tier (`internal/linux/shields.go` createdShields/removeCreatedShields, `internal/linux/linux.go` and `degraded.go` cancel arms, `internal/launcher` leaked-group sweep, scratch writes) | New axis. 16 fixes on shields.go alone and a long one-at-a-time run of `fix(cancel)`/`fix(degraded)`/`harden(launcher)` commits, each closing one termination mode; three open beads name single cells (bv2-ntncf, bv2-dyz92, bv2-2dpgj) | Teardown may leave behind only what it can prove bento did not create; it must never leave a bento-created artifact inside the checkout unreclaimed and unreported, and never report a discarded write as applied | termination mode (clean exit, target error, setup failure, cancel before start, cancel mid-run, SIGKILL of bento, SIGKILL of the target) x artifact class (materialized file shields, created mount-point dirs, scratch writes, leaked process groups, proxy/recorder) x tier (bwrap, degraded) - collapse tier where the artifact is tier-bound, ~30 | Strong. States, not interleavings: a WHEN axis, not a `concurrency-audit` | grid |
| 32 | Limits probe internals vs reported limit state (`internal/linux/limits.go`: cacheProbe, measureScope, measureDelegatedControllers, hostSafetyDelegationState, cpuDelegationState, unifiedCgroupReadable, abandonedProbeReason) | Carried: bv2-03sfk, nominated 2026-08-17, never picked. 39 commits on limits.go; `(T, bool)` caches and `known bool` threaded through every helper | A limit may be reported UNENFORCED when it was in fact enforced; it must never be reported enforced when the probe was unknown, timed out, the cgroup was unreadable, or the controller was undelegated | limit kind (3) x probe outcome (delegated, undelegated, controllers unknown, cgroup unreadable, timed out or abandoned, cached from an earlier run) ~18 | Good | grid, scoped strictly BELOW the layer boundary: `state-grid-admission.md` (posture x layer state, incl. requested limit) and `state-grid-layer-consumers.md` own the layer above. The doc bv2-03sfk tells a reviewer to read first, `state-grid-layer-attestation-2026-08-16.md`, is gone from the tree - strip that instruction |
| 33 | Launcher restriction sequence, bwrap tier vs degraded (`internal/launcher/launcher.go` vs `degraded.go` RunDegraded/degradedPrerequisites/restrictDegraded) | Carried: bv2-76t24, nominated 2026-08-17, never picked. The mirror is named in the code (degraded.go:97, :135 "Order mirrors the bwrap launcher"); 35 `fix(launcher)` in 60 days, and eight since 2026-09-17 alone (/dev fence, bwrap resolution, new session) | The degraded tier may drop a restriction the bwrap tier applies, but only where the absent bwrap structurally forces it and the applied report records the drop; never a shared restriction applied in an order that leaves a window the bwrap tier does not have | restriction (~8) x state (applied, dropped and recorded, dropped silently or misordered) ~24 | Good. `threat-model-launcher.md` (2026-09-17) covered attacker capability against this area, not the restriction-by-restriction parity; the two are complementary per Phase 0 | grid. Both scope-boundary docs the bead cites, `state-grid-launcher-encode-parity.md` and `state-grid-applied-report-wire.md`, are gone - strip that instruction too |
| 34 | `trust.groupReach` and the facts built on it x consumers (`trust/accounts.go`, `trust/trust.go`, `internal/linux/limits.go`, `internal/linux/scopeattest.go`) | New: a deliberately three-valued degradation flag (`groupUnknown` is the zero value on purpose, accounts.go:19-21) read in two packages outside its own; the classic empty-because-unasked shape, which is the shape bv2-hqqlp and the gate-unknowns grid both turned out to be | No consumer reads `groupUnknown` as `groupPrivate`: a group nothing could be learned about never presents as proven to hold nobody | flag value (3) x fact built on it (foreign owner, shared-group write, scope attestation, limits delegation) x consumer form ~18 | Medium: small surface, but the invariant is sharp and one-sided | grid, small |

Declined this sweep, with reasons:
- Tree-wide `= iota` turned up three enums no earlier sweep names - `journalVerdict`
  (journal.go:66), `convergeStop` (converge.go:186), `grantChoice` (prompt.go:15). All three
  are read essentially in their own file (journal 37 of 40 references, converge 24 of 28,
  prompt 7 of 11). One dimension, linear flow: ordinary review, not a grid. `convergeStop`
  pairs with open bv2-mfvki, which is one bead, not a row.
- Exit codes (`bentoFailed` 125, `postureShortfall` 124, passthrough) x command. Nothing
  branches on an exit code except render.go's hint heuristics and profile.go:1411 - emission
  plus documentation for CI wrappers. The hint half was already declined twice (third and
  fourth outcomes, R16 and "documented choices"). bv2-uyx1h is a bead, not a grid.
- `internal/denylist` stays parked behind open P1 bv2-h7k3b, unchanged from rows 24 and 30 -
  but it is 52 fix commits in 60 days, the second-highest scope in the repo, and the only
  reason it is unexamined is that one undecided bead. Deciding bv2-h7k3b may be worth more
  than a fourth grid.
- `proxy.ipClass` x nat64: proxy was routed to `failure-modes` twice and that run is spent
  (`docs/failure-modes/`); bv2-khpb1 is the open cell.
- `namespaceProbe` (probe.go, 25 of 27 references): the consuming half is what
  `state-grid-layer-consumers.md` already walked.

## Sixth outcome, 2026-09-18

Rows 31, 32, 33 and 34 were all gridded: `state-grid-teardown.md` (35 cells),
`state-grid-limits-probe.md` (30, reshaped into two grids), `state-grid-launcher-order.md`
(52 restriction cells plus 8 ordering cells), `state-grid-group-reach.md` (18). Every cell
in all four got a verdict; no reviewer returned an unwalked cell.

**The reviewer worktrees were based on `main` (924e291), 89 commits behind this branch.**
Earlier sweeps hit the same thing and noted it in passing; this round it produced a false
finding that two reviewers independently "confirmed", so it is worth stating as a rule. Each
reviewer was sent back for a base correction against 0a45ddb after its re-open pass, and each
appended one to its grid. Dispatch a future round from the working branch, or budget the
correction pass from the start.

Filed: bv2-t41ij, bv2-obrnf, bv2-tws9i (teardown); bv2-tdwfx, bv2-3ka8n, bv2-wq8zh (limits
probe); bv2-xwz5v, bv2-7nv8y, bv2-lpuue, bv2-tkbsx (launcher); bv2-2duoj, bv2-5c02s (group
reach). Appended rather than filed: bv2-ntncf, bv2-dyz92, bv2-2dpgj, bv2-76tn4 (teardown
cells the board already held), bv2-d8vkd (worse on the degraded tier than it records).
Closed as discharged: bv2-03sfk (row 32's nomination), bv2-76t24 (row 33's).

Withdrawn during the base correction: the degraded tier failing to attest its scope limits.
Both the limits reviewer and the launcher reviewer found it independently, from the probe side
and the restriction-parity side, and it was already fixed at 3cc71f9 - `runDegraded` calls
`noteScopeLimits` at degraded.go:247 ahead of all four return arms, pinned by
`TestDegradedRunReconcilesTheLimitsLayersItGot`. Two reviewers agreeing meant less than it
looked, because the agreement was about a tree neither was looking at. The limits reviewer's
own phrasing is the lesson worth keeping: a stamp certifies the method, not the tree.

One dismissal retracted on a re-open pass: the group-reach grid reported "no `--json` surface
for trust flaws at all", stamped VERIFIED BY EXECUTION. There are three, all through one
converter. It surfaced only because the re-open brief carried a closed decision (f2d50d2,
ef9e36a) that contradicted it - the false-dismissal case the skill exists to catch.

The recurring defect this round, found independently by all four reviewers: **a true statement
scoped to one cell, written where a reader takes it as a verdict on the whole mechanism.**
Three instances in the launcher alone (launcher.go:728, args.go:518-528, applied.go:23-28),
one in a test (`TestCreatedShieldsExcludesPreexistingPaths`, right about a user's own
`.git/config`, silent about a leftover bento created), one in a comment claiming a disclosure
the report does not make (degraded.go:421-424), and two in the tracker's own text (bv2-ntncf's
option (1), bv2-76tn4's "that cleanup is correct"). Prose, mostly, which is why none of it
fails a test.

Not filed, with reasons:
- `trust.Flaw` has three fields and `flawJSON` two, so a `--json` consumer cannot distinguish an
  advisory flaw from one `approve` would refuse over: the tolerated direction, any consumer
  treating every entry as a problem over-warns. Recorded on bv2-5c02s.
- ef9e36a's hint fix carried to all three JSON call sites, structurally - it went into the shared
  converter, so it could not be half-applied. The "one frontend fixed, a sibling left behind"
  hypothesis was wrong here, and the rejection is recorded rather than dropped.
- The `/dev` fence run (4cca01a, fa39384, f8801b3) carried structurally: the degraded tier mounts
  no `/dev` and Landlock denies every ungranted name, so there is no counterpart to add.
- Teardown F5, a discarded scratch write reported as applied: all eight terminal arms read, none
  carries a field describing scratch or tmpfs content. Dismissal verified inverted.
- `PR_SET_DUMPABLE` ordering asymmetry between the tiers (launcher F5): the exploit is a race,
  out of scope for a grid. Recorded in the doc.
- `reapUntil`'s Wait4(-1) dropping the bridge's status (bv2-73e4c): a distinct artifact class
  from leaking a process tree, declared not-walked rather than omitted.

Grid gaps recorded for a later session to inherit, rather than left implicit: the during-run
window (bv2-76tn4's cell, folded away by the teardown grid's dimensions), in-sandbox tmpfs
`/tmp` and `/dev/shm` as a discarded-write class with no row, and `reapUntil`'s wait target.
Plus one unverified follow-on worth a cell: a leftover empty `.git` may change where the next
run's workspace shields anchor, because `checkoutRoot` (shields.go:179) anchors by name.

Correction to row 34's own text: `internal/linux/scopeattest.go` and `internal/linux/limits.go`
are NOT consumers of `trust.groupReach`. Every "group" in them is a cgroup. The enum is
unexported and confined to package `trust`; the reviewer reshaped the grid around producers
instead, which is where the defect was.

## Seventh sweep, 2026-09-18

Different from the six before it: 21 commits landed today, so a real part of the surface is
code no grid has ever seen - including code the sixth round's own fixes wrote
(`restrictCapabilityBound`, `TestTierDifferential`, `warnResidue`, `scopeLimits.sampled`,
`absentWrites`, `terminalResidual`/`capBoundResidual`). Signals used: the diff of today's
commits for new functions and new degradation fields, post-run report-correction sites
counted against the `enforce.Layer` enum, and the grid gaps the sixth round recorded rather
than walked.

| # | Candidate | Signals | Invariant (one-sided) | Grid shape | Fit | Route |
|---|-----------|---------|----------------------|------------|-----|-------|
| 35 | Post-run report corrections x layer (`enforce/run.go` postRunShortfall and the admission arms, `internal/linux/linux.go` worsenNetwork + the residue warnings, `scopeattest.go` noteScopeLimits, `degraded.go` degradedProbe's rewrite) | New. ~20 correction call sites against an 8-constant `enforce.Layer` enum - the enum-times-call-sites shape, and nobody has gridded the CORRECTION axis (`state-grid-layer-consumers.md` walked the consumer axis, `state-grid-admission.md` the posture axis). Two of the sites were added today | A post-run correction may only ever worsen a layer, never improve one; and a worsening that refuses a run must reach the report, the shortfall and the operator's channel alike - a layer worsened in one and not the others is the forbidden direction | layer (8) x correction site class (pre-run probe, in-run attestation, post-run shortfall, degraded rewrite, operator channel) ~40, collapse the layers that share a correction path | Strong. bv2-dnda5 is already a live cell in it: an unsampled reading now refuses a completed default-posture run, a failure mode that did not exist this morning | grid |
| 36 | The during-run artifact window (`internal/linux/shields.go` materialization, the checkout, the target's own view) | Carried, and recorded as a gap by the sixth round's teardown grid rather than walked: that grid's dimensions folded "during" away entirely. bv2-76tn4 and bv2-2dpgj are each one cell of it, both open | An artifact bento materializes inside the user's checkout is either invisible to everything that would capture it, or disclosed - never present, capturable and unmentioned | artifact class (materialized file shield, mount-point dir, in-sandbox tmpfs /tmp and /dev/shm, scratch) x window (before start, during run, after teardown) x observer (the target, the host user, git) ~30 | Good. The in-sandbox tmpfs class has no row in any existing grid | grid |
| 37 | The sixth round's own output (`restrictCapabilityBound` + its seams, `TestTierDifferential`'s 4 rows against Grid A's 13 restrictions, `warnResidue` x entry path, `scopeLimits.sampled` x reader) | New code, one day old, gated but never gridded. Each of the round's five fixes introduced a state that did not exist before, and two of them self-reported blast radius (bv2-dnda5, bv2-3mxlo). `TestTierDifferential` covers 4 of the 13 restrictions in the launcher grid | Every state the new code introduces is disclosed on every path that can reach it - no entry path silently discards a residue or an unsampled reading | new mechanism (4) x entry path (run, degraded, profile, embed, supervise) ~20 | Medium, and honestly declared: Phase 0 says decline a churning area, and this churned today. It is gated and not mid-refactor, but verdicts here are the youngest and rot fastest. bv2-0hy3m and bv2-dhj3o are already two of its cells | grid only if the user wants the round audited; otherwise let it settle a week |
| 38 | `internal/denylist` | Unchanged from rows 24, 30 and the fifth sweep: still the second-highest fix scope in the repo, still unexamined, still parked behind P1 bv2-h7k3b, which has now been open since 2026-08-17 - a month | - | - | Decline again, for the same reason, which is now the finding | **Deciding bv2-h7k3b is worth more than a fourth grid.** Three sweeps have declined this area for one undecided bead |

Declined this sweep, with reasons:
- `TestTierDifferential` covering 4 of 13 restrictions is a coverage list, not a grid - the
  missing rows are named and the table was built to take them. File as a test item, not a round.
- `reapUntil`'s wait target (bv2-73e4c), recorded as not-walked by the teardown grid: it is about
  which child a wait consumes, an ordering question. `concurrency-audit`, not this.
- `internal/proxy`: routed to `failure-modes` twice and that run is spent; bv2-khpb1 is the open cell.
- The frontends (validate, approve, doctor, render, manifest, clamp, gate, shield verdicts,
  landlock ABI, exec record, trust flaws, output parity, platform stubs, result arms): all
  gridded in rounds one through five. Re-grid only on a specific reason, not on a sweep.
