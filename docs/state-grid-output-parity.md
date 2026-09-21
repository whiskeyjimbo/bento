# State grid: human vs JSON output parity (validate, doctor, run, approve)

Base: docs/state-grids 5a98897, checked out detached in a reviewer worktree. File:line
references drift across branches, so each cell names the function as well; validate.go
lines are the branch's, render.go/run.go lines are within a few of main's.

## Phase 0 - fit

Fits, but as a grid that feeds a guard test rather than a grid alone. Signal: a mirror pair
on every frontend (a human writer and a JSON envelope fed from the same inputs), and a fix
history of one-at-a-time carries (approval_note, the callout fields, unshieldable_runtime_dir,
unshieldable_relocations) that each closed one cell.

Invariant: every fact a frontend's human output states (refusal, warning, callout, remedy,
layer state, note) is also present in that frontend's JSON; JSON may carry more.

Reflection cannot enforce it on its own: the human facts are prose from ~40 writer functions,
not an enum or a struct, so there is nothing to range over. The deliverable is the grid below
plus a table-driven guard (see "Guard test design").

Scope notes, decided from the code:
- **approve has no --json** (approve.go has no flag). Its JSON mirror is validate --json,
  which carries approve's callouts (setCallouts). approve is gridded only through that.
- **stderr-in-both-modes.** run's pre-run notes go to stderr in human and --json alike. They
  are not dropped from the --json invocation, only from the envelope. Graded separately
  (tier 2) from facts that exist only in human mode.
- **Derivable** means the JSON carries the exact inputs the human sentence is computed from,
  with no host state in between (e.g. exec mode -> the static execve note). Graded HANDLED
  (derivable). A judgement needing host state or a function the consumer does not have is
  not derivable.

## Grid V - validate: human fact x --json (24 cells)

| # | Human fact (writer) | JSON field | Verdict | Stamp |
|---|---|---|---|---|
| V1 | manifest ok / entrypoint / interpreter / workdir / read / write / env / network / exec / limits lines (writePolicySummary) | entrypoint, interpreter, interpreter_args, workdir, read, write, env, network, exec, limits | HANDLED, toPolicyJSON | READING |
| V2 | resolved grant "on this host" (writeResolvedGrants) | resolved_read / resolved_write | HANDLED, toGrantTargetsJSON shared by both | READING |
| V3 | resolved interpreter "on this host" (writeResolvedInterpreter) | interpreter_on_host | HANDLED, fixed in 66c8850 (was UNHANDLED: exec.LookPath on this host's PATH; the stamp does not attest PATH) | READING |
| V4 | broad grant notes (writeBroadGrantNotes) | broad_read_grants / broad_write_grants | HANDLED, setCallouts | READING (TestValidateJSONCarriesTheApprovalCallouts exists) |
| V5 | shielded-grant opt-in note | shielded_grants | HANDLED, toShieldGrantsJSON | READING |
| V6 | REFUSED beside the lists, healthy host (writeGrantRefusals: shielded, looped, file-write, mount, root, carve) | refused_grants | HANDLED, gate.refusals is the same six classes (gate/gate.go:173-181) | READING |
| V7 | REFUSED beside the lists on a host that cannot anchor shields: looped/file-write/mount/root refusals still printed (zero shield set) | refused_grants, shields_unknown true | HANDLED, fixed in 9451ea4 (was WRONG: gate.Check returned before refusals(), and setRunnable set RefusedGrants only when !ShieldsUnknown) | TEST (9451ea4 made gate.ShieldSet swappable; TestCheckStillRefusesUnshieldedClassesWithoutAnchors) |
| V8 | HOME not passed through / allowlisted but unset / HOME inside sandbox (writeSandboxHome) | sandbox_home_from_host, home_not_passed_through, home_allowlisted_unset | HANDLED, fixed in 66c8850 (was UNHANDLED: depends on host $HOME, not on the env list alone) | SPIKE |
| V9 | allowlisted env not set on this host (writeUnsetEnvNotes) | unset_env | HANDLED, fixed in 66c8850 (was UNHANDLED: host environment, not derivable) | SPIKE |
| V10 | network rule covers a guard-refused destination | network_blocked | HANDLED | READING |
| V11 | unreadable blocked-host key | network_blocked_unreadable | HANDLED | READING |
| V12 | loopback network rule will not reach the host's loopback | loopback_network_rules | HANDLED, fixed in 66c8850 (was UNHANDLED: a judgement (isLoopbackHost), not a field) | SPIKE |
| V13 | exec strict / exec none static notes | exec | HANDLED (derivable, static text keyed on exec) | READING |
| V14 | footer: shields could not be anchored | shields_unknown | HANDLED, same gate.ShieldSet error under both | READING |
| V15 | footer: EXCEPT N shielded paths | shielded_grants | HANDLED | READING |
| V16 | callouts: writes covering manifest / entrypoint, tmp grants | writes_covering_manifest, writes_covering_entrypoint, tmp_grants | HANDLED, setCallouts via selfWriteGrants/tmpGrants | READING |
| V17 | callouts: interpreter_args, exec: all | interpreter_args, exec | HANDLED (derivable) | READING |
| V18 | callout: grants could not be resolved | runnable absent (setRunnable returns early on Unresolved) | HANDLED | READING |
| V19 | runnable yes / NO + problems / unknown | runnable, runnable_problems, runnable absent | HANDLED | READING |
| V20 | grants: unknown / grants: NO | shields_unknown / refused_grants | HANDLED (V7 fixed in 9451ea4) | READING |
| V21 | file-ish write, missing read, credential alias, alias scan partial notes | fileish_write_grants, missing_read_grants, credential_aliases, credential_aliases_partial | HANDLED, setRunnable | READING |
| V22 | XDG_RUNTIME_DIR unshieldable note | unshieldable_runtime_dir | HANDLED | READING (TestValidateJSONCarriesAnUnshieldableRuntimeDir) |
| V23 | relocatable yes / NO + pinned | relocatable, pinned_paths | HANDLED, setRelocatable | READING |
| V24 | approval line + stamp note | approval, approval_note | HANDLED; unnamed state: human errors (writeApprovalLine default), JSON "unapproved" | READING |

warnStampAtRisk writes stderr in both modes (validate.go:65, before the mode split): tier 2,
same class as run's pre-run notes, not counted as a cell. --json carries it as stamp_at_risk,
the key run uses.

## Grid D - doctor: human fact x --json (14 cells)

| # | Human fact (writer) | JSON field | Verdict | Stamp |
|---|---|---|---|---|
| D1 | platform, verified or not (writePlatform) | platform, platform_verified | HANDLED | READING |
| D2 | no backend on this platform | reason | HANDLED, doctor.go checkPlatform arm | READING |
| D3 | layer table: layer, tier, state, detail, consequences (writeReportTable) | layers[] | HANDLED, toReportJSON | READING |
| D4 | shields cannot be anchored, runs refused | shield_anchors, ready=false | HANDLED | READING |
| D5 | core shortfall, runs refused | ready=false | HANDLED, gatedShortfall shared | READING |
| D6 | degraded summary refused / reported / host-only split (writeDegradedSummary) | layers[] tier + layer | HANDLED (derivable: tier and layer name decide the split) | READING |
| D7 | anchor set "Credential shields anchor on: ..." (writeShieldAnchors) | shield_anchor_homes | HANDLED, fixed in c973708 (was UNHANDLED) | SPIKE |
| D8 | no usable passwd home, $HOME is the only anchor | no_usable_passwd_home | HANDLED, fixed in c973708 (was UNHANDLED: the caller-steerable half of D7) | READING (same writer, branch not constructed) |
| D9 | XDG_RUNTIME_DIR unshieldable | unshieldable_runtime_dir | HANDLED, fixed in c973708 (was UNHANDLED; validate carries it, doctor did not) | SPIKE |
| D10 | libc NSS caveat (writeNSSCaveat) | libc_nss_passwd_lookup | HANDLED, fixed in c973708 (was UNHANDLED) | SPIKE |
| D11 | nested anchors (writeNestedAnchors) | nested_anchors | HANDLED; keyed row in the guard | SPIKE |
| D12 | dropped relocations, store NOT shielded (writeDroppedRelocations) | unshieldable_relocations | HANDLED, fixed in c973708 (was UNHANDLED; validate carried unshieldable_relocations and doctor did not) | SPIKE |
| D13 | relocated shields, variable -> path (writeRelocatedShields) | relocated_shields | HANDLED; keyed row in the guard | SPIKE |
| D14 | credential stores the shields walk covered only to its bound (writeTruncatedStores) | truncated_stores | HANDLED; keyed row in the guard | SPIKE |

## Grid R - run result: human fact x --json event (26 cells)

| # | Human fact (writer) | JSON field | Verdict | Stamp |
|---|---|---|---|---|
| R1 | refusal reason + short layers (writeRefusal) | refusal.reason, refusal.report | HANDLED | READING |
| R2 | limits remedy: --allow-degraded would admit this run, or drop limits (writeRefusalRemedy on Refusal.Waivable) | allow_degraded_would_admit | HANDLED, fixed in 0eacfd5 (was UNHANDLED: Waivable was not in streamRefusalJSON and is not derivable) | TEST |
| R3 | "run bento doctor" consequences pointer | report.layers[].consequences | HANDLED | READING |
| R4 | shield summary counts by kind (writeShieldSummary) | shields[] | HANDLED | READING |
| R5 | shields that followed an env var | shields[].source | HANDLED | READING |
| R6 | WARNING: $VAR relocation NOT shielded in this run (writeShieldSummary) | unshieldable_relocations | HANDLED, fixed in 0eacfd5 (was UNHANDLED) | TEST |
| R7 | shielded grant warning | shielded_grants | HANDLED (verdict and failed) | READING |
| R8 | accepted alias warning | accepted_aliases | HANDLED (verdict and failed) | READING |
| R9 | exposed warning | exposed | HANDLED (verdict and failed) | READING |
| R10 | PATH shadow (writeSandboxPathShadow) | shadowed_path_dirs | HANDLED (verdict and failed) | READING |
| R11 | degradations, host-only vs policy (writeDegradations) | report.layers[] | HANDLED | READING |
| R12 | changed auto-exec / redirected hooks / unresolved hooks | changed_auto_exec, redirected_hooks, unresolved_hooks | HANDLED (verdict and failed) | READING |
| R13 | guard blocked / metadata probe / egress denied / gate denied / untunneled | guard_blocked, guard_blocked_metadata, egress_denied, gate_denied, untunneled | HANDLED | READING |
| R14 | target unreached: exit N is bento's, the script never ran (writeTargetUnreached) | target_never_ran | HANDLED, fixed in 0eacfd5 (was UNHANDLED: a consumer read exit_code as the script's) | TEST |
| R15 | signal notice, certain | signal | HANDLED | READING |
| R16 | signal notice, hedged 128+n inference | none | HANDLED by design (run.go verdict comment on Signal) | READING |
| R17 | exec hint / egress hint / profile hint / HOME miss / PATH miss | none | HANDLED (derivable): heuristics over exit_code, policy and fields present; remedies, not outcome facts. Flagged for a human call | READING |
| R18 | denial legend | none | HANDLED (derivable), as R17 | READING |
| R19 | exec record (writeExecRecord) | exec_record | HANDLED | READING |
| R20 | posture shortfall line | posture_shortfall | HANDLED | READING |
| R21 | failure path error text | failed.reason | HANDLED, failJSON | READING |
| R22 | pre-run missing read grants | missing_read_grants (verdict only) | HANDLED | READING |
| R23 | pre-run unrecorded / shared-journal stamp note (run.go:91) | stamp_at_risk, approval_note | HANDLED, fixed in 0eacfd5 (was UNHANDLED tier 2) | TEST |
| R24 | pre-run unset env notes | unset_env | HANDLED, fixed in 0eacfd5 (was UNHANDLED tier 2) | TEST |
| R25 | pre-run blocked-host notes, runtime dir note | network_blocked, network_blocked_unreadable, unshieldable_runtime_dir | HANDLED, fixed in 0eacfd5 (was UNHANDLED tier 2) | TEST |
| R26 | pre-run file-ish write notes | none | HANDLED by design (writeFileishWriteNotes comment: stderr only, on purpose) | READING |

## Grid A - approve callouts x validate --json (5 cells)

| # | approve callout | validate --json | Verdict | Stamp |
|---|---|---|---|---|
| A1 | self-write (manifest, entrypoint) | writes_covering_* | HANDLED | READING |
| A2 | tmp grants | tmp_grants | HANDLED | READING |
| A3 | broad grants | broad_*_grants | HANDLED | READING |
| A4 | interpreter_args, workdir, exec: all | raw fields | HANDLED (derivable) | READING |
| A5 | shielded grant, blocked host | shielded_grants, network_blocked | HANDLED | READING |

Total: 68 cells, every one with a verdict.

## Findings, forbidden direction (human states it, JSON drops it)

Blast-radius order.

1. **FIXED in c973708. D12, D9, D7/D8 - doctor --json drops every shield-anchor fact.** A host whose relocation
   variable leaves a credential store unshielded, whose runtime dir is outside every shield, or
   whose shields are placed by a caller-chosen $HOME alone reports `ready: true` and nothing
   else. validate --json already carries two of these. VERIFIED BY SPIKE (toDoctorJSON beside
   writeShieldAnchors with GNUPGHOME=$HOME and a relative XDG_RUNTIME_DIR: human named the
   anchor, the runtime dir and GNUPGHOME; envelope was
   `{"layers":[],"fully_enforced":false,"ready":true,"platform":"linux/amd64","platform_verified":true}`).
   D8 VERIFIED BY READING.
2. **FIXED in 0eacfd5. R6 - run verdict drops "store NOT shielded in this run".** Same fact as D12, on the run
   that hands the store out. VERIFIED BY SPIKE (writeRunResult in both modes with one shield
   and GNUPGHOME=$HOME; verdict had shields[] and no relocation).
3. **FIXED in 9451ea4. V7 - validate --json drops shield-independent refusals when shields are unknown.** Human
   prints REFUSED for looped/file-write/mount/root grants; gate.Check returns before computing
   them, so refused_grants is absent. The gate learns the host refuses but loses which manifest
   defects to fix. WRONG at the time; 9451ea4 made gate.ShieldSet swappable and pins the fix
   with TestCheckStillRefusesUnshieldedClassesWithoutAnchors.
4. **FIXED in 0eacfd5. R14 - run verdict does not say the target never ran.** VERIFIED BY SPIKE
   (Setup=SetupTargetUnreached, ExitCode 127: human said "never ran ... exit 127 is bento's",
   verdict was `{"event":"verdict","exit_code":127,...}`).
5. **FIXED in 0eacfd5. R2 - refusal event drops Waivable.** Human tells the reader --allow-degraded admits this
   run; JSON cannot say that. VERIFIED BY SPIKE.
6. **FIXED in 66c8850. V8, V9, V12 - validate --json drops the HOME, unset-env and loopback notes.** VERIFIED BY
   SPIKE (all three printed human, envelope carried only env and network lists).
7. **D10, D11, D13, V3** - NSS caveat, nested anchors, relocated shields, resolved interpreter.
   D10 fixed in c973708, V3 in 66c8850, D11 and D13 via nested_anchors and relocated_shields.
   D10 VERIFIED BY SPIKE; D11, D13, V3 VERIFIED BY READING (writers with no JSON counterpart).
8. **FIXED in 0eacfd5. Tier 2: R23, R24, R25, warnStampAtRisk** - stderr in both modes, absent from the envelope.
   VERIFIED BY READING (run.go pre-run block writes os.Stderr unconditionally; the verdict
   struct has no field for them).

JSON-only facts (unshieldable_relocations on validate, egress_connections) are the allowed
direction and not counted.

## Rejected / dismissed, with reasons

- R16 hedged signal: deliberate, documented on the Signal field in run.go.
- R26 file-ish write on run: deliberate, documented on writeFileishWriteNotes.
- R17/R18 hints and legend: remedies computed from fields the envelope carries. Left HANDLED
  (derivable) and flagged, because the invariant as stated includes remedies and R2 shows one
  remedy that is not derivable.
- V13, V17, A4, D6: static text keyed on a field present in JSON.
- approve human vs approve JSON: no JSON mode exists; callouts are mirrored by validate --json.
- Dismissal checks: V6 (human and JSON refusal sets agree on a healthy host) rests on
  writePolicySummary and gate.refusals calling the same six gate functions, READ not executed.
  V22 rests on an existing test, not re-run.

## Guard test design

Landed as cmd/bento/output_parity_test.go: parityRows is the table (writers, fixture, human
marker, json key, or exempt reason), rendered once per fixture (run verdict, run target
unreached, run refusal, validate via the command, doctor, doctor with nested anchors and a
relocated shield, profile merge), and TestEveryHumanWriterHasAParityRow
is the go/ast pass. A sibling of 5c3676f rather than an extension: that guard ranges over
gate.Runnability's fields, and these facts are prose with no struct to range over. Exempt rows:
R16, R17/R18, R26, V13, D6, D8 (unconstructible branch), writeJSON, run's pre-run note
writers (whose runNotesJSON fields are filled beside the write in newRunCmd), Grid A and
approve's review (approve has no --json), and the file writers and dispatcher. The ast pass
scans every non-test file in cmd/bento for write* and warn* functions. The two trust warnings
are keyed rows: warnStampAtRisk as validate's stamp_at_risk (a stamped fixture in a
world-writable directory, which the ordinary validate fixture is not), and warnUntrusted as
profile's location_flaws.

The original design, for reference:

One table-driven test in cmd/bento, one row per fact:
`{name, setup func(t), humanMarker string, jsonKey string, exempt string}`. Per row: run the
frontend in human mode and assert the marker is present (so a row cannot go stale silently),
then with --json and assert jsonKey is non-empty. run rows drive writeRunResult with a
constructed enforce.Result, as run_test.go already does; doctor rows drive writeShieldAnchors
and toDoctorJSON under t.Setenv; validate rows use writeManifest + runCapturingStdout. Derivable
and by-design cells carry `exempt` with the reason instead of a jsonKey, so the table is the
grid. A reflection half is cheap: parse render.go, validate.go and doctor.go with go/ast and
fail if a `write*` func is named by no row, which catches a new human writer added without a
parity decision.

Spikes deleted; reviewer worktree `git status` clean.

## Re-open pass

- **8422b26 (stamp note in json):** closed V24. It did not reach run: R23 (the same stampNote
  on run's stderr, absent from the verdict) is still open.
- **F4 callouts (docs/state-grid-validate-run.md):** closed V4, V16, A1-A3. Nothing in that row
  is left open. The sibling notes printed beside grants rather than as callouts (V8 HOME,
  V9 unset env, V12 loopback, V3 resolved interpreter) were never part of F4's row; 66c8850 closed them.
- **0085cec / bv2-ofg48 (seccomp legend keyed on tier):** human-only (R18). It doesn't change
  any parity cell. The legend has no JSON counterpart, and the tier it keys on (res.Degraded)
  isn't in the verdict either. This is not a duplicate of any finding here.
- **5c3676f (Runnability JSON guard):** covers V19-V21 and V14/V20 at the setRunnable seam.
  It does not cover V7 (closed separately in 9451ea4), because the dropped refusals are lost upstream in gate.Check before
  Runnability is built. It also doesn't cover validate's non-Runnability notes (V3, V8, V9,
  V12), doctor, or run. The guard test design above is the extension.
- **bv2-rw0ae (strict refuses a carve the degraded tier admits):** is about the verdict, not
  parity. It touches V6 only in which set is right. Not a duplicate.
- **bv2-uyx1h (--relocatable exit 125 ambiguity):** is about exit codes. V23 is HANDLED on
  fields. Not a duplicate.
- **bv2-oq59k (note fields a host posture will refuse):** is a new human note. If it ships,
  it needs a JSON field or it opens a new cell of this grid. Not a duplicate.
- **Duplicates:** none of findings 1-8 duplicates a listed item. V7 is adjacent to the
  refused-set work behind bv2-rw0ae, but it is a different defect (a dropped list, not a
  wrong verdict).
