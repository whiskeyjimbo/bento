# State grid: gate.Check "could not tell" flags vs their consumers

Reviewed 2026-09-17 against 7bc186f. Area: `gate/gate.go` (`Check`, `Refusals`), `gate/alias_unix.go`,
`gate/alias_other.go`; consumers `cmd/bento/validate.go` (human, `--json`, `--strict`) and
`examples/embed/main.go`. Adjacent callers of the same qualified answers: `cmd/bento/approve.go`
(`gate.Refusals`), `cmd/bento/clamp.go` (`gate.Refusals`).

## Phase 0 - fit

Good fit. `Runnability` carries three could-not-tell flags, each qualifying a named subset of the
answer, and two consumers render it in four forms. The invariant is statable as given.

**Flags found in the code** (no others on `Runnability`):

| Flag | Set at | Qualifies |
|---|---|---|
| `Unresolved` | gate.go:112 (nil policy) | every field: all empty because unasked |
| `ShieldsUnknown` | gate.go:140-143 (`shieldSet()` error) | `Refusals` short of the shielded classes; `CredentialAliases` unasked; `CredentialAliasesPartial` left false |
| `CredentialAliasesPartial` | alias_unix.go:84,93 (unread anchor, entry budget); alias_other.go:18 (no hardlink identity) | `CredentialAliases` bounded, not complete |

**Other callers of gate.Check:** none. `grep gate.Check(` hits only validate.go:67 and
examples/embed/main.go:155 outside tests. `clamp.go` and `approve.go` call `gate.Refusals`, which
carries no flag at all (gate.go:163-166: "quietly SHORT"), so they are gridded separately in Grid C.

**Invariant (one-sided):** a consumer never presents an answer computed under an unknown or partial
flag as complete. Saying unknown about something known is allowed.

Forms: H = validate human, J = validate --json, S = validate --strict exit (shared
`strictRunnableError`, both modes), E = embed stderr.

## Grid A - Unresolved

| # | Answer | Form | Verdict | Stamp |
|---|---|---|---|---|
| A1 | Problems / runnable | H | HANDLED: "runnable: unknown ... nothing above is a clean bill" (validate.go:271-273) | SPIKE |
| A2 | Refusals / grants line | H | HANDLED: grants line is silent, but A1's line already said unknown and precedes it | SPIKE |
| A3 | CredentialAliases, Partial | H | HANDLED: none printed; A1 covers | SPIKE |
| A4 | **Summary footer "Credentials, SSH keys, and shell profiles are shielded even if a path above would otherwise expose them"** | H | **WRONG.** `writePolicySummary` passes `resolvedRead=nil` to `explicitShieldGrants`, which returns no error, so the unqualified footer (validate.go:846 arm skipped) prints over grants that were never checked against the shields. The callout below ("nothing below was checked") and A1 partly contradict it, but the footer itself asserts completeness | SPIKE |
| A5 | every field | J | HANDLED: `setRunnable` returns early (validate.go:628), `runnable` absent is the documented third answer (validate.go:476-479); `shielded_grants`, `resolved_read` also absent (validate.go:698) | SPIKE |
| A6 | exit code | S | **WRONG (documented).** `strictRunnableError` blocks on nothing for Unresolved (validate.go:347-358), so an approved manifest exits 0 under --strict while gate.go:104-108 says that host refuses the run. Contradicts the ShieldsUnknown arm's own rationale (validate.go:340-346: "a run on that host is refused whatever the manifest says"). Same cell as state-grid-validate-run A4 | SPIKE (unit; end-to-end masked by the approval failure) |
| A7 | every field | E | IMPOSSIBLE: embed returns at main.go:144-147 on a Resolve error, so `gate.Check` never sees nil | READING |

## Grid B - ShieldsUnknown

| # | Answer | Form | Verdict | Stamp |
|---|---|---|---|---|
| B1 | Refusals (short) | H | HANDLED: "grants: unknown" arm wins over the count (validate.go:287-290) | SPIKE |
| B2 | Refusals (short) | J | HANDLED: `shields_unknown` set beside `refused_grants` (validate.go:636-637) | SPIKE |
| B3 | Refusals (short) | S | HANDLED: blocks (validate.go:352-354) | SPIKE |
| B4 | Refusals (short) | E | HANDLED: note precedes the refusal lines (main.go:289-291) | SPIKE |
| B5 | **CredentialAliases (unasked)** | H | **UNHANDLED.** Output is "grants: unknown ... not checked against them" and nothing about the alias scan; no alias note, no partial note (Check leaves Partial false). A reader of "runnable: yes / grants: unknown" gets no signal that the second-name scan was skipped, which Partial exists to say when it runs short | SPIKE |
| B6 | CredentialAliases (unasked) | J | HANDLED: aliases and partial suppressed, `shields_unknown` doc names `credential_aliases` as unanswered (validate.go:494-502, 638-643) | SPIKE |
| B7 | CredentialAliases (unasked) | S | IMPOSSIBLE to mislead: aliases never block (by design) and B3 already fails | READING |
| B8 | **CredentialAliases (unasked)** | E | **WRONG.** Note ends "everything else stands" (main.go:290), a positive completeness claim over an alias list that was never computed; no partial note either | SPIKE |
| B9 | shielded_grants / opt-in notes | H | HANDLED: footer arm names the anchor error (validate.go:846-850) | READING |
| B10 | shielded_grants | J | HANDLED: absent beside `shields_unknown: true` (validate.go:704-705, 636) | READING |
| B11 | CredentialAliasesPartial | all | IMPOSSIBLE: Check returns before `credentialAliases` (gate.go:141-143) | READING (existing check_internal_test.go) |

## Grid C - CredentialAliasesPartial

| # | Answer | Form | Verdict | Stamp |
|---|---|---|---|---|
| C1 | CredentialAliases (bounded) | H | HANDLED: note printed with or without aliases (validate.go:317-323). Its reasons omit the no-hardlink-platform cause, but the flag still reads as partial | SPIKE |
| C2 | CredentialAliases (bounded) | J | HANDLED (validate.go:642) | SPIKE |
| C3 | CredentialAliases (bounded) | S | IMPOSSIBLE to mislead: aliases never block | READING |
| C4 | CredentialAliases (bounded) | E | HANDLED (main.go:314-316) | READING (+ existing TestWriteRunnabilitySurfacesEveryField) |

## Grid D - gate.Refusals callers (the flagless form of the same answer)

| # | Caller | Verdict | Stamp |
|---|---|---|---|
| D1 | approve `requireHonorableGrants`, anchors fail | HANDLED: prints the anchor note before asking (approve.go:202-204) | READING |
| D2 | approve, resolved nil | Allowed direction per validate-run A4; out of this area | READING |
| D3 | clamp `withholdGateRefused`, anchors fail | HANDLED as far as this area reaches: the shield clamp is skipped (clamp.go:405), the short refusal set is withheld from, and the run the proposal feeds is refused on that host. Whether profile tells the reader the proposal was not shield-clamped is a profile-output question, not gridded here | UNVERIFIED (read profile's render of a failed `commandShieldSet`) |

## Findings, forbidden direction first

1. **B8 WRONG** - embed says "everything else stands" under ShieldsUnknown with CredentialAliases never computed. VERIFIED BY SPIKE.
2. **A4 WRONG** - validate human under Unresolved prints the unqualified "shielded even if a path above would otherwise expose them" footer. VERIFIED BY SPIKE (HOME=relhome, captured output).
3. **B5 UNHANDLED** - validate human under ShieldsUnknown never says the alias scan was skipped. VERIFIED BY SPIKE. Arguably covered by "not checked against them"; the JSON form (B6) names it explicitly, so the forms disagree.
4. **A6 WRONG (documented)** - --strict passes Unresolved while failing ShieldsUnknown on the same "host refuses every run" reasoning. VERIFIED BY SPIKE (unit on `strictRunnableError`). Duplicate of state-grid-validate-run A4.

## Rejections

- `refused_grants` present under ShieldsUnknown (B2): flagged beside it, not a gap.
- Partial suppressed in JSON under ShieldsUnknown: never set there (B11), and `shields_unknown` covers.
- C1 partial note wording missing the off-unix reason: flag still reads as partial; wording only.
- "grants: unknown" hiding a known refusal count (B1): allowed direction.

Inverted dismissals (a spike asserting B2, B3, B6, C1, C2, A5 hold) passed.

## Re-open pass

All three commits are ancestors of 7bc186f, so the grid above already reviewed code after them.

- **9451ea4** (refusals before the ShieldsUnknown return, `refused_grants` under `shields_unknown`) is behind cells B1-B4 being HANDLED. Its row was carried along into the comments on the Runnability field and in Check. It did leave the alias scan skipped (gate.go:141-143), and that is correct: the scan walks the shielded stores and has no set to walk. There was nothing to carry on the computation side. What is missing is the disclosure, which is B5 (human) and B8 (embed). B6 (JSON) carried it: the `shields_unknown` doc names `credential_aliases`.
- **8db0da3** changed "were not checked" to "were not checked against the shields" and left "- everything else stands" untouched (verified with `git show`). So it fixed half the sentence. B8 stays WRONG against the current text.
- **66c8850** (host notes into --json) touches no flag-qualified answer in this grid. No cell moves.

**A6 vs state-grid-candidates.md "Not filed: a `~` grant under an unusable `$HOME` passing strict: a host fault, not the manifest's".** This restates the finding rather than refuting it on attributability. It does add one reason the call is inconsistent: ShieldsUnknown is equally a host fault, and --strict fails on it (validate.go:340-354) because "a run on that host is refused whatever the manifest says". An unusable $HOME refuses the run on the same terms (gate.go:104-108). Either both are host faults that should pass strict, or both should fail it. The earlier rejection didn't weigh that asymmetry, so the decision is the owner's. Not re-marked as a new finding.

**D3 settled: IMPOSSIBLE in practice (READING).** `printProposalWarnings` (profile.go:1254) prints nothing when `commandShieldSet` fails, and clamp.go:405 skips the shield clamp silently, so the code path itself is UNHANDLED. But `clampProposal` only runs after a profiling run completed in a sandbox, and sandbox construction returns the same anchor error on both tiers (validate.go:342-343). The unclamped proposal is reachable only if the anchors break between the profiling run and the clamp, within one environment, since the cache is keyed on os.Environ. Not spiked. A spike would need a seam on commandShieldSet that fails after the run.

**Open beads nearby:** I didn't read bv2-kxv8p, bv2-rw0ae or bv2-ati60 with `bd show`. None of them is a could-not-tell flag in `Runnability` and none maps to a cell here: kxv8p and rw0ae are refusal-set parity, ati60 is stamp-at-risk.

## Re-open, 2026-09-21 - derived carve half

Reviewed against 265a790. New producers: `Runnability.ShieldCarveUnknown` (gate.go:134, set at
gate.go:169) and `RefusalSet`, whose two qualifications `AnchorErr` and `CarveUnknown`
(gate.go:386, 393) are set at gate.go:363-369. `CarveUnknown` comes from
`derivesWorkspaceShields` (gate.go:199-207): any write grant that lands on an existing directory.

**Phase 0:** still a fit. The new flag is a fourth could-not-tell qualifier with the same
consumers, plus a mirror pair (`derivesWorkspaceShields` vs internal/linux `shieldRules`' skip at
shields.go:168). The invariant is unchanged. `gate.Refusals` is no longer flagless, so Grid D's
premise ("carries no flag at all") no longer holds. The rows below replace it for that reason.

Consumers found by grep: validate (H/J/S), approve (`requireHonorableGrants`), clamp
(`withholdGateRefused`, feeding profile), embed. examples/supervise does not import gate at all.

### Grid E - ShieldCarveUnknown / RefusalSet.CarveUnknown

| # | Cell | Verdict | Stamp |
|---|---|---|---|
| E1 | validate human (H) | HANDLED: a note printed beside the grants verdict, not as a switch arm, so it survives real refusals (validate.go:320-326) | EXECUTION (TestEveryRunnabilityFieldReachesTheUser) + SPIKE |
| E2 | validate --json (J) | HANDLED: `shield_carve_unknown` set beside `refused_grants` (validate.go:664, 817) | EXECUTION + SPIKE |
| E3 | validate --strict exit (S) | HANDLED (documented narrowing): passes on carve-unknown alone (validate.go:482-493). The field and the note still reach stdout in both modes. Failing here would refuse most manifests that hold a directory write grant, and the package rules that direction out. The exit code alone is a green over an unknown: see Rejections | SPIKE |
| E4 | embed stderr (E) | HANDLED: note precedes the refusal lines and says "no refusal below covers that" (main.go:297-299) | EXECUTION (TestWriteRunnabilitySurfacesEveryField) |
| E5 | approve, CarveUnknown | HANDLED: note printed before the stamp decision and before the already-approved shortcut (approve.go:216-218, called at approve.go:78, shortcut at :91) | EXECUTION (TestApproveCarriesTheCarveUnknownItsRefusalSetIsShortOf) |
| E6 | clamp/profile, CarveUnknown | HANDLED by deferral: `withholdGateRefused` ignores it on purpose (clamp.go:511-518). Profile makes no completeness claim over the proposal: it lists only what it withheld (profile.go:1409) and sends the reader to validate and approve (profile.go:354), and both of those say it. The clamp doc names the stronger shape as open work: clamp.go already has `workspaceShields` and could settle the half | READING |
| E7 | examples/supervise | IMPOSSIBLE: not a gate consumer (no `/gate"` import outside cmd/bento and examples/embed) | READING |
| E8 | validate/approve summary REFUSED marks and footer | HANDLED: the summary asks `ShieldCarveProblems` directly (validate.go:982) and so has no flag. But its footer claims the shields hold, not that the refusals are complete, and "grants: NO ... marked REFUSED" fires only on a refusal. E1 (validate) and E5 (approve, printed first) carry the qualifier | READING |
| E9 | producer parity: gate raises vs run derives | HANDLED: both ask stat-following is-dir of the landed grant (gate.go:201-203; internal/linux args.go:783-786 via shields.go:168). Over-raising is allowed (coarse, see gate.go:188-196). Dir, symlink-to-dir and relative dir raise; file and missing do not | SPIKE |
| E10 | CarveUnknown x AnchorErr / ShieldsUnknown | IMPOSSIBLE: suppressed when anchorErr != nil (gate.go:367). The larger unknown covers in every form (B1-B4, approve.go:207-209) | SPIKE |
| E11 | CarveUnknown x Unresolved | IMPOSSIBLE: Check returns at gate.go:142-143 before Refusals. approve returns at approve.go:197. A-row covers | SPIKE |
| E12 | approve, AnchorErr (was D1) | HANDLED: now read off the set (approve.go:207-209) instead of a second ask | READING |

### Old cells re-verdicted (the text they judged has changed)

| # | Was | Now | Stamp |
|---|---|---|---|
| A4 | WRONG | HANDLED: the footer has a `resolved == nil` arm saying nothing was checked against the shields (validate.go:1046-1049) | SPIKE (the footer is absent for a nil resolved) |
| A6 | WRONG (documented) | unchanged: `strictRunnableError` still passes Unresolved | SPIKE |
| B5 | UNHANDLED | HANDLED: "no second name for a credential was looked for" (validate.go:305-307) | SPIKE |
| B8 | WRONG | HANDLED: "everything else stands" is gone. The note now says no second name was looked for (main.go:292) | READING |
| D1 | HANDLED | superseded by E12 | READING |
| D3 | IMPOSSIBLE in practice | inherited. The anchor path is untouched: clamp.go:425 still skips silently, and E6 is the carve analogue | inherited |

Re-checked by execution (existing tests green at 265a790): A5, B1-B4, B6, C1, C2, C4 via
TestEveryRunnabilityFieldReachesTheUser and embed's TestWriteRunnabilitySurfacesEveryField.
Inherited without re-check: A1-A3, A7, B7, B9-B11, C3, D2.

### Rejections

- **E3, strict exit green under carve-unknown.** This is the same shape as aliases never
  blocking: an exit-code-only consumer gets no qualifier. It is rejected as a finding because the
  alternative refuses honorable runs, the forbidden direction of the package's own one-sided
  rule, and `shield_carve_unknown` is there for a gate that reads fields. The owner should weigh
  it beside A6, which runs the other way (strict passing a host that refuses every run).
- **E6, the proposal not being carve-clamped over derived shields.** This is the allowed
  direction. The run refuses the grant, and nothing says that it will not. It is already
  disclosed as open work at clamp.go:516-518.

Spikes: gate/zz_spike_test.go and cmd/bento/zz_spike_test.go were written, passed and deleted.
`git status` in the worktree is clean.

### Re-open pass (2026-09-21)

- **ab80ec0** (report the derived carve half unknown) produced the flag and fixed E1, E2 and E4.
  It touched validate and embed only, so its row was not carried to approve and clamp. That gap
  is exactly bv2-x2oae.
- **15347ac** (carry the refusal set's qualifications, which closed bv2-x2oae) carried the row
  to E5 and E12 (approve) and handed both qualifications to clamp. Clamp acts on neither, on
  purpose, so E6 stays open as bv2-rj5ow.
- **71631bf** and **3bc0b2c** are prose only. They are the coarseness text that E9 relies on. No
  cell moves.
- **bv2-rj5ow (open) is E6.** It is the allowed direction, since the run refuses the grant and
  nothing presents the proposal as complete. It is still worth doing: rj5ow's first option (let
  clamp assemble `workspaceShields` into the set) turns the unknown into an answer. That would
  also close the only consumer that neither answers nor prints the flag.
- **bv2-wbrff (open)** is out of the grid. The workdir verdict is not a could-not-tell flag,
  so no cell here depends on it.
- **bv2-iap38 (closed)** is E8's precondition: the carve refusal gets a REFUSED mark in the
  summary (validate.go:982). It is carried and still holds.
- **bv2-rw0ae (closed)** is the opposite axis: strict refuses a carve that the degraded tier
  admits. Its rationale is that strict judges the default tier. That is consistent with E3, and
  no cell moves.
- **bv2-c80hv (closed)** is the owner's decision on A6. A6 stays documented, not re-filed.

**E3 vs A6: no, this is not an inconsistency the invariant forbids.** The two cells do not run
in opposite directions. `--strict` exits green in both. What strict fails on is a single test:
"this host refuses every run" (ShieldsUnknown, validate.go:470-481). Carve-unknown does not meet
that test, because most runs flagged with it succeed. Failing strict there would invent refusals,
which is the direction the gate package rules out, and the qualifier still reaches stdout in both
modes. A6 is the one cell that is out of line with strict's own test: Unresolved also means the
host refuses the run, yet strict passes. That asymmetry is c80hv's recorded decision, and E3
adds nothing to it. No new finding.

Final ledger: 0 WRONG and 0 UNHANDLED among the new cells. A6 remains WRONG (documented,
c80hv), and E6 is tracked by bv2-rj5ow.

Orchestrator correction, 2026-09-21: B4, C1 and C2 were marked re-checked above, but the tests
run never exercise them. They are inherited unverified, like the rest. B4's cite is now
examples/embed/main.go:291-296.
