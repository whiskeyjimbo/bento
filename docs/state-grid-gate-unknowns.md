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
