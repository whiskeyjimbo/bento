# Fuzz oracle audit - bento @ 0abf849

Scope requested: the `policy.Validate` / `policy/match.go` mirror pair. Plus a quick oracle
grade of every other target in the repo.

## Inventory

16 targets in 8 packages. Grade distribution: **PROPERTY 16, STRUCTURAL 0, NONE 0.**
Not one target in this repo is panic-only. That is unusual and it is the headline.

Harness (BY READING - Makefile:52,166-176 and .github/workflows/fuzz.yml):

- Targets are discovered automatically per package via `go test -list='^Fuzz'`, so a new
  target is covered the moment it lands. No hand-maintained list to rot.
- `make fuzz` default FUZZTIME=30s (a build smoke test, correctly excluded from `make check`).
  The nightly workflow runs `make fuzz FUZZTIME=5m`.
- The interesting-input corpus lives in `$GOCACHE/fuzz` and is cached between workflow runs
  with a `fuzz-${os}-` restore prefix, so runs are not cold.
- Crashers are uploaded and land in the package's `testdata/fuzz` as committed regression
  seeds. Five such corpora already exist (manifest, profile, internal/linux x3).
- Findings are converted to SARIF (`cmd/fuzz-sarif`) and uploaded to code scanning.

Budget honesty: 5m/target nightly is a real but modest budget, and it is described as such
in the workflow header. No longer-running continuous fuzzing exists (no OSS-Fuzz, no
ClusterFuzz). For targets whose grammars are small - the policy pair below saturates in
under a minute - 5m is genuinely enough; for `internal/linux/resolve` and the splicers it
is a sampling run, not a search.

## Verdict on the Validate / match pair

**The coverage gap is real. The defect is not.** Neither of the two possible easy answers
is right: it is not "already covered" and it is not "here is a hole".

What the two existing targets do:

- `FuzzPolicyValidation` (policy/policy_adversarial_test.go:443) - **PROPERTY.** Asserts
  Validate/Problems agreement, idempotence, non-mutation, and then a real refusal-side
  oracle on the accepted side: no unsafe rune survives, no empty entrypoint or grant, no
  other user's home, no negative PIDs, and the port must satisfy `wellFormedRulePort`, a
  restatement of the grammar written in the test rather than a call back into the code.
  Textbook. But every assertion is about Validate alone.
- `FuzzPortMatches` (:549) - **PROPERTY, and the strongest in the package.** It restates the
  matcher's *lenient* port grammar (`lenientPortNum`, deliberately looser than the rule-side
  `canonicalPortNum`), asserts both directions of the range branch, and - the part that
  matters here - asserts `PortMatches(pattern, port) == Allows(rule{Port: pattern}, ..., port)`.
  So the port half of the pair *is* cross-asserted: the resolved-IP guard and the ordinary
  egress path cannot part ways on a port.

So the gap is narrower than the grid doc's row 28 states, and also wider:

- Narrower: the port axis is already covered, by `FuzzPortMatches`' `Allows` cross-check.
- Wider: **nothing at all cross-asserts the host axis.** `matchHost` has no reference
  implementation anywhere, and match.go's own comments state four invariants that no fuzz
  target asserts: `.suffix` must not reach the apex (match.go:76-78), a v4-mapped target must
  not match a v4 rule (:84-89), the fold is ASCII-only so U+212A must not reach an ASCII rule
  (match.go:51-57 on `normalizeHost`), and the NUL-truncation precondition (policy/match.go:20-26).

### Spike 1 - the property the task named

`policy/zz_spike_fuzz_test.go` (deleted): for every `(host, port)` pair `NetworkRule.Validate`
accepts, build the witness target the rule is written to authorize (`*` -> a hostname,
`.suffix` -> `sub` + suffix, literal -> itself; `*` -> 443, range -> its low bound) and assert
`Allows` admits it. This is "Validate must never accept a rule the matcher cannot match as
written", stated as non-vacuity.

Ran: `GOWORK=off go test -run='^$' -fuzz='^FuzzValidateAcceptsOnlyMatchableRules$'
-fuzztime=90s ./policy/`. **PASS, 7,784,412 execs, 310 new interesting inputs, no crasher.**
STAMP: **VERIFIED BY SPIKE.** The property holds today, and it holds by construction:
`validateHostPattern` refuses exactly the spellings the matcher could not match - a suffix
wildcard over an IP (documented at policy.go:505-510 in precisely these terms), non-canonical
IP shorthand, and a bare dot - and `parsePortNum` refuses `"+443"`/`"08080"` for the same
stated reason ("a silently dead allowlist entry"). Someone already reasoned this pair through
in prose; nobody wrote the assertion down.

### Spike 2 - the host-side invariants

`policy/zz_spike2_fuzz_test.go` (deleted): a differential against a reference restatement of
matchHost's three-case grammar, gated on `validateHostPattern(pattern) == nil` (the matcher's
stated precondition), plus the apex, v4-mapped and ASCII-fold invariants as separate
assertions. Ran at `-fuzztime=90s`: **PASS, 8,521,700 execs, 60 new interesting.**
STAMP: **VERIFIED BY SPIKE.** All four hold.

Two things the spike taught about oracle shape, both worth carrying into the permanent target:

1. Without the `validateHostPattern` precondition gate, the apex assertion fires immediately
   on pattern `"."` against host `""` (`matchHost` treats `"."` as a suffix pattern that
   normalizes to `""` and suffix-matches everything). Validate refuses `"."`, so this is not
   a defect - it is proof the precondition in match.go:17-19 is load-bearing rather than
   decorative, and an oracle that omits it grades the wrong function.
   STAMP: **VERIFIED BY SPIKE** (crasher reproduced, then reclassified, corpus file deleted).
2. `normalizeHost` is **not idempotent** on a doubled trailing dot: `normalizeHost("A..")` is
   `"a."`, and normalizing again gives `"a"`. A naive idempotence assertion fires here. It is
   not a hole and it is already known: internal/proxy/proxy.go:1088-1098 documents that the
   CONNECT screen strips exactly one label "as normalizeHost strips one", that a doubled dot
   survives both, and that the divergence is safe because `net.ParseIP` rejects the remaining
   dot so no IP grant can outlive it. The permanent target should therefore **not** assert
   idempotence of `normalizeHost`; it would be asserting a property the design deliberately
   does not have. STAMP: **VERIFIED BY SPIKE**, cause **VERIFIED BY READING**.

### What the missing target should assert

One target, `FuzzValidatedRuleMatchesItsOwnWitness` in package `policy`, signature
`(host, port string)`:

1. `if r.Validate() != nil { return }` - the matcher's documented precondition.
2. **Non-vacuity (the named property):** the witness target built from the rule is admitted by
   `Allows`. A rule that validates and authorizes nothing is a dead allowlist entry, which is
   the failure both files' comments say they are avoiding.
3. **Both range bounds and the apex pair, not just one witness** - costs nothing: assert the
   range's `lo` and `hi` are both admitted and `lo-1`/`hi+1` are not; assert `.suffix` admits
   `sub.suffix` and refuses the bare apex.
4. **Host differential:** a three-case reference restatement of matchHost in the test, the way
   `wellFormedRulePort` and `lenientPortNum` already restate the port grammars. This is the
   piece with no counterpart today.
5. **The three stated host invariants** as named assertions, so each of match.go's prose
   guarantees has a test that fails when it stops holding: no ASCII rule reached by a
   non-ASCII target, no v4 rule reached by a v4-mapped target, no suffix rule reaching its apex.

Seed the corpus from the spellings the grid row cares about: `("*","*")`, `(".example.com","80-90")`,
`("10.0.0.1","443")`, `("::1","443")`, `("API.Example.COM","443")`, `("xn--bcher-kva.example","1-65535")`.

For `state-grid`: row 5 / row 28 in docs/state-grid-candidates.md can be closed as a
fuzz-oracle item, not a grid. The space is two small grammars crossed, it saturates in a
minute of fuzzing, and the invariant was already written in prose - which is the condition
under which the skill says fuzz rather than grid.

## Per-target grades - the rest of the repo

Read in full by me: `policy/policy_adversarial_test.go` (both targets), `policy/match.go`,
`policy/policy.go`, the Makefile and fuzz workflow, and internal/proxy/proxy.go around the
CONNECT screen. The twelve grades below came from a delegated full read of each file; I did
not re-read those bodies myself, so they are one confidence level weaker than the policy
findings. STAMP for this section: **VERIFIED BY READING** (delegated).

- `internal/denylist` `FuzzCoversAgreesWithIndex` - **PROPERTY.** Differential, linear `Covers`
  vs `NewIndex().Covers`, verdict and Deny/Dir compared. 12 varied adversarial seeds. Note the
  harness drops unclean/relative rule lines (documented, pinned by a separate test), which
  narrows the rule side but not the query side.
- `internal/launcher` `FuzzLaunchCodecRoundTrip` - **PROPERTY.** Encode/decode round-trip over
  every Config field including repeated-flag lists. Seeds include flag-lookalike paths.
- `internal/launcher` `FuzzLaunchDegradedCodecRoundTrip` - **PROPERTY.** Same round-trip over
  DegradedConfig's four repeated flags sharing one namespace.
- `internal/launcher` `FuzzDecodeLaunchNarrowsExec` - **PROPERTY.** Refusal-side: a decode that
  yields `!Block` must have been asked for it in the argv. Necessary-not-sufficient, and says so.
- `internal/linux` `FuzzParseAppliedNeverOverClaims` - **PROPERTY, one of the strongest.**
  Corruption spliced into well-formed bases; asserts a per-layer severity floor (corruption may
  never improve a verdict) plus a byte-counted bound on recorded runs. Positive control test
  guards vacuity.
- `internal/linux` `FuzzParseObservationsNeverOverClaims` - **PROPERTY.** Same shape over the
  observation report: any count that rose, or flag that flipped true, must be named by the bytes
  before the marker. Silent on losses, by design.
- `internal/linux` `FuzzPersistenceShieldsCoverReachableSurfaces` - **PROPERTY.** Security
  invariant over a real planted checkout, with ground truth recorded at plant time and a
  refusal-side coupling (`(err != nil) == coveredBy(...)`) that blocks vacuity.
- `internal/linux` `FuzzShieldCoversReachableSecrets` - **PROPERTY.** Two couplings to an
  independent ground-truth function plus both shield properties. Exhaustive companion test
  covers the finite axis - exactly the "enumerate small, fuzz large" shape.
- `internal/linux` `FuzzResolveSymlinkTree` - **PROPERTY, the best in the repo.** Differential
  against the kernel's own resolution, plus a fixed-point check, loop-aware. Structure-blind
  `[]byte` but the decoder is total, so there is no fuzz blocker.
- `internal/proxy` `FuzzNAT64DiscoveryOnlyNarrows` - **PROPERTY.** Narrowing invariant
  (discovery may never reclassify a non-public address as public) with positive teeth. DNS is a
  fake, so the real resolver path is not reached - documented, and the typed signature is a
  deliberate choice to beat the "derives no prefix two thirds of the time" blocker.
- `internal/proxy` `FuzzReadConnect` - **PROPERTY.** Refusal-side: anything accepted must be
  renderable (valid UTF-8, no deceiving rune). 13 strong adversarial seeds.
- `internal/proxy` `FuzzClassifyIPIsRenderingAgnostic` - **PROPERTY, weakest of the three.**
  Agreement among renderings only; blind to a hole that moves all renderings together, and says so.
- `internal/proxy` `FuzzGuardUpstreamRefusesNonPublicRenderings` - **PROPERTY.** Oracle phrased
  against an independent prefix table rather than against `classifyIP`, with an allow-side
  positive control so a guard broken shut also fails.
- `manifest` `FuzzParseManifest` - **PROPERTY, weakest per unit of budget.** The live half is
  error-text terminal safety, which does bite on random bytes. The success branch is near
  unreachable: structure-blind `[]byte` against YAML. The file states this and adds the typed
  target below, which is the right remedy.
- `manifest` `FuzzManifestRoundTrip` - **PROPERTY.** Marshal then Parse, `DeepEqual` on the
  policy, with Marshal's refusal aligned to Validate's. Pins a shipped regression.
- `profile` `FuzzProfileSynthesize` - **PROPERTY.** Narrowing (no grant wider than the
  observation), cross-component agreement with `Validate` (a proposal must be approvable), and
  idempotence.
- `trust` `FuzzParseAccountsRefusesCompat` - **PROPERTY.** Biconditional, so "refuses
  everything" fails too.
- `trust` `FuzzParseAccountsMembershipIsMonotone` - **PROPERTY.** Growth is append-only, asserted
  as a literal prefix.

## Packages with unbounded input and no target

Ranked by oracle availability, not by scariness. STAMP: **VERIFIED BY READING** (delegated).

1. **`internal/observe`** - CLOSED. `FuzzExecImageDecode`
   (internal/observe/execimage_fuzz_linux_amd64_test.go) now covers `execImage` /
   `execImageChain`, with both oracles this entry named: a differential against
   `refShebangImage`, a restatement of binfmt_script's decode written in the test, and the
   chain's bound plus `complete` as a narrowing invariant (complete implies every named path
   is absolute and really appears in the bytes it was decoded from). The reference is itself
   pinned to the kernel by `TestBinfmtReferenceMatchesTheKernel`, which execs ten hand-built
   scripts with chosen interpreters - the fuzz target never execs its input, because the
   fuzzer reaches `#!/bin/sh` within seconds and running one would hand it a shell.
   `TestImageDecodeOracleRejectsAWrongAnswer` is the positive control. The two sides of the
   differential are necessarily the same small algorithm, so its value comes from the exec
   table holding the reference to the kernel, not from independence - and the third defect
   below was a blind spot shared by both sides until that table grew a case for it.

   **The gap was a defect, not just missing coverage.** The seed corpus alone found two
   divergences from binfmt_script, both confirmed by exec: `#!/bin/true\x00junk` was decoded
   as the name `/bin/true\x00junk` (the kernel's name is a C string and ends at the NUL, and
   the openat2 of the NUL-bearing name then failed EINVAL, counting a drop against a file the
   kernel opened fine); and `#!/bin/sh\rx` was decoded as `/bin/sh` and reported COMPLETE,
   because `strings.Fields` splits on unicode whitespace while the kernel splits on space and
   tab alone - the kernel opened `/bin/sh\rx`, found nothing, and the manifest would have
   named an interpreter the run never touched. A third, found by the review that followed:
   with no newline in the 256-byte buffer the kernel still ends the name at the first space
   or tab and execs it, and only a buffer holding none of newline, NUL, space or tab is the
   ENOEXEC case - `#!/bin/echo ` followed by 300 filler bytes runs `/bin/echo`, where the
   decoder reported a lost observation. Conservative rather than wrong (a spurious drop, not
   a false complete), but it is a drop against a file the kernel opened. All three fixed in
   the same change.
   STAMP: **VERIFIED BY SPIKE** (both reproduced by exec, red on the seeds, green after).
2. **`gate`** - `Check` and eleven `*Problems` predicates, no target. The oracle is already
   written by hand: `TestShieldedGrantProblemsMirrorTheRunsRefusals` asserts gate-vs-`internal/linux`
   agreement over a table. A fuzzer generalises that table directly, and this is a second mirror
   pair of exactly the shape the scoped one turned out to be.
3. **`internal/denylist/audit`** - two third-party text-profile parsers (`ParseAppArmor`,
   `ParseFirejail`) plus `SplitByScope`, which is a total partition and therefore free to assert
   (in + out equals input, no duplicates, idempotent).
4. **`internal/credhunt`** - `TestIndexedHuntMatchesLinear` is already the
   `FuzzCoversAgreesWithIndex` differential, written as a table. Promote it.
5. **`internal/grantrefusal`** - 14 error constructors rendering attacker-influenced paths into
   operator-facing text. The terminal-safety property `FuzzParseManifest` already asserts applies
   verbatim; a ten-line target.
6. **`internal/pathresolve`** - `Existing` is fuzzed, but from `internal/linux`. Fine as is.
7. **`internal/landlock`, `internal/seccomp`, `internal/i386`, `backend`, `cmd/*`** - no cheap
   in-process oracle (process-global kernel effects, or thin dispatch over an already-fuzzed
   codec). Do not add panic-only targets here. If `internal/seccomp`'s argv0 validation is worth
   covering, that one predicate is fuzzable; the filters are not.

## Findings, stamped

| # | Finding | Stamp |
|---|---|---|
| 1 | Nothing cross-asserts Validate against the matcher; the port half is covered by `FuzzPortMatches`' `Allows` check, the host half by nothing | VERIFIED BY READING |
| 2 | The non-vacuity property holds: no validated rule is unmatchable. 7,784,412 execs, PASS | VERIFIED BY SPIKE |
| 3 | matchHost's three stated host invariants (apex, v4-mapped, ASCII fold) all hold under a differential. 8,521,700 execs, PASS | VERIFIED BY SPIKE |
| 4 | An oracle that omits the `validateHostPattern` precondition fires on pattern `"."` - the precondition is load-bearing, not decorative | VERIFIED BY SPIKE |
| 5 | `normalizeHost` is not idempotent on a doubled trailing dot; safe, known, documented at proxy.go:1088. An idempotence oracle here would be wrong | VERIFIED BY SPIKE + BY READING |
| 6 | 16 targets, zero NONE or STRUCTURAL; 5 ship an explicit positive control or exhaustive companion | VERIFIED BY READING (delegated) |
| 7 | Harness: auto-discovery, 30s local / 5m nightly, corpus cached in GOCACHE, crashers committed as seeds, SARIF upload | VERIFIED BY READING |
| 8 | `internal/observe` has no target and has an oracle (kernel binfmt differential + chain narrowing) - since ADDED as `FuzzExecImageDecode`, and it found two real binfmt divergences on its seeds | VERIFIED BY SPIKE |
| 9 | `gate` has no target and its oracle is already written as a table test | VERIFIED BY READING (delegated) |
| 10 | Whether a 5m nightly budget is adequate for the splicer and resolve targets | UNVERIFIED - would need a long run and a coverage comparison |
| 11 | Whether `internal/landlock` / `internal/seccomp` filters admit anything a fuzzer could find | UNSPIKEABLE HERE - installs process-global kernel state |

Cleanup: both spike files deleted, the two corpus files the spikes produced under
`policy/testdata/fuzz` deleted (neither proved a defect), `git status --porcelain` empty.
