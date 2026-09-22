# perf-hunt - merged findings across four grids

Measured at `9f80de6` on `perf/shield-rule-cost`. Four measurers, one per path; each grid
is its own file. Candidate census and ranking in `perf-hunt-candidates.md`.

- `perf-grid-probe-limits.md` - per-run probe and limits preflight
- `perf-grid-shield.md` - shield derivation and verdict
- `perf-grid-gate-alias.md` - gate credential-alias walk
- `perf-grid-denylist.md` - denylist rule construction and coverage

No fixes applied. Wall time deliberately not taken anywhere: the four measurers shared one
machine, so only counts (execs, syscalls, allocs, filesystem ops) are trustworthy here.
Each finding below needs a serialized before/after when it is fixed.

## The cross-cutting result

Three of the four grids independently found the same shape: **a memo exists, and a sibling
call site computing the identical value does not consult it.** Not a missing optimization -
an optimization that was landed once and not carried across its row.

- `shield`: `e9f2682` memoized resolve-per-rule into `s.targets` (`rules.go:156`), consulted
  only at `rules.go:211`; `verdict.go:179` and `:230` recompute it in a loop.
- `shield`: `e1ce786`'s `shieldRulesCache` covers `denyArgs`/`createdShields`; the two grant
  checks build the same rules and miss it.
- `probe`: `cacheProbe` (`limits.go:63`) memoizes the limits half of `Probe`;
  `usableNamespaces` (`probe.go:69`) has no memo, so the second `Probe` per run pays a full
  bwrap fork+exec.
- `denylist`: `policy.CoversResolved` carries a comment refusing the allocating
  `HasPrefix(p, r.Path+sep)` spelling (`8607323`); `insideDenyAllTree:1698` and
  `underDenyAll:1714` both still spell it that way.

The per-path grids each ranked this shape first or second on their own evidence. That is
the argument for gridding rather than profiling: a profiler shows the site that is hot on
today's input, and the fix lands there and stops.

## Unguarded invariants

`AllocsPerRun` appears **zero** times in this repository (verified tree-wide). Every
allocation property a prior perf commit established - `CoversResolved`'s zero-alloc
guarantee among them - is currently held by nobody and regresses silently. This is why
Phase 4 requires the count test in the same commit as the fix.

## Instrument gaps found

- Nothing benchmarks `shield.Set.Contains` - the hottest cell measured anywhere in this hunt.
- Nothing benchmarks `aliasableCredentials` - the uncapped half of the gate walk.
- Nothing benchmarks `denylist.Relocated` - the most expensive construction stage.
- Nothing reaches the probe/limits path at all.
- `BenchmarkWorkspaceShieldWalk` (`shield_scale_test.go`) does not measure what it claims:
  `nestedCheckouts`/`projectConfig` are nil so the dominant cell sits outside it,
  `shieldCache` is nil in both arms so the memo delta is contaminated, and `homes` is
  `/home/u`, absent on the runner.
- No benchmark in the repo runs at two input sizes, so no existing instrument can fail on a
  scaling change.

## Trap for Phase 4, from the shield grid

The shield measurer first labelled its findings 2-4 quadratic off a pathological column
that varied grants, nested checkouts and rule count together. A grant-isolated sweep showed
all three are **linear in grants with a per-grant constant equal to the whole rule set**.
Consequence: a red-first scaling test that varies grant count alone draws a straight line
and reads as healthy. It has to vary the rule count too.

## Findings, merged and ranked

Rank is scaling-on-a-hot-path first, then constant-on-a-hot-path by magnitude.

| # | Finding | Class | file:line | Measured |
|---|---------|-------|-----------|----------|
| 1 | **The budget does not bound the scan.** Two halves, neither bounded: `aliasableCredentials` takes no budget at all and the `len(want)==0` fast return sits downstream of its walk; and the grant walk's shared allowance is charged for roots already visited, because dedup is exact-root equality | scaling, unbounded | `gate/alias_unix.go:143`, walk at `:197`, fast return at `:77`, dedup at `:88` | 61,486 lstats in one `Check` on a 60k-entry anchor, 20% past `aliasBudget`, returning `want=0`; nested grant charged another 202 entries already visited |
| 2 | The `Relocated` screen is O(defaults²) with an allocating inner loop, quadratic in the `Home` table | scaling | `denylist.go:1686` | **doubling the defaults raised allocs 2.76x with emitted count held flat** - the controlled result, no env dependence. Illustration only: 27,540 allocs on the measurer's dev env vs 110 on an empty one, which depends on which relocation vars that box had set |
| 3 | `Contains` re-resolves every rule per write verdict, ignoring the assembly-time memo | constant, hot | `verdict.go:179`, `:230` vs `rules.go:156` | 2,654 syscalls per call, ~8 calls per write grant ≈ 21k syscalls/grant |
| 4 | `Probe` runs twice per run from identical inputs; the namespace half is unmemoized | repeat | `enforce/run.go:152` + `internal/linux/linux.go:116`; `probe.go:69` | a full bwrap fork+exec plus namespace build/teardown, every run |
| 5 | A zero-limits manifest probes scope creation for a reading nothing reads | constant, hot | `probe.go:97-116` vs `run.go:461` | 7 execs + 2 D-Bus round trips; with #4, 9 of 14 execs on a zero-limits run are avoidable |
| 6 | `checkWriteNotUnderReadOnlyShield` re-resolves rules in force plus workspace rules per grant | constant, hot | `grants.go:174`, `:177`, `verdict.go:157` | 308,544 resolves at G=64/N=96/C=512 |
| 7 | Both denylist screens hand-roll the allocating prefix idiom this repo already fixed | constant, hot | `denylist.go:1698`, `:1714` | `Covers` 0 allocs vs 52 each, same 537-rule table |
| 8 | `shieldRules` resolves once per (grant × rule in force) | constant, hot | `shields.go:208`, `:243` | 154,845 resolves at the pathological size |
| 9 | `checkWorkspaceShieldNotRedirected` derives per grant *before* the dedup decides whether to test | constant, hot | `grants.go:222` vs `:223` | 103,758 resolves |
| 10 | `Contains` allocates on the common path: `Clean` + two `Split` per rule failing the byte test | constant, hot | `verdict.go:303` | 16,583 allocs per write verdict, 1,408 per read |
| 11 | `effectiveABI` uncached | constant | `internal/landlock` | 12 `landlock_create_ruleset` per `Probe`, should be 2 |
| 12 | `pathresolve.Existing` unmemoized across anchors, grants, rules | constant | `gate/alias_unix.go:87`, `:161`, `:172`, `gate/gate.go:199` | 107 resolves per `Check` = 735 syscalls, 3,393 allocs |
| 14 | `clamp.go` rebuilds `denylist.Home(root)` inside a per-grant loop | repeat | `cmd/bento/clamp.go:346` | 538 allocs per rebuild |
| 15 | `bento profile` redoes `resolveBwrap`'s trust walk after `Probe` | repeat | `cmd/bento/profile.go:484` + `:65` | the other three call sites are memoized |

## Correctness findings surfaced by the perf grids

These are not perf items and should be filed as their own work.

- **One alias allowance, spent in grant order** (`gate/alias_unix.go:86`, `:92`). With the
  budget spent, a real hardlinked alias under a later read grant returns `found=0,
  stopped=true` - on disk, granted, invisible. `CredentialAliasesPartial` does reach the
  operator (`cmd/bento/validate.go:354`), so it is not a silent clean bill, but one boolean
  cannot say which grants went unlooked-at, and coverage is order-dependent rather than
  proportional. The double-charging half of finding 1 makes it worse by spending the
  allowance on entries already seen.

Why these two halves are one item and not two: both are "the budget does not bound the
scan". Filed apart, the dedup gets fixed, the item closes green, and the unbounded anchor
walk survives behind that checkmark - the carried-row failure this whole hunt exists to
find, reproduced in the filing.
- **The unhealthy-systemd cell is the worst on the probe path and invisible on a healthy
  machine.** `cacheProbe` deliberately does not memoize a non-answer, so on a busy or
  restarting user manager the whole limits probe repeats per `Probe` - finding 5's 7 wasted
  execs become 14 per run, plus a bare canary, against a 5s timeout.

## Explicitly not to be "fixed"

- **The per-directory device prune in the gate walk.** `getdents64` returns `d_type` and
  `d_ino` but never `d_dev`, so `identify` is not re-fetching something the walk already
  had. It is ~1% of lstats and can skip whole subtrees.
- **The provenance walk's repeated resolution** (`trustLauncherPath`). It is a security
  check; memoizing changes when a planted binary is noticed. Needs a decision about the
  window, not a cache.

## Left unmeasured

- Wall time, everywhere. Serialize before claiming any speedup.
- Degraded tier and userns-blocked hosts (not reproducible here).
- Cold page cache (shared machine; the gate docstring's "15.7s cold" remains untested).
- `dirEnvs` anchors pointed at arbitrary absolute paths (`GNUPGHOME=/srv/keys`,
  `denylist.go:2016`) - structurally finding 1 with no home-shaped bound at all. Read from
  code, not measured.
- `cmd/bento/clamp.go`'s `Contains` call sites (`:99`, `:131`, ~2,160 resolves per write
  grant with no `shieldCache`, plus an unmemoized `Assemble` at `:566`) - read, not
  measured, so treat those numbers as derived.
