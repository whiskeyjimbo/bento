# Perf grid - shield derivation and verdict

Base commit: **9f80de6** (`perf/shield-rule-cost`), measured in a detached worktree at that
SHA. Counts only - allocations and FS-seam operations (`shield.FS`, `sandbox.resolve`) plus
one strace syscall count. No wall-time medians: three measurers ran concurrently on this
machine.

**Provisioning note:** this measurer's worktree was checked out at **80f0799**, not at the
`9f80de6` the task named. It was detached to `9f80de6` before any number below was taken,
and the shield-package counts were re-run there and came out identical (verdict.go is
untouched by the six perf commits). Any sibling measurer provisioned the same way is
reporting numbers from the wrong tree unless it checked.

Instrumentation: a counting wrapper around `shield.Host()` (`shield.FS` is the seam the
package was designed with) and a counting `sandbox.resolve`. Both were throwaway test files,
deleted after measuring.

## Invariant

Each stage's cost is bounded by a known function of its input, and the per-unit constant is
what the design needs and no more. Symbols: **G** write grants, **R** assembled rules
(540 on the measured host), **W** workspace rules passed to a verdict, **N** nested
checkouts, **C** project config entries, **D** path depth, **E** credential-store entries.

## Scales measured

| axis | minimal | typical | pathological |
|---|---|---|---|
| grants G | 1 | 4 | 64 |
| nested checkouts N | 0 | 2 | 96 (`maxNestedCheckouts`) |
| project config C | 0 | 2 | 512 (`maxProjectConfig`) |
| path depth D | 1 | 4 | 40 |
| store entries E | 0 | 8 | 256 |
| assembled rules R | 540 | 540 | 540 (fixed by `denylist`) |

## How often each stage runs per top-level operation

`checkGrants` runs **twice** per full-tier run (`args.go:289` compile, `linux.go:750`
launch); once on the degraded tier (`degraded.go:56`). Per pass a write grant gets **4**
`Set.Contains` calls (`checkWriteNotShielded`, `checkWriteNotUnderReadOnlyShield`,
`checkWriteNotAboveShield`, and on the degraded tier `checkWriteNotAboveWriteShield`), so
**8 Contains per write grant per run**. A read grant gets 1 per pass.

| stage | file:line | runs / top-level op | memoized? |
|---|---|---|---|
| `shield.Assemble` | `shield/rules.go:88` | ~10 call sites, **1** walk | yes, `shieldCache` (unkeyed, per run) |
| `Set.Mount` / `target` | `shield/rules.go:205,240` | per derivation | yes, `s.targets` (e9f2682) |
| `Set.Contains` | `shield/verdict.go:98` | **8 per write grant** | **no** |
| `FoldedWorkspaceShields` | `shield/verdict.go:259` | 1 per write grant | no (cheap) |
| `OptIns` | `shield/verdict.go:403` | ~4 per run | no |
| `findWorkspaceEntries` | `linux/shields.go:255` | 1 per resolved write grant | yes, `nestedCheckouts`/`projectConfig` |
| `workspaceShields` | `linux/shields.go:324` | ≥6 per grant | yes, `workspaceShieldCache` |
| `shieldRules` | `linux/shields.go:162` | 2 (denyArgs, createdShields) | yes, `shieldRulesCache` (e1ce786) |
| `derivedWorkspaceRules` | `linux/shields.go:220` | **per grant, in 3 callers** | **no** |

The **clamp** caller (`cmd/bento`) is a second consumer of the same two stages and is not
memoized by the sandbox at all:

| clamp stage | file:line | runs / top-level op | cost |
|---|---|---|---|
| `clampShieldedGrants` drop probe | `clamp.go:56` | 2 per grant (both spellings), **Read** kind | 0 resolves |
| `clampWriteShieldedGrants` | `clamp.go:99` | 2 per write grant, **Write** kind + workspace | **2 × (R + W) resolves** |
| `aboveWriteShieldGrants` | `clamp.go:131` | 2 per write grant, **Write** kind | **2 × R resolves** |
| `workspaceShieldSet` → `shield.Assemble` | `clamp.go:566` | 1 extra full assembly on the `CarveUnknown` path | R resolves + the store walk, **no memo** |

So the clamp pays roughly **4 × 540 ≈ 2,160 resolves (~10,600 syscalls) per write grant** on
top of the backend's 8 - the same finding-1 cost, at a second call site, with no `shieldCache`
behind it. `cmd/bento` was not measured directly (only read); the counts above are the
backend's per-call numbers multiplied by the clamp's own call structure.

## Grid - measured cells

`resolve` = calls to the path-resolution seam. Each one is a real
`pathresolve.Existing`: **~4.9 syscalls per resolve** measured (below), so resolve counts
are syscall counts divided by ~5.

### A. Assembly (shield package, counting FS)

| stage | minimal | typical | patho | complexity | verdict |
|---|---|---|---|---|---|
| Assemble: resolve | 541 | 541 | 541 | O(R) | **ok** |
| Assemble: isDir | 152 | 160 | 408 | O(R + E) | **ok** |
| Assemble: listDir | 3 | 11 | 259 | O(E) | **ok** |
| Assemble: sameFile | 0 | 0 | 0 | O(1) | **ok** |
| `Mount` on the assembled set | 0 resolves (memo hit) | " | " | O(1) per known rule | **ok** (fixed by e9f2682) |

### B. Verdict (`Set.Contains`, one call, one grant)

| cost | minimal | typical | patho | complexity | verdict |
|---|---|---|---|---|---|
| resolve, **write** kind | **540** | **540** | **540** | **O(R) per call** | **scaling - worst cell** |
| resolve, **read** kind | 0 | 0 | 0 | O(1) | ok |
| sameFile | 0 | 0 | 0 | O(1) unless the host folds | ok |
| allocs, write | - | **16,583** | - | O(R) | **constant** |
| allocs, read | - | **1,408** | - | O(R) | **constant** |
| syscalls, write (strace, ~D=6) | - | **2,654** (2,005 `newfstatat` + 649 `readlinkat`) | - | O(R·D) | **scaling** |

Scaled to a run: **8 Contains per write grant × 2,654 ≈ 21,000 syscalls per write grant**,
before any workspace rules. Measured G-scaling of the 4-calls-per-pass shape:

| | G=1 | G=4 | G=64 |
|---|---|---|---|
| resolves, 4×Contains per grant | 2,160 | 8,640 | **138,240** |
| resolves, 1×Contains per grant with workspace W=4G | 544 | 2,224 | **50,944** |

### C. Verdict, workspace half and opt-ins

| stage | minimal | typical | patho | complexity | verdict |
|---|---|---|---|---|---|
| `FoldedWorkspaceShields` resolve | 4 (W=4) | 16 (W=16) | 256 (W=256) | O(W) | ok |
| `FoldedWorkspaceShields` sameFile | 4 | 16 | 256 | O(W) | **constant** - one `SameFile` syscall per workspace rule even where no name can fold |
| `Contains` workspace loop (`verdict.go:157`) | +4 | +16 | +256 per call | O(W) per call, uncached | **constant** |
| `OptIns` resolve | 1 | 1 | 1 | O(matches) | ok |
| `OptIns` allocs | - | 16 | - | O(matches) | ok |
| `OptIns` scan | R×reads `slices.Contains` | | | O(R·reads), no syscalls | ok at these sizes |

### D. Derivation (internal/linux, counting `sandbox.resolve`)

The pathological column below varies G, N and C together, so it does not isolate the G
exponent. A second sweep varying **G alone** with N=C=2 settles it - see section E.

| stage | G=1 / N=0 / C=0 | G=4 / N=2 / C=2 | G=64 / N=96 / C=512 | complexity | verdict |
|---|---|---|---|---|---|
| `findWorkspaceEntries` | walk, 0 nested | 2 nested + 2 config | 96 nested + 512 config | O(tree) once per grant | ok |
| `shieldRules` resolves | 542 | 2,881 | **154,845** | **O(G·(R+W))** - 154,845/64 ≈ 2,419 = one resolve per rule in force, per grant | **constant (severe)** |
| `derivedWorkspaceRules`, one call | 1 | 571 | 2,397 | O(R + C + N) per call | ok per call, **but called per grant** |
| `checkWriteNotUnderReadOnlyShield` | 555 | 4,676 | **308,544** | **O(G·(R+W))** - per grant it re-resolves every rule in force and every workspace rule | **constant (severe) - second-worst cell** |
| `checkWorkspaceShieldNotRedirected` | 15 | 2,306 | **103,758** | **O(G·(R+W))** - `slices.Concat(shields(sb).Rules(), ws)` then a fresh `derivedWorkspaceRules` per grant | **constant (severe)** |
| `foldedWorkspaceExposure` | 14 | 56 | 896 | O(G·W/G) = O(W) | ok |

### E. G isolated (N=C=2 fixed, R=584, W small)

| stage | G=1 | G=4 | G=16 | G=64 | per grant | complexity |
|---|---|---|---|---|---|---|
| `shieldRules` | 1,126 | 2,881 | 9,901 | 37,981 | 1126 → 593 | linear in G, constant ≈ R |
| `checkWriteNotUnderReadOnlyShield` | 1,169 | 4,676 | 18,704 | 74,816 | **1,169 flat** | exactly linear in G |
| `checkWorkspaceShieldNotRedirected` | 629 | 2,306 | 9,014 | 35,846 | 629 → 560 | linear in G, constant ≈ R |

So none of the three is quadratic in G. Each is **linear in G with a per-grant constant
equal to the whole rule set in force**. The patho column's 308k is G × (R + W) with W ≈
1,856 derived rules - the second factor is driven by N and C, not by G. A red-first scaling
test must therefore vary **N and C** (or the rule count) as well as G; a G-only sweep
reproduces a straight line and would read as healthy.

### Syscalls per resolve (strace, `newfstatat`/`readlinkat`/`openat`)

One `Set.Contains(write)` at D=6 on a 540-rule set: 2,005 `newfstatat` + 649 `readlinkat`
= 2,654 syscalls. 2,654 / 540 resolves ≈ **4.9 syscalls per resolve**.

## Findings, ranked

**1. `Contains` resolves every rule on every write verdict.** (Class: **constant**, not
scaling - consulting all R rules is the right shape; resolving each one is the needless
per-unit cost. Ranked first on magnitude at *typical* size, not on growth.) `verdict.go:179` and
`verdict.go:230` compute `filepath.Join(s.fs.Resolve(filepath.Dir(a.Rule.Path)), ...)` inside
the loop over `s.applied`. The value depends only on the rule's own path, which is fixed at
assembly, yet it is recomputed 540 times per call and the call happens 8 times per write
grant: **~21,000 syscalls per write grant**, 138,240 resolves at 64 grants. Read verdicts
cost 0, which is the control showing the cost is avoidable.
*Cause:* `internal/shield/verdict.go:179`, `internal/shield/verdict.go:230`.

**2. `checkWriteNotUnderReadOnlyShield` re-resolves every rule in force, per grant.**
`internal/linux/grants.go:169-175` accumulates `workspace` across all grants, then
`grants.go:177` asks `Contains` once per grant against the whole accumulated list, and
`verdict.go:157` resolves each workspace rule on every one of those calls. 308,544 resolves
at G=64/N=96/C=512. Isolated: 1,169 resolves **per grant**, flat, so the growth is linear in
G and linear in (R + W) - the blow-up comes from the per-grant constant being the entire
rule set, not from a quadratic in G.
*Cause:* `internal/linux/grants.go:174`, `internal/linux/grants.go:177`,
`internal/shield/verdict.go:157`. Verified against the base SHA.

**3. `shieldRules` pays one resolve per rule in force, per grant.** `derivedWorkspaceRules`
(`linux/shields.go:220`) returns early when a grant holds no findings, but where it does not,
`accept(above...)` (`shields.go:243`) resolves every rule already in force - and `shieldRules`
calls it per grant with an `above` that grows as rules are appended. 154,845 resolves at
G=64, ≈ one per (grant × final rule).
*Cause:* `internal/linux/shields.go:208`, `internal/linux/shields.go:243`. Isolated G-sweep:
1,126 → 593 resolves per grant, converging on R.

**4. `checkWorkspaceShieldNotRedirected` rebuilds the derivation per grant.**
Verified at the base SHA: `grants.go:222` calls
`derivedWorkspaceRules(sb, w, slices.Concat(shields(sb).Rules(), ws), nested)` **for every
grant, before** the `seen[root]` check at `grants.go:223` decides whether the shields need
testing at all. So d238af5's dedup removes the duplicate *test* while the duplicate
*derivation* - which is where the resolves are - still runs per grant. 103,758 resolves at
G=64/N=96/C=512; 629 → 560 per grant isolated.
*Cause:* `internal/linux/grants.go:222`.

**5. `Contains` allocates 16.5k times per write verdict, 1.4k per read verdict.**
`covers` (`verdict.go:303-304`) does `filepath.Clean` + `strings.Split` on **both** paths for
every rule that fails the byte-exact `policy.CoversResolved` test - two slices per rule, on
the path that is the common case. The component walk is only needed once `EqualFold` could
matter. Right shape, needless per-unit cost, on a path called 8 times per grant.
*Cause:* `internal/shield/verdict.go:303`.

**6. `FoldedWorkspaceShields` and the folded-write loop pay a `SameFile` syscall per rule.**
`foldsCase` (`verdict.go:348`) already skips a base name with no letters without a syscall,
but every `.git/hooks`-shaped name has letters, so W syscalls are paid per grant on hosts
that fold nothing. Linear, so within the invariant; noted as the cheapest remaining constant.
*Cause:* `internal/shield/verdict.go:359`.

## Re-open pass: what the six perf commits fixed, and what their rows kept

| commit | cell it fixed | rest of the row |
|---|---|---|
| `e9f2682` reuse assembled targets in `Set.Mount` | resolve-per-rule in `Mount`/`target` | **NOT carried.** The same "resolve a rule's own path" cost lives at `verdict.go:179` and `:230` and does not consult `s.targets`. Finding 1. |
| `479c83d` resolve rules in force once per derivation | the O(findings × rules) inside one `derivedWorkspaceRules` | **NOT carried.** The per-call cost is now linear, but the call is still made per grant from three callers, each re-resolving all rules in force. Findings 3 and 4. |
| `e1ce786` derive a run's shield rules once | `shieldRulesCache` for `shieldRules` | Partial. `denyArgs`/`createdShields` share the memo; the two grant checks build the same rules on their own paths and miss it. Findings 2 and 4. |
| `803ff2c` probe each shield path once, after pure checks | ordered the pure test before the probe in the `linux` shield walk | Carried within its own file. The same idiom is **absent** in `verdict.go`'s hot loop, which probes (resolve) unconditionally before any pure test. Finding 1. |
| `d238af5` test a checkout's redirects once | duplicate redirect testing | **NOT carried.** The dedup covers the test, not the per-grant rebuild of what is tested. Finding 4. |
| `74beff9` keep memoized shield rules from aliasing | correctness of the `slices.Clip` on memoized rules | n/a (correctness). |

Pattern: the memoization went in at each site that was profiled, one at a time, and the
verdict half of the same cost class was never visited. Every "NOT carried" row above is the
same cost - *resolving a path whose resolution was already computed at assembly.*

## Benchmark audit - do the existing instruments measure what they claim?

- **`BenchmarkWorkspaceShieldWalk`** (`internal/linux/shield_scale_test.go:68`) claims "one
  run's worth of workspace-shield derivation". It leaves `nestedCheckouts` and
  `projectConfig` nil, so `derivedWorkspaceRules` returns at its early exit and the
  **dominant cell (findings 2-4, 150k-300k resolves) is entirely outside the benchmark**. It
  also leaves `shieldCache` nil in both arms, so both pay a full `Assemble` per call site and
  the memo delta it reports is contaminated; and `homes` is `/home/u`, a path that does not
  exist on the runner, so the credential walk it is timing walks nothing. `statID` is nil,
  so any input that reached `SameFile` would panic - the fold path is never exercised.
- **`BenchmarkCredentialLinkWalk`** (`internal/linux/workspace_shield_test.go:287`) does
  measure what it claims: 10 `shields()` calls, memo vs no memo, over a real populated farm
  home. Sound.
- **No benchmark reaches `Set.Contains` at all.** The hottest cell in this grid (2,654
  syscalls per call, 8 calls per write grant) has no instrument in the repo. Any fix to
  finding 1 needs a count assertion written from scratch.

## Cells not measured, and why

- `credhunt`/alias-scan interaction with the shield set: out of this path's scope.
- Wall time anywhere: three measurers shared the machine; medians would be noise.
- Instructions retired: not needed - the resolve and syscall counts already separate the
  cells, and `perf` counters are as machine-shared as wall time here.
- `Contains` on a genuinely case-folding mount (vfat/ciopfs): no such mount available, so the
  `covers` component walk and `foldsCase` were measured only on their non-folding path. That
  is the common path; the folding path adds one `SameFile` per differing component and is
  bounded by D.
