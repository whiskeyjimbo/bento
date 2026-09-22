# Perf grid: gate credential-alias walk

Path: `gate/alias_unix.go` - `credentialAliases` (:70) and everything under it.
Base commit: `9f80de6` (measured detached in a worktree; `make check` not run, nothing
shipped). The worktree handed to this measurer was on branch
`worktree-agent-a2d1e1a93b590ac9d` at `80f0799`, which is **not** a descendant of `9f80de6`
and does not contain `BenchmarkAliasWalkBudget` at all - everything below was measured
after checking out `9f80de6` detached, and the branch was restored afterwards.
Host: Intel i7-7700, ext4, warm cache. Three other measurers ran concurrently, so **no wall
time here is load-bearing** - every verdict rests on counts (entries, syscalls, allocs),
which do not jitter. Wall time appears only where it is an order-of-magnitude statement.

Invariant: each stage's cost is bounded by a known function of its input, and per-unit
constants are what the design needs and no more.

## Harness

Instrumentation was a throwaway `gate/zzperfhunt_test.go` (deleted; the tree is clean).
Grant trees were prebuilt outside the measured process so setup never lands in the counts:

| tree | shape | entries (`find | wc -l`) |
|---|---|---|
| s1-minimal | 2 dirs x 20 files | 47 |
| s2-typical | 100 dirs x 200 files, 2 levels | 20,203 |
| s2-hardlink50% | same, every 2nd file hardlinked to the credential | 20,203 |
| s3-patho | 1000 dirs x 200 files | 202,003 |

Syscalls by `strace -f -c` on a prebuilt `go test -c` binary, one scale per run.

## Stage rows

| # | stage | file:line | runs per `gate.Check` |
|---|---|---|---|
| R1 | anchor list + resolve | `alias_unix.go:151-175`, `pathresolve.Existing` | 1 list; **107 resolves** (this host), 88 of them on paths that do not exist |
| R2 | anchor walk | `alias_unix.go:197` `WalkDir` | once per distinct present anchor root (19 here). **No budget parameter.** |
| R3 | `identify` per anchor entry | `alias_unix.go:219`, `:296` | 1 per regular file under an anchor |
| R4 | grant resolve + dedup | `alias_unix.go:87-91` | 1 per grant; exact-root dedup only |
| R5 | grant walk | `alias_unix.go:263` `WalkDir` | once per distinct grant root, **only if `len(want) > 0`** (:77) |
| R6 | `identify` per grant entry | `alias_unix.go:273`, `:281` | 1 per entry - every directory (device prune) *and* every regular file |
| R7 | collect + sort + compact | `alias_unix.go:107-118` | 1; `O(f log f)` in findings |

## The grid

### R1 - anchor list + resolve (input: number of listed anchors, not host size)

| cost class | minimal | this host (107 anchors) | verdict |
|---|---|---|---|
| filesystem ops | - | **394 `newfstatat` (88 ENOENT) + 341 `readlinkat` = 735** | **constant** |
| allocs | - | **3,393 allocs, 194 KB** | **constant** |
| complexity | O(anchors x path components) | linear, no memo (`pathresolve.Existing` has no cache) | ok (shape) |
| wall | - | ~0.85 ms/op | supporting only |

Paid unconditionally on every `Check`, before anything decides whether the scan is needed.

### R2+R3 - anchor walk (input: entries under the credential anchors) - **UNCAPPED**

Measured: `HOME` pointed at a fake home whose `.gnupg` holds 60,603 entries (60,300 regular
files) - deliberately **above `aliasBudget = 50_000`**, so "something else bounds it" is not
available as a reading. One `aliasableCredentials` call, straced.

| cost class | real dev home | fat anchor (60,603 entries) | verdict |
|---|---|---|---|
| entries walked | 178 | 60,603 | **scaling** |
| `newfstatat` | 127 regular files | **61,486** (60,300 anchor files + 394 resolve + real-home anchors) | **scaling** |
| `getdents64` | - | 1,302 | - |
| `openat` | - | 660 | - |
| budget charged | **0** | **0** - `aliasableCredentials` takes no `budget` parameter at all | **scaling** |

The fat-anchor run found **zero** aliasable credentials (`want = 0`), so the grant walk was
skipped entirely: 61,486 lstats bought nothing, and the `len(want)==0` fast path at :77 is
*downstream* of them. The walk ran 20% past the budget that exists to stop exactly this.

Measured with `shield.Set{}`, so rule-derived anchor roots (`set.Rules()`,
`CallerDenies()`, `CredentialLinks()` at :159-175) contributed nothing. A real `Check` adds
roots on top, so this is a floor, not the figure.

### R5+R6 - grant walk (input: entries under the granted trees) - capped at 50,000

| cost class | s1 (47) | s2 (20,203) | s3 (202,003) | per entry | verdict |
|---|---|---|---|---|---|
| entries charged | 47 | 20,203 | 202,003 | 1.00 | ok |
| `newfstatat` | 48 | 20,204 | 202,004 | **1.00** | ok (shape), see F4 |
| `getdents64` | 12 | 404 | 4,006 | 2 per directory | ok |
| `openat` | 13 | 209 | 2,009 | 1 per directory | ok |
| allocs | 323 | 123,055 | 1,230,229 | **6.09** | **constant** |
| bytes | 37 KB | 14.4 MB | 153 MB | **758 B** | **constant** |

Perfectly linear in entries across 3 orders of magnitude - no scaling bug in the walk
itself. `BenchmarkAliasWalkBudget` agrees independently: 300,993 allocs for 50,000 entries
= 6.02/entry.

Hardlink density (s2 vs s2-hardlink50%, same 20,203 entries, 1 finding vs 10,001):

| | s2 | s2-hl50% | verdict |
|---|---|---|---|
| entries / lstats | identical | identical | ok - `identify` cost is density-independent |
| allocs | 123,055 | 123,079 | ok |
| bytes | 14.4 MB | 15.8 MB | **findings are unbounded in memory** (F5) |

### R7 - collect/sort/compact

| cost class | verdict |
|---|---|
| complexity | `O(f log f)` in findings, `f` bounded only by entries walked - ok in shape |
| allocs | inside the 6.09/entry above; not separable | ok |

## Findings, ranked

**F1 - scaling, hot path. The anchor walk has no budget.**
`aliasableCredentials` (`gate/alias_unix.go:143`) walks every present anchor to the bottom
with no allowance; only `aliasesUnder` takes `*budget` (:256). Measured: a 60,603-entry
`.gnupg` costs **61,486 `newfstatat`** on every `Check` - 20% past `aliasBudget`, which was
never consulted - and in that run `want == 0`, so the capped half never ran at all. The
docstring's "2.5ms on a developer home" (:44) is true of *this* host (178 entries) and says
nothing about the bound. A cap on one half of a two-walk scan is not a bound on the scan.
This is the headline: the budget names a blow-up and then guards the wrong walk.

**F2 - correctness, reported as asked. One allowance, spent in grant order.**
`budget` is shared across all grants and consumed in `slices.Concat(reads, writes)` order
(:86, :92). Measured: with `budget` already spent, a grant containing a real hardlinked
alias returned **`found=0, stopped=true`** - the alias is on disk, under a read grant, and
invisible. `CredentialAliasesPartial` does reach the operator (`cmd/bento/validate.go:354`),
so this is not a silent clean bill; but one boolean cannot say *which* grants were never
looked at, and coverage is order-dependent rather than proportional. A manifest whose first
grant is a module cache spends the whole allowance there and scans nothing else.

**F3 - constant, hot path. Nested grants are charged twice.**
The dedup at :88 is exact-root equality. Measured with `read: <tree>` alongside
`read: <tree>/d1`: the outer walk charged 20,203 entries and the nested grant charged
another 202 for entries already visited. `slices.Compact` at :118 cleans the *output*, not
the budget. Under F2 this is worse than waste - double-charging shortens the scan.
Fix shape: skip a root that `policy.CoversResolved` an already-seen root, as :187 already
does for opt-ins.

**F4 - trivial, ranked last. One wasted lstat per grant.**
`aliasesUnder` calls `identify` on `root` itself (:273) and then discards the result via
`p != root`. One lstat per grant; worth a line only because it is free to remove.

Explicitly **not** a finding: the per-directory `identify` that drives the device prune.
`getdents64` yields `d_type` and `d_ino` but never `d_dev`, so nothing in the listing says
whether a child is a mount point - the stat is not buying a fact the walk already had. It
is 202 of 20,203 lstats (~1%) and can skip a whole subtree, which is the trade :243-247
describes. The only alternative is the mount table, which :31-33 deliberately leaves to the
platform.

**F5 - constant. Findings accumulate unbounded.**
`out` grows one `enforce.CredentialAlias` per hit (:283) with no cap; the 50%-hardlink tree
produced 10,001 findings and +1.4 MB. Entry-bounded, so not a scaling break, but a
deduplicating store under a grant makes the report itself the cost.

**F6 - constant. `pathresolve.Existing` is called repeatedly on the same paths, unmemoized.**
107 anchor resolves per `Check` (735 syscalls, 3,393 allocs, 88 on absent paths), plus one
per grant at :87, plus one per rule at :161/:172, plus again per write grant in
`derivesWorkspaceShields` (`gate/gate.go:199`). No cache anywhere in `pathresolve`.
Reconciles with the prose at :42-44, which attributes ~2.5 ms per `Check` to "a walk of the
credential anchors": on this host that walk is 178 entries, while *resolving* the anchor
list is 735 syscalls / 3,393 allocs on its own. A large share of the cost the docstring
blames on walking is resolution.

**F7 - prose. The `aliasBudget` rationale is unpinned and now partly wrong.**
`:121-127` and `:44` make hard quantitative claims (40ms->1.14s, "a few microseconds warm",
"roughly 200ms warm", "2.5ms on a developer home") and nothing in the repo pins any of them.
:44's is the one F1 falsifies *as a bound* - it describes a 178-entry home and reads as a
statement about the anchor walk's cost in general. Under the repo's own "cross-file prose
needs a test or a bead" convention these want a pin, and a pin should assert counts
(entries walked, lstats) rather than milliseconds.

## Benchmark audit

- `BenchmarkAliasWalkBudget` (`gate/alias_budget_test.go:59`) - **sound.** Tree built
  before `b.Loop`, budget reset inside each iteration, and the `stopped` precondition
  asserted once outside the timing. Its 300,993 allocs / 50,000 entries independently
  reproduced my 6.09 allocs/entry. It measures only the capped branch.
- `BenchmarkHostAliasesUnder` (`internal/linux/alias_test.go:1800`) - **sound**, same shape,
  fixture verified outside the loop. Single fixed size (~5,100 entries), so it can detect a
  constant regression but not a scaling one.
- **Gap:** nothing benchmarks `aliasableCredentials` - the uncapped half (F1). Nothing
  benchmarks at two sizes, so no instrument in the repo can fail on a scaling change.

## Not measured

- Cold cache. Every number here is warm; the docstring's "15.7s cold" claim is untested and
  I did not drop caches on a shared machine.
- Real anchor shapes beyond this host's 19 present / 178 entries. F1's fat anchor is
  synthetic (a 60,603-entry `.gnupg`); a Nix or `pass`-with-history home is the realistic
  source and I did not have one. The anchor walk was measured at one size above the budget,
  not at three - enough to show it is uncapped, not enough to plot its slope independently
  of the grant walk's (which is linear, and shares the same WalkDir/`identify` machinery).
- `dirEnvs` anchors pointed at an arbitrary absolute path (`GNUPGHOME=/srv/keys`,
  `denylist.go:2016`) - structurally the same as F1 with no home-shaped bound at all, read
  from the code, not measured.
