# Perf grid - denylist rule construction and coverage lookup

Measured at base commit **9f80de6** (`test(shield): pin the clip that keeps memoized rules apart`).

> **Base note for whoever merges the four grids.** The dispatched worktree arrived detached at
> `80f0799`, a *divergent* branch that is missing commits `9f80de6` has (`internal/linux/shield_cost_test.go`,
> most of `internal/linux/shields.go`, 32 lines of `internal/denylist/index_test.go`). It was moved to
> `9f80de6` before any measurement. `internal/denylist/denylist.go`, `index.go` and `policy/path.go` -
> the whole of this path - are byte-identical between the two commits, so nothing here depends on the choice.

Invariant under test: each stage's cost is bounded by a known function of its input, and per-unit
constants are what the design needs and no more.

Cost classes measured: **allocations** and **comparisons** (inner-loop iterations). No syscalls, execs
or filesystem ops occur on this path - it is pure CPU and memory work over in-memory rule slices.
Wall-time medians were deliberately not taken: three other measurers ran concurrently on this machine.

---

## The suspicion, answered

> *"An `Index` exists, yet linear `Covers`/`underDenyAll` scans are still called - possibly from inside
> loops over paths, which would make the product rules x paths."*

**Half disproved, half confirmed.** Every non-test call site, exhaustively:

| Linear form | Non-test call sites | In a loop over paths? |
|---|---|---|
| `denylist.Covers` (:1809) | **exactly one**: `audit.Diff`, `internal/denylist/audit/audit.go:602` | **Yes** - loop over candidates. But `audit` is the offline firejail-parity check (`make audit`), **not the launch path**. |
| `underDenyAll` (:1709) | `denylist.go:1309`, inside `Relocated`'s `covered()` closure | **Yes** - once per relocation candidate, scanning all defaults. |
| `insideDenyAllTree` (:1696) | `denylist.go:1686`, `Relocated`'s final screen | **Yes** - and against *both* `defaults` and `rules`, which is quadratic. |
| `Index` / `NewIndex` (index.go:43) | **exactly one**: `internal/credhunt/credhunt.go:189` | n/a - it is the indexed form, used correctly. |

So the feared `rules x paths` product on the **launch path does not exist**. `shield.Assemble`
(`internal/shield/rules.go:89`) never calls the linear `Covers`. The real cost is not where the
suspicion pointed - it is **inside rule construction**, in `Relocated`, where two hand-rolled linear
scans run against each other.

---

## Measured sizes ("typical" - measured, not guessed)

| Quantity | Value |
|---|---|
| `Home(anchor)` rules | **537 per anchor** |
| ...of which `DenyAll` + `Dir` (the inner-loop work) | **222** |
| `Runtime(...)` rules | 2 |
| `Relocated(...)` output, **empty env** | 1 |
| `Relocated(...)` output, **ordinary dev-box env** (13 relocation vars set) | **225** |
| `Workspace(dir)` / `WorkspaceGitfile(dir)` | 14 / 12 |
| `AliasAnchors(home)` | 107 |
| Rule path length | mean **22 B**, max **48 B** |

The path-length row is load-bearing: Go keeps a string concatenation in a stack temp up to ~32 bytes
and heap-allocates above it. Measured directly - `pathlen=4` → **0.0 allocs**, `pathlen=53` → **1.0 alloc**.
That is why the cost below appears only at realistic path lengths and is invisible on toy inputs.

## Invocations per top-level operation

Counted with package-level counters over one end-to-end `shield.Assemble` (since deleted):

| Stage | single-anchor run | two-anchor run |
|---|---|---|
| `Home` | 1 | 2 (once per anchor - correct) |
| `Relocated` | 1 | **1** (once over the whole anchor set, as its comment promises) |
| `Runtime` | 1 | 1 |

**No rebuild finding on the launch path.** The three prior perf commits (`d238af5`, `803ff2c`, `74beff9`)
did land; `Assemble` is clean. One rebuild finding survives *off* the launch path - see F4.

---

## The grid

Rows are stages; each cell is allocations / comparisons, at three input scales.

### Lookup stages

| Stage | file:line | minimal | typical (537 rules) | 100x (53,700 rules) | growth | verdict |
|---|---|---|---|---|---|---|
| `Covers` (linear) | denylist.go:1809 | 1 cmp, 0 alloc | 537 cmp, **0 alloc** | 53,700 cmp, 0 alloc | O(rules), alloc-free | **ok** (shape is correct for its one caller) |
| `Index.Covers` | index.go:65 | 1 lookup | **depth** (4-10), 0 alloc | depth (unchanged), 0 alloc | O(path depth), independent of rules | **ok** |
| `NewIndex` | index.go:43 | - | **9 allocs** / 537 rules | O(rules) | linear | **ok** |
| `underDenyAll` | denylist.go:1709 | 1 cmp, 0 alloc | 537 cmp, **52 allocs** | 53,700 cmp, ~5,200 allocs *(extrapolated; 537 measured)* | O(rules), **1 alloc per long-path DenyAll rule** | **constant** (F2) |
| `insideDenyAllTree` | denylist.go:1696 | 1 cmp, 0 alloc | 537 cmp, **52 allocs** | O(rules) *(extrapolated)* | same | **constant** (F2) |
| `policy.CoversResolved` | policy/path.go:40 | - | **0 allocs** | 0 | O(1) | **ok** - but unguarded, see F5 |

All three lookup rows are measured over the **same real `Home("/home/jrose")` table (537 rules)**:
`Covers` **0**, `underDenyAll` **52**, `insideDenyAllTree` **52**. `Covers` routes through
`policy.CoversResolved`'s index comparison; the two hand-rolled scans do
`strings.HasPrefix(p, r.Path+sep)` and pay a heap allocation per long-path `DenyAll` rule. (Over a
*synthetic* rule set with longer paths both scans measure 82 rather than 52 - that gap is path length,
not a difference between the two functions.)

### Construction stages

| Stage | file:line | minimal | typical | 10-100x | growth | verdict |
|---|---|---|---|---|---|---|
| `Home` | :552 | - | **538 allocs** (537 rules) | O(rules) | linear, ~1 alloc/rule | **ok** |
| `Runtime` | :1748 | - | ~2 allocs | O(1) | - | **ok** |
| `Workspace` | :1849 | - | 17 allocs | O(1), fixed table | - | **ok** |
| `WorkspaceGitfile` | :1929 | - | ~12 allocs | O(1) | - | **ok** |
| `AliasAnchors` | :2001 | - | 216 allocs (107 anchors) | O(anchors) | linear | **ok** |
| `HomeAnchors` | :277 | - | O(1) + one passwd read | O(1) | - | **ok** |
| `UnshieldableRelocations` | :382 | - | O(relocation vars) | linear | - | **ok** |
| **`Relocated`** | **:1302** | **110 allocs** (empty env) | **27,540 allocs** (dev env) | **920,250 allocs** at 10x rules (synthetic) | **quadratic in the `Home` table** | **SCALING (F1)** |

### `Relocated` broken down

The final screen at `denylist.go:1686` is `for r in rules { insideDenyAllTree(r, defaults) && insideDenyAllTree(r, rules) }`
→ `O(len(rules) x (len(defaults) + len(rules)))`, with an **allocating** inner comparison.

| emitted `rules` | defaults | comparisons | allocations |
|---|---|---|---|
| 1 | 537 | 538 | 52 |
| **225** (real dev box) | 537 | **171,450** | **30,151** |
| 2,250 (10x, *synthetic*) | 537 | **6,270,750** | **920,250** |

10x the rules gives **36.6x** the comparisons and **30.5x** the allocations. That is the quadratic term
dominating, measured, not inferred. The screen accounts for essentially all of `Relocated`'s 27,540 allocs
at dev-box scale. The 2,250 row is a synthetic rule set - a real environment cannot emit that many today;
the reachable ceiling is the ~225 row, and this row is retained as the shape proof.

**`len(rules)` is itself proportional to `len(defaults)`, so the screen is quadratic in the `Home` table.**
Measured with `XDG_CONFIG_HOME` set alone:

| anchors | defaults | `.config/` rules in defaults | emitted rules | `Relocated` allocs |
|---|---|---|---|---|
| 1 | 537 | **126** | **127** | 14,300 |
| 2 | 1,074 | 252 | 127 *(one XDG base, correctly deduped)* | **39,461** (2.76x for 2x defaults) |

The XDG restatement derives its output from the defaults - every rule `Home` placed under an anchor's
`.config/` is restated at the relocated base - so emitted count tracks the `.config/` count almost exactly
(126 → 127). **Adding credential classes to the `Home` table therefore grows both sides of the screen**,
making `Relocated` **O(defaults²)** rather than quadratic in a bounded emitted count. The two-anchor row
shows the effect independently: emitted count held flat at 127 while defaults doubled, and allocations
still grew **2.76x** - superlinear, because the screen and the `covered()` closure both rescan all
defaults per candidate.

### Audit path

| Stage | candidates | rules | `CoversResolved` calls | allocs |
|---|---|---|---|---|
| `audit.Diff` (audit.go:599) | 1 | 539 | 539 | 0 |
| | 1,000 | 539 | 539,000 | 0 |
| | 10,000 | 539 | **5,390,000** | 0 |

Alloc-free, but the product is real and it is `O(candidates x rules)` with no index, while an `Index`
built once would make it `O(candidates x depth)`. Ranked low: offline tooling, zero allocations.

---

## Findings, ranked

### F1 - SCALING, hot path. `Relocated`'s final screen is O(defaults²) with an allocating inner loop
`internal/denylist/denylist.go:1686` (calling `insideDenyAllTree`, :1696)

`O(rules x (defaults + rules))` comparisons, each allocating when the rule path exceeds ~32 bytes.
**27,540 allocations for a single `Relocated` call on an ordinary dev box**, against 110 on an empty
environment - a 250x difference that only appears once the relocation variables a real developer has
set are present, which is exactly the input nobody profiled. It is on the launch path: `shield.Assemble`
→ `rules.go:119` → `Relocated`.

Worse than a bounded quadratic: because the XDG restatement derives emitted rules from the defaults
(126 `.config/` rules → 127 emitted, measured), **`len(rules)` scales with `len(defaults)`, so this is
quadratic in the `Home` table itself** - a table that grows every time a credential class is added, and
which nothing in the cost model bounds. Doubling defaults raised `Relocated`'s allocations 2.76x with
the emitted count held flat.

Fix shape (Phase 4 is the orchestrator's): build a `NewIndex` over `defaults` once before the screen,
and the DenyAll-dir subset of `rules` once, turning the screen into `O(rules x depth)`. The index already
exists and already shares `stricter` with `Covers`, so this adds no second definition of coverage.

### F2 - CONSTANT, hot path. Two scans hand-roll the allocating comparison the codebase already fixed
`internal/denylist/denylist.go:1698` and `:1714` - both `strings.HasPrefix(p, r.Path+string(filepath.Separator))`

`policy.CoversResolved` carries an explicit comment saying it is spelled as an index comparison rather
than `HasPrefix(path, grant+sep)` *because* "the concatenation allocates, and this runs once per rule for
every file of a whole-home walk" (commit `8607323`). These two scans are the allocating spelling that
comment warns about. Measured over the identical real 537-rule `Home` table: **`Covers` 0 allocs vs
`underDenyAll` 52 and `insideDenyAllTree` 52**. The fix is to call `policy.CoversResolved` - one line each, and it deletes the
divergence rather than adding an abstraction. This is also most of F1's constant factor.

### F3 - SCALING, offline. `audit.Diff` is `O(candidates x rules)` with an index available
`internal/denylist/audit/audit.go:602`

5.39M `CoversResolved` calls at 10k candidates. Alloc-free, and `make audit` is dev-time only, so this
is a real but low-priority cell. One `NewIndex(rules)` hoisted above the loop makes it `O(candidates x depth)`.
Noted mainly because it is the *only* place the feared `rules x paths` product actually occurs.

### F4 - REBUILD, off the launch path. `denylist.Home` rebuilt inside a per-grant loop
`cmd/bento/clamp.go:346` - `for _, r := range denylist.Home(root)`

Inside `reaches(g)`, which runs per grant and per each of two spellings. `Home` costs **538 allocations
for 537 rules** per call (measured); the "per grant x 2 spellings" multiplier is **read from the code, not
measured** - `foreignHomeShields` is unexported in package `main`, so there is no seam to call it through.
It is rebuilt from an argument that takes few distinct values. Hoist to a small
`map[string][]Rule` memo keyed by `root`, or build once per distinct root before the loop. This is the
same "built once per run, not once per use" shape as `d238af5` and `803ff2c`, in a spot those passes did
not reach.

### F5 - UNGUARDED PRIOR FIX. `CoversResolved`'s zero-alloc property has no test
`policy/path_test.go:67`, `BenchmarkCoversResolved`

The benchmark's own doc says it plainly: *"Reported, not asserted: a benchmark cannot fail on an allocation."*
Commit `8607323` made this allocation-free and nothing in the tree stops it regressing. Verified, not
inferred: `grep -rn 'AllocsPerRun' --include='*.go'` over the whole tree returns **zero matches** - this
repo has no allocation assertion anywhere, so no pin lives in another package either. A
`testing.AllocsPerRun(100, ...) != 0` assertion is three lines and pins the invariant F2 depends on.

## Benchmark audit (do the existing instruments measure what they claim?)

- **`BenchmarkIndex`** (`internal/denylist/index_test.go:151`) - **honest.** Setup (`NewIndex`, the coverage
  pre-check) is outside the timed loops; `new` and `covers` are separate sub-benchmarks so construction is
  not billed to lookup; it asserts the queried path is really covered, so the benchmark cannot silently
  degenerate into timing the miss path. No change needed.
- **`BenchmarkCoversResolved`** (`policy/path_test.go:67`) - **honest but gates nothing**, see F5. Results
  go to a package-level `sink`, so it is not optimized away.
- **Gap:** nothing benchmarks `Relocated`, which is where F1 lives - the most expensive stage on this path
  has no instrument at all. A red-first `testing.AllocsPerRun` scaling assertion (allocs at n vs 10n rules)
  is the natural count test for F1.

## Cells not measured, and why

- **Real `audit.Diff` candidate count.** The firejail profiles are a dev-time input and are not vendored
  (`audit.go:805`), and `make audit` needs them. Diff was measured at synthetic 1 / 1,000 / 10,000 instead;
  the complexity is what matters and it is exact.
- **Wall time / instructions retired.** Excluded by instruction - three measurers ran concurrently, so both
  would be contaminated. Inner-loop comparison counts were used as the deterministic instruction proxy.
- **F4's rebuild multiplier** at `cmd/bento/clamp.go:346` - `foreignHomeShields` is unexported in package
  `main`, so the per-grant count is read from the code while the 538-allocs-per-`Home`-call figure is measured.
- **`underDenyAll` / `insideDenyAllTree` at 100x** - measured at 537 rules only; the 100x cells are
  extrapolated from the confirmed linear shape, and are labelled as such in the table.

## Handoff to another measurer

`internal/shield`'s `set.Contains` (reached from the loop at `internal/linux/linux.go:1104`) looks like the
same linear-scan-inside-a-loop shape, but it is in `internal/shield` and belongs to that path's measurer.
Not measured here.

---

*All instrumentation (`zz_*.go` counters, size/alloc/comparison probes) was deleted; the worktree was left clean.*
