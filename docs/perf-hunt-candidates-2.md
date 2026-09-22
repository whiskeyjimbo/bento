# perf-hunt Phase A, round 2 - hot path inventory

Swept 2026-09-22 at `bca2d24` (`perf/shield-rule-cost`, level with `main`). Nothing measured
yet; census and ranking only. Worktrees under `.claude/` excluded.

Round 1 (`perf-hunt-candidates.md`, `perf-hunt-findings.md`) gridded four paths - probe and
limits, shield derivation, the gate alias walk, the denylist - and the second batch closed
every finding on them. This round ranks what those four grids never reached, plus one
cross-stage re-grid, because fifteen fixes landed stage by stage and fixes move cost between
stages.

## Sweep tells

- Perf commits since round 1 are all in the four gridded areas: shield, linux, gate,
  denylist, clamp. Zero ever in `internal/observe`, `internal/proxy`, `internal/launcher`,
  `internal/landlock`, `internal/linux/args.go`.
- Benchmarks (10): `BenchmarkContains`, `BenchmarkWriteVerdictsOnHost`, `BenchmarkRelocated`,
  `BenchmarkIndex`, `BenchmarkHunt`, `BenchmarkHostAliasesUnder`, `BenchmarkCoversResolved`,
  `BenchmarkAliasWalkBudget`, `BenchmarkWorkspaceShieldWalk`, `BenchmarkCredentialLinkWalk`.
  Every one sits in a round-1 area or credhunt. `AllocsPerRun` now appears in four test
  files, all round-1 fixes.
- Nothing benchmarks a whole launch; round 1's before/after for the end-to-end path was an
  ad hoc `strace -c` + hyperfine over `bento validate`.
- Per-event loops with no instrument: the ptrace stop loop in `observe_linux_amd64.go`
  (every syscall of the profiled program), and `copyIdle` in `proxy.go:1519` (every read on
  every tunnel).

## Candidates

| # | Path | Frequency | Scales with | Entry / scalable input | Benchmark | Rank | Route |
|---|------|-----------|-------------|------------------------|-----------|------|-------|
| 1 | `internal/observe` ptrace tracer - `Trace:184`, stop loop, `inspect:996`, `readString:1717`, `fdPath:1666` | **per syscall of the profiled program**, two stops each | total syscalls, not file syscalls: `PTRACE_O_TRACESYSGOOD` + `PtraceSyscall` (`:270`, `:356`) stops on every syscall, and each stop pays `PTRACE_GET_SYSCALL_INFO` + `PTRACE_GETREGS` before the number is looked at. Each path read is open+pread+close of `/proc/pid/mem` rather than one `process_vm_readv`; relative opens add a readlink and a stat | `observe.Trace(argv)` on a workload whose syscall count and file/non-file mix you set (a loop of `getpid` vs `open`) | **none** - costs a harness in Phase 0 | 1 | grid |
| 2 | Whole-launch re-grid - `bento validate` / `run` from manifest parse through gate, shield assembly, args compile, probe, bwrap exec | per launch | grants x rules x nested checkouts; round 1 measured stages separately and the second batch moved cost between them | `bento validate` over synthetic manifests at 1 / 24 / 240 grants; `strace -f -c` counts per stage | **none** end-to-end | 2 | grid |
| 3 | bwrap argv compile + Landlock rule build - `internal/linux/args.go:259 compile`, `hostExists`/`hostIsDir`/`hostListDir`/`hostResolve` (`:814`-`:896`), `landlock.existing:569`, `classifyRules:316` | per launch | grants x shields; each host helper is its own stat/readlink with no shared memo visible at the call sites, and `existing` stats every path again inside the sandbox | `compile(p, proc, sb)` with N grants | none | 3 | grid (folds into #2 if both picked) |
| 4 | Proxy tunnel data path and per-connection guard - `copyIdle:1519`, `tunnel:1444`, `guardUpstream:492`, `literalGrantFor:573` | per read on every tunnel; per connection | bytes / read size for the copy (`time.Now` + two `SetDeadline` per 32 KiB read); network rules for `literalGrantFor`, a linear scan per connection | `tunnel` over loopback via the `WithDialer:262` seam; scale bytes and rule count | none | 4 | grid - the deadline races are `concurrency-audit`'s, already covered there |
| 5 | Launcher in-sandbox verification - `verify.go` `verifyShields:197`, `shieldHidden:242`, `nestedShieldNames:269`, `foreignPids:88` | per launch, inside the sandbox before exec | hidden shields x all shields (`nestedShieldNames` loops every shield per hidden one, after a `ReadDir`); `/proc` entries | the functions are pure enough to call directly with shield lists | none | 5 | grid - Phase 0 may decline if real shield counts stay small |
| 6 | `credhunt.Hunt:176` | per approve / doctor | $HOME size and depth | `Hunt(Options)` over a generated home | `BenchmarkHunt` | 6 | grid - already has the depth bound and rule index; lower expected yield |
| 7 | `internal/linux/alias.go` host alias walks (`:880`, `:936`) | per launch | paths x ancestor depth | `hostAliasesUnder` | `BenchmarkHostAliasesUnder` | 7 | grid - neighbouring round-1 fixes (`dec3e87`, `7970505`) touched it without a grid |
| 8 | seccomp filter assembly (`internal/seccomp`) | per launch | fixed syscall tables, no user input | - | none | - | **skip** - Phase 0 declines, no scalable input |
| 9 | `observe` exec-image ELF reading | per profiled exec | section count | - | - | - | route to `fuzz-oracle` (malformed input), as in round 1 |

## Base commit

Unambiguous this round: `bca2d24` is `main` and contains every round-1 fix. Measure there.
If #2 is picked and a before/after against round 1's baseline is wanted, the base is
`9f80de6`.
