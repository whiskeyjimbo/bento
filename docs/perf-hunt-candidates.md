# perf-hunt Phase A - hot path inventory

Swept 2026-09-22 on `perf/shield-rule-cost` (HEAD 9f80de6). Nothing measured yet; this is
the candidate census and ranking only. Worktrees under `.claude/` excluded.

Ranked by frequency x input growth, per the skill.

## Sweep tells

- Perf commits by area: `internal` 13, `cmd` 2, `gate` 1, `policy` 1; zero in `backend`,
  `enforce`, `manifest`, `profile`, `trust`. Within `internal` the cluster is shield (6),
  linux/alias (4), credhunt (2).
- Existing benchmarks (7): `BenchmarkHunt`, `BenchmarkIndex`, `BenchmarkHostAliasesUnder`,
  `BenchmarkWorkspaceShieldWalk`, `BenchmarkCredentialLinkWalk`, `BenchmarkCoversResolved`,
  `BenchmarkAliasWalkBudget`.
- Explicit budgets/caps: `gate/alias_unix.go:128 aliasBudget = 50_000`, credhunt's depth
  bound (`1b8fbd8`), the probe timeouts in `internal/linux/limits.go`.
- Directory walks: `gate/alias_unix.go:197,263`, `internal/linux/shields.go:298`,
  `internal/linux/alias.go:880,936`, `internal/credhunt/credhunt.go:210`.
- Subprocess execs on a per-run path: `internal/linux/probe.go:680` (bwrap),
  `internal/linux/limits.go:171,272,447` (systemd-run + canary), `degraded.go:240`,
  `profile.go:223`, `linux.go:280`.

## Candidates

| # | Path | Frequency | Scales with | Entry / scalable input | Benchmark | Rank | Route |
|---|------|-----------|-------------|------------------------|-----------|------|-------|
| 1 | `internal/linux` probe + limits preflight - `probe.go:63 Probe`, `limits.go` `measureScope`/`runScopeProbe` | once per run, before the target starts | host probes, not user input - but each is a **fork+exec** of bwrap or systemd-run, the most expensive cost class here | `Enforcer.Probe(ctx)`; scale = number of probe subprocesses per launch, and whether any repeat across `validate`/`profile`/`run` | **none** | 1 | grid |
| 2 | Shield derivation + verdict - `internal/shield/verdict.go` (`Contains`, `FoldedWorkspaceShields`, `covers`), `internal/linux/shields.go:298` | per launch, per grant x per workspace rule | grants x nested checkouts x path depth | shield walk over a synthetic checkout tree | `BenchmarkWorkspaceShieldWalk`, `BenchmarkCredentialLinkWalk` | 2 | grid |
| 3 | Gate credential-alias walk - `gate/alias_unix.go` `credentialAliases`/`aliasesUnder` | per launch | directory entries under each read grant; already capped at 50k, which is an admission it blows up | `gate.Check` on a home-shaped tree | `BenchmarkAliasWalkBudget`, `BenchmarkHostAliasesUnder` | 3 | grid |
| 4 | Denylist rule build + coverage - `denylist.Home/Relocated/Runtime`, `Covers:1809`, `insideDenyAllTree:1696`, `underDenyAll:1709` | per launch, then per path checked | rules x paths; the `underDenyAll` helpers are linear scans called inside loops while `NewIndex` exists | `NewIndex`/`Covers`; rule count | `BenchmarkIndex`, `BenchmarkCoversResolved` | 4 | grid |
| 5 | Proxy per-connection - `internal/proxy/proxy.go` `guardUpstream:492`, `classifyNAT64`, `literalGrantFor:573` | **per network connection** - highest frequency in the tree | connections x network rules | `WithDialer:262` is a real fake seam, so it is measurable | **none** - costs a harness in Phase 0 | 5 | grid |
| 6 | `credhunt.Hunt:176` | per approve/doctor, not per run | $HOME size and depth; reads file heads | `Hunt(Options)` over a generated home | `BenchmarkHunt` | 6 | grid |
| 7 | `internal/linux/alias.go` host alias walks (`:880`, `:936`) | per launch | paths x ancestor depth, stat per component | `hostAliasesUnder` | `BenchmarkHostAliasesUnder` | 7 | grid |
| 8 | `internal/launcher/verify.go` (`:62`, `:135`, `:253`, `:408`) - post-sandbox `/proc` and `/dev` verification | per launch | `/proc` entry count, task count | in-launcher, hard to reach without a launch | none | 8 | grid, but Phase 0 may decline - no seam |
| 9 | `manifest.Parse`/`Load`/`Resolve` | per launch, once, on one small file | manifest size (bounded by the author) | `Parse(r)` | none | - | **skip** - runs once at trivial size, Phase 0 declines |
| 10 | `internal/observe` exec-image reading (`execimage_linux_amd64.go`) | per profiled exec | ELF section count | observe harness | none | - | route to `failure-modes` / `fuzz-oracle` - the open question there is malformed input, not cost |

## Base commit note

HEAD already contains the six shield perf fixes (`803ff2c`, `479c83d`, `e1ce786`,
`e9f2682`, `d238af5`, plus `74beff9`). If candidate 2 is picked, the base for measurement
has to be named: grid HEAD as it stands, or bisect from before `803ff2c`.

## Why candidate 2 is ranked high despite the recent work

Six one-at-a-time perf commits in one area is the signal that the space was never mapped,
not that it is finished. Each of those fixed the bar that round's profile showed.
