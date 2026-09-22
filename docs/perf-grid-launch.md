# Perf grid - one launch, end to end

Base commit: **bca2d24** (`perf/shield-rule-cost`), confirmed with `git rev-parse HEAD` in the
measuring worktree before any number was taken. Counts only - syscalls by kind, execs, seam
calls, `MemStats.Mallocs` deltas. Other measurers shared the machine throughout, so no wall
time was taken and none is evidence here.

Covers `bento validate <manifest>` and `bento run --allow-unapproved <manifest> -- /bin/true`
end to end: manifest load, grant resolve, gate, shield assembly, probe, `newSandbox`,
grant checks, preflight, bwrap argv compile, the bwrap exec, the in-sandbox launcher and its
Landlock rule build, and the post-run reconcile. `bento run` works on this host (bwrap is not
setuid and user namespaces are available), so nothing was declined.

## How it was measured

- Binary built with the Makefile's flags (`GOWORK=off CGO_ENABLED=0 go build -trimpath
  -buildvcs=false -tags osusergo`).
- Throwaway instrumentation, deleted afterwards: a `perfmark` package whose `Mark(stage)`
  prints the stage's malloc delta and seam-call counts to stderr and `lstat`s
  `/perfmark/<stage>` as a marker; counters (calls / distinct paths) in `hostExists`,
  `hostIsDir`, `hostListDir`, `hostResolve`, `hostWritable`, `hostWritablePrefix`,
  `hostRootDirs`, autoexec's `resolved` and `hookRunnerDir`, `bounded`, `shield.Assemble`,
  `shield.Host`'s resolve misses / isDir / listDir / sameFile, and Landlock's `classifyRules`.
- `strace -f -Y --seccomp-bpf -e trace=%file,%process,%desc`, split on the marker lstats and
  attributed by comm (`bento-inst` = host process, `bento` = the in-sandbox launcher, plus
  `bwrap`, `git`, `sh`, `systemd-run`, ...).
- **Instrumentation does not perturb the counts:** the clean binary under the same strace
  gives identical totals to the instrumented one minus the marker lstats (A1 run 3,995 /
  2,147 / 145 / 222 stat/readlink/open/getdents; N64 run 30,491 / 10,019 / 337 / 350; B24
  run 7,560 / 2,135 / 241 / 240; A1 validate 7,012 / 4,031 / 185 / 326 - identical both ways).
- Every cell was run twice. Seam counts and stat/readlink/open/access/execve are identical
  across the two runs; `getdents` jitters by 1 and mallocs by under 0.1% (a handful), so
  mallocs below are rounded and getdents is +/-1.
- Unfiltered `strace -f` deadlocked twice, in the launcher's Landlock `restrict_self` with
  TSYNC (`landlock_restrict_sibling_threads` waiting on a thread in `ptrace_stop`). The
  seccomp-bpf filter avoided it in every later run. It is a tracer interaction, not a
  finding against bento, but anyone repeating this should know unfiltered `strace -f` on
  `bento run` can hang.

## Fixtures (the three scales and the rule-count axis)

Round 1's trap - a grant-only sweep draws a straight line when the per-grant constant is the
whole rule set - is handled by three separate axes:

| fixture | reads | writes | what varies |
|---|---|---|---|
| A1 / A24 / A240 | 0 / 12 / 120 | 1 / 12 / 120, **each its own `git init`'d checkout** | grants AND rules together (each checkout brings its own workspace shields) |
| B1 / B24 / B240 | 0 / 12 / 120 | 1 / 12 / 120, **plain subdirectories of one checkout** | grants only; rule set fixed |
| N0 / N8 / N64 | 0 | 1 checkout with 0 / 8 / 64 nested `git init`'d checkouts | rules only (nested checkouts), G fixed at 1 |
| C8 / C64 | 0 | 1 checkout with 8 / 64 `.vscode/tasks.json` project-config entries | rules only (project config), G fixed at 1 |

Built-in rule set on this host: `shield.Assemble` resolves **639-644** distinct paths
(189 isDir, 57 listDir). R is the same in every fixture; only workspace rules vary.

## Stages, and how many times each runs per launch

| # | stage | entry | runs / validate | runs / run |
|---|---|---|---|---|
| S1 | manifest load + trust | `cmd/bento/validate.go:150 loadDocument` | 1 | 1 |
| S2 | grant resolve | `manifest.Resolve`; `internal/linux/grants.go:401 resolveGrants` | 1 | 1 + 2 in the backend (second a memo hit, 0 syscalls) |
| S3 | gate | `gate/gate.go:149 Check` + `writePolicySummary` refusals (`validate.go:984-996`) | **Refusals 2x from identical inputs** | `ManifestProblems`/`MissingReads`/`FileishWrites` only |
| S4 | shield assembly | `shield.Assemble` | **2 from identical inputs** (`gate.go:174`, `validate.go:984`) | 1 (`shieldCache`) |
| S5 | probe / limits | `Probe` / `ProbeFor` | 1 **full** `Probe` incl. limits (`validate.go:475`) | 1 `ProbeFor` (af0664c holds) |
| S5b | bwrap trust walk (`resolveBwrap`) | `internal/linux` | 1 | 2 (probe + `Run`) - round 1 rules out caching it |
| S6 | `newSandbox` incl. `findWorkspaceEntries` | `internal/linux/linux.go:907` | - | 1 |
| S7 | grant checks | `internal/linux/grants.go:28 checkGrants` | - | 2 (preflight, compile); the second is 1.1x-35x cheaper (A1 140 vs 4 stat; B24 206 vs 84; B240 962 vs 840 - there its `exists` calls, 480 for 121 paths, are finding 4) |
| S8a | created shields | `shields.go:779 createdShields` | - | **2** (`checkShieldsCarvable` `linux.go:775`, `linux.go:159`) |
| S8b | `denyArgs` | `shields.go:579` | - | **2** (`createShieldAncestors` `linux.go:172`, `compile`) |
| S8c | auto-exec hook resolution | `autoexec.go:300 hookRunnerDirs` | - | 2 (baseline `linux.go:152`, after `autoexec.go:217`) - before/after by design, but see finding 1 |
| S9 | bwrap argv compile | `internal/linux/args.go:259 compile` | - | 1 |
| S10 | Landlock rule build | `internal/landlock/landlock_linux.go:300 backstopRules` | - | 1 (in the launcher) |
| S11 | bwrap exec + launcher verify | `internal/launcher/launcher.go:124 Run` | - | 1 |
| S12 | post-run reconcile + shield reclaim | `linux.go:328`, `shields.go:925` | - | 1 |

## Totals per launch (bento processes; child programs separate)

`execve` excludes bento's own. Zero-limits manifest throughout.

| fixture | validate stat / readlink | validate execs | run stat / readlink / open / getdents / access | run execs | run mallocs |
|---|---|---|---|---|---|
| A1 | 7,012 / 4,031 | 9 | 4,017 / 2,147 / 164 / 240 / 42 | 8 | 48.6k |
| A24 | 9,267 / 4,031 | 9 | 11,310 / 3,368 / 395 / 460 / 207 | 30 | 108k |
| A240 | 30,867 / 4,031 | 9 | 117,693 / 15,356 / 1,092 / 696 / 1,707 (refused, see below) | 122 | 830k |
| B24 | 9,267 / 4,031 | 9 | 7,581 / 2,135 / 264 / 244 / 51 | 30 | 70k |
| B240 | 30,867 / 4,031 | 9 | **250,905** / 2,135 / 1,344 / 460 / 267 | **246** | **1.36M** |
| N8 | 7,012 / 4,031 | 9 | 7,427 / 3,131 / 245 / 369 / 146 | 8 | 79k |
| N64 | 7,012 / 4,031 | 9 | 31,281 / 10,019 / 804 / 1,264 / 874 | 8 | 291k |
| C8 | 7,012 / 4,031 | 9 | 4,169 / 2,147 / 172 / 256 / 42 | 8 | 50k |
| C64 | 7,012 / 4,031 | 9 | 5,233 / 2,147 / 228 / 368 / 42 | 8 | 60k |

**A240 `run` is refused** by `checkBwrapArgCount` (9,326 args > 9,000) at the very end of
`compile` - after the preflight has already run 120 `git` execs and 64,200 stats. S10/S11
at G=240 are therefore measured on B240, which launches. `validate` never walks nested
checkouts (by design - it says so in its output), so its N and C columns are flat.

Exec ledger for A1 `run`: bento, canary bwrap, its `sh`, **git**, bwrap, launcher, target
(`dash`, `true`), **git** = 9. Round 1's "5 execs" (bento, canary, sh, bwrap, launcher)
omitted the two `git rev-parse --git-path hooks` per write grant (`autoexec.go:132`), which
predate round 1 (63dee59 is an ancestor of 9f80de6). With W write grants the run execs
5 + 2W infrastructure processes.

`validate` A1: bento plus 9 probe execs - bwrap, sh, systemd-run x2, true, sh, grep, cut,
cat. `run` probes with 2 (bwrap, sh).

## Grid - `bento run`, per stage

Host process unless noted. Each cell: `stat / readlink / open / getdents / access` (zero
kinds dropped, named when ambiguous), execs, allocs (rounded; jitter under 0.1%), and the
seam calls that explain it as calls/distinct.

### G axis, layout A (each write grant its own checkout; G and R grow together)

| stage | A1 | A24 | A240 | complexity | verdict |
|---|---|---|---|---|---|
| S1 load | 23 / 1 / 13 open; 0.9k allocs | 23 / 1 / 13 open; 1.6k | 23 / 1 / 13 open; 9.0k | O(manifest) | ok |
| S2 resolve + `ManifestProblems` | 37 stat, 1 open; 0.1k | 236, 1 open; 0.9k | 2,180, 1 open; 8.2k | O(G), ~9 stat/grant | ok |
| S5 probe (`ProbeFor`) | host 32 / 2 / 2 open / 2 getdents / 18 access; 2 execs (bwrap, sh), 141 child syscalls; 0.3k | same; 0.5k | same; 2.2k | O(1) | ok |
| S5b trust walk, 2nd | 16 stat, 9 access; 78 allocs; writable 8/4 | same | same | O(1) | ok (round 1: not to cache) |
| S6 `newSandbox` + `findWorkspaceEntries` | 18 / 3 / 2 open / 2 getdents; 0.2k | 128 / 3 / 13 open / 24 getdents; 1.0k | 1,208 / 3 / 121 open / 240 getdents; 8.7k | O(W + tree) | ok |
| S4 assembly (in `newSandbox`) | 2,652 / 1,996 / 57 open / 114 getdents; 29.8k; resolve 639/639 | same | same | O(R), once | ok |
| S7 `checkGrants` (preflight) | 140 / 111 / 2 open; 1.3k | 1,692 / 1,332 / 24 open; 15.6k | 16,920 / 13,320 / 240 open; 155k | O(W x rules per checkout), 141 stat per checkout flat | ok (round-1 fixes hold) |
| S7 aliases + opt-ins | 629 / 34 / 50 open / 98 getdents; 8.0k | same | same | O(credential stores) | ok |
| S8a carvable (`createdShields` #1) | 47 stat, 13 access; 0.7k; exists 46/29, writable 13/2 | 432, 156 access; 6.8k; exists 420/216, writable 156/24 | 4,212, 1,560 access; 66k; exists 4,092/2,052, writable 1,560/240 | O(shields x depth) | **constant** |
| `prepareWriteDirs` | 1 stat | 12 | 120 | O(W) | ok |
| S8c auto-exec baseline | 59 / 0 / 5 open / 2 getdents / 1 access; 1 git (84 child syscalls); 0.4k; evalSymlinks 2/2 | 1,236 / 0 / 60 / 24 / 12; 12 git (1,008); 7.5k; evalSymlinks 90/24 | **64,200 / 0 / 600 / 240 / 120; 120 git (10,080); 340k; evalSymlinks 7,380/240** | **O(W^2)** | **scaling** |
| S8a `createdShields` #2 | 32 stat, 1 open; 0.4k; exists 30/28 | 241; 3.3k; 228/204 | 2,293; 30.6k; 2,172/1,932 | O(shields) | **repeat** |
| S8b `denyArgs` #1 (ancestors) | 32; 0.5k; exists 29/28 | 252; 3.5k; 216/204 | 2,412; 32.1k; 2,052/1,932 | O(shields) | **repeat** |
| S7 `checkGrants` (compile) | 4; 60 allocs | 60; 0.6k | 600; 5.7k | O(W) | ok |
| S9 symlinks + system mounts | 26; 0.3k; exists 25/13 | 48; 0.6k | 264; 3.0k | O(G) | ok |
| S9 `denyArgs` #2 | 30; 0.5k; exists 27/27 | 228; 3.2k; 192/192 | 2,172; 29.2k; 1,812/1,812 | O(shields) | **repeat** of S8b |
| S9 tail (`shieldChecks` + `shieldsApplied`) | 28; 0.4k; exists 28/14 | 336; 4.2k; 336/168 | 3,360; 41.6k; 3,360/1,680 | O(shields), 2 lstat per shield | **constant** |
| post-compile (`foldedWorkspaceExposure`, limits check) | 18; 0.3k | 216; 3.3k | refused: 13,440 stat reclaiming, 52.6k | O(W) | ok |
| S11 bwrap (child) | 257 / 298 / 82 open / 4 getdents, 70 mounts | 2,401 / 2,561 / 326 / 4, 391 mounts | not measurable (refused) | O(mount args) | ok (bwrap's own) |
| S11 launcher start + verify | 17 / 0 / 11 open / 18 getdents; 1.3k + 0.4k | 149 / 0 / 88 / 172; 1.3k + 1.1k | not measurable (refused) | O(applied shields) | ok |
| S10 Landlock | 5 stat + 5 open; 40 allocs | 16 + 16; 83 | not measurable (refused); B240: 124 + 124, 0.4k | O(W + 4) | ok |
| S8c auto-exec after | = baseline | = baseline | not measurable (refused) | O(W^2) | **scaling** |
| S12 reclaim | 112 / 0 / 2 open / 2 getdents; 0.5k | 1,344; 5.4k | not measurable (refused; failure-path reclaim above) | O(created shields x depth) | ok (security re-check) |

### G axis, layout B (write grants are plain subdirs of one checkout; R fixed)

| stage | B1 | B24 | B240 | complexity | verdict |
|---|---|---|---|---|---|
| S6 `findWorkspaceEntries` | 12 / 0 / 1 open / 2 getdents | 122 / 0 / 12 / 24; 0.9k | 1,202 / 0 / 120 / 240; 8.5k | O(W) | ok |
| S7 `checkGrants` (preflight) | 128 / 99 / 2 open; 1.2k | 206 / 99 / 2; 2.1k; exists 52/16 | 962 / 99 / 2; 9.9k; exists 484/124 | O(W) | ok |
| S8a carvable | 17; 0.2k | 50; 0.7k | 374; 4.7k | O(W) | ok |
| **S8c auto-exec baseline** | 44 / 0 / 4 open / 0 / 1 access; 1 git (88 child syscalls); 0.3k; evalSymlinks 2/2 | **1,584 / 0 / 48 / 0 / 12; 12 git (1,056); 8.8k; evalSymlinks 156/13** | **119,520 / 0 / 480 / 0 / 120; 120 git (10,560); 619k; evalSymlinks 14,520/121** | **O(W^2)** EvalSymlinks; O(W) git for 1 checkout | **scaling - worst cell** |
| S8a `createdShields` #2 | 15; 0.2k | 48; 0.6k | 372; 4.7k | O(W) | repeat (small here) |
| S8b `denyArgs` #1 | 15; 0.2k | 48; 0.7k | 372; 4.7k | O(W) | repeat (small here) |
| S7 `checkGrants` (compile) | 6; 86 allocs | 84; 0.9k; exists 48/13 | 840; 8.7k; exists 480/121 | O(W) | **constant** - costs 87% of the preflight pass |
| S9 symlinks + mounts | 26; 0.3k | 48; 0.6k | 264; 3.0k | O(W) | ok |
| S9 `denyArgs` #2 | 15; 0.2k | 48; 0.7k | 372; 4.7k | O(W) | repeat |
| S9 tail | 0 stat; 21 allocs | 0; 22 | 0; 25 | O(shields) = 0 here | ok |
| post-compile | 3; 45 allocs | 36; 0.5k | 360; 4.4k | O(W) | ok |
| S11 bwrap (child) | ~335 child syscalls | 339 / 595 / 144 open, 126 mounts | 2,473 / 4,673 / 542 open, 523 mounts | O(W) | ok |
| S11 launcher verify | 5 / 0 / 4 open / 4 getdents; 0.3k | same | same | O(applied shields) = O(1) here | ok |
| S10 Landlock | 5 stat + 5 open; 43 allocs | 16 + 16; 83 | 124 + 124; 0.4k | O(W + 4) | ok |
| **S8c auto-exec after** | = baseline | = baseline | = baseline (another 119,520 stat, 120 git, 619k) | O(W^2) | **scaling** |
| S12 reclaim | 0 stat, 2 open, 2 getdents; 76 allocs | same | same | O(created shields) = 0 here | ok |

At B240 the two auto-exec passes are **239,040 of the run's 250,905 host stats (95%)** and
**1.24M of its 1.36M allocations (91%)**, plus 240 `git` execs (12,240 child stats) that all
answer the same hooks path.

### Rule axis (G = 1; nested checkouts N, project config C)

| stage | N0 | N8 | N64 | C8 | C64 | per unit | verdict |
|---|---|---|---|---|---|---|---|
| S7 `checkGrants` (preflight) | 140 / 111 / 2 open; 1.3k | 1,356 / 1,095 / 18; 12.4k | 9,868 / 7,983 / 130; 89k | 220 / 111 / 2; 1.8k | 780 / 111 / 2; 4.5k | 152 stat + 124 readlink + 1.4k allocs per N, flat N8 to N64; 10 stat per C | ok - linear (c272f27 holds) |
| S8a carvable | 47 stat, 13 access; 0.7k; writable 13/2 | 399, 117; 6.0k; exists 398/165, writable 117/18 | 2,863, 845; 42k; exists 2,862/1,117, writable 845/130 | 55, 13; 0.9k | 111, 13; 1.5k | ~44 stat, 13 access per N | **constant** |
| S8a `createdShields` #2 | 32, 1 open; 0.4k | 256; 3.3k; 254/164 | 1,824; 22.8k; 1,822/1,116 | 40; 0.5k | 96; 1.2k | | **repeat** |
| S8b `denyArgs` #1 | 32; 0.5k | 184; 2.5k | 1,248; 16.7k | 56; 0.8k | 224; 2.8k | | **repeat** |
| S9 `denyArgs` #2 | 30; 0.5k | 158; 2.2k | 1,054; 14.4k | 46; 0.7k | 158; 2.0k | | **repeat** of #1 |
| S9 tail | 28; 0.4k; 28/14 | 252; 3.2k; 252/126 | 1,820; 22.6k; 1,820/910 | 44; 0.6k | 156; 1.9k; 156/78 | 2 lstat per shield | **constant** |
| S11 bwrap (child) | 283 / 324 / 116 open, 105 mounts | 1,891 / 1,924 / 276, 321 mounts | 13,147 / 13,124 / 1,396, 1,833 mounts | 467 / 676 / 148, 137 mounts | 1,755 / 3,140 / 372, 361 mounts | ~200 stat + 200 readlink per N | ok (bwrap's own, O(mounts)) |
| S11 launcher verify | 17 / 0 / 11 / 18 getdents; 0.4k | 118 / 0 / 75 / 130; - | 785 / 0 / 459 / 914; 4.6k | 17 / 0 / 11 / 18 | 17 / 0 / 11 / 18 | ~12 stat + 14 getdents per N | ok (O(applied shields)) |
| S10 Landlock | 5 + 5 | 5 + 5 | 5 + 5 | 5 + 5 | 5 + 5 | flat (W = 1) | ok |
| S12 reclaim | 112 / 0 / 2 / 2; 0.5k | 1,112; 4.5k | 8,112; 31.9k | 112; 0.5k | 112; 0.5k | ~125 stat per N | ok (security re-check) |
| whole run, host + launcher | 4,017 / 2,147 / 164 / 240 / 42 access; 48.6k | 7,427 / 3,131 / 245 / 369 / 146; 79k | 31,281 / 10,019 / 804 / 1,264 / 874; 291k | 4,169 / 2,147 / 172 / 256 / 42; 50k | 5,233 / 2,147 / 228 / 368 / 42; 60k | ~427 stat + 123 readlink + 3.8k allocs per N; ~19 stat per C | ok - linear |


### Run-wide seam calls vs distinct paths

The same host question asked again from the same inputs. `resolve` is memoized run-wide
(`alias.go:197`), so its ratio is 1.0; the other seams are not.

| fixture | `exists` | `isDir` | `writable` | `bounded` goroutines+timers |
|---|---|---|---|---|
| A1 | 207 / 33 (6.3x) | 206 / 196 | 36 / 9 | 1,622 |
| A24 | 1,549 / 253 (6.1x) | 382 / 262 | 179 / 31 | 3,856 |
| A240 | 14,605 / 2,413 (6.1x) | 1,990 / 910 | 1,583 / 247 (6.4x) | 29,091 |
| N8 | 1,319 / 193 (6.8x) | 262 / 236 | 140 / 25 | 3,022 |
| N64 | 9,103 / 1,313 (6.9x) | 654 / 516 | 868 / 137 (6.3x) | 12,822 |
| B240 | 2,371 / 257 | 1,273 / 313 | 23 / 7 | 34,337 (29,040 of them autoexec) |

## Grid - `bento validate`, per stage

| stage | A1 | A24 | A240 | complexity | verdict |
|---|---|---|---|---|---|
| S1 load | 23 / 1 / 13 open; 0.9k allocs | same; 1.6k | same; 9.0k | O(manifest) | ok |
| S3+S4 `gate.Check` (assembly #1 + Refusals #1 + aliases) | 3,661 / 2,026 / 107 open / 212 getdents; 25.9k allocs; `S.assemble` 1, resolve misses 644 | 4,614 / 2,026 / 107 / 212; 29.6k | 13,794 / 2,026 / 107 / 212; 64.6k | O(R) + 41 stats/grant | **repeat** (see S3/S4 below) |
| S5 probe | 9 execs (bwrap, sh, systemd-run x2, true, sh, grep, cut, cat); host 52 / 5 / 4 open / 0 / 52 access; 0.5k allocs; children 322 syscalls | same | same | O(1) | **constant** - 7 execs serve limits layers a zero-limits manifest does not require |
| S3+S4 summary (assembly #2 + Refusals #2) | 3,274 / 1,999 / 57 open / 114 getdents; 23.7k allocs; `S.assemble` 1, resolve misses 637 | 4,576 / 1,999 / 57 / 114; 28.9k | 16,996 / 1,999 / 57 / 114; 78.5k | O(R) + 57 stats/grant | **repeat** |
| total | 7,012 / 4,031 / 185 / 326 / 52 access; 9 execs; 52.6k allocs | 9,267 / 4,031 / 185 / 326 / 52; 9; 62.3k | 30,867 / 4,031 / 185 / 326 / 52; 9; 155k | O(R + G) | linear; ~half is the repeat |

Within each assembly stage, `ShieldCarveProblems` issues one following `stat` per mounted
rule before its reachability test: 734 following stats in the summary stage at A1, of which
189 are the assembly's own `isDir`, leaving ~545 against ~R rules - with one write grant
that reaches none of them. Twice per validate, so ~1,090 of its 7,012 stats.

## Findings, ranked

Rank: scaling on a hot path, then constant on a hot path by magnitude, then the rest.

**1. Auto-exec hook resolution is O(W^2) and runs git once per write grant, twice per run.**
(Class: **scaling, hot** - every `bento run` with write grants.) `hookRunnerDir`
(`internal/linux/autoexec.go:124`) is called once per write grant by `hookRunnerDirs`
(`:300-302`), and inside it `for _, w := range writes { filepath.Rel(resolved(w), dir) }`
(`:161-162`) re-resolves every write grant - each `resolved` a `bounded` goroutine plus a full
`EvalSymlinks` - until one covers the hooks dir. When the hooks dir is under no grant
(layout B: grants inside one checkout) the loop runs to the end for every grant: W + W^2
EvalSymlinks per pass. Both passes run: the baseline (`linux.go:152`) and `changed`
(`autoexec.go:217`).
Measured EvalSymlinks per pass: B1 2, B24 156, B240 **14,520**; A1 2, A24 90, A240 7,380
(W + W(W+1)/2). At B240 the two passes are 239,040 host stats (95% of the run), 1.24M
allocs (91%), and 240 `git rev-parse` execs for **one** distinct checkout.
The `git` exec is `O(W)` where `O(checkouts)` is what the answer depends on - a second,
constant half of the same finding.
*Fix sketch:* resolve `writes` once per `hookRunnerDirs` call and pass the resolved slice
down - safe, since it stays per pass and keeps the before/after freshness. Keying the `git`
answer by checkout root is the riskier half: bento's `checkoutRoot` can disagree with git's
own discovery (a `.git` file, a nested checkout, `core.worktree`), so the dedup key has to
match what git would answer. The O(W^2) half is unambiguous; the dedup half needs that key.
*Red-first count test:* in package `linux`, replace `evalSymlinks` (already a var,
`autoexec.go:188`) with a counting wrapper; call `hookRunnerDirs` over W=8 and W=64 plain
subdirectories of one `git init`'d temp checkout; assert `calls(64) <= 8 * calls(8) + c`
(linear). Today it is 4,160 vs 72. For the git half, put a counting `git` shim first on
`PATH` and assert one exec per distinct checkout.

**2. `validate` assembles the shield set twice, and computes the grant refusals twice.**
(Class: **constant, hot** on the `validate` path - also the CI gate path.) `gate.Check`
reads `shieldSet` (`gate/gate.go:174`, a var over `ShieldSet` at `:567`, no memo), and
`writePolicySummary` then calls `commandShieldSet()` (`cmd/bento/validate.go:984`), whose
memo (`cmd/bento/render.go:403`) the gate never consulted - so `shield.Host()`'s per-FS
resolve memo (dced93f) is built twice: **1,281 resolve misses for 644 distinct paths**,
3,661 + 3,274 stats and 2,026 + 1,999 readlinks, ~29k allocs each. The summary then
recomputes `ShieldedReadProblems` / `ShieldedWriteProblems` / `ShieldCarveProblems`
(`validate.go:985-996`) on the same set and grants that `gate.Check`'s `Refusals`
(`gate.go:362`) already answered: 41 + 57 stats per grant. The same "memo exists, sibling
call site does not consult it" shape round 1 found three times.
*Red-first count test:* no existing seam reaches it from `cmd/bento`: `gate`'s `shieldSet`
var (`gate.go:546`) is unexported, and wrapping `gate.ShieldSet` does not reach the call
`Check` makes internally. The fix has to add the seam - e.g. `gate.Check` taking the set, so
`validate` passes `commandShieldSet()`'s answer (its callers are `validate.go:77` and
`examples/embed/main.go:157`). The test then counts assemblies through a counting
`commandShieldSet` stand-in across one validate command and asserts 1. Today: 2.

**3. `validate` runs the full `Probe`, limits half included, for a manifest with no limits.**
(Class: **constant, hot** on `validate`.) `probeHost` calls `e.Probe(ctx)`
(`cmd/bento/validate.go:475`), while `hostPosture` reads only
`enforce.RequiredLayers(p, ...)` (`validate.go:414-416`). The `run` path was fixed to
`ProbeFor` in af0664c; `validate` was not carried. 9 probe execs per validate, of which 7
(systemd-run x2 with their D-Bus round trips, `true`, `sh`, `grep`, `cut`, `cat`) answer
limits layers a zero-limits manifest never reads. `run` probes with 2.
*Red-first count test:* `probeHost` (`validate.go:470`) is the var that contains the `Probe`
call under test, and `backend.New` (`backend/backend_linux.go:32`) is a plain func, so no
existing seam can observe which layers are asked for. The fix has to add one - e.g.
`probeHost` taking the required layers and a backend constructor var - and the test hands it
a fake `ProbeFor` that records its layers, runs validate on a zero-limits manifest, and
asserts no `LayerLimits*` was requested and `Probe` was not called.

**4. The host `exists` / `writable` / `isDir` seams have no run-wide memo, and three
derivations run twice from the same inputs.** (Class: **constant, hot** - linear, but 6-7x
per distinct path on every run.) Only `resolve` is memoized run-wide (`alias.go:197`); every
`exists`/`isDir`/`writable` call is a fresh `bounded` goroutine, timer and string concat
(`alias.go:52-72`, `:171-190`) plus the syscall. `probedOnce` (`shields.go:703`) memoizes
inside one `denyArgs` call only (`:585`), so its answers are discarded and recomputed:
- `denyArgs` runs twice: `createShieldAncestors` (`linux.go:172`) and `compile`
  (`args.go` `denyArgs` call) - A240 2,052 then 1,812 exists; N64 1,117 then 923.
- `createdShields` runs twice: `checkShieldsCarvable` (`linux.go:775` -> `shields.go:821`)
  and `linux.go:159` - A240 4,092 then 2,172; the carvable walk also re-asks `writable` on
  the same parents (`shields.go:828-831`): 1,560 calls for 240 dirs.
- `compile`'s tail asks every applied shield twice more: `shieldChecks` via `shieldMount`
  and `shieldsApplied` (`shields.go:46`) - A240 3,360 calls for 1,680 paths.
Run-wide: A240 **14,605 exists for 2,413 paths**, N64 9,103 for 1,313, and 29,091 / 12,822
`bounded` goroutines. Caveat for the fix: bento itself mkdirs between these stages
(`prepareWriteDirs`, `createShieldAncestors`), so a run-wide `exists` memo must be keyed or
invalidated the way the `resolve` memo and `workspaceShieldCache` are, not simply cached.
*Red-first count test:* a sandbox literal with a counting `exists` fake over a tree with N
nested checkouts; run `preflightGrants` + `createdShields` + `createShieldAncestors` +
`compile`; assert `exists` calls <= distinct paths + bento's own mkdirs. Today ~6-7x.

**5. `ShieldCarveProblems` stats every mounted rule before its pure reachability test.**
(Class: **constant**, `validate` path.) `gate/gate.go:733`: `if _, err := os.Stat(mount);
err == nil || !reachableFrom(mount, resolved)` - the syscall is evaluated first, so each call
pays ~R stats even when no write grant reaches any rule. ~545 per call, 2 calls per validate
(`gate.go:370`, `validate.go:996`). 803ff2c ("probe each shield path once, after pure
checks") fixed this ordering in `internal/linux`; the gate copy kept it.
*Red-first count test:* `testing.AllocsPerRun` over `ShieldCarveProblems` with a set of ~500
rules under a temp dir and one write grant that reaches none: `os.Stat` allocates per call,
so today allocs include at least one per rule. `set.Mount(set.Rules())`,
`pathresolve.Existing` and the opt-in build allocate either way, so assert that allocations
drop by at least R against the pre-fix figure, not that they reach zero.

**6. A run over the bwrap argument ceiling is refused only after the whole preflight.**
(Class: constant, failure path.) `checkBwrapArgCount` sits at the end of `compile`
(`args.go:514`); A240 paid 120 git execs, 64,200 baseline stats and 13,440 reclaim stats
before being refused at 9,326 args. Low rank: it is the refusal path, not a launch.

### Explicitly not findings

- **Landlock re-stats the write grants - on the full tier, inside the sandbox**
  (`landlock_linux.go:319`): W + 4 stats and opens (5 / 16 / 124). It runs in the sandbox's
  own mount namespace, where the host-side answers do not apply, and `go-landlock` needs the
  O_PATH open per rule anyway. O(W), needed per namespace. **The verdict depends on the
  tier:** on the degraded tier `degradedRules` (`:459`) and `existing` (`:569`) run in the
  host's own namespace, after the host side has already resolved the same grants, so there
  the suspicion is true - a real duplicate of W + k stats. Read from code, not run (no
  degraded fixture here); small, and not on the default launch path.
- **bwrap argv compile's own helpers**: `hostResolve` is memoized run-wide; the un-memoized
  `hostExists`/`hostIsDir`/`hostWritable` are finding 4. `hostRootDirs` ran 0 times (no `/`
  grant) and is enumerated once per compile by design (`args.go:299`).
- **`resolveBwrap`'s trust walk twice per run** (15 + 8 `access`): round 1 ruled out caching
  the provenance walk without a decided window.
- **Shield reclaim** (`parentResolved`, `shields.go:985`): one `EvalSymlinks` per created
  shield path, ~13 lstats each at this depth. It is the symlink-swap guard before an
  `rmdir`; memoizing it changes the window. Linear.
- **bwrap's own per-mount cost** (~7 stat/readlink per mount argument) scales with the argv
  bento hands it; not bento code.

## Reconciliation with round 1 and the second batch

| fix | holds at HEAD? | evidence |
|---|---|---|
| `aa5e915` shield `loc` memo / `2575e34` `Contains` allocations | **holds** | `checkGrants` is linear: A1 -> A24 -> A240 host stats 140 -> 1,692 -> 16,920 (12.1x, 10.0x for 12x, 10x checkouts); no G x R product. Zero-alloc per `Contains` not isolatable at stage granularity |
| `c272f27` `insideDirShield` ancestor lookup | **holds** | `checkGrants` per nested checkout 152 stats flat from N8 to N64; no N^2 term |
| `dced93f` `shield.Host()` memoizes Resolve per FS | **holds within one FS; not carried across** | `validate` builds two `Host()` FSes (finding 2): 1,281 misses / 644 distinct |
| `af0664c` one `Probe` per run, `ProbeFor` | **holds for `run`; not carried to `validate`** | run: 1 canary, 2 probe execs, no `run.probe` stage work; validate: full probe, 9 execs (finding 3) |
| exec ledger "5 execs for a zero-limits run" | **incomplete** | 5 + 2 per write grant (`git rev-parse`, predates round 1) + target = 9 at A1; 30 at W=12, 246 at W=120 |
| `f9fc978` gate anchors resolved through the set | **holds** | `bento validate examples/agent/agent.manifest.yaml`, unfiltered `strace -f -c`: 7,168 + 4,031 + 313 + 330 = 11,842 stat/readlink/open/getdents vs 11,728 recorded (host drift, same order) |
| `f0b1cc8` `Relocated` ancestor index | **holds (indirect)** | assembly is 29.8k allocs and 2,652 stats in every fixture, flat across G, N, C |
| `26641f5` clamp `Home(root)` per grant | not on this path | `clamp.go` is not reached by `validate` or `run` |
| `deb4c98` alias dedup / unwalked grants | holds (correctness) | alias stage flat at 629 stats across all fixtures |
$1| `76d98c5` gate anchor-walk bound | holds, no count delta expected | round 1 itself recorded no count change on a normal home; the alias stage is flat at 629 stat / 98 getdents in every fixture, far inside the allowance |
| `c6ed833` per-run `sb.resolve` memo | **holds** | `resolve` calls equal distinct paths at every scale: A1 674/674, A24 851/851, A240 2,579/2,579, N64 1,570/1,570. This also settles round-1 findings 6, 8 and 9 (`checkWriteNotUnderReadOnlyShield`, `shieldRules`, `checkWorkspaceShieldNotRedirected` resolve counts), which the second batch reclassified as memo hits: they are map hits here too |
| `aa5e915` like-for-like: `validate` with 24 write trees | **holds, and lower** | round 1 at `aa5e915`: 13,141 `newfstatat` + 4,935 `readlinkat` (from 81,866 + 21,173). HEAD, same method (unfiltered `strace -f -c`, 24 write grants, twice, identical): **10,391 + 4,031**. Per write grant on `run`, round 1's ~21,000 syscalls are now ~141 stat + 111 readlink per checkout in `checkGrants` |

## Cells not measured, and why

- **A240 S10 / S11 / S12 (launch half)**: not measurable because `checkBwrapArgCount`
  refuses A240 at 9,326 args (> 9,000); B240 measures S10/S11 at G=240.
- **`validate` on the N and C axes**: flat by design - `validate` does not walk nested
  checkouts or project config (it says so in its output).
- **Wall time, everywhere**: shared machine; none taken.
- **Per-call allocs of a `bounded` seam call**: not isolated; the stage malloc deltas
  include the work around them. Finding 4's count test counts calls, not allocs.
- **Limits-bearing manifests, degraded tier (`RestrictDegraded`/`degradedRules`,
  `execAllowlistRules`)**: not on the default launch path measured here; `degradedRules`
  and `execAllowlistRules` share `classifyRules` with the backstop (O(paths) stats) and were
  read, not run.
- **Cold page cache**: shared machine.
