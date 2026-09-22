# Perf grid: per-run probe and resource-limit preflight

Base commit `9f80de6` (measured detached in an isolated worktree; the binary was
`make build` at that SHA). perf-hunt Phases 0-3 only - **no fixes applied**, Phase 4 is
the orchestrator's.

Host the numbers come from: bwrap present, user namespaces usable, a healthy systemd
user manager (`systemd-run --user --scope /bin/true` exits 0), cgroup v2 unified,
Landlock present. Counts on an unhealthy-manager host differ (see "Cells not measured").

Measurement method: `strace -f -qq -e trace=execve` over one real invocation. argv
attributes every exec to its stage with no instrumentation, so **nothing was added to
the tree and nothing needed deleting**. Syscall classes from `strace -c -f`.

## Phase 0 - fit check

Fit: **accepted, with the scaling axis declared vacuous.**

Nothing on this path iterates a user-sized input. `namespaceFlags`, `pseudoFSFlags`,
`sessionFlags` are fixed lists; `measureDelegatedControllers` reads a bounded controller
set; no grant, path, rule or manifest list enters `Probe` or `preflightLimits`. The path
is O(1) in manifest size, so **the scaling half of the invariant is satisfied by
construction and every finding here is of the "constant" or "repeat count" kind.**

The depth axis is therefore **configuration**, not size: {validate/doctor} x {run,
zero limits} x {run, limits set}. That is the grid the question actually asks - how many
fork+exec a launch pays before the target starts, and what is probed twice.

No benchmark reaches this path and none was written: a Go benchmark cannot exec bwrap
and systemd-run thousands of times meaningfully, and the deliverable is a *count*, which
one straced invocation gives exactly and deterministically.

## The measured exec ledger

Every `execve` in one invocation, in order. `/bento` (the in-sandbox launcher) is the
first exec of the target's own stack; everything above it is preflight.

| # | exec | stage | `validate` / `doctor` | `run` (no limits) | `run` (limits set) |
|---|------|-------|---|---|---|
| 1 | `bento` | the CLI itself | 1 | 1 | 1 |
| 2 | `bwrap --unshare-... --bind / /` | `canUnshare` (probe round 1) | 1 | 1 | 1 |
| 3 | `sh -c 'read _ _ n < /proc/self/uid_map...'` | that probe's canary | 1 | 1 | 1 |
| 4 | `systemd-run --user --scope -p MemoryMax=64M -- /bin/true` | `measureScope` -> `runScopeProbe` | 1 | 1 | 1 |
| 5 | `/bin/true` | that scope's canary | 1 | 1 | 1 |
| 6 | `systemd-run --user --scope -p MemoryMax=64M -p TasksMax=64 -p CPUQuota=100% -- sh -c ...` | `measureDelegatedControllers` | 1 | 1 | 1 |
| 7 | `sh -c` the controllers snippet | that scope's snippet | 1 | 1 | 1 |
| 8 | `grep ^0:: /proc/self/cgroup` | inside the snippet | 1 | 1 | 1 |
| 9 | `cut -d: -f3` | inside the snippet | 1 | 1 | 1 |
| 10 | `cat /sys/fs/cgroup/.../cgroup.controllers` | inside the snippet | 1 | 1 | 1 |
| 11 | `bwrap --unshare-... --bind / /` | **`canUnshare` (probe round 2)** | - | 1 | 1 |
| 12 | `sh -c 'read _ _ n < /proc/self/uid_map...'` | **round 2's canary** | - | 1 | 1 |
| 13 | `systemd-run ... -p MemoryMax=128M -- /bin/true` | `preflightLimits` -> `runScopeProbe` | - | - | 1 |
| 14 | `/bin/true` | that canary | - | - | 1 |
| 15 | `systemd-run ... -p MemoryMax=128M ...` | the REAL scope wrapper | - | - | 1 |
| 16 | `bwrap --die-with-parent --new-session ...` | the REAL sandbox | - | 1 | 1 |
| 17 | `/bento __bento_launch ...` | the launcher (target's stack begins) | - | 1 | 1 |
| | **total execve** | | **10** | **14** | **17** |
| | **execs before the real launch stack begins** (row 16 / row 15) | | 10 | **12** | **14** |
| | of which are host probing | | 9 | **11** | **13** |

So the answer to "how many fork+exec does one `bento run` pay before the target starts":
**12 on a zero-limits manifest, 14 with limits - of which 11 and 13 respectively are
host probing rather than launching.**

Reproduce: `strace -f -qq -e trace=execve -o out ./bento run <manifest> --allow-unapproved`
then `grep -c 'execve(' out`.

## Phase 1/2 - the grid

Rows are the stages read out of the code, not guessed. "Runs per `bento run`" is the
column the question singles out.

| stage (file:line) | runs per `bento run` | execs/forks per call | syscalls per call | filesystem ops per call | allocs | complexity |
|---|---|---|---|---|---|---|
| `(*Enforcer).Probe` `probe.go:63` | **2** (`enforce/run.go:152` and `internal/linux/linux.go:116`) | 9 on call 1, **2 on call 2** | ~12 landlock + 2 seccomp + ~45 `faccessat` per call | ~6 `EvalSymlinks` + per-component write walks per call | not isolated | O(1) |
| `usableNamespaces` `probe.go:596` -> `canUnshare` `probe.go:626` | **2** - **uncached** | **2 (bwrap + sh), both times** | full userns/mountns setup + teardown, twice | `LookPath` bwrap + `LookPath` sh + 2 trust walks, twice | n/a | O(1) |
| `resolveBwrap` `probe.go:530` + `trustLauncherPath` `probe.go:571` | 2 from Probe, +1 at `linux.go:118`, +1 at `profile.go:65` | 0 | `faccessat(W_OK)` once per path component | `EvalSymlinks` + component walk, **uncached** | n/a | O(path depth) |
| `shBinary` `limits.go:480` -> `trustedProbeBinary` | **4** per run (2x `canUnshare`, 1x `measureDelegatedControllers`, +1 if degraded) | 0 | same per-component walk | **uncached**, same answer every time | n/a | O(path depth) |
| `measureScope` `limits.go:132` (via `scopeProbe` = `cacheProbe`) | 1 (memoized) | **2** (systemd-run + `/bin/true`) + 1 D-Bus round trip | - | `LookPath` systemd-run + trust walk + `trueBinary` walk | n/a | O(1) |
| failure canary `limits.go:171` | 0 on a healthy host, **1 extra exec** on a manager that refused | 1 | - | `trueBinary` walk | n/a | O(1) |
| `measureDelegatedControllers` `limits.go:400` (memoized) | 1 | **5** (systemd-run, sh, grep, cut, cat) + 1 D-Bus round trip | - | `unifiedCgroupReadable` (OnceValue: 1 read + 1 stat) | n/a | O(1) |
| landlock capability probes `probe.go:30-39` -> `effectiveABI` | **6 funcs x 2 Probes = 12**, +6 more on the degraded tier (`degraded.go:420`) | 0 | **12 `landlock_create_ruleset`** per Probe (2 per call: ABI + errata), **uncached** | 0 | ~0 | O(1) |
| seccomp capability probes `probe.go:34-37` | 4 per Probe | 0 | 2 `seccomp` + `prctl`s | 0 | ~0 | O(1) |
| `autoExecReportLayer` `probe.go:133` | 2 | 0 (LookPath only) | PATH walk | `LookPath("git")` | small | O(PATH entries) |
| `preflightLimits` `limits.go:230` -> `runScopeProbe` `limits.go:255` | 1, only when `!p.Limits.IsZero()` | **2** + 1 D-Bus round trip | - | `resolveScopeRunner` walk + `trueBinary` walk | n/a | O(1) |

## Phase 3 - verdicts, ranked

The invariant's scaling half holds everywhere (all cells O(1)). Everything below is the
constant half or the repeat-count half.

### 1. `Probe` runs twice per `bento run`, from identical inputs - **constant / repeat, hot path**

`enforce/run.go:152` computes `probed` for admission; `internal/linux/linux.go:116` then
calls `e.Probe(ctx)` again to seed the run's report, and `enforce.Run` never hands the
first result to the backend. `Probe` takes only a `context.Context`, so the two calls
cannot differ. On the degraded tier it is the same shape at `degraded.go:416`.

Only the limits half is protected: `scopeProbe` and `cachedDelegatedControllers` go
through `cacheProbe` (`limits.go:63`), so round 2 skips them. `usableNamespaces` has no
such memo, so **round 2 still pays a full bwrap fork+exec that builds and tears down a
user/mount/pid/uts/cgroup/net namespace, plus its `sh` canary** - execs #11 and #12
above, measured on every run.

Cause: `probe.go:69` calls `usableNamespaces(ctx)` directly, with no `cacheProbe`
wrapper, unlike its two siblings at `:97` and `:111`.

Two independent fixes exist and the orchestrator should pick one, not apply both
blindly: wrap `usableNamespaces` in `cacheProbe` (matches the file's own established
pattern, and fixes `doctor` + `validate` + `profile` too), or thread the
already-computed report from `enforce.Run` into `RunOptions`. The memo is the smaller
diff; note it caches a host verdict for the process lifetime, which `cacheProbe`'s own
doc comment already argues is correct for a definitive answer.

### 2. A zero-limits manifest pays 7 execs and 2 D-Bus round trips for a reading it discards - **constant, hot path**

`probe.go:97-116` calls `canCreateScope` and `delegatedControllers` **unconditionally**.
But `requiredLayers` (`enforce/run.go:461-469`) adds `LayerLimits*` only when the policy
names a limit, `probed.forLayers(wanted)` drops them, and `res.Report = required`
(`enforce/run.go:228`) is what the caller sees. For the commonest manifest shape - no
`limits:` block - **execs #4 through #10 produce a verdict nothing reads.**

That is 7 of the 14 execs of a zero-limits run, and both systemd D-Bus round trips.
Combined with finding 1, **9 of 14 execs on a zero-limits `bento run` are avoidable**.

Both other run-path consumers of the limits reading were checked and neither keeps it
alive on a zero-limits manifest: `screenRunID` (`limits.go:585`) returns before
`canCreateScope` when the run id is empty and refuses outright when `p.Limits.IsZero()`,
and `noteScopeLimits` (`scopeattest.go:183`) skips every controller `c.requested(l)`
rejects. So all 7 execs really are unread, not just the 5 controller ones.

Caveat the orchestrator must respect: `bento doctor` legitimately needs these layers
unconditionally - it exists to report them - so the fix is laziness at the `Probe` call
site, or a `Probe` variant taking the wanted layer set, **not** deleting the probe.
Getting this wrong fails open on a limits manifest, which is the bug `cacheProbe`'s and
`hostSafetyDelegationState`'s comments are both written around.

### 3. `effectiveABI` is uncached: 12 `landlock_create_ruleset` per Probe - **constant, hot path, cheap**

Measured: exactly 12 `landlock_create_ruleset` in one `bento validate`. Six probe
functions (`Available`, `TruncateRestricted`, `IoctlDevRestricted`,
`ResolveUnixRestricted`, `NetTCPRestricted`, `ScopedIPCRestricted`) each call
`detectedABI` (`landlock_linux.go:684`), which issues `LandlockGetABIVersion` plus
`LandlockGetErrata`. The kernel ABI cannot change within a process, so the honest count
is 2. Doubled by finding 1, and the degraded tier calls all six a third time at
`degraded.go:420`.

Low value on its own - these are microseconds - but it is nearly free to fix. Note
`effectiveABI` is already a `var` for testability, so a `sync.OnceValue` must go
**behind** the var, not in front of it, or the tests that construct an ABI-0 host break.

### 4. The provenance walk is repeated 4-6x per launch - **constant, hot path, cheap**

`trustedProbeBinary` (`limits.go:510`) -> `trustLauncherPath` (`probe.go:571`) does
`EvalSymlinks` plus a `faccessat(W_OK)` per path component, and is uncached.
`shBinary()` alone resolves the same `/bin/sh` four times per run (twice from
`canUnshare`, once from `measureDelegatedControllers`); `trueBinary()` twice;
`resolveBwrap` three to four times. Measured: 45 `faccessat` across one `bento validate`
- a whole-process `strace -c` figure, not attributed per trust walk.

Cheap in syscalls, but this is a *security* check, so memoizing it changes when a
planted binary would be noticed within one process lifetime. Flagged as a finding and
explicitly **not** recommended for a blind fix - it needs the security argument made, or
it should be left alone.

### 5. `bento profile` duplicates the resolution work `Probe` just did - **constant, cold-ish path**

`profile.go:484` calls `Probe`, then `profile.go:65` `resolveBwrap`, `:78`
`canCreateScope`, `:89` `delegatedControllers`, `:211` `preflightLimits`. The last three
are memoized so they cost nothing; `resolveBwrap` redoes the trust walk. Measured: a
profile invocation paid the same 9 probe execs as `validate`. Lowest rank - profiling is
not a hot path.

## Cells not measured, and why

- **Degraded tier (`degraded.go:416`, `:193`).** Reaching it needs a host where user
  namespaces are blocked; this host's work. Read from the code it is finding 1 plus a
  third round of all six landlock probes at `degraded.go:420`, but the exec count is
  **unverified**.
- **Unhealthy systemd user manager (`limits.go:171`).** On a manager that refuses the
  scope, `measureScope` runs an *extra* bare `/bin/true` to separate "no scope" from
  "canary will not run". Not reproduced - this host's manager answers. Code-read cost:
  +1 exec, and because `cacheProbe` deliberately does not memoize a non-answer, **that
  whole limits probe repeats on every call on such a host** - so finding 2's 7 wasted
  execs become 7 wasted execs *per Probe*, i.e. 14 per run. That is the worst cell in the
  grid and it is the one nobody can see on a healthy machine.
- **Allocations.** Not isolated per stage. Allocation is not the cost class that matters
  here - execs dominate by orders of magnitude - and isolating them needs exactly the
  instrumentation this grid deliberately avoided.
- **Wall time - the only remaining evidence for the real cost.** Three other measurers
  were running concurrently, so no wall time was taken and none should be read from this
  file. It matters more here than the exec count suggests: each bwrap probe is
  fork + exec + namespace construction + teardown + a second exec, and each systemd-run
  probe is a **D-Bus round trip to the user manager**, which is a different order of
  magnitude from a fork. `scopeProbeTimeout` is 5s and `probeWaitDelay` 1s, so on a busy
  or restarting manager these constants stop being microseconds and become a visible
  stall before the target starts. **Whoever applies the fixes should take a serialized
  before/after wall-time measurement of `bento run` on a zero-limits manifest** - that is
  the number a user feels, and this grid does not contain it.
