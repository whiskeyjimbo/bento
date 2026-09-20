# State grid: the launcher's restrictions and the order they are applied

Area: `internal/launcher/launcher.go` (bwrap tier) against `internal/launcher/degraded.go`
(`RunDegraded`, `degradedPrerequisites`, `restrictDegraded`), plus the host-side halves the
two tiers assemble their restriction sets in - `internal/linux/args.go` (`baseFlags`,
`namespaceFlags`, `pseudoFSFlags`) and `internal/linux/degraded.go` (`runDegraded`,
`degradedSystemPaths`, `degradedProbe`).

Out of scope by instruction: the wire codec (`EncodeLaunch*`/`DecodeLaunch*`) and the shape
of the applied report. Restrictions and their sequence only.

Date: 2026-09-18. Dimensions derived from the code, not from git history or the tracker.

## Phase 0 - fit

**Good fit.** Two strong signals and a one-sided invariant:

- A mirror pair named in the code itself: `degraded.go:97` ("restrictDegraded is the mirror
  of those three"), `degraded.go:135` ("Order mirrors the bwrap launcher").
- A tier/config surface (bwrap vs degraded, block vs none-strict, Landlock ABI floors)
  that multiplies against the restriction set.

Caveat stated up front: several cells need a host this session does not have (userns-blocked,
root, pre-6.10 kernel), so they are read-verified. The seam vars at `degraded.go:103-112` and
the `applyLayers` split at `launcher.go:280` buy back more execution than that implies, and
two of the three spikes below run on this host.

**Invariant (one-sided).** The degraded tier may DROP a restriction the bwrap tier applies,
but only where the drop is structurally forced by the absent bwrap AND is recorded. It must
never apply a shared restriction in an order that leaves a window the bwrap tier does not
have, and never drop one silently.

### What "recorded" means here

The code has three disclosure channels and one non-channel, and `degraded.go:88-95` is
explicit that `blockEgress` / `blockProcessReach` / `blockTerminalInjection` have no report
line at all. So the state axis is defined as:

- **A - APPLIED IN BOTH**: parity, or a substitute of comparable reach.
- **B - DROPPED, RECORDED**: a machine-readable channel the host reconciles - an applied
  report line, `degradedProbe`'s `LayerFilesystem`/`LayerNetwork` rewrite
  (`internal/linux/degraded.go:386-399`, text built in `probe.go:249`), or
  `Exposed`/`ShieldedGrants` on the `Result`.
- **C - DROPPED, FATAL-ONLY**: no record, but the call is fatal and the report marker is
  therefore the attestation (`degraded.go:88-95`, pinned by
  `TestRunDegradedRefusesWithoutTheRealFences`).
- **D - DROPPED SILENTLY**: neither recorded nor fatal. **This is the forbidden direction.**

A code comment is not a channel. Several residuals below are documented only in a comment
and are counted as D.

## Grid A - restriction x state (13 x 4 = 52 cells, all walked)

Each cell carries exactly one verdict. "IMPOSSIBLE" means that state cannot arise for that
restriction and names the mechanism.

| # | Restriction | A applied-both | B dropped+recorded | C dropped+fatal-only | D dropped silently |
|---|---|---|---|---|---|
| 1 | Filesystem fence (mount ns + binds + deny-list vs Landlock path ruleset) | HANDLED - `args.go:234` compile / `degraded.go:232` `restrictDegraded`; both confine, by different mechanisms | HANDLED - the shield/mount-ns half IS dropped and recorded: `probe.go:279` Consequences "no mount namespace...", plus `Exposed` (`internal/linux/degraded.go:130`) and `ShieldedGrants` | IMPOSSIBLE - it has a report line (`AppliedLandlock`, `degraded.go:235`), so this is not the no-record case | HANDLED (no silent drop) - the alias, grant-safety and write-shield checks are shared (`internal/linux/degraded.go:52-60`) so the manifest cannot mean two things |
| 2 | Network / egress fence (netns + bridge vs seccomp egress block) | HANDLED - `args.go:303` `--unshare-net` / `degraded.go:209` `blockEgress` | HANDLED - netns absence recorded at `internal/linux/degraded.go:395` (`LayerNetwork` to Unavailable with the reason) | HANDLED - `blockEgress` itself has no report line and is fatal (`degraded.go:209-211`); the coupling that leans on is a deliberate design, see the dismissals | HANDLED (no silent drop) - unix-socket and netlink residuals are in the Consequences text (`probe.go:367-381`) |
| 3 | PID ns / cross-process reach | HANDLED - `args.go:501` `--unshare-pid` / `degraded.go:216` `blockProcessReach` + Landlock signal scope (`landlock_linux.go:429`) | HANDLED - `probe.go:280-285` names the shared process table, the group sweep and the setsid escape | HANDLED - `blockProcessReach` fatal, no report line (`degraded.go:216-218`) | HANDLED - the one residual (`/proc/<pid>/cmdline`) is named at `seccomp_linux.go:121-127`; the SysV-IPC sibling is row 11, finding F3 |
| 4 | exec-block seccomp filter | HANDLED - one shared `installExecFilter` (`launcher.go:890`) called from `applyLayers:284` and `degraded.go:200` | IMPOSSIBLE - never dropped in degraded; same call, same strict/basic fallback | IMPOSSIBLE - it has a report line (`AppliedExecFilter`, `launcher.go:291` / `degraded.go:204`) | IMPOSSIBLE - same reason |
| 5 | Landlock | HANDLED - `applyLayers:303` (writes only, backstop) / `degraded.go:232` (read+write+exec, primary) | HANDLED - both record; bwrap distinguishes `AppliedNo`/`AppliedAbsent` (`launcher.go:305-312`), degraded records `AppliedYes` only after a fatal call | IMPOSSIBLE - recorded on both tiers | HANDLED - the asymmetry is the ALLOWED direction: bwrap warns-and-proceeds (`launcher.go:304`), degraded is fatal. Strictly tighter in the tier with no mount ns |
| 6 | Terminal detach (`--new-session` vs TIOCSTI/TIOCLINUX block) | HANDLED - `args.go:519` / `degraded.go:226`; rationale for the substitution at `degraded.go:219-225`. Availability is refused outright when the fence is missing (`degraded.go:127`) | IMPOSSIBLE - no channel records anything about the terminal on either tier, so a recorded drop cannot arise | HANDLED - `blockTerminalInjection` fatal, no report line | ~~UNHANDLED - see F4~~ **B (dropped and recorded), fixed in d441ca5.** The substitute is still narrower than `--new-session` (two ioctls vs no controlling terminal at all) - apply is structurally impossible, since setsid refuses a process-group leader and the stage is started `Setpgid` - but `terminalResidual` (`probe.go:447`) now says so unconditionally in the degraded Consequences, which `degradedProbe` rewrites `LayerFilesystem` with. Narrowness measured by `TestTierDifferential`'s controlling-terminal and tty-inject-ioctl rows (bv2-lpuue) |
| 7 | Pseudo-FS: `/proc`, `/dev`, `/tmp` | HANDLED - `pseudoFSFlags` (`args.go:512`) / `degradedSystemPaths` (`internal/linux/degraded.go:451`) plus the scratch TMPDIR (`degraded.go:185-191`) | HANDLED - "any granted /proc is the host's" (`probe.go:279`); the degraded read set contains no `/proc` at all and `checkGrants` refuses `read: /proc` (`internal/linux/degraded.go:52-56`) | IMPOSSIBLE - these are host-side argv/ruleset decisions, not in-launcher fatal calls | HANDLED - the one gap, `/dev/full` absent from `degradedSystemPaths` while `permittedStdioDevice` allows it, is a compat nit named at `launcher.go:823-829`; it grants nothing (ENOSPC on write) |
| 8 | Environment / HOME / TMPDIR / proxy vars | HANDLED - both build from the shared `sandboxEnv` (`args.go:665`); `--clearenv` (`args.go:662`) / `envSlice(sandboxEnv(...))` (`internal/linux/degraded.go:186`), plus `StripEnv` dropped at `degraded.go:184` and TMPDIR de-duplicated at `degraded.go:189` | IMPOSSIBLE - nothing is dropped; the HOME literal differs by design and the reason is in the shared doc comment (`args.go:655-664`) | IMPOSSIBLE - same | HANDLED - proxy-var scrubbing is bwrap-only (`launcher.go:241`) because degraded runs no bridge; allowed direction |
| 9 | Inherited FDs + stdio + non-dumpable | HANDLED - `dropInheritedFDs` (`launcher.go:189` / `degraded.go:172`), stdio refusal (`launcher.go:200` / `degraded.go:177`), `PR_SET_DUMPABLE` (`launcher.go:224` / `degraded.go:180`) | IMPOSSIBLE - nothing dropped | IMPOSSIBLE - the calls are fatal on both tiers | HANDLED - degraded is STRICTER: no `AllowNetworkStdio` waiver, and the refusal says so (`launcher.go:566-572`). Allowed direction |
| 10 | Capability bounding set | ~~UNHANDLED~~ **A (applied), fixed in 89bf735/f3b781d.** `restrictCapabilityBound` (`internal/launcher/degraded.go:141`) attempts `PR_CAPBSET_DROP`, re-reads `CapBnd` from the kernel rather than assuming it, and refuses the run when the set is still non-empty and the caller holds permitted capabilities | ~~IMPOSSIBLE~~ **B, fixed in d441ca5** - `capBoundResidual` (`probe.go:460`) discloses the unprivileged residual, worded about unspendability rather than about the drop failing, so it holds in every cell the branch emits | HANDLED - fatal on the privileged case, per the call at `degraded.go:327` | ~~WRONG - see F2~~ **fixed in 89bf735/f3b781d/d441ca5** (bv2-7nv8y, bv2-bweer). The unprivileged residual is inert: the call sits after the seccomp installs that set `PR_SET_NO_NEW_PRIVS`, and a bounding set can only be spent through a setuid or file-capability exec |
| 11 | IPC / UTS / cgroup namespaces | UNHANDLED for System V IPC - `--unshare-ipc` (`args.go:501`) has no degraded substitute: Landlock's scoped IPC covers abstract unix sockets and signals only (`landlock_linux.go:416-428`) and `BlockProcessReach` (`seccomp_linux.go:128`) lists no `shmget`/`shmat`/`msgget`/`semget`. UTS/cgroup likewise unshared only on bwrap. ~~UNHANDLED~~ **A (applied), fixed in 7e483d7**: `BlockProcessReach` now denies all 12 System V IPC syscalls (`seccomp_linux.go:147-149`). POSIX mqueue deliberately excluded - named files under `/dev/mqueue`, already denied by Landlock. UTS/cgroup unchanged | IMPOSSIBLE - nothing records them; the probe text names mount, pid and network namespaces and stops (spike 3) | IMPOSSIBLE - not fatal, nothing called | ~~WRONG - see F3~~ **fixed in 7e483d7** (bv2-xwz5v). Chose apply over record: the fence is cheap and verifiable and the filter beside it already exists for the same threat. Pinned by `TestTierDifferential`'s sysv-ipc row; cost recorded as bv2-3mxlo |
| 12 | Limits (systemd scope) + teardown | HANDLED for the wrap - the same `wrapWithLimits` on both (`linux.go:197` / `internal/linux/degraded.go:215`), same `canCreateScope` gate and `preflightLimits`; `--die-with-parent` (`args.go:519`) / `Pdeathsig` + process-group sweep + `WaitDelay` (`internal/linux/degraded.go:226-233`) | IMPOSSIBLE - the limits layers are deliberately left "as the probe found them" (`internal/linux/degraded.go:378-381`), so no degraded channel carries a drop | IMPOSSIBLE - not fatal | ~~WRONG - see F1~~ **HANDLED - `internal/linux/degraded.go:247` (3cc71f9).** F1 is struck: that commit routes `runDegraded` through `runCmd` with a sampling callback and calls `noteScopeLimits` once, ahead of all four return arms. See the base-correction section below - F1 was found by two reviewers independently and both were reading a stale base |
| 13 | In-sandbox self-verification | HANDLED - `verifyEmptyNetns`/`FreshTmp`/`DevMount`/`Shields`/`PidNamespace`/`EmptyCapBound` (`launcher.go:165-195`) / `degradedPrerequisites` (`degraded.go:120`) | IMPOSSIBLE for the first five - they verify that bwrap built the sandbox it was asked for; the degraded tier installs its fences itself and the kernel's own return value attests them (`degraded.go:75-95`). No bwrap to be shimmed | IMPOSSIBLE - same | ~~UNHANDLED for the capability leg~~ **fixed with row 10** - `verifyEmptyCapBound` was the one verify with a live counterpart question on this tier; `restrictCapabilityBound` now supplies it, verifying against the kernel rather than assuming. See also bv2-d8vkd (bv2-1qsug was closed as its duplicate), a provenance gap this grid has no row for: a scoped run of either tier is wrapped in a `systemd-run` resolved on PATH. Closed in e607a3b - `resolveScopeRunner` (`internal/linux/limits.go:89`) holds it to the same `trustLauncherPath` refusal as bwrap, and `preflightLimits` (`limits.go:230`) is the gate every wrapped launch reaches |

## Grid B - ordering (8 pairs)

An ordering cell asks: is restriction B applied after something could already act? Every
pair below was read; the first five are also settled by spike 1.

| Pair | Verdict |
|---|---|
| exec filter before Landlock | HANDLED, both tiers. `applyLayers:284` then `:303`; `degraded.go:200` then `:232`. Spike 1 |
| Landlock last, after all setup | HANDLED, both tiers. Rationale `launcher.go:293-302` / `degraded.go:230`. Spike 1 |
| egress, process-reach, terminal between exec filter and Landlock (degraded only) | HANDLED. Observed order `exec-filter egress process-reach terminal landlock` (spike 1). None of the three needs a path, so none is affected by Landlock landing after |
| `dropInheritedFDs` / stdio refusal / non-dumpable before any filter | HANDLED, both tiers, same relative position (`launcher.go:189-226`, `degraded.go:172-182`) |
| applied report written after every layer, before the target | HANDLED, both tiers (`launcher.go:261`, `degraded.go:241`); the marker is what attests the fences |
| The pre-Landlock window in `RunDegraded` (process start to `degraded.go:232`) runs on the bare host filesystem, where the bwrap tier's equivalent window runs inside an already-built mount namespace | HANDLED - dismissal, verified inverted by spike 2: nothing between entry and `restrictDegraded` opens any path. The only `openat`s in the window are the Go runtime's own startup, before `RunDegraded` is entered |
| Strict exec filter (fork/clone block) installed before three more seccomp installs | HANDLED - `strictFilter` permits `CLONE_THREAD` (`strict_linux_amd64.go:100-103`), so Go runtime thread creation survives; each later install is `prctl` plus `seccomp(TSYNC)`, and a partial sync is a hard error (`strict_linux_amd64.go:120-126`) rather than a silent unfiltered run. Spike 1 exercised the sequence with the installs seamed; the live-filter version is UNSPIKEABLE HERE without an amd64 run that then execs |
| `PR_SET_DUMPABLE(0)` lands at `degraded.go:180`, after process start, in the HOST process table | UNHANDLED (low blast radius) - see **F5**. In the bwrap tier the same window sits inside a pid+user namespace that `verifyPidNamespace` proves is empty; in the degraded tier every same-uid host process shares the table for that window |

## Findings, forbidden direction first

### F1 - a degraded run can report `LayerLimitsCPU/Memory/PIDs: Enforced` for a target that ran with `cpu.max = max`
`VERIFIED BY READING` (grep of every `noteScopeLimits` call site)

`wrapWithLimits` is shared, but systemd accepts a property on an undelegated controller and
silently does not apply it. The bwrap tier closes that with `noteScopeLimits`, which reads
the scope's `memory.max`/`pids.max`/`cpu.max` and worsens the layer
(`internal/linux/scopeattest.go:155-176`), and calls it on all four return arms
(`linux.go:285, 305, 325, 359`). `runDegraded` calls it on none of its four arms
(`internal/linux/degraded.go:265, 277, 285, 293`), and `degradedProbe` deliberately leaves
the limits layers "as the probe found them" (`internal/linux/degraded.go:378-381`) on the
grounds that the launcher "wraps the same systemd scope" - true of the wrap, not of the
attestation. Forbidden direction: a shared restriction whose enforcement can be absent while
the report says Enforced, with no channel saying otherwise.
What would settle it: a host with an undelegated `cpu` controller, run degraded with
`limits.cpu` set, and compare `Report.StateOf(LayerLimitsCPU)` against the scope's `cpu.max`.

### F2 - no capability-bounding-set drop on the degraded tier, and no disclosure of that
**FIXED in 89bf735 / f3b781d (drop, verified against the kernel, fatal on the privileged case) and d441ca5 (disclosure of the inert residual). Beads bv2-7nv8y, bv2-bweer.**
Non-disclosure: `VERIFIED BY SPIKE` (spike 3 asserted the probe text does not mention
capabilities; the assertion held). Absence of the drop itself: `VERIFIED BY READING` (no
`PR_CAPBSET_DROP` anywhere in the tree, no root refusal on this path).

`--cap-drop ALL` is in `namespaceFlags` (`args.go:502`) precisely so the reliance is bento's
own rather than an unstated bwrap default (`args.go:488-498`), and `verifyEmptyCapBound`
(`verify.go:113`) re-checks it from inside. The degraded tier does neither: nothing calls
`PR_CAPBSET_DROP`, nothing refuses a root-started run, and `RunDegraded` sets only
`PR_SET_NO_NEW_PRIVS` (via the seccomp installs). Landlock is not bypassed by capabilities,
so the path fence holds; what does not is everything that is not a path decision -
`mount(2)`, `setns(2)`, module load, raw IO. `launcher.go:706-710` already reasons about
exactly this case ("a run started by root is inside the owning namespace and the setns
succeeds outright... Nothing refuses a root run") and closes only the inherited-nsfs-stdio
route. A comment is not a channel, so as far as the report is concerned this is a silent
drop.

### F3 - System V IPC is shared with the host on the degraded tier, unblocked and undisclosed
**FIXED in 7e483d7 - applied rather than recorded: all 12 System V IPC syscalls denied in `BlockProcessReach`. Bead bv2-xwz5v; the cost of choosing apply is bv2-3mxlo.**
Non-disclosure: `VERIFIED BY SPIKE` (spike 3). The rest: `VERIFIED BY READING`.

`--unshare-ipc` is applied on the bwrap tier (`args.go:501`). On the degraded tier:
`BlockProcessReach` enumerates ptrace, `process_vm_*`, `process_madvise`, `kcmp`,
`pidfd_getfd`, `move_pages`, `get_robust_list`, `perf_event_open`
(`seccomp_linux.go:128-143`) and no SysV call; Landlock's scoped IPC is abstract unix
sockets plus signals only (`landlock_linux.go:416-428`); and the probe's Consequences names
mount, pid and network namespaces and stops. So a restriction the bwrap tier applies is
dropped with nothing substituting for it and nothing recording it.

Untested leg, stated rather than assumed: that a same-uid host segment is in practice
attachable from inside a degraded run (`shmget` an existing key, `shmat` it under
`restrictDegraded`'s ruleset) was NOT executed. It is spikeable on this host and is the
first thing to do with this finding. UTS and cgroup unshares are dropped undisclosed too;
those are information-only and `/sys` is not in the degraded read set, so they are noted
rather than filed.

### F4 - the terminal substitute is narrower than `--new-session`, and the difference is not disclosed
**FIXED in d441ca5 by disclosure, not by application - apply is structurally impossible (setsid refuses a process-group leader; the stage is started `Setpgid` so `killProcessGroup` can sweep). Beads bv2-lpuue, bv2-bweer.**
`VERIFIED BY READING`

bwrap's `--new-session` gives the target no controlling terminal at all. The degraded
substitute denies two ioctl requests, TIOCSTI and TIOCLINUX
(`terminal_linux_amd64.go:26-34`). Everything else a controlling terminal carries - reading
the user's keystrokes, `TIOCSWINSZ`, writing escape sequences a terminal emulator acts on,
`SIGINT` delivery to the foreground group - stays. `degraded.go:219-225` explains why the
seccomp block is used instead of Landlock's `ioctl_dev`, but neither it nor the probe text
says the substitution is partial. The gap is in the allowed direction only if it is
recorded, and it is not.

### F5 - the degraded launcher is dumpable and in the host process table until `degraded.go:180`
**STILL OPEN, and deliberately not filed: the exploit is a race, which a state grid cannot see. Recorded as an asymmetry only.**
`VERIFIED BY READING` (ordering traced; the exploit window is not spikeable without a second same-uid process racing it, which is out of scope as a race)

Both tiers call `PR_SET_DUMPABLE(0)` at the same point in their sequence, but the window
before it means different things: in the bwrap tier it is inside a pid+user namespace
`verifyPidNamespace` (`verify.go:60`) proves contains only bwrap's init and the launcher, and
`launcher.go:220-223` notes the userns crossing clears dumpable anyway. In the degraded tier
the launcher is an ordinary host process for that window, with the inherited descriptors
still open and `/proc/<pid>/fd` readable by any same-uid process. Low blast radius - a
same-uid attacker on the host defeats this tier by other means - and it edges into a genuine
race, which the grid does not cover. Recorded as an ordering asymmetry, not filed as a fix.

## Dismissals, verified inverted

- **The three fatal-only fences are a design, not a gap.** `VERIFIED BY READING`.
  `blockEgress`, `blockProcessReach` and `blockTerminalInjection` have no line in the applied
  report, so the marker's presence is their only attestation (`degraded.go:88-95`). The
  design is seamed and pinned by `TestRunDegradedRefusesWithoutTheRealFences`. Listed only
  because the invariant's "recorded" clause has to be read against it. No action.
- **The pre-Landlock window opens no path.** `VERIFIED BY SPIKE` (spike 2). strace over a
  `RunDegraded` run to the point `restrictDegraded` is reached shows only the Go runtime's
  startup opens (`/etc/ld.so.cache`, `libc.so.6`, `/proc/self/maps`, cgroup files), all of
  them before `RunDegraded` is entered. The launcher's own body opens nothing.
- **The strict filter does not break the installs that follow it.** `VERIFIED BY READING`
  plus spike 1. `CLONE_THREAD` is explicitly allowed (`strict_linux_amd64.go:100-103`).
- **Landlock's fatal/warn asymmetry is the allowed direction.** `VERIFIED BY READING`. The
  tier with no mount namespace is the stricter one.
- **The missing `AllowNetworkStdio` waiver is the allowed direction.** `VERIFIED BY READING`
  (`launcher.go:566-572` refuses and says why).
- **`verifyEmptyNetns`/`FreshTmp`/`PidNamespace` have no degraded counterpart because there
  is no bwrap to be shimmed.** `VERIFIED BY READING`. Note `checkLauncher`
  (`internal/linux/linux.go:976`) is a test seam (`launchGuard`), not a verification - it
  does not stand in for these and must not be cited as one.

## Spikes (all deleted; Phase 4)

1. `internal/launcher/zz_spike_order_test.go` - swapped the seam vars at `degraded.go:103-112`
   for recorders and ran `RunDegraded` in a child process. Output:
   `exec-filter egress process-reach terminal landlock`. A second case ran `applyLayers`
   with the same seams: `exec-filter landlock`. Both tiers therefore agree on the shared
   subsequence, with the degraded extras in between. `VERIFIED BY EXECUTION`.
2. strace of that same child with `-e trace=openat,write,execve`, cut at the write that
   prints `landlock`. `VERIFIED BY EXECUTION`.
3. `internal/linux/zz_spike_disclosure_test.go` - called `filesystemLayer(namespacesBlocked,
   degradedTierReason, ...)` for both `scopedIPC` settings and asserted the Reason plus
   Consequences text does NOT mention System V IPC, shared memory, an IPC namespace,
   capabilities or a cgroup namespace. The assertion held (the one hit was a substring false
   positive on "uts"). The spike fails if the claim of silence is wrong; it did not.

## Gates

No source changed - the three spikes were deleted and the tree is clean - so a gate run here
would be vacuous and was not made.

## Cells not walked

None in Grid A (52/52) or Grid B (8/8). The cells carrying a weaker stamp than the rest are
named as such: Grid B's strict-filter row is read-verified for the live-filter case
(UNSPIKEABLE HERE - needs an amd64 run that installs the real filters and then execs), F1 is
read-verified (needs a host with an undelegated cgroup controller), F3's attachability leg is
untested but spikeable here, and F5's window is read-verified (the exploit is a race, out of
scope).

---

# Re-open pass

Run after the grid above, with the known-open board list and the freedom to read history
that Phase 1 withheld. Same rules: every claim stamped, tracker untouched, spikes deleted.

## Base correction - read this before anything above

**The grid above was built against `main` at 924e291. The branch this work lands on,
`docs/state-grids`, is at 0a45ddb - 89 commits ahead, 20 of them touching
`internal/launcher`, `internal/linux`, `internal/seccomp` or `internal/landlock`.** Every
verdict above was therefore reached on a tree that predates those 20. A stamp certifies
the method, not the tree. This section re-checks the lot against 0a45ddb, in the main
checkout.

### F1 is WITHDRAWN - it was fixed before the grid was written

`VERIFIED BY READING` at 0a45ddb, first-hand.

Commit 3cc71f9 "fix(linux): attest degraded tier's scope limits" (2026-09-16) replaced
`cmd.Run()` in `runDegraded` with `runCmd(cmd, func(pid int){ ... attestScopeLimits(pid) })`
and calls `noteScopeLimits(&report, p.Limits, attested)` at
`internal/linux/degraded.go:247` - once, ahead of all four return arms, so the arm-by-arm
gap the grid describes does not exist. `TestDegradedRunReconcilesTheLimitsLayersItGot`
(`internal/linux/degraded_limits_test.go:152`) pins it, as the degraded twin of the bwrap
test. Grid A row 12, column D is corrected to **HANDLED - `internal/linux/degraded.go:247`
(3cc71f9)**, and F1 is struck from the findings.

Worth recording why it survived two reviewers: this reviewer and a sibling reached it
independently and the sibling spiked it, but both ran on the same stale base, so the
agreement attested a tree neither was looking at. Independence of reviewers does not buy
independence of base.

### Cite audit against 0a45ddb

- **`internal/launcher/degraded.go` is untouched in all 89 commits.** Every cite into it
  holds byte for byte: `:88-95` (the fatal-only rationale), `:97` (the mirror sentence),
  `:103-112` (the seam vars), `:120`, `:127`, `:135` (the order sentence), `:172`, `:177`,
  `:180`, `:184-191`, `:200`, `:204`, `:209`, `:216`, `:226`, `:232`, `:235`, `:241`.
- **`internal/seccomp` is untouched.** The filter cites in F3 and F4 hold
  (`seccomp_linux.go:128-143`, `terminal_linux_amd64.go:26-34`,
  `strict_linux_amd64.go:100-126`).
- **`internal/landlock`** changed only in its off-Linux stubs and its probe helper; the
  degraded ruleset and the scoped-IPC domain (`landlock_linux.go:416-429`) are unchanged.
- **`internal/launcher/launcher.go` gained a fifth verify** (see below), so cites after
  line 155 shift by roughly +5 - and has since gained a sixth, `verifyShields`
  (`verify.go:197`), shifting them again, and two comment blocks grew: `PR_SET_DUMPABLE` is now
  `:229` (was 224), `applyLayers` `:285` (was 280), `landlockRestrict` `:322` (was 303),
  `refuseNetworkStdio` `:585` with its degraded-waiver text at `:590` (was 566-572), and
  the "Nothing refuses a root run" sentence F2 leans on is now at `:728` (was 706-710).
  All still say what the grid says they say.
- **`internal/linux/args.go`: `--new-session` moved out of `baseFlags` into its own
  `sessionFlags` var** (`args.go:518-528`, commit 3b7a6d1), so the F4/row-6 cite
  `args.go:519` is now `args.go:527` with `baseFlags` at `:530`. `namespaceFlags` is still
  `:501-503` and `pseudoFSFlags` `:512-516`.
- **`internal/linux/probe.go` was substantially rewritten** (686226d, f21e1bd). The
  disclosure text grew three residuals the grid did not see: passed MPTCP sockets, the
  Landlock file-metadata residual (stat/chmod/chgrp/utimes/setxattr on any nameable path),
  and an ABI-past-9 caveat. None of them touches F2, F3 or F4, and the spike below was
  re-run against the new text.

### Findings re-verified at 0a45ddb

- **F2 (no capability-bounding-set drop, undisclosed) HOLDS.** `PR_CAPBSET_DROP` appears
  nowhere in the tree at 0a45ddb (`VERIFIED BY READING`, whole-tree grep), and the rebuilt
  disclosure text still never mentions capabilities (`VERIFIED BY SPIKE`, spike 3 re-run).
- **F3 (System V IPC) HOLDS and is now fully spiked** - see the next section.
- **F4 (terminal substitute narrower than `--new-session`) HOLDS, and 3b7a6d1 sharpened
  the shape rather than fixing it.** *Fixed in d441ca5 (bv2-lpuue); the `sessionFlags`
  comment quoted below was rewritten and now says plainly that the substitute is narrower
  and names the four residuals, and the cite moved to `args.go:518-537`. Quoted verbatim
  because the finding is about what it said.* The new `sessionFlags` comment (`args.go:518-528`)
  says the degraded tier "substitutes a seccomp filter and refuses fatally if it will not
  install (degraded.go:120, :226)" - a true sentence that a reader takes as a statement of
  equivalence, which is exactly what it is not: setsid leaves no controlling terminal,
  while the filter denies two ioctl requests. The rebuilt probe text mentions a terminal
  only inside the process-group-sweep clause ("also stops a target that reads an
  interactive terminal"), which is about the sweep, not about this fence.
  `VERIFIED BY SPIKE` for the non-disclosure, `VERIFIED BY READING` for the narrowness.
- **F5 (dumpable window) HOLDS.** `degraded.go:180` unchanged; the bwrap counterpart moved
  to `launcher.go:229`.
- **Every dismissal in the grid above re-checked and still holds**, with one addition:
  `checkLauncher` (`internal/linux/linux.go:976`) is STILL only the `launchGuard` test
  seam at 0a45ddb (`linux.go:950-954`), despite the launcher-trust work of 3b7a6d1. It
  must not be cited as a provenance check on either tier.

## F3's untested leg, settled

`VERIFIED BY SPIKE` at 0a45ddb, both halves, differential.

A parent created a System V shared-memory segment at a known key and wrote a marker into
it. A child then installed the degraded tier's real fences in the tier's own order -
`landlock.RestrictDegraded` (read set `/usr`, `/lib`, `/lib64`, `/bin`; no `/dev`, no IPC
of any kind), `seccomp.BlockEgress`, `seccomp.BlockProcessReach`,
`seccomp.BlockTerminalInjection` - and then attached the segment by key.

```
FENCED landlock / egress / process-reach / terminal
READ  HOST-SEGMENT-CONTENT
WROTE XOST-SEGMENT-CONTENT
```

It both read and **wrote** another process's memory, through the door the cross-process
filter beside it exists to close. The mirror half ran the identical child under
`bwrap --unshare-user --unshare-ipc --dev-bind / /`:

```
FENCED landlock / egress / process-reach / terminal
SHMGET-DENIED no such file or directory
```

So the bwrap tier hides the segment and the degraded tier hands it over, read-write, with
nothing recording the difference. F3 is no longer a reading; it is the measured behaviour
of the current tree. (Same uid on both sides, which is the threat model the whole
cross-process filter is written against - `seccomp_linux.go:90-127` denies ptrace and
`process_vm_*` for precisely this attacker.)

## Row-carry audit of the recent fixes

The instruction was to hunt for a fix that closed the bwrap cell and left the degraded one.
Walked all 20 commits in `924e291..0a45ddb` touching these packages; the load-bearing ones:

| Commit | Cell it fixed | Was the row carried? |
|---|---|---|
| 4cca01a / fa39384 / f8801b3 / 3091825 / dd20d59 (the `/dev` fence) | Grid A row 7, bwrap side: `verifyDevMount` (now `verify.go:134`) added as a FIFTH in-sandbox verify, asserting `/dev` is the mount bwrap built and letting a `/dev` grant and a nested grant past. `verifyShields` (`verify.go:197`) has since been added as a sixth | **Yes, structurally.** The degraded tier mounts no `/dev`; its exposure is the four nodes `degradedSystemPaths` grants plus anything `resolveGrants` adds, and Landlock denies every other `/dev` name by default. There is no degraded counterpart to add. Row 7's verdicts stand with `verify.go:134` added to the bwrap cite |
| 3b7a6d1 (verify the launcher and the new session) | Grid A row 6, bwrap side: `sessionFlags` shared with the probe plus an in-sandbox canary proving `--new-session` took | **No - this is the row that was not carried.** The bwrap terminal cell got a proof; the degraded cell got a sentence in the same comment asserting the substitute exists. See F4, and F6-new below |
| 3fa521e (refuse a bwrap resolved out of the cwd) + `hostWritablePrefix` (`args.go:797-818`) | Provenance of the sandbox builder, bwrap tier only (`resolveBwrap`, `probe.go:452-520`) | **Not applicable rather than not carried** - the degraded tier launches no bwrap. But see F6-new: the *conclusion* that commit recorded is written where it reads as covering both tiers |
| 3cc71f9 (attest degraded scope limits) | Grid A row 12 | **Yes** - this is the degraded half of the bwrap attestation, and it is what withdraws F1 |
| 686226d / f21e1bd / d39a454 (disclose degraded ABI, MPTCP and metadata residuals) | Grid A rows 1 and 2, disclosure side | **Yes**, and they are why the B column of those rows reads HANDLED. They also show the project's own channel for exactly the kind of gap F2 and F3 name, which is what makes those two silences filable rather than debatable |

### F6-new - "the report's origin is established by resolveBwrap" is written where it covers both tiers, and is true of one
`VERIFIED BY READING` at 0a45ddb - **FIXED in d441ca5/6be6fce (bv2-tkbsx)**

> Stale quotation warning, 2026-09-18: the paragraph quoted below was rewritten and the
> cite moved to `internal/linux/applied.go:23-34`. It is preserved verbatim because the
> finding is about what it said. The fix narrowed the comment's scope rather than adding a
> check, and that judgement was confirmed independently on stronger grounds than this
> finding used: `runDegraded` re-execs `sb.bentoPath`, which `bentoSelfPath` derives from
> `os.Executable()`, so on the unscoped path there is no resolution step to aim at - which
> is exactly what `resolveBwrap` guards on the other tier. One over-correction was caught
> in review: a SCOPED run of either tier *is* wrapped in a PATH-resolved `systemd-run`, so
> "no resolution step" is wrong there. That became bv2-1qsug.

`internal/linux/applied.go:23-28` (added by 3b7a6d1) reasons about the applied report's
trustworthiness: nothing in the bytes authenticates the writer, "The report's origin is
established by resolveBwrap instead, which refuses to launch a sandbox builder this uid
could have replaced." That paragraph sits on `appliedReportFD`, which BOTH tiers use -
`runDegraded` passes the same descriptor at `internal/linux/degraded.go:207` and parses it
with the same `parseApplied`. But `runDegraded` never calls `resolveBwrap`; it re-execs
`sb.bentoPath` directly (`degraded.go:213`), guarded only by `checkLauncher`, which is the
test seam. So the degraded tier's report has no origin establishment of the kind the
comment asserts for the mechanism as a whole.

The practical exposure is thin - `sb.bentoPath` is the running bento binary, so
substituting it means bento was already substituted - which is why this is filed as the
comment's scope rather than as a missing check. It is the third instance this review found
of the shape two sibling reviewers reported independently: a true statement scoped to one
cell, written where a reader takes it as a verdict on the whole mechanism (F2's
`launcher.go:728`, F4's `args.go:518-528`, and this).

## Board items against the grid

- **bv2-76t24** (state-grid the restriction sequence, bwrap vs degraded) - **discharged by
  this document**, with two corrections to its own text. Its scope-boundary instruction
  cites two grid docs that no longer exist in the tree (already stripped from the dispatch
  brief, and nothing was inherited from them). And its framing assumes the sequence is the
  interesting axis: the sequence turned out to be clean on both tiers and settled by
  execution (Grid B, spike 1), while every finding came from the restriction SET - what the
  degraded tier drops and whether anything records it. A follow-up nomination should say
  "restriction set and its disclosure", not "sequence".
- **bv2-775q3** (Config carries no grant set, so shields and `/dev`'s extra names cannot be
  checked against what was granted) - lands on Grid A rows 1 and 7, bwrap side. Closed
  since this pass: `Config` carries the hidden and read-only shield sets and the run's
  `/dev` grant names, `verifyShields` confirms the shields from inside, and
  `foreignDevNodes` compares against what was granted rather than asking whether a name is
  a mount of its own. The Landlock backstop is still writes-only for its own reason
  (`launcher.go:330-345`), which is why the shields needed a verify rather than a
  backstop.
- **bv2-dyz92** (descendants of a supervising launcher orphan a SIGKILLed bento) - Grid A
  row 12, teardown half. Consistent with the grid: the process-group sweep is disclosed
  (`probe.go` Consequences names the setsid escape), so it is a recorded weakness, not a
  silent one. Closed since by `teardownResidual` (`probe.go:454`), which discloses the
  other half - that a SIGKILLed bento runs no sweep at all.
- **bv2-73e4c** (nothing asserts the observe stage has no other live child) and **bv2-83kke**
  (observe resolves exec images in its own mount namespace) - the profiling path, which
  applies no fences at all (`launcher.go:391`). Outside this grid's rows by construction.
- **bv2-yxgrq** (a user-installed bwrap is refused with no escape hatch) - the other side of
  3fa521e. Bwrap tier only; no degraded counterpart, since that tier launches no bwrap.
- **bv2-d8vkd** (systemd-run comes off PATH and wraps the sandbox launch) - Grid A row 12,
  and it is the one board item that is strictly WORSE on the degraded tier than the grid
  shows: both tiers wrap with `wrapWithLimits`, but the bwrap tier puts a
  provenance-checked bwrap between systemd-run and the target, while on the degraded tier
  a PATH-resolved `systemd-run` execs the bento launcher directly. Worth noting on that
  item; not a new finding, since the PATH resolution itself is what the item is about.
- **bv2-9rqim** (default exec none on arm64) - `installExecFilter` is shared by both tiers
  (Grid A row 4, HANDLED in every column), so whatever is decided there applies to both
  without a mirror risk.

## What the re-open changed

- Withdrawn: **F1** (fixed at 0a45ddb by 3cc71f9; grid row 12 corrected to HANDLED).
- Upgraded: **F3**, from read-verified with an untested leg to `VERIFIED BY SPIKE` on both
  halves of the mirror.
- Unchanged and re-verified at 0a45ddb: **F2**, **F4**, **F5**, and every dismissal.
- Added: **F6-new**, the `applied.go` origin claim scoped to the bwrap tier.
- Nothing else in the grid above changed its verdict; the cite shifts are listed in the
  cite audit rather than rewritten in place, so the two sections can be read against each
  other.

## Gates, re-open pass

Three spikes were written, run and deleted; no source file changed, so a gate run would be
vacuous and was not made.
