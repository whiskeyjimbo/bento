# State grid: teardown and reclaim across termination modes and both tiers

Technique: `state-grid` (Phases 0-3). Phase 4 tracker filing is the orchestrator's.
Scope: what a run leaves on the host when it ends, and whether the run's own report
says so. Dimensions derived from the code only - no git log, no tracker, no candidate
list.

## Phase 0 - fit call: ACCEPT

Signals present:

- **Mirror pair, and a strong one.** `createdShields` (internal/linux/shields.go:475)
  and `denyArgs` (internal/linux/shields.go:351) are two functions that must select the
  same rule set - one to enforce it, one to reclaim what enforcing it created. The file
  says so itself at shields.go:102-106: "a divergence would either leak a host artifact
  or leave a path unshielded." A second mirror pair sits behind it: the bwrap tier and
  the degraded tier tear down the same run through entirely different mechanisms (pid
  namespace + `--die-with-parent` vs. process group + `Pdeathsig`).
- **A lifecycle axis with real branches.** `Run` has four terminal arms (cancel, nil,
  exit-error, default), `runDegraded` has four, and each assembles a different subset
  of the result. That is an enumerable WHEN axis, not an interleaving.
- **Degradation states.** `bounded`/`boundedSeam` (internal/linux/alias.go:52, :212)
  make several host answers "I could not tell", and the reclaim path swallows that
  answer entirely.

Invariant (one-sided), adopted as proposed:

> Teardown may leave behind only what it can prove bento did not create. It must never
> leave a bento-created artifact inside the user's checkout unreclaimed **and**
> unreported, and never report a discarded write as applied.

Allowed direction: leaving something *and saying so*, or reclaiming more cautiously
than necessary. Forbidden direction: silent host residue, or a report that overstates
what was discarded.

Out of scope, routed elsewhere (both are orderings, not states):

- `killedByCancel`'s "narrow race where the launcher had already computed the status
  when the group kill landed" (internal/linux/degraded.go:345) -> `concurrency-audit`.
- `removeCreatedShields`'s "the zero-length check is not atomic with the unlink"
  (internal/linux/shields.go:577) -> `concurrency-audit`.

## Phase 1 - dimensions

**WHEN - termination mode (7).** Read off the four terminal arms of `Run`
(internal/linux/linux.go:256, :301, :315, :335), the four of `runDegraded`
(internal/linux/degraded.go:248, :273, :285, :292), and the two structurally
handler-less modes.

| id | mode |
|----|------|
| T1 | clean exit (target exits 0) |
| T2 | target error exit (non-zero, or a signalled target the wrapper converts to 128+N) |
| T3 | setup failure (an error return after the host was already touched, before the target ran) |
| T4 | cancel arriving before the wrapper starts (`cmd.ProcessState == nil`) |
| T5 | cancel mid-run |
| T6 | SIGKILL of bento itself (no in-process handler can run) |
| T7 | SIGKILL / signal of the target, or of the scope around it (OOM under `Limits`) |

**WHAT - artifact class (5), with tier folded in.** Tier is not its own axis because
every class is either tier-bound or tier-identical; folding it keeps the grid at 35
cells instead of 84. The fold, stated so nothing reads as dropped:

| id | artifact class | tier |
|----|----------------|------|
| A1 | materialized file shields and the mount-point directories bwrap was made to create | bwrap only - the degraded tier has no mount namespace and emits no shield mounts; it reports them as *exposed* instead (internal/linux/degraded.go:137) |
| A2 | write-grant directories `prepareWriteDirs` MkdirAll'd (internal/linux/linux.go:690) | both, identical code, one call from `preflightGrants` and one from `runDegraded` |
| A3 | the run's temp tree: bwrap `bento-run-*` (runDir, empty shield file, proxy socket, applied report); degraded `bento-degraded-*` (scratch = the target's TMPDIR) | both, different mechanism, same defer shape |
| A4 | leaked process trees | both - bwrap: pid ns + `--die-with-parent` (internal/linux/args.go:519); degraded: process group + `Pdeathsig` (internal/linux/degraded.go:417) |
| A5 | the egress proxy listener, the bridge liveness pipe, the applied-report channel and the exec recorder | bwrap only - `runDegraded` runs no proxy, no bridge and never a recorder (internal/linux/degraded.go:245-251) |

Grid = 7 x 5 = **35 cells**.

## Phase 2 - verdicts

### A1 - shield mount points bwrap created (bwrap tier)

Reclaim mechanism: `preflight.createdShields` at internal/linux/linux.go:129 and
profile.go:132, reclaimed by `defer removeCreatedShields(...)` at linux.go:130 /
profile.go:133 -> internal/linux/shields.go:587.

| mode | verdict |
|------|---------|
| T1 clean exit | **WRONG** - the defer runs (linux.go:130), but every failure inside it is discarded: the bound's error at shields.go:588 (`_, _ =`), a non-regular or non-empty file at shields.go:590 (`continue`), and the rmdir at shields.go:598 (`_ = syscall.Rmdir`). The function returns nothing, so no caller can learn a mount point survived. When any of those fires, the artifact is inside the user's checkout, unreclaimed **and** unreported. |
| T2 target error exit | **WRONG** - same mechanism, same silence. |
| T3 setup failure | **HANDLED** - a failure before linux.go:129 cannot leave a shield mount, because bwrap is not started until linux.go:234 (`runCmd`); a failure after it is covered by the defer registered at linux.go:130. |
| T4 cancel before wrapper starts | **HANDLED** - `exec.CommandContext` never starts bwrap, so nothing was created, and the defer runs regardless (linux.go:130). |
| T5 cancel mid-run | **WRONG** - the defer runs, with the same swallowed outcome as T1. |
| T6 SIGKILL of bento | **UNHANDLED** - no defer runs, and nothing on any *later* run reclaims it either: `createdShields` skips any path where `sb.exists` is true (internal/linux/shields.go:480), so the empty `.git/hooks` a killed run left behind is permanently invisible to every future reclaim. Headline finding F1. |
| T7 SIGKILL / signal of the target | **HANDLED** - bento itself survives and returns through an arm, so the defer runs. |

### A2 - write-grant directories created by `prepareWriteDirs`

No reclaim mechanism exists on any path.

| mode | verdict |
|------|---------|
| T1 clean exit | **UNHANDLED, by design** - the grant is the user's own and the run used it. Rationale recorded at profile.go:80-88 for `Profile` only; `Run` and `runDegraded` create the same artifact with no comment defending it. Allowed direction (the manifest named the directory), so not a defect - but undocumented at two of its three call sites. |
| T2 target error exit | **UNHANDLED, by design** - as T1. |
| T3 setup failure | **UNHANDLED** - `prepareWriteDirs` runs at linux.go:671, inside `preflightGrants`; five things can still fail before the target runs (`startProxy` :146, `newAppliedReport` :159, `compile` :165, `preflightLimits` :194, `checkLauncher` :207). Each returns a bare error having created a host directory the target never used, with nothing reclaiming it and nothing naming it. Forbidden direction. Finding F3. |
| T4 cancel before wrapper starts | **UNHANDLED** - same directory, same silence; here nothing at all ran. Finding F3. |
| T5 cancel mid-run | **UNHANDLED, by design** - the target ran, so this collapses into T1. |
| T6 SIGKILL of bento | **UNHANDLED, by design** - as T1. |
| T7 SIGKILL of target | **UNHANDLED, by design** - as T1. |

### A3 - the run's temp tree (both tiers)

bwrap: `os.MkdirTemp("", "bento-run-")` at linux.go:786, `cleanup` closure at :790,
deferred at :108 (Run) and by `defer cleanup()` in `Profile`. Applied report dropped at
linux.go:163. Degraded: `os.MkdirTemp("", "bento-degraded-")` at degraded.go:153,
`defer os.RemoveAll(dir)` at :157, scratch inside it at :158.

| mode | verdict |
|------|---------|
| T1 clean exit | **HANDLED** - linux.go:108 / degraded.go:157. |
| T2 target error exit | **HANDLED** - same defers; both arms return normally. |
| T3 setup failure | **HANDLED** - `newSandbox` calls `cleanup()` itself on each of its own late failures (linux.go:794, :831, :841, :879); after it returns, the defer covers the rest. |
| T4 cancel before wrapper starts | **HANDLED** - the defers run on the cancel arms (linux.go:297, degraded.go:270). |
| T5 cancel mid-run | **HANDLED** - as T4. |
| T6 SIGKILL of bento | **UNHANDLED** - `/tmp/bento-run-*` and `/tmp/bento-degraded-*` leak, and on the degraded tier the leak carries whatever the target wrote to TMPDIR. 0700, outside the checkout, and nothing later reclaims it. Does **not** violate the invariant's checkout clause; recorded as a real residual of the structurally-impossible column. |
| T7 SIGKILL of target | **HANDLED** - bento returns through an arm; defers run. |

Second clause of the invariant, checked here: the degraded tier's scratch **is** a
discarded write surface (deleted at degraded.go:157), and nothing in `enforce.Result`
claims TMPDIR content persisted. No false "applied" claim.

### A4 - leaked process trees

| mode | verdict |
|------|---------|
| T1 clean exit | **HANDLED** - bwrap: the pid namespace collapses when bwrap exits. degraded: `killProcessGroup` at degraded.go:239 after `cmd.Run`, plus `cmd.WaitDelay` at :233. |
| T2 target error exit | **HANDLED** - same two mechanisms; both run on every arm after `cmd.Run` returns. |
| T3 setup failure | **IMPOSSIBLE** - a setup failure before dispatch means no child exists; `killProcessGroup` guards `p == nil \|\| p.Pid <= 0` explicitly (degraded.go:426) so it cannot degenerate into `kill(-0)`, which would sweep bento's own group. |
| T4 cancel before wrapper starts | **IMPOSSIBLE** - same guard, same cite (degraded.go:426); `cmd.ProcessState == nil` is the arm that names this state (degraded.go:273, linux.go:281). |
| T5 cancel mid-run | **HANDLED** - degraded: `cmd.Cancel` is overridden to sweep the group (degraded.go:227). bwrap: `exec.CommandContext` SIGKILLs the wrapper, and under `systemd-run --scope` the wrapper *is* bwrap, because a scope execs its command in place (measured - see F4). bwrap's own init then tears the namespace down. |
| T6 SIGKILL of bento | **DISCLOSED** - bwrap: `--die-with-parent` at internal/linux/args.go:519 is what makes this column a real verdict rather than the vacuum it invites. degraded: `Pdeathsig: syscall.SIGKILL` at degraded.go:417. The degraded mechanism carries two residuals - a `setsid()` descendant escapes the group, and on a SIGKILLed bento no sweep runs at all while `Pdeathsig` reaches neither a supervised target nor anything the target started - and both *are* surfaced to the operator, the first in the `Consequences` sentence at internal/linux/probe.go:284 and the second in `teardownResidual` (probe.go:454) concatenated at :286. Reported, not silent. Read as HANDLED in the original pass; corrected below. |
| T7 SIGKILL of target | **HANDLED** - bwrap: pid ns collapse. degraded: the post-`Run` sweep at degraded.go:239 runs on every arm. |

### A5 - proxy listener, bridge liveness pipe, applied report, exec recorder (bwrap)

| mode | verdict |
|------|---------|
| T1 clean exit | **HANDLED** - `stopProxy` is called explicitly before the collector is read (linux.go:302) and is `sync.OnceValue` (linux.go:1016), so the defer at :150 is a safety net, not a double close. The socket lives in runDir and goes with A3. |
| T2 target error exit | **HANDLED** - linux.go:318 / :341, same shape. |
| T3 setup failure | **HANDLED** - the defer at linux.go:150 covers every error return after the proxy started; `Profile` keeps the equivalent net and nils it on the happy path. |
| T4 cancel before wrapper starts | **HANDLED** - `stopProxy()` at linux.go:272 runs on the cancel arm ahead of the collector read, which is the point of not relying on the defer. |
| T5 cancel mid-run | **HANDLED** - as T4. The liveness read is deadlined at linux.go:520 so a sandbox outliving the reaped process cannot turn a cancel into a hang. |
| T6 SIGKILL of bento | **IMPOSSIBLE** - nothing to reclaim: the listener and the pipes are process-local file descriptions, closed by the kernel on exit. The only host-visible object is the unix socket inode, which lives inside runDir and is therefore A3/T6. |
| T7 SIGKILL of target | **HANDLED** - bento survives; the arms above run. |

Second clause, checked here: on the exec-block path the recorder's seeded entry is
explicitly nulled before the report is written (internal/launcher/launcher.go:339)
precisely so the record cannot claim an exec that never happened. The invariant is
already enforced in this class, in the right direction.

## Phase 3 - findings, forbidden direction first

### F1 - a SIGKILLed run's shield mount points are unreclaimable forever

Cell A1/T6. `createdShields` skips any path that already exists
(internal/linux/shields.go:480). That check is the whole safety argument of the
function (shields.go:465-469) and is correct for a user's own `.git/config`. Its cost,
which the argument does not name, is that an *empty artifact bento itself left* is
indistinguishable from user content on every subsequent run, so no later run reclaims
it and no run reports it.

This refutes a recorded decision: `TestCreatedShieldsExcludesPreexistingPaths`
(internal/linux/shields_test.go:59) pins the skip as a safety property. The test is
right about the case it names and silent about this one.

**VERIFIED BY SPIKE.** A throwaway test asserted the safe behaviour - that an empty
leftover at `<grant>/.git/hooks` is scheduled for reclaim on the next run - and it
failed:

```
SPIKE F1 CONFIRMED: a bento-created leftover at /home/u/proj/.git/hooks is not
scheduled for reclaim; dirs=[/home/u/proj/.vscode /home/u/proj/.cargo
/home/u/proj/.idea] files=[/home/u/proj/.git/config ...]
```

Spike deleted. Forbidden direction: bento-created, inside the user's checkout,
unreclaimed, unreported.

Note the shape of the fix this does *not* prescribe: "remove it if it is empty" would
reclaim a user's own empty directory, which is the exact thing shields.go:465-469
refuses. A durable marker of what a run created, or a report naming what was skipped,
are the two directions that keep the existing safety argument intact.

### F2 - `removeCreatedShields` cannot report a reclaim it failed to do

Cells A1/T1, T2, T5, T7. Three independent silent-failure routes in one nine-line
function (internal/linux/shields.go:587-602): the bound's error (`_, _ =`, :588), the
skip on a file that is not regular or not empty (`continue`, :590), and the rmdir
(`_ = syscall.Rmdir`, :598). The function has no return value, so the silence is
structural rather than an omitted check at the call site.

The comment at shields.go:579-586 records the dismissal - "Best effort throughout: a
kill before this runs leaves the artifact, as before" and "An expiry leaves the
artifact, which is what a kill here already does". Those two sentences equate a mode
where nothing *can* run (T6) with modes where bento is alive, holding the paths, and
returning a `Result` it could have named them in. The invariant permits leaving the
artifact; it does not permit leaving it silently.

**VERIFIED BY SPIKE.** A throwaway test shortened `credentialWalkTimeout` (var,
internal/linux/alias.go:34) and pointed `shieldLstat` (var, shields.go:606) at a
blocking stub, then asserted the safe behaviour: either the mount point is gone, or the
caller learns it survived:

```
SPIKE F2 CONFIRMED: .../config survived the reclaim and removeCreatedShields
returned nothing a caller could report
```

Spike deleted. The rmdir-ENOTEMPTY case is the same defect, not a second one, and is
folded here.

Observed while spiking, worth one line: `bounded` does not cancel the call, it abandons
it (alias.go:42-51). So after an expiry the reclaim loop keeps running on a detached
goroutine and may unlink mount points minutes after `Run` returned its `Result`. That
is in-model for `bounded` elsewhere, where the run is refused anyway; here the run has
already reported success.

### F3 - a setup failure after `prepareWriteDirs` leaves an unmentioned host directory

Cells A2/T3 and A2/T4. `prepareWriteDirs` MkdirAlls at internal/linux/linux.go:721,
inside `preflightGrants`; five later steps can fail before the target ever runs
(linux.go:146, :159, :165, :194, :207) and each returns a bare error. The directory is
bento-created, may sit inside the checkout, is never reclaimed, and is not named by the
error or by any `Result` - those arms return `enforce.Result{}`.

`preflightGrants`'s comment at linux.go:664 asserts the ordering keeps refusals from
leaving a directory behind. That is true of the checks it names, and it does not extend
to the five failures after it - which the comment reads as if it covers.

**VERIFIED BY SPIKE.** A throwaway test drove `prepareWriteDirs` with a write grant that
did not exist, then asserted the safe behaviour - that after a failing run the host
holds no directory the grant caused:

```
SPIKE F3 CONFIRMED: .../build/out survives a run that failed setup after
prepareWriteDirs, unreclaimed and unnamed
```

Spike deleted. Severity below F1/F2: the directory is one the manifest explicitly
named, so a user reading their own manifest can predict it. It is listed because it is
forbidden-direction under the stated invariant, and because the rationale exists at
exactly one of its three call sites.

### F4 - two comments in this package contradict each other; measurement settles it

`bridgeReportedDeath`'s doc (internal/linux/linux.go:512-514) says "Under the limits
wrapper the process reaped is systemd-run, and a cancelled run can leave bwrap orphaned
with the bridge still holding the write end." `removeCreatedShields`'s doc
(shields.go:583) says the opposite for the same configuration: it "runs on a defer on
all three entry paths, after the target has exited."

`systemd-run --user --scope` execs its command in place, so the process bento reaps *is*
bwrap; there is no systemd-run left to orphan it. degraded.go:212 states this correctly
("A scope execs its command in place"), which makes linux.go:512 the odd one out.

**VERIFIED BY EXECUTION.** `systemd-run --user --scope --quiet -- sh -c 'echo $$ $PPID'`
reported the child's parent as the invoking shell's own pid, not a surviving
systemd-run. The deadline the comment justifies is a harmless backstop either way, so
this is a documentation defect rather than a behavioural one - but two comments in one
package now disagree about how a cancelled limited run ends.

Second, smaller documentation defect in the same function: `removeCreatedShields` says
"all three entry paths". There are two callers (linux.go:130, profile.go:133);
`runDegraded` never calls it, correctly, because that tier applies no shields.

### F5 - the degraded tier's `discarded` kind: checked and dismissed

`shieldsApplied` labels an unborn DenyWrite directory `discarded`
(internal/linux/shields.go:40-42) because bwrap would give it a tmpfs. The degraded
tier reuses that labelling through `exposedShields` (shields.go:58) on a tier that
applies no shields at all, so a write there really does land on the host - which reads
at first like the invariant's second clause being violated.

**Dismissed, and the dismissal verified, inverted.** The safe behaviour the dismissal
assumes is that the field is framed as protection *withheld*. `enforce.Result.Exposed`'s
contract says so explicitly ("it is the protection this tier did NOT deliver ... not
evidence anything was hidden", enforce/enforce.go:479-491), and the only renderer,
`writeExposedWarning` (cmd/bento/render.go:1999), prints the list under "a normal run
would hide or make read-only were left exposed to the script - review".
**VERIFIED BY READING** of both the field contract and its single render site.

Residual worth one line, not a finding: that warning sentence names two kinds and the
list can print a third, `discarded`, which the sentence does not explain.

### Verification of the remaining verdicts

- A4/T6 on the degraded tier rests on `Pdeathsig` firing for a launcher under the
  systemd-run scope. The claim at degraded.go:415 (PDEATHSIG survives an ordinary
  execve) is true, but the SIGKILL-of-bento path was not executed here.
  **UNSPIKEABLE HERE** without killing the test runner's own supervisor.
- A3/T6's claim that nothing later reclaims `/tmp/bento-*` is **VERIFIED BY READING**:
  no sweep of stale run directories exists anywhere in the tree - `bento-run-` and
  `bento-degraded-` appear only at their two creation sites.
- Every other HANDLED and IMPOSSIBLE verdict above is **VERIFIED BY READING**, traced
  first-hand to the cited line.

## Cells not walked

None. All 35 cells carry a verdict.

## Handoff to other techniques

- Every WRONG and UNHANDLED cell above is a permanent seed: F1 and F3 are cheap
  table-driven cases over `createdShields`/`prepareWriteDirs`; F2 needs the two existing
  vars and nothing else.
- The two interleavings named in Phase 0 go to `concurrency-audit`, not here.

---

# Re-open pass (Phase 2, second half)

Run after the grid was written, against the known-open board items held back during
Phase 1. Tracker untouched: items were read, nothing was written. Spikes deleted.

## Disposition against the open items

### F1 (A1/T6) vs **bv2-ntncf** - SAME CELL, with a correction to its preferred remedy

bv2-ntncf is exactly A1/T6, and it is better evidence than my grid: it has a measured
three-arm experiment (clean / SIGTERM / SIGKILL) showing `.cargo .git .vscode .idea`
left in the checkout plus an orphaned `/tmp/bento-run-*`. That also settles two of my
own cells from outside - it confirms A3/T6 (the run directory leaks) and corroborates
A4/T6 bwrap ("No bwrap survives either way"), which I had only read-verified.

So F1 is not a new item. **Append, do not file.** What it adds is a correction to the
item's own preferred fix, which as written cannot be implemented against the function
it names:

> "(1) reclaim stale artifacts at the START of a run - bento already computes exactly
> which paths it would create, so it can recognise and clear its own leftovers"

`createdShields` computes the **complement** of the leftovers: it filters on
`!sb.exists(r.Path)` (internal/linux/shields.go:480), so a stale artifact is precisely
what it will not return. A start-of-run reclaim has to invert that filter, and
inverting it is what `TestCreatedShieldsExcludesPreexistingPaths`
(internal/linux/shields_test.go:59) exists to forbid - for a good reason, since the same
inversion would reclaim a user's own empty `.git/hooks`. The remedy therefore needs a
third thing neither the ticket nor the code has: a durable record of what *this host's*
prior run created, or the ticket's own option (2), reporting the paths so a supervisor
can clear them. **VERIFIED BY READING** of shields.go:480 and the test; the underlying
skip was **VERIFIED BY SPIKE** in F1 above.

Also worth carrying to that item: its remark that an empty `.git` appearing in a
non-repository checkout is its own hazard compounds with `checkoutRoot`
(internal/linux/shields.go:179), which anchors by the *name* `.git`. A leftover empty
`.git` from a SIGKILLed run changes where the next run's workspace shields anchor. I
did not walk that as a cell and do not claim it as a defect - flagged as the one
follow-on the F1 cell implies. **UNVERIFIED**; what would settle it is a two-run
sequence over a non-repository write grant, killed between them.

### F2 vs **bv2-76tn4** - DISTINCT, and it refutes a sentence in that item

bv2-76tn4 is a different cell: the *during-run* window (A1/T1-T2 while the target is
alive), where a broadly-staging target commits the materialized files before teardown
removes them. My grid did not cover the in-run window at all, only the end state, so
that item is a cell my dimensions could not see - a WHEN axis of "during" that I folded
away. Recorded as a gap in my Phase 1, not as agreement.

But the item contains a closed decision that F2 refutes:

> "That cleanup is correct and is not the bug - the window during the run is."

`removeCreatedShields` is correct on its success path only. F2 (spike-verified above)
shows three routes by which it silently does not reclaim, with no return value for a
caller to learn from. The sentence is right about the case it names - the cleanup is not
what causes the commit window - and silent about whether the cleanup always happens.
This is the same shape as the `TestCreatedShieldsExcludesPreexistingPaths` finding:
a correct statement about one cell read as a clean bill of health for the row.

**File F2 separately, cross-referenced to both bv2-76tn4 and bv2-ntncf.** It is not a
sibling of either: ntncf is "teardown did not run", F2 is "teardown ran and did not
say it failed".

One corroboration to carry the other way: bv2-76tn4's measurement that a materialized
*directory* shield is a writable tmpfs whose content is discarded matches
`shieldMount`'s absent-directory branch (internal/linux/shields.go:672, `--tmpfs`), and
that discard **is** reported - `shieldsApplied` labels exactly that case `discarded`
(shields.go:40-42). So on the full tier the second clause of the invariant holds for
shield tmpfs. **VERIFIED BY READING.**

### A4/T6 degraded vs **bv2-dyz92** - MY VERDICT WAS WRONG, and has since been earned

bv2-dyz92 says Pdeathsig reaches only bento's direct child, so on the supervise path
(`superviseTarget`/`superviseTraced`) the launcher dies and the target plus anything it
backgrounded survives a SIGKILLed bento, with nobody left to run `killProcessGroup`.
That is correct, and at the time of the grid my **A4/T6 verdict of HANDLED was wrong**:
the mechanism existed, did not cover the supervise sub-case, and nothing said so. The cell
now reads **DISCLOSED** - the mechanism still does not cover that sub-case, and the
degraded tier's `Consequences` now names the gap, which is the allowed direction under
this invariant. Recorded here rather than silently edited above, so the miss stays
visible.

The specific thing I got wrong is worth naming, because it is another instance of the
pattern: I accepted `launcherProcAttr`'s own comment
(internal/linux/degraded.go:413-416), which names both residuals and then says "which
the degraded report discloses". The report discloses one of them.

**VERIFIED BY SPIKE, AND SINCE CLOSED.** A throwaway test called `filesystemLayer` in
its degraded branch and asserted the safe behaviour - that the tier's `Consequences` text
mentions bento, a parent, or a supervisor dying. At the time it did not:

```
SPIKE R1 CONFIRMED: the degraded tier's disclosure names the setsid escape but never
says a SIGKILLed bento leaves a supervised target running
```

The only disclosed sentence was "a background process it leaves is swept only best-effort
by killing the run's process group, which a setsid() escapes" - about a descendant
escaping the sweep, not about the sweep never running. Spike deleted.

bv2-dyz92 closed by adding `teardownResidual` (internal/linux/probe.go:454), which the
degraded `Consequences` now concatenates at probe.go:286. It says the sweep "does not run
at all if bento itself is killed outright - the launcher is torn down with it, but that
death reaches the target only where the target was execveat'd over the launcher, and
reaches nothing the target started in either shape, so a background process it left - and,
on a run the launcher supervises rather than execs over, the target itself - stays alive
with nothing left to sweep it". That is both halves R1 named: the sweep never running, and
`Pdeathsig` reaching neither the supervised target nor its descendants.

Also worth carrying to that item: it already records "systemd-run execs bwrap in place,
so bwrap's parent is bento". That is the same fact my **F4** measured independently.
So the correct fact is *already in the tracker* and the stale comment at
internal/linux/linux.go:512-514 survived alongside it. F4's severity is unchanged
(documentation only) but its shape is now clearer: not an unexamined assumption, a
belief that was corrected somewhere the code comment never heard about.

### F5 vs **bv2-2dpgj** - re-checked against that item's claim specifically; dismissal STANDS, but it names a cell my grid missed

bv2-2dpgj's claim is "a discarded scratch write reports success and vanishes silently",
about the **bwrap tier's per-run tmpfs `/tmp` and `/dev/shm`** on a `write: none` run.
Re-checking my dismissal against that rather than against the degraded `discarded`
kind:

- The item's "reports success" is the *target's* write returning 0, not bento's
  `Result` asserting the write landed. Bento asserts nothing about `/tmp` content on
  either tier. So the invariant's second clause - "never report a discarded write as
  applied" - is still not violated. **Dismissal stands, VERIFIED BY READING** of the
  `Result` construction on all four bwrap arms (internal/linux/linux.go:297, :314,
  :334, :368) and all four degraded arms (degraded.go:270, :284, :291, :301): none
  carries a field describing scratch or tmpfs content.
- What the item does expose is a **cell my Phase 1 did not enumerate**. My class A3 was
  the *host-side* run temp tree (`bento-run-*`, `bento-degraded-*`). The in-sandbox
  tmpfs write surfaces - `/tmp` and `/dev/shm` under bwrap - are a separate discarded-
  write class that appears in no row of my grid. Had I enumerated it, its T1 cell would
  be UNHANDLED by exactly the reasoning bv2-2dpgj gives. Recorded as a Phase 1 miss.

Note the asymmetry that item and bv2-76tn4 together reveal, which neither states: a
shield tmpfs inside the checkout **is** reported as `discarded` (shields.go:40-42),
while the runtime tmpfs `/tmp` and `/dev/shm` are reported not at all. Same mechanism,
two disclosure outcomes. That is the sharpest framing for bv2-2dpgj's ask, and it is
**VERIFIED BY READING**.

### bv2-73e4c - outside this grid, and a cell I did not walk

The launcher's Wait4(-1) precondition is not a teardown-and-reclaim question; it is
about which child a wait consumes. But it points at an A4 cell I did not enumerate:
`reapUntil` (internal/launcher/launcher.go:1058) waits on -1 and drops the bridge's
status on the floor by design (documented at launcher.go:1001-1004). "Reaping the wrong
child" is a distinct artifact-class row from "leaking a process tree", and my grid has
no row for it. **Not walked**; declared rather than quietly omitted.

## Sibling hunt: closed decisions right about their cell, silent about the row

This was the pass's main assignment. Four found, of which one was already in the grid.

1. **`TestCreatedShieldsExcludesPreexistingPaths`** (shields_test.go:59) - pins the
   existence skip as a safety property. Right about a user's own `.git/config`, silent
   about a leftover bento itself created. Already reported as F1. **VERIFIED BY SPIKE.**
2. **bv2-76tn4's "That cleanup is correct and is not the bug."** Right that the cleanup
   does not cause the commit window; silent about whether the cleanup runs to completion.
   F2 is the rest of that row. **VERIFIED BY SPIKE** (F2).
3. **`launcherProcAttr`'s "which the degraded report discloses"** (degraded.go:415).
   Right about the setsid escape; silent about the supervise-path orphan it names in the
   same sentence. **VERIFIED BY SPIKE** (R1 above).
4. **bv2-ntncf's "bento already computes exactly which paths it would create."** Right
   about a fresh run; false for leftovers, because the function named computes the
   complement (shields.go:480). **VERIFIED BY READING.**

The recurring shape across all four: a true statement scoped to one cell, written in a
place a reader takes as a verdict on the whole mechanism. Three of the four are
comments or ticket prose rather than code, which is why none of them fails any test.

## Filing recommendation

| finding | disposition |
|---------|-------------|
| F1 (A1/T6) | **append to bv2-ntncf** - same cell; add the shields.go:480 correction to its option (1) |
| F2 (reclaim silence) | **file new**, P2, cross-ref bv2-ntncf and bv2-76tn4; it refutes bv2-76tn4's "the cleanup is correct" |
| F3 (write dir on setup failure) | **file new**, P3; touches no open item |
| F4 (contradictory comments) | **file new**, P4/chore; the correct fact is already recorded in bv2-dyz92 |
| A4/T6 degraded correction | **appended to bv2-dyz92** - the residual was undisclosed, not merely unfixed (spike R1). Closed since: `teardownResidual` (probe.go:454) discloses it |
| F5 | **no item** - dismissal stands; instead append to bv2-2dpgj the shield-tmpfs-vs-runtime-tmpfs disclosure asymmetry |
| grid gaps | bv2-76tn4's during-run window, bv2-2dpgj's in-sandbox tmpfs class, and reapUntil's wait target are three classes my Phase 1 did not enumerate - noted so a later grid inherits them rather than rediscovering them |

---

# Base correction

The grid and the re-open pass above were walked in a worktree based on `main`
(924e291). The branch this work lands on is `docs/state-grids` at 0a45ddb, 89 commits
ahead. Every `file:line` cited above has been re-checked against 0a45ddb in the main
checkout, and the four spikes were re-run there.

**Headline: nothing died. F1, F2, F3 and the R1 correction all still reproduce at
0a45ddb, and none of them was fixed in the 89 commits.** The only casualties are line
numbers.

Why the risk was low for this area specifically, and this is checkable rather than
reassuring: `git diff 924e291..HEAD` reports **`internal/linux/shields.go`,
`internal/linux/alias.go`, `internal/linux/shields_test.go` and
`internal/launcher/degraded.go` byte-identical** across the 89 commits. Those four
files carry F1, F2, the `bounded` machinery and the closed decision F1 refutes.
`internal/linux/linux.go` changed by two lines at :94-99 (`exec.LookPath("bwrap")` ->
`resolveBwrap()`), net zero, so every cite from line 100 onward is untouched. The seven
shield-named commits in the range are validate/doctor/gate **reporting** changes, and
every added `.go` file is a test - no new reclaim path exists anywhere.

## Re-run at 0a45ddb

All four throwaway spikes were rewritten against the main checkout, run, and deleted.
Each asserts the safe behaviour and each still fails.

| spike | result at 0a45ddb | stamp |
|-------|-------------------|-------|
| F1 - a leftover `<grant>/.git/hooks` is scheduled for reclaim | `F1 STILL CONFIRMED: leftover not scheduled; dirs=[.vscode .cargo .idea]` | **RE-VERIFIED BY SPIKE at 0a45ddb** |
| F2 - a failed reclaim reaches the caller | `F2 STILL CONFIRMED: config survived and nothing was returned` | **RE-VERIFIED BY SPIKE at 0a45ddb** |
| F3 - no write-grant dir survives a post-`prepareWriteDirs` setup failure | `F3 STILL CONFIRMED: build/out survives` | **RE-VERIFIED BY SPIKE at 0a45ddb** |
| R1 - the degraded disclosure names the supervise-path orphan | `R1 STILL CONFIRMED: no mention of a SIGKILLed bento leaving a supervised target` | **RE-VERIFIED BY SPIKE at 0a45ddb** |

`F4` was already measured in the main checkout after the environment moved, so its
`systemd-run --scope` execution result needs no re-run. `F5`'s dismissal rests on two
prose cites, both re-read below.

## Cites that match byte for byte at 0a45ddb

Whole files unchanged, so every line cited in them is exact:

- **internal/linux/shields.go** - :40-42, :58, :102-106, :179, :351, :465-469, :475,
  :480, :577, :579-586, :583, :587-602, :588, :590, :598, :606, :672
- **internal/linux/alias.go** - :34, :42-51, :52, :212
- **internal/linux/shields_test.go:59** - `TestCreatedShieldsExcludesPreexistingPaths`,
  the closed decision F1 refutes, unchanged
- **internal/launcher/degraded.go** - unchanged

Unchanged region of a changed file (the edit is confined to :94-99 and is net-zero):

- **internal/linux/linux.go** - :104, :108, :110, :121, :129, :130, :146, :150, :159,
  :163, :165, :194, :207, :210, :234, :256, :272, :281, :297, :301, :302, :314, :315,
  :318, :334, :335, :341, :368, :520, :664, :671, :690, :721, :786, :790, :794, :831,
  :841, :879, :988, :1016

## Cites that moved but hold

| cited above | at 0a45ddb | note |
|-------------|-----------|------|
| internal/linux/args.go:519 (`--die-with-parent`) | **:531** | the line was refactored - `--new-session` moved into `sessionFlags` - but `--die-with-parent` is still emitted unconditionally, so the A4/T6 bwrap HANDLED verdict is unaffected |
| internal/linux/probe.go:284 (the setsid disclosure) | **:285** | text unchanged; R1 re-verified against it by spike, not by reading the line |
| internal/linux/degraded.go, every cite after :237 | **+8** | an 8-line insertion at :238 reads the scope back while the target is alive. So :239->:247, :245-251->:253-259, :248->:256, :270->:278, :273->:281, :284->:292, :285->:293, :291->:299, :292->:300, :301->:309, :345->:353, :413-416->:421-424, :415->:423, :417->:425, :426->:434. Cites at or below :237 (:137, :153, :157, :158, :211, :227, :233, :235) are unchanged. |
| internal/linux/profile.go:132, :133 | **:135, :136** | +3 |
| internal/launcher/launcher.go:339 (`rec.runs = nil`) | **:358** | |
| internal/launcher/launcher.go:1001-1004, :1058 | **~:1019-1022, :1077** | |
| enforce/enforce.go:479-491 (the `Exposed` contract) | **:489-501** | wording unchanged; F5's dismissal re-read in full and intact |
| cmd/bento/render.go:1999 (`writeExposedWarning`) | **:2027**, warning text at :2032 | wording unchanged, including the two-kinds-names-three residual |

## Cites that were wrong in the original pass, independent of the base

Two, found by this re-check and corrected here rather than silently:

- **internal/linux/profile.go:80-88** for the "that mkdir is the one host artifact
  profiling leaves" rationale. That was wrong in the worktree too, not a base drift -
  the comment sits at **profile.go:123-130** at 0a45ddb and was around :122 before.
  F3's claim that the rationale exists at exactly one of three call sites is unaffected;
  only the pointer was bad.
- **internal/linux/linux.go:512-514** for `bridgeReportedDeath`'s systemd-run sentence.
  It spans **:511-514**; my range was off by one. F4 stands - the sentence is verbatim
  what I quoted.

## Nothing that does not survive

No finding, dismissal or verdict above is invalidated by the newer tree.

- **F1** - `createdShields`'s existence skip is byte-identical (shields.go:480) and the
  test pinning it is byte-identical. The bv2-ntncf remedy correction stands verbatim.
- **F2** - `removeCreatedShields` is byte-identical, all three silent routes included,
  and it still returns nothing.
- **F3** - `prepareWriteDirs` is unchanged and the five post-`prepareWriteDirs` failure
  sites are all still present at their cited lines.
- **F4** - both contradicting comments are still in the tree, at :511-514 and
  shields.go:583 ("all three entry paths", still two callers). The tracker already
  carried the correct fact; 89 commits later the stale comment is still there.
- **F5** - the `Exposed` contract and its single renderer are unchanged in wording. The
  dismissal stands.
- **R1 / the A4/T6 degraded correction** - was still open at this stamp:
  `launcherProcAttr` and its half-true disclosure claim were unchanged (degraded.go:425,
  comment at :421-424), and the degraded `Consequences` text never mentioned a SIGKILLed
  bento. Closed after this stamp by `teardownResidual` (probe.go:454); see the A4/T6
  section above.

The filing recommendation table above is therefore unchanged. What this pass changes is
only the line numbers a reader would follow, and the honesty of two cites that were bad
from the start.

A stamp certifies the method, not the tree - so every stamp above should be read as
`... at 0a45ddb`, which is what this section establishes.
