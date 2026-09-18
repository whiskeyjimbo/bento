# State grid: the DURING-RUN window for host artifacts bento materializes

Technique: `state-grid` (Phases 0-3). Phase 4 tracker filing is the orchestrator's.

**Worked from commit `09ddde4f6f41bfbc14799888a2fcb8e231c3ca1f`** (`docs: seventh state
grid sweep`). The worktree was branched from `main`, 111 commits behind; it was detached
onto 09ddde4 and `git rev-parse HEAD` confirmed before a single source file was read.

Scope: what exists on the host, and where, **while the target is alive** - the window
`docs/state-grid-teardown.md` explicitly recorded that its dimensions "folded away
entirely" (that file, line 361). Dimensions derived from the code only: no git log, no
tracker, no candidate list.

---

## Phase 0 - fit call: ACCEPT

Signals present:

- **A mirror pair, three-way.** One rule set (`shieldRules`, internal/linux/shields.go:97)
  is consumed by three functions that must agree about the same path:
  `shieldMount` (shields.go:673) decides what the *target* sees, `shieldsApplied`
  (shields.go:31) decides what the *operator* is told, and `createdShields`
  (shields.go:475) decides what gets *reclaimed*. Two of the three independently consult
  the same `sb.exists` seam and branch on it differently.
- **An enum times its call sites.** `denylist.Deny` x `Rule.Dir` x host existence = 8
  outcomes, consumed by those three switch sites. The grid writes itself.
- **A degradation flag.** `sb.exists` is a bounded seam (`boundHostSeams`); args.go:438-441
  already names in prose the case where it expires and makes `shieldsApplied` say
  read-only for a shield that got a tmpfs.

Invariant (one-sided), adopted as proposed:

> An artifact bento materializes inside the user's checkout is either invisible to
> everything that would capture it, or disclosed - never present, capturable and
> unmentioned.

Allowed direction: over-disclosing, or shielding more cautiously than needed. Forbidden
direction: a capturable artifact nobody named, or one named in terms that say it was
already there.

**Routed elsewhere, not verdicted here** (orderings, not states - the nominating prompt
asked for these to be named rather than guessed at):

- `removeCreatedShields`' "the zero-length check is not atomic with the unlink"
  (shields.go:577) -> `concurrency-audit`. Already routed by the teardown grid; repeated
  so the capture finding below cannot be swept out with it.
- "a host process that CREATED one of these paths and still holds the descriptor"
  (shields.go:575) -> `concurrency-audit`.
- With `TMPDIR` under a write grant, the target can read and write bento's own run
  directory (the shield empty-file, `proxy.sock`) - that is an attacker-capability
  question about an enforcement seam, not a cell -> `threat-model`. Spike-observed below
  as part of C5/O3; the *disclosure* half of it is verdicted here, the *capability* half
  is not.

---

## Phase 1 - dimensions

Window is the scope, not an axis: "before start" is five trivial IMPOSSIBLEs (nothing is
materialized until bwrap runs) and "after teardown" is the committed teardown grid's. The
before/during coupling that genuinely exists gets its own small Grid B instead of being
multiplied through.

**Grid A - artifact class (6) x observer (3) = 18 cells**, all during-run.

Classes, read off the branches of `shieldMount` (shields.go:673-707), `createdShields`
(shields.go:475-500), `pseudoFSFlags` (args.go:512-518) and the run temp trees
(linux.go:851, degraded.go:153):

| id | artifact class | mechanism |
|----|----------------|-----------|
| C1 | **materialized file shield** - an absent `DenyWrite`/`DenyAll` *file* rule | shields.go:705 / :689 `--ro-bind <emptyFile> <path>`; bwrap creates a zero-byte host file at `<path>` |
| C2 | **mount-point directory** - an absent rule with `Dir: true` | shields.go:697 / :687 `--tmpfs <path>`; bwrap creates the host directory |
| C3 | **in-sandbox tmpfs `/tmp`** | args.go:515 `--tmpfs /tmp`, verified by the launcher at internal/launcher/verify.go:21-39 |
| C4 | **in-sandbox `/dev/shm`** | args.go:512 `--dev /dev`; bwrap synthesizes an empty tmpfs at `/dev/shm`. denylist.go:61 names it in `ManagedMounts` |
| C5 | **scratch write / host run temp tree** - `bento-run-*` (linux.go:851) and the degraded tier's `bento-degraded-*` scratch exported as `TMPDIR` (degraded.go:153, :272-273) | `os.MkdirTemp("")`, so the location follows the host `$TMPDIR` |
| C6 | **intermediate mount-point parent** - the `.cargo/` above an unborn `.cargo/config.toml` | shields.go:489-495 synthesizes it for reclaim; bwrap mkdirs it |

C6 is split out from C2 deliberately: C2's directory is a *rule path* and reaches
`shieldsApplied`; C6's is not a rule path and reaches nothing but the reclaim list. Same
mechanism, different disclosure, so folding them would hide the verdict.

The in-sandbox tmpfs classes (C3, C4) are kept as their own rows, per the teardown grid's
flag, and are *not* collapsed into C5: C5 is a host-side directory that follows `$TMPDIR`,
C3/C4 are namespace-local mounts that no host path names.

Observers, which the code itself branches on:

| id | observer | where the code has an opinion about it |
|----|----------|----------------------------------------|
| O1 | the target inside the sandbox | `shieldMount`'s tmpfs-vs-ro-bind choice is exactly this observer's view |
| O2 | the host user / operator | `enforce.ShieldApplied.Kind` (enforce.go:556-566) and the stderr legends |
| O3 | git in the checkout | `ChangedAutoExec` (enforce.go:502-525) is the code explicitly reasoning about host-side capture of files under a write grant |

**Grid B - the before-start existence snapshot (5 cells).** `createdShields` reads
existence *before* the run (shields.go:478-483, and the doc comment at :551-556 calls that
"the whole safety argument"), and everything downstream trusts that snapshot for the
duration.

Total: **23 cells. All 23 are walked below.**

---

## Phase 2 - verdicts

### Grid A

#### C1 - materialized file shield

| observer | verdict |
|----------|---------|
| **O1 target** | **HANDLED** - shields.go:702-705: an absent `DenyWrite` file gets `--ro-bind sb.emptyFile <path>`. The target reads zero bytes and writes get EROFS. The reported kind `read-only` (enforce.go:558) is *accurate for this observer*. |
| **O2 host user** | **WRONG** - and wrong twice over. (i) *Nothing names the path inside this grid's window at all*: `Result.Shields` is populated only on the terminal arms (linux.go:316, :333, :353, :387), every one of which returns after the target has exited, and spike 2 shows the `sandbox engaged: 7 ... shielded` line printing after the target's own output. While the target is alive the operator has no channel naming `<checkout>/.cargo/config.toml`. (ii) When the line does arrive it says `Kind == "read-only"`, because `shieldsApplied` reaches `"discarded"` only under `if r.Dir && !sb.exists(r.Path)` (shields.go:40-42) - so the one kind whose documented meaning is "the path did not exist on the host" (enforce.go:559-561) structurally cannot fire for a file. enforce.go:556-561 does not *say* that `read-only` means the path pre-existed - it says `read-only` is "the path stays readable but cannot be written" and reserves the did-not-exist sentence for `discarded`. The pre-existence is what an operator infers from the contrast, and the contrast is the defect: the vocabulary has a word for "bento created this" and withholds it here. |
| **O3 git** | **WRONG - forbidden direction, headline.** `denylist.Workspace` (denylist.go:1820-1821) emits `<checkout>/.cargo/config.toml` and `<checkout>/.cargo/config` as `DenyWrite` **file** rules outside `.git`. Absent on a normal checkout, so bwrap creates both as zero-byte host files for the whole run. `git status` lists them untracked and `git add -A` stages them. Nothing excludes them, and the only thing that names them says `read-only`. See **F1**. |

#### C2 - mount-point directory (rule path)

| observer | verdict |
|----------|---------|
| **O1 target** | **HANDLED** - shields.go:697 `--tmpfs`; writable, contents vanish with the namespace. This is the behaviour the `discarded` kind exists to describe. |
| **O2 host user** | **HANDLED** - shields.go:40-42 reports `discarded`, and render.go's closing legend ("a discarded shield reports no error at all: the write succeeds, and reached a scratch mount that goes away with the run, not the host") spells it out. Observed on a real run below. |
| **O3 git** | **IMPOSSIBLE - with the mechanism named as EXTERNAL, which is the whole of its weight.** `.vscode` and `.idea` are created as *empty* host directories, and git does not track directories, so `git status` sees nothing. Verified by execution: the spike's `git status --porcelain -uall` listed only the two `.cargo` files, never `.vscode` or `.idea`. There is no `file:line` in this repo to cite - the enforcing mechanism is git's index format, not bento's code - so this cell is held by nobody here, and a rule shape that later put a file inside such a directory would move straight into C1/O3 with nothing failing to compile. Recorded as the coupling gap Phase 2 asks for. |

#### C3 - in-sandbox tmpfs `/tmp`

| observer | verdict |
|----------|---------|
| **O1 target** | **HANDLED** - args.go:515 mounts it fresh; internal/launcher/verify.go:29-39 refuses the run if `/tmp` is not `TMPFS_MAGIC`, so the target cannot be handed the host's scratch under a granted write. |
| **O2 host user** | **UNHANDLED - tolerated direction.** `enforce.Result` carries no field for the runtime tmpfs and no stderr line names it on an enforced run. This is the asymmetry the teardown grid flagged: a shield tmpfs inside the checkout is reported `discarded` (shields.go:40-42), the tmpfs every single run mounts is reported not at all - same mechanism, two disclosure outcomes. It stays in the *tolerated* direction because the artifact is outside every checkout and dies with the mount namespace, so it is under-disclosure of a **non-capturable** artifact. Partial mitigation exists only on the profiling path (`printScratchWrites`, cmd/bento/profile.go:1080-1091). See **F3**. |
| **O3 git** | **IMPOSSIBLE** - the mount lives in the run's own mount namespace (args.go:506 `--unshare-*` plus bwrap's own namespace) at `/tmp`, which is outside every checkout; verify.go:39 asserts it is a fresh tmpfs rather than a bind of anything a host process can reach. |

#### C4 - in-sandbox `/dev/shm`

| observer | verdict |
|----------|---------|
| **O1 target** | **HANDLED** - args.go:512 `--dev /dev`; bwrap synthesizes `/dev/shm` as a fresh empty tmpfs (verified by execution, below). denylist.go:61 lists it in `ManagedMounts` so a grant cannot bind the host's over it. |
| **O2 host user** | **UNHANDLED - tolerated direction.** Weaker than C3/O2: `/dev/shm` is not even reached by the profiling frontend's scratch messaging, which hardcodes `sandboxTmp = "/tmp"` (cmd/bento/profile.go:887, profile/profile.go:140). A target's shm segments are invisible in every report. Non-capturable, outside every checkout, so tolerated. Folded into **F3**. |
| **O3 git** | **IMPOSSIBLE** - denylist.go:61 `ManagedMounts` and the `--dev` mount; the path is `/dev/shm`, outside every checkout, namespace-local. |

#### C5 - host run temp tree / scratch write

| observer | verdict |
|----------|---------|
| **O1 target** | **HANDLED** - bwrap tier: nothing of `runDir` is bound in by name except `sb.emptyFile` and `proxy.sock` (linux.go:851-900), both of which the target sees only as the shield mount and the socket. Degraded tier: the scratch dir **is** deliberately exported as `TMPDIR`/`TMP`/`TEMP` (degraded.go:272-273), with any inherited value dropped first. |
| **O2 host user** | **UNHANDLED - tolerated direction.** `os.MkdirTemp("", "bento-run-")` (linux.go:851) and `"bento-degraded-"` (degraded.go:153) are reclaimed by `defer cleanup()` (linux.go:112) and `defer os.RemoveAll(dir)` (degraded.go:157), and named in no report while the run is alive. Ordinarily under the host temp dir, outside the checkout - hence tolerated. |
| **O3 git** | **UNHANDLED - forbidden direction.** `os.MkdirTemp("")` honours `$TMPDIR`. Nothing in `newSandbox` or `runDegraded` constrains where that points, so an operator whose `TMPDIR` is inside their checkout gets `<checkout>/.../bento-run-NNNN/` as a live, git-visible host directory for the whole run, named in no report. Spike-observed. See **F2**. |

#### C6 - intermediate mount-point parent

| observer | verdict |
|----------|---------|
| **O1 target** | **UNHANDLED - tolerated direction.** The target sees a directory (`<checkout>/.cargo/`) that was not there before, and no code names it to anyone. Disclosure to the untrusted party is not what the invariant protects, so this is tolerated; recorded so the cell is not silently absent. |
| **O2 host user** | **UNHANDLED - forbidden direction, narrowly.** shields.go:489-495 builds these paths *for reclaim only*; `shieldsApplied` iterates rules (shields.go:35) and a synthesized parent is not a rule, so `<checkout>/.cargo` appears in no report anywhere. It surfaces only if reclaim fails, via `warnResidue` (linux.go:144). The mitigating fact: its children *are* named, so an attentive operator can infer the parent. Folded into **F1**, which is the same root. |
| **O3 git** | **UNHANDLED - subsumed, non-additive.** git cannot stage a directory, so this parent reaches a commit only through its children, which are C1/O3. Verified by execution: `git status --porcelain -uall` named `.cargo/config` and `.cargo/config.toml`, not `.cargo/`. |

### Grid B - the before-start existence snapshot

`createdShields` fixes the artifact set from `sb.exists` *before* the run
(shields.go:478-483); the reclaim, the report kind and the carvability check all trust
that one read.

| id | cell | verdict |
|----|------|---------|
| B1 | the snapshot is taken before anything is materialized | **HANDLED** - shields.go:551-556 states and relies on it: a path already on the host is never in the list, so reclaim can only remove what bento caused to appear. `preflightGrants` orders it before `prepareWriteDirs` (linux.go:700-706) and `absentWrites` (linux.go:700) records the same way for write grants. |
| B2 | a path appears on the host between the snapshot and the launch | **UNHANDLED - tolerated.** bwrap then binds over an existing path rather than creating one, and reclaim will try to remove it; `removeCreatedShields` refuses a non-empty file and a non-empty directory (shields.go:603-619), so a *populated* one survives. A file created empty in that window is removed. Ordering-flavoured, but it is a state at launch time, so it is verdicted rather than routed. |
| B3 | a path present at the snapshot is removed before the launch | **HANDLED** - it is not in `createdShields`, so nothing reclaims it; bwrap creates the mount point and it is left standing. That is the *over-cautious* direction the teardown invariant permits, and `warnResidue` does not fire because the path was never in the list. |
| B4 | the `sb.exists` seam expires at snapshot time | **HANDLED** - args.go:438-444 computes `shieldsApplied` *ahead* of the `deadMount` check precisely so an expiry is on record before the check reads it, and the run is refused rather than shipped with an audit nobody can vouch for. This is the one place the codebase already names this grid's class of defect in prose. |
| B5 | a leftover artifact from a prior SIGKILLed run makes the snapshot say "exists" | **UNHANDLED** - `createdShields` skips any path where `sb.exists` is true (shields.go:479-481), so an empty `.cargo/config.toml` a killed run left behind is permanently invisible to every future reclaim *and* flips its reported kind forever. This is the teardown grid's F1 (its A1/T6 cell) seen from the during-run side; it is that item's row, not a new one. Recorded, not filed twice. |

Every one of the 23 cells has exactly one verdict. No cell was left unwalked.

---

## Phase 3 - verification

### Spike 1 - the capture cell (C1/O3, C1/O2, C2/O3, C6/O3)

A throwaway `internal/linux/spike_duringrun_test.go` built a real git checkout in a temp
dir, called `createdShields`/`denyArgs`/`shieldsApplied`/`shieldMount` against it with the
checkout as the only write grant, materialized exactly the paths `createdShields` named,
and asked git what it saw. It needs no user namespace, so it survives bwrap being
unavailable.

```
createdShields dirs=[<repo>/.vscode <repo>/.cargo <repo>/.idea]
createdShields files=[<repo>/.git/config.worktree <repo>/.cargo/config.toml <repo>/.cargo/config]
REPORT <repo>/.cargo/config        kind=read-only
REPORT <repo>/.cargo/config.toml   kind=read-only
REPORT <repo>/.idea                kind=discarded
REPORT <repo>/.vscode              kind=discarded
MOUNT  <repo>/.cargo/config.toml -> [--ro-bind <run>/shield <repo>/.cargo/config.toml]
MOUNT  <repo>/.vscode            -> [--tmpfs <repo>/.vscode]

git status during run:
  ?? .cargo/config
  ?? .cargo/config.toml
git add -A staged:
  .cargo/config
  .cargo/config.toml
```

The test was written to fail if the claim is true, and it failed.

### Spike 2 - a real enforced run

`./bento run --allow-unapproved` on a manifest with that checkout as its only write grant,
the target listing the checkout from inside the sandbox:

```
.cargo  .git  .idea  .vscode  README      <- during the run, in the checkout
.cargo: config  config.toml
stat -f .cargo/config.toml  -> ext2/ext3   <- a ro-bind of a host file, not scratch
stat -f .vscode             -> tmpfs       <- the discarded shield, as reported
stat -f /tmp /dev/shm       -> tmpfs tmpfs
[bento] sandbox engaged: 7 credential/host-service path(s) shielded
        (0 hidden, 5 read-only, 2 discarded)
=== HOST AFTER: .git  README
```

Independently corroborates Spike 1's counts (5 read-only / 2 discarded), confirms the
teardown path reclaims cleanly on a clean exit, and confirms that the run's *only*
operator-facing word about the two files it created in the checkout is "read-only".

### Spike 3 - `TMPDIR` inside the checkout (C5/O3)

Same manifest, `TMPDIR=<checkout>/tmpdir`:

```
ls -a tmpdir  ->  .  ..  bento-run-488597496
```

A live bento-owned host directory inside the user's checkout for the whole run, named in
no report.

### Spike 4 - inverting a dismissal (C4/O1)

The claim that bwrap's `--dev` yields a *fresh empty* `/dev/shm` is an assertion about an
external binary, so it was executed rather than recalled:

```
$ bwrap --ro-bind / / --proc /proc --dev /dev --tmpfs /tmp --unshare-user --unshare-pid \
    sh -c 'stat -f -c %T /tmp /dev/shm; ls -a /dev/shm; ls -a /tmp'
tmpfs
tmpfs
.  ..
.  ..
```

Both empty, both tmpfs. The C4/O1 HANDLED and the C3/O3 and C4/O3 IMPOSSIBLE verdicts rest
on this and it holds.

---

## Findings, forbidden direction first

### F1 - a bento-created file inside the user's checkout is git-capturable for the whole run, and the report says it was already there

**Cells: C1/O3 (headline), C1/O2, C6/O2. Verdict WRONG. `VERIFIED BY SPIKE`** (spikes 1
and 2, both run, output above).

Stamp precision: the conjunction was proved in two steps rather than observed live. Spike
2 proved bwrap creates these host files (the in-sandbox `stat -f` answers `ext2/ext3`, a
ro-bind of a host inode, not scratch, and teardown then removes them); spike 1 proved git
stages files at exactly those paths. Neither spike ran a host-side `git status` while a
target was alive. The composition is sound but it is a composition, not one observation.

`denylist.Workspace` emits `.cargo/config.toml` and `.cargo/config` as `DenyWrite` **file**
rules (denylist.go:1820-1821) - the only Workspace rules that are files *and* sit outside
`.git`, where git can see them. On the ordinary checkout that has neither, bwrap creates
both as zero-byte host files, plus `<checkout>/.cargo/` to hold them. For the entire run:

- `git status` lists them untracked;
- `git add -A` stages them, and a target doing broad staging commits them;
- **inside the window, nothing names them.** `Result.Shields` is post-run by construction
  (linux.go:316, :333, :353, :387 are all terminal arms), so the disclosure channel does
  not exist while the artifact is capturable;
- when it does arrive, it says `Kind == "read-only"`, which enforce.go:558 defines as "the
  path stays readable but cannot be written". That sentence never claims the path
  pre-existed; the operator infers it from the contrast with the kind that *does* carry the
  did-not-exist sentence. The kind that exists to say "the path did not exist on the host" is
  `discarded`, and `shieldsApplied` gates it behind `r.Dir` (shields.go:40-42), so it
  structurally cannot fire for a file;
- `<checkout>/.cargo/` is synthesized for reclaim only (shields.go:489-495) and appears in
  no report at all, before or after.

This is the forbidden direction without qualification: present, capturable, unmentioned -
and then, after the fact, mentioned in terms that assert it was already there. A kind that
asserts pre-existence is worse than silence, because it tells the operator not to look.

The observer split is what makes this precise and is why the axis earned its place: the
`read-only` kind is **correct** for the in-sandbox observer (the target really does get a
read-only empty file) and **wrong** for the host observer. One field is being asked to
describe two views that diverge exactly here.

**The DenyAll arm is the same root and a `r.Dir` fix does not reach it.** Read
shields.go:37-43 whole:

```go
kind := "hidden"
if r.Deny == denylist.DenyWrite {
    kind = "read-only"
    if r.Dir && !sb.exists(r.Path) { kind = "discarded" }
}
```

The `DenyAll` arm never consults `sb.exists` at all, so it can never report `discarded`
whatever `r.Dir` says. Meanwhile `createdShields` gates on `!sb.exists(r.Path)` alone
(shields.go:480) with no test on `Deny`, and `shieldNeeded` returns true for an absent
`DenyAll` path that is writable (shields.go:648-652). So an absent `DenyAll` path inside a
write-granted checkout - reachable through `Options.DenyPaths` / `sb.extraDeny`, which is
exactly the supervising-embedder shape shields.go:726-733 documents - is created by bwrap,
tracked for reclaim, and reported `hidden` with no existence test anywhere in its path.

**Severity corrected in the Re-open pass below, by spike.** The sibling arm's disclosure
defect is real and confirmed, but it is *not* git-capturable and so is not F1's direction.
Read this paragraph with R1 below.

So the fix is **"consult existence in both arms"**, not "drop `r.Dir`": `shieldsApplied`
should ask `!sb.exists(r.Path)` before choosing any kind, and `enforce.go:559-561`'s
wording needs extending to cover the ro-bind-of-empty-file case - bento created the path,
which is the part that matters, but writes EROFS rather than vanishing, so the kind's
sentence has to carry the distinction rather than eliding it. Filing note: this is **one**
item, not two - a fix that lands only on the `DenyWrite` file case leaves the identical
defect in the sibling arm, which is precisely the one-cell-fix-in-an-unmapped-row shape
this technique exists to catch - though R1 below establishes that the two arms differ in
*severity*, so the single item covers two directions of the invariant, not one.

The regression test for the cell is spike 1, graduated.

### F2 - `TMPDIR` inside a checkout puts bento's run directory in the user's checkout, undisclosed

**Cell: C5/O3. Verdict UNHANDLED. `VERIFIED BY EXECUTION`** (spike 3).

`os.MkdirTemp("", "bento-run-")` (linux.go:851) and `os.MkdirTemp("", "bento-degraded-")`
(degraded.go:153) follow `$TMPDIR`, and nothing constrains it. With `TMPDIR` under the
checkout the run directory - holding the shield empty-file and, when egress is on,
`proxy.sock` - is a git-visible host artifact inside the checkout for the run's duration,
named in no report.

Lower blast radius than F1 (it needs an unusual `TMPDIR`) but it is the *unambiguous*
forbidden direction: present, capturable, and named nowhere at all. The lazy fix is a
sentence, not a mechanism: either refuse a `TMPDIR` that resolves under a write grant, or
name the run directory in the report the way the shields are named. The capability half of
this - the target can read and write bento's own run directory when `TMPDIR` is under a
write grant - is routed to `threat-model` and deliberately not verdicted here.

### F3 - the runtime tmpfs disclosure asymmetry, recorded and not inflated

**Cells: C3/O2, C4/O2. Verdict UNHANDLED, tolerated direction. `VERIFIED BY EXECUTION`**
(spike 2's stderr named 7 shields and nothing about `/tmp`; spike 4 confirmed `/dev/shm`).

A shield tmpfs inside the checkout is reported `discarded` (shields.go:40-42); the `/tmp`
tmpfs every run mounts (args.go:515) and the `/dev/shm` every run gets (args.go:512) are
reported not at all. Same mechanism, two disclosure outcomes - the asymmetry the teardown
grid recorded and did not pursue.

**It stays in the tolerated direction.** Both are outside every checkout, namespace-local,
and die with the mount namespace, so this is under-disclosure of a *non-capturable*
artifact - which the invariant permits. The one place it bites is the profiling frontend,
which already says it partially (`printScratchWrites`, cmd/bento/profile.go:1080-1091,
`/tmp` only; `/dev/shm` reaches no message because `sandboxTmp` is hardcoded at
cmd/bento/profile.go:887 and profile/profile.go:140). Worth a line in the enforced run's
legend; not worth a field.

### Dismissals, verified inverted

- **C2/O3 dismissed** ("empty `.vscode`/`.idea` are invisible to git"), and downgraded from HANDLED to IMPOSSIBLE-with-an-external-mechanism because no line in this repo enforces it. Inverted and
  asserted in spike 1: `git status --porcelain -uall` was asked for *everything* and named
  only the two `.cargo` files. **`VERIFIED BY EXECUTION`.** Flagged as vacuous: the
  protection is git's semantics, not bento's code.
- **C3/O3, C4/O3 dismissed as IMPOSSIBLE.** Both cite an enforcing line (verify.go:39 for
  `/tmp`, denylist.go:61 plus args.go:512 for `/dev/shm`) and spike 4 executed the external
  assumption underneath them rather than recalling it. **`VERIFIED BY EXECUTION`.**
- **B4 dismissed as HANDLED.** Rests on args.go:438-444 ordering `shieldsApplied` ahead of
  the `deadMount` check. Traced first-hand, nothing executed: **`VERIFIED BY READING`.**
  What would settle it is a fake-seam test that expires `exists` between the two and
  asserts the run refuses.
- **B2 left UNHANDLED-tolerated.** The claim that `removeCreatedShields` refuses a
  non-empty file and a non-empty directory is read off shields.go:603-619 only:
  **`VERIFIED BY READING`.**

---

## What was not walked

Nothing in the 23 cells. Deliberately outside the grid, each with its route:

- the three orderings named in Phase 0 (`concurrency-audit`, `threat-model`);
- the whole **after-teardown** window - `docs/state-grid-teardown.md` owns it, and B5 is
  that grid's A1/T6 cell seen from this side, recorded rather than re-filed;
- the **degraded tier's** shield story, which has no mount namespace and reports `exposed`
  instead of `applied` (degraded.go:137) - it materializes nothing in the checkout, so it
  has no row in a grid about materialized artifacts. C5 is the one class where it appears,
  and it appears there with the bwrap tier.

## Handoff to fuzzing

Grid A is finite and small: the per-cell assertion is one function - *given a rule and a
host existence state, does the kind reported to the operator agree with what bwrap was
told and with what a host observer can see* - looped over the 8 `Deny` x `Dir` x `exists`
outcomes. The unbounded dimension is the checkout shape underneath it, which is what
`persistence_fuzz_test.go` and `shield_fuzz_test.go` already mutate. F1 and F2 are
permanent corpus seeds.

---

# Re-open pass (Phase 2, second half)

The known-open list was withheld until the grid above was written, so nothing in Phase 1
was derived from it. This section is the cell-by-cell re-open: for each open item touching
this area, which cell it fixed, and whether the rest of its row was carried along.

## R1 - the DenyAll sibling arm: settled by spike, and my own severity claim was wrong

**`VERIFIED BY SPIKE`.** A throwaway `internal/linux/spike_denyall_test.go` put an absent
caller deny (`Options.DenyPaths`, the supervising-embedder shape) inside a write-granted
checkout and asked the three consumers what they each did with it:

```
RULE   <repo>/control-store  deny=DenyAll dir=true
MOUNT  -> [--tmpfs <repo>/control-store]
REPORT <repo>/control-store  kind=hidden
createdShields dirs=[<repo>/control-store ...]  files=[... .cargo/config.toml .cargo/config]
```

Two results, and the second corrects me:

1. **The disclosure defect is confirmed.** The path did not exist on the host, bwrap
   creates it, and the operator is told `hidden` - which enforce.go:557 defines as "the
   path is absent". It is not absent; it is a writable tmpfs bento created in the checkout,
   into which the target can write for the whole run and lose everything at teardown. That
   is precisely what the `discarded` kind exists to say, and the `DenyAll` arm cannot reach
   it because it never consults `sb.exists`.
2. **My severity was wrong, and the spike is what caught it.** I wrote the sibling arm up
   as the same direction as F1. It is not. `buildExtraDeny` forces `dir := true` for any
   path that does not exist (linux.go:992-995), so a caller deny **never** becomes a
   materialized host *file* - it is always a `--tmpfs` directory. Empty directories are
   invisible to the index (C2/O3), so the sibling arm is **tolerated direction**:
   under-disclosure of a non-capturable artifact, the F3 family rather than the F1 family.

So the answer to "can it be settled by spike rather than left at VERIFIED BY READING" is
yes, and it should have been spiked before the stamp was chosen: the reading was correct
about the mechanism (`shieldsApplied` never tests existence in that arm) and wrong about
what the mechanism produces, because `buildExtraDeny` decides `r.Dir` one file away and I
had not opened it. Recorded rather than quietly amended, because a reviewer who trusts the
first paragraph and skips this one gets the wrong priority.

What survives for filing: **"consult existence in both arms" is still the right fix**, and
it is still one item, because one edit to shields.go:37-43 fixes both. But the two arms sit
on opposite sides of the invariant, so the item's acceptance needs two regression cells,
not one: the DenyWrite-file case (capturable, F1) and the DenyAll-absent case
(non-capturable, disclosure only).

## R2 - F1 vs bv2-76tn4: SAME CELL. Evidence appends there; do not file a new item.

The bead already has more than my spike does, and it is fair to say so: it carries a
measured broad-staging lane at bento cd2f3ef that produced an actual commit carrying
`.cargo/config` and `.cargo/config.toml`, and it already reasons through why `.vscode` and
`.idea` never showed the same thing (the index does not track empty directories - the same
fact my C2/O3 cell rests on, arrived at independently). My spikes reproduce that, they do
not extend it. **The capture claim is the bead's, not mine.**

Three things the bead does **not** have, all of them about disclosure rather than capture:

1. **Its option (1) is under-specified in a way that matters.** The bead proposes "list the
   paths bento materialized inside the checkout in the run report and the epilogue". Both of
   those are **post-run**: `Result.Shields` is populated only on the terminal arms
   (linux.go:316, :333, :353, :387), and spike 2 shows the epilogue printing after the
   target's output. A report that arrives after the artifact stopped being capturable does
   not close the cell it is proposed for. An in-window channel is a different change from a
   richer post-run one. **`VERIFIED BY EXECUTION`** (spike 2's ordering).
2. **The reporting channel option (1) asks for already exists, and is actively misleading.**
   The bead reads as though these paths are unreported. They are reported - as
   `Kind: "read-only"`, the kind reserved for a path that stays readable but cannot be
   written, while the kind carrying the did-not-exist sentence is withheld by the `r.Dir`
   gate at shields.go:40-42. So option (1) is cheaper than the bead thinks (fix a kind on a
   list that ships today) and more urgent than it thinks (the current line does not merely
   omit - it invites the wrong inference). **`VERIFIED BY SPIKE`** (spike 1's `REPORT` lines).
3. **The sibling arm, R1.** Same edit site, opposite direction, absent from the bead.

Also worth appending: the bead's `.vscode`-as-writable-tmpfs measurement and my C2/O2
verdict agree, and both point at the same place - `discarded` is the vocabulary that
already describes this correctly for directories, which is why extending it to the other
two branches is the fix rather than inventing a fourth kind.

**Filing recommendation: append to bv2-76tn4, do not open a new bead.** Its acceptance
should become: the kind is computed from existence in both arms; an in-window disclosure
channel (or an explicit decision that post-run is enough, recorded); regression cells for
DenyWrite-file and DenyAll-absent.

## R3 - F3 vs bv2-2dpgj: SAME CELL, already appended by a prior grid. One correction to its ask.

The sharpest framing in that bead's notes - "a shield tmpfs inside the checkout IS reported
as 'discarded' (shields.go:40-42) while the runtime tmpfs is reported not at all" - is
exactly F3, appended there on 2026-09-18 before I started. My C3/O2 and C4/O2 verdicts
agree with it and add nothing to the framing.

They do correct its **ask**. The bead asks for "N files written to scratch, discarded" in
the report and epilogue. As the code is scoped, that message cannot reach `/dev/shm`:
`sandboxTmp` is the literal `"/tmp"` in both frontends (cmd/bento/profile.go:887,
profile/profile.go:140), and `profile.SandboxScratch` answers about `/tmp` alone
(profile/profile.go:449-465). A target that stages in `/dev/shm` - which the bead's own
rejected-alternative note says several runtimes need - is counted by nothing. **`VERIFIED
BY READING`** for the two constants; **`VERIFIED BY EXECUTION`** that `/dev/shm` is a real
fresh writable tmpfs on this tier (spike 4). The ask should name both mounts, or name the
class rather than the path.

I also confirm the prior reviewer's reading that this is *not* an invariant violation:
under my one-sided invariant both mounts are outside every checkout and non-capturable, so
this is the tolerated direction. F3 is a P3 visibility item and should stay one.

## R4 - B5 vs bv2-ntncf: same cell, remedy analysis unchanged, one consequence to add

My Grid B B5 is that bead's cell from the before-start side, and I confirm its correction
holds: `createdShields` filters on `!sb.exists(r.Path)` (shields.go:480), so a stale
artifact is exactly what it will not return, and inverting the filter is what
`TestCreatedShieldsExcludesPreexistingPaths` forbids for a good reason. **Nothing in my
before-start snapshot changes the remedy analysis** - a start-of-run reclaim still needs a
durable record of what a prior run created, or option (2). Said plainly rather than
dressed up as an addition.

One consequence the bead does not carry, which falls out of F1: a stranded artifact does
not only evade reclaim, it **flips its own disclosure forever**. Once the stranded
`.cargo/config.toml` exists, every subsequent run's `sb.exists` answers true, so
`createdShields` skips it *and* - on the fixed-kind version of F1 - `shieldsApplied` would
report it `read-only` rather than `discarded`, correctly, because from that run's point of
view it genuinely did pre-exist. The stranded artifact therefore becomes permanently
indistinguishable from a file the user wrote. That raises the value of option (2) relative
to option (1) and is worth one line in the bead. **`VERIFIED BY READING`** (shields.go:40-42
and :480 together); not spiked, because it needs a SIGKILLed run followed by a second run,
and the first half of that is bv2-ntncf's own measured experiment.

## R5 - the two beads closed today, checked for a stopped row

- **bv2-t41ij** (`removeCreatedShields` now returns unreclaimed paths). It fixed the
  *teardown* silence: `removeCreatedShields` now returns the paths still standing
  (shields.go:597-626) and `warnResidue` prints them (linux.go:144, :732-740). **The row was
  carried along for its own window and stops exactly at mine.** The mechanism it added
  reports only on failure, only after the run - so the during-run window it walks past has
  no channel at all. This is not a defect in that fix; it is the boundary that makes F1's
  point (1) above a genuinely separate change rather than a follow-on.
- **bv2-obrnf** (setup-failure directories now reported). Same shape: `absentWrites`
  (linux.go:711-722) records before the `MkdirAll` and the deferred `warnResidue`
  (linux.go:113-121) names them when a run did not start. That is Grid B's B1, which I
  verdicted HANDLED, and the cite is that work. **No stopped row**: its own cell is
  complete. Worth noting that its pattern - record the absent set *before* touching the
  host, then report what is left - is exactly the shape F1's in-window channel would reuse,
  so the two are neighbours rather than duplicates.

## R6 - F2's disclosure fix: is it F1's fix? No - and here is the test that separates them.

Asked because the answer decides one bead or two.

F1's fix is a **kind computation** on a list that already ships: `shieldsApplied` consults
existence in both arms. It changes no path set. Applied on its own it does nothing at all
for F2, because the run directory under a checkout-local `$TMPDIR` is not a shield, has no
`denylist.Rule`, and never enters `shieldsApplied`.

F2's fix is a **path set** question: the run directory is absent from every list bento
reports. So they are one bead only if the in-window channel from R2 point (1) is scoped as
*"every host path bento creates for this run"*. Scoped that way - `createdShields`' dirs
and files **plus** `sb.runDir` (linux.go:851) and the degraded scratch (degraded.go:153) -
one change covers both. Scoped as `createdShields`' output alone, which is the natural
reading of bv2-76tn4's option (1) and of what the code makes easy, it covers F1 and misses
F2 entirely.

**Recommendation: file F2 separately, cross-referenced to bv2-76tn4.** Two reasons. The
scopes genuinely differ (a shield rule set versus the run's whole host footprint), and F2
has a second fix available that F1 does not - refusing or relocating a `$TMPDIR` that
resolves under a write grant, which removes the artifact instead of describing it, and is
the cheaper change. If the orchestrator prefers one bead, the merge is safe **only** if the
acceptance says "every host path this run creates", in those words; the moment it says
"the materialized shields" the F2 cell is silently dropped. That is the one-cell-fix shape
again, so it is worth the sentence.

## Re-open pass summary

| finding | cell | route |
|---------|------|-------|
| F1 | C1/O3, C1/O2, C6/O2 | **append to bv2-76tn4** - same cell; the capture claim is the bead's, the three disclosure corrections and R1 are the additions |
| R1 (DenyAll arm) | C1/O2 sibling | **same bead, same edit** - but tolerated direction, and the acceptance needs both regression cells |
| F2 | C5/O3 | **file new**, cross-ref bv2-76tn4; merge only under a "every host path this run creates" acceptance |
| F3 | C3/O2, C4/O2 | **no new item** - already on bv2-2dpgj; append the `/dev/shm` scoping correction to its ask |
| B5 | Grid B | **no new item** - bv2-ntncf's cell; append the permanent-misclassification consequence |
| bv2-t41ij, bv2-obrnf | - | no stopped row; boundary noted, both are neighbours of F1's in-window channel |

Stamps in this section: R1 `VERIFIED BY SPIKE`; R2 points 1 and 2 `VERIFIED BY EXECUTION` /
`VERIFIED BY SPIKE`; R3 mixed `VERIFIED BY READING` and `VERIFIED BY EXECUTION` as marked;
R4 `VERIFIED BY READING`; R5 `VERIFIED BY READING`; R6 is an argument about scope, not a
claim about behaviour, so it carries no stamp - what would settle it is the wording of the
acceptance criterion, which is the orchestrator's to write.
