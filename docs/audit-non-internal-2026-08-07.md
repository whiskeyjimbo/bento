# Adversarial audit: all non-internal packages, 2026-08-07

Third non-internal round (after 2026-07-20 and 2026-07-26), run through the `audit-loop`
formula as wisp `bv2-wisp-42x`. Ten parallel Opus 5 subagents audited the live files on
`fix/shields-trust-records-and-relocations`; no diff was consulted.

Beads filed from this round are labelled `audit-non-internal-2026-08-07`. The two earlier
rounds did not label theirs, which is why this round's prior-art brief had to be rebuilt by
matching file paths against bead bodies.

## Scope and split

15,382 non-test lines, split by line count rather than by directory, plus one reserved
seams slot. Nothing in scope was skipped.

| Agent | Scope | Non-test LOC |
|---|---|---|
| 1 | `cmd/bento/render.go` | 1684 |
| 2 | `cmd/bento/profile.go` + `profile/` | 2343 |
| 3 | `cmd/bento/` validate, clamp, doctor, root, main, version, platform shims | 1572 |
| 4 | `cmd/bento/` run, journal, converge, prompt | 1423 |
| 5 | `cmd/bento/` trust, trust_linux, approve, accounts | 1352 |
| 6 | `policy/` + `manifest/` | 1443 |
| 7 | `enforce/` + `backend/` + `gate/` | 1929 |
| 8 | `examples/embed` + `cmd/denylist-audit` + `cmd/credhunt` | 938 |
| 9 | `examples/supervise` | 2669 |
| 10 | cross-package seams | - |

Per-agent reports, including each agent's own scope statement and its proved negatives, are
preserved verbatim in the session scratchpad and summarised below.

## The two P1s

### approve reports a manifest this host never reviewed as "already approved"

`cmd/bento/approve.go:80-83` short-circuits on `doc.Provenance.Approves ==
doc.Policy.Fingerprint()` alone. The stamp is an unkeyed sha256 that travels inside the
manifest, so that condition is satisfied identically by a manifest this host stamped and by
one that arrived from anywhere already stamped. Everything the command exists to do sits
after the return: the policy summary, the callouts, the confirmation prompt, and the journal
write. `bento approve --yes` in CI is green over a manifest nobody on that host ever saw.

The discriminator already exists and approve already computes it - `readApprovalRecord`
returns `journalAbsent` for a stamp with no local entry - but `writeReapprovalNotice`
consults the journal only on the drift path. The shortcut is also self-perpetuating: it
skips `writeApprovalRecord`, so a host in this state never acquires a journal entry.

approve's own docstring says "Review a manifest you got from elsewhere before approving it -
a shipped stamp is its author's, not your review." The command silently does the opposite for
exactly that case.

Idempotent re-approve is legitimate; the fix is to condition the shortcut on
`readApprovalRecord` returning `journalMatches` and let everything else fall through to the
full review path. That needs no new state and does not change when `run` refuses.

This extends **bv2-o3np**, which is scoped to `validate` and `run` and was deferred because
it changes when `run` refuses. approve is the third command and changes nothing about `run`.
Separately: **bv2-o3np's blocked status is discharged** - it is blocked on bv2-tg20's
journal, tg20 is closed, and `journal.go` is in the tree.

### gate.Refusals omits the credential-alias refusal, so approve stamps a manifest run refuses

The backend refuses a run on seven grant facts, not six. `preflightGrants` runs `checkGrants`
- the six `gate.Refusals` mirrors - and then `checkAliasedCredentials`, which aborts the run
when a second readable name for a shielded credential's inode exists anywhere inside a tree
the run can read. `gate.Refusals` mirrors none of it.

Each side is individually correct, which is why this needed the seams slot: `gate` promises
to mirror `checkGrants` and does, but the set the run applies is `checkGrants` plus the alias
scan.

Two aggravating facts. `requireHonorableGrants` gates the approval stamp on `gate.Refusals`
being empty, with the words "approving it would stamp a permission that does not exist" - so
`bento approve` fingerprints a manifest whose first enforced action is a refusal, and that
stamp is what CI trusts. And `gate.go:290` claims "Two narrowings remain against a run" and
names two; the alias refusal is an undocumented third, so a reader auditing the mirror for
completeness is told the list is closed when it is not.

The gap is answerable: the alias scan is pure host inspection - stat the shielded set that
`gate.ShieldSet()` already builds, compare `st_nlink`, walk the exposed trees, read
`/proc/self/mountinfo`. The only obstacle is that it lives behind `//go:build linux` while
`gate` is cross-platform, which is the obstacle bv2-pj8x already solved once by lifting
shield assembly into `internal/shield`.

Trigger: any host where a snapshot or dedup tool has hardlinked against a live credential
(`cp -al`, rsync `--link-dest`) plus a manifest granting read over the tree holding the
alias. `validate --strict` exits 0, `approve` stamps, `run` refuses. It is fail-closed for
the sandbox boundary and fail-open for the review boundary, which is what
`requireHonorableGrants` is.

Extends **bv2-jro3**, whose fix counted the mirror against `checkGrants` alone; the alias
refusal sits one call later in `preflightGrants` and was never in that count.

## Findings that refute work already shipped

Nine findings say an existing bead's fix is incomplete or has gone stale. Those are recorded
here because a wrong belief that has had time to spread costs more than a fresh bug.

- **bv2-8bm8's disclosure is now false.** `writeDegradations` tells the operator that the
  degraded tier "never scans for credential aliases, so a second name for a shielded
  credential under a granted tree was exposed rather than acknowledged." Commit `ea19261`
  (2026-08-06) made the degraded tier call the same `checkAliasedCredentials` the bwrap tier
  calls, and that function refuses rather than reports. Both halves of the sentence are now
  wrong, on the tier where an operator is least able to check, and the stale claim is
  repeated at three sibling sites - including `run.go:149`'s flag help, which tells the
  operator `--accept-alias` is inert under `--allow-degraded`, wrong in the direction that
  discourages the correct flag. `render_test.go:1130` asserts the false sentence in both
  directions, which is why `ea19261` could land without anyone noticing.
- **bv2-brc0's store-mode fix is on the wrong side of the run.** `tightenStoreDir` runs
  inside `write()`, after the run; `loadStore` performs no mode check at all. The bead's own
  stated harm - "anyone who can write there can grant themselves an allow the next run
  applies without prompting" - survives one full run, cross-uid, and the warning prints after
  the exposure it describes.
- **bv2-brc0's locking fix covered one of five call sites.** Its description named
  `forgetPerms` and `resetPerms` as carrying the same window; the close reason fixed only
  `perms global deny` and records no rationale for the others. `perms` loads the store
  unlocked and then writes the stale snapshot under `LOCK_EX`, so the lock does not narrow
  the race - it decides it in the losing direction. A concurrent run's denies are
  deterministically clobbered, and both processes exit 0.
- **bv2-rqk got a second check, not a second layer.** The trial run passes
  `DenyPaths: []string{s.dir}` and gets a kernel shield on the permission store; the enforced
  run, executing the target under every approved grant, gets none. `assertStoreShielded` is a
  second evaluation of the same `coversStore` predicate, so any hole in it is a hole in both.
  `go doc enforce.Options` documents `DenyPaths` as being for exactly this caller.
- **bv2-bm3 taught the shield clamps to resolve and left `isBroadDir` literal.**
  `isBroadDir` is the only clamp in the profiler that judges a path without resolving it,
  and it is the one whose stated job is refusing to auto-propose a tree that would re-expose
  every credential the deny-list does not enumerate. A profiled target that plants
  `$scriptdir/link -> $HOME` gets a whole-home read grant that `risky` rates false, so under
  `[a]ll` it is auto-accepted with no per-path prompt.
- **bv2-jz3 covered the rendering half of run.go, not `RunE`.** `parseEnvFlags` is named by
  no test anywhere in the tree. Nothing runs `bento run` on an approved manifest at all, so
  nothing would fail if `manifest.Resolve` moved above the approval check.
- **bv2-2lrf swept `limits.cpu` and not `limits.memory`.** `parseBytes` deliberately accepts
  lowercase `k`/`m`/`g`; the backend forwards the original string and systemd refuses it.
  Measured on this host: `MemoryMax=128M` is accepted, `MemoryMax=128m` fails to parse.
- **bv2-51jy's zero floor is not symmetric.** `memory: "0"` and `cpu: "0%"` are refused
  precisely because a zero that silently means something else is a trap; `pids: 0` validates,
  emits no `TasksMax=`, and renders as a limits block that declares no ceiling.
- **bv2-pgv9's "cheap first step" was never followed up.** That bead proposed setgid as the
  fatality signal for group-writable directories. Since then `withGroup` and
  `groupHoldsOnly` arrived, so `dirFlaws` now proves the group is shared and discards the
  proof: `fileFacts.privateGroup` is a two-valued field for a three-valued question, so
  "proven to hold other users" and "nothing could be learned" are indistinguishable, and the
  branch's comment justifies non-fatality with the private-group case that `sharedWrite`
  already removed.

## The HomeAnchors cluster

Three findings from two agents share one root. `denylist.HomeAnchors()` failing is a hard,
unconditional refusal of every run - `newSandbox` returns that error on both tiers - but
nothing in `Enforcer.Probe` consults it, so it never becomes a layer status and reaches no
machine surface.

- `gate.Check` sets `Unresolved` only for a nil policy, so an anchorless host yields an empty
  `Refusals` and a clean verdict, on the one field designed to say "I could not tell you."
- `doctor` reports `ready: true` and exits 0. Its human output prints the truth via
  `writeShieldAnchors` and then prints "This host enforces every layer." on the same screen.
  `doctorJSON` has no field for it at all.
- `validate --strict --json` returns green with `runnable: true` and no field qualifying it,
  while the human running the identical command is told a run there is refused.

Enforcement fails closed throughout - no run proceeds unshielded. What is lost is the CI gate
and the operator's diagnosis, on hosts where `os.UserHomeDir()` yields no absolute path and
the uid has no passwd entry. The tree already documents this path as untested:
`doctor_test.go:86-88` says it "needs a uid with no passwd entry, which a test on a normal
host cannot arrange."

## Two tests that pinned behaviour the code had outgrown

Worth naming as a pattern rather than as two findings.

`render_test.go:1130` asserts the degraded-tier alias disclosure in both directions - the
sentence that `ea19261` made false. `enforce/run_test.go:751-770` asserts that a mid-run
core-tier degradation returns nil under the default posture, which contradicts `admit`'s own
default branch (a core layer merely `Degraded` is enough to refuse at admission). The second
is a deliberate choice rather than an oversight, and the agent said so; the finding is that
nothing records the reasoning, and the argument the strict-only comment makes applies
verbatim to the default posture.

A test that pins a disclosure's exact words locks in the claim, not the mechanism. When the
mechanism moves, the test defends the stale claim.

## Other findings

Recorded in the beads; summarised here by area.

**Consent surfaces.** A path grant declined at the converge prompt is reinstated by the merge
union when the manifest at `--out` is unapproved or stale - `applyExecAnswer` closes exactly
this hole for `exec` and its docstring names the case, but the path half was left open.
approve's manifest-covering-write callout is skipped whenever the manifest is reached through
a symlink, because the grants are anchored lexically to the typed name while `manifestPath`
is the kernel's resolved answer; the docstring claims both are resolved the same way.
`homeRoot` does not know `/var/home`, and its "used only to warn, never to drop" defence
stopped being true when `foreignShielded` became the `[a]ll` consent gate.

**Reporting honesty.** `kept_read`/`kept_write` are computed before declined seeds are
dropped, so the merge notice and the `--json` envelope describe a manifest that was not
written. The resolved-spelling write floors have no reporting sibling, so those withheld
accesses leave no trace - the exact failure the printers were added to remove. `examples/embed`
reads one of the five fields `gate.Check` returns, so the reference embedder is silent about
an unstartable manifest. `writeDenialLegend` reads `LayerFilesystem == Degraded` as "the
Landlock-only tier" and prints a network claim contradicting the manifest, because the same
enum is set on the bwrap tier after a non-fatal Landlock failure.

**Gate freshness.** `gate.ShieldSet`'s memo is keyed on the environment alone, while the set
it caches is walked off disk - and the docstring claims the key covers all the moving input.
Both directions are wrong, and the stale-shield direction is the one `gate.go:14-16`
explicitly forbids.

**Portability and drift.** `aclNamedWrite` does not handle darwin's `ENOATTR`, so the whole
ACL check errors there; unreachable today because `manifestLocation` refuses first, live the
day macOS gets a location check. `cmd/credhunt`'s package doc says "It always exits 0" and two
paths return 1. The `denylist-audit` wrapper's status-to-verdict mapping - where the bv2-dsm2
P0 actually lived - has no test, though the Go side's statuses do and that test names the
wrapper.

## What the round did not settle

- The anchorless-host trigger for the `HomeAnchors` cluster is unspikeable on a normal host,
  by the test suite's own admission.
- Whether `profile.Synthesize` can mint a grant that `gate.Refusals` refuses. The seams agent
  traced the `skip` predicate far enough to believe the `ManagedMounts` set is covered but did
  not exhaustively check `FileWriteGrantProblems` against the write-collapse logic.
  `cmd/bento/profile.go` does not run `gate.Refusals` over the manifest it writes, so if such
  a case exists nothing catches it. Worth a follow-up pass.
- Whether the alias mirror is cheap enough to run in the gate on a large home. The backend
  gates the expensive half on `st_nlink > 1`, which suggests it is, but it was not measured.
  This shapes the fix, not whether the gap is real.
- The exact systemd `CPUQuota=` ceiling was bounded to (10000000%, 42949672%), not pinned.

## Method notes for the next round

**The brief method held.** Building it from open beads plus an explicitly headed "CLOSED -
already fixed, in the tree today" section produced zero staleness false positives for the
second round running. Keep doing this.

**`bd search` is not a dedup tool as agents will use it.** It excludes closed issues by
default and searches titles only. Two agents concluded it was non-functional and fell back to
the brief; every "Prior art: none" that rested on it was unverified. A sweep with
`--status all --desc-contains` afterwards found real prior art for two findings the agents had
recorded as novel - including bv2-pgv9, whose own text proposed the "cheap first step" that
one finding shows was never followed up. Put `bd search --status all --desc-contains` in the
next brief explicitly, or pre-run the sweep and hand agents the result.

**Splitting by line count worked again.** The seams slot earned its place unambiguously this
round: its P1 is a composition hole that neither the `gate` reviewer nor an `internal/linux`
reviewer could see, since each side satisfies its own contract.

**Two agents independently reached the same conclusion three times** - approve-before-resolve
holds, bv2-brf0's fix is complete with no sibling keying mismatch, and the `ShieldSet` memo is
stale. Independent corroboration through different derivations is worth more than a spike on
those, and none was spent.
