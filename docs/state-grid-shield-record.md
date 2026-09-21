# State grid: shield-record provenance - what a record proves vs what reclaim does with it

Area: `internal/linux/shields.go` - `recordCreatedShields` (:922), `reclaimStrandedShields`
(:993), `parseShieldRecord` (:1066), `openOwnRecord` (:1099), and the path half of
`removeCreatedShields` (:677) that reclaim delegates to; call sites `internal/linux/linux.go:102`
/ `:150` and `internal/linux/profile.go:109` / `:154`. Reviewed at 265a790.

Inherited, not re-walked: the artifact-class x termination-mode verdicts in
`state-grid-teardown.md` (a killed run strands mount points; the record is the fix for its F1)
and `state-grid-during-run.md`. Deliberate planting in a shared `/tmp` by another uid is routed
to `threat-model`; only the distinctions `openOwnRecord` actually makes are cells here.

## Phase 0 - fit

Fit. Mirror pair: the writer (`recordCreatedShields`) and the reader (`parseShieldRecord` +
`openOwnRecord`) must agree on what a trustworthy record is, and the record must agree with
the host path it names at reclaim time. An enum-ish dimension (record state) crosses a second
(what now sits at the recorded path). Not churning at HEAD.

Invariant (one-sided): reclaim may leave a stranded shield behind. It must never remove or
alter a path that a record does not prove this user's bento created, and it must never report
a reclaim it did not do. Allowed: leaving, over-reporting. Forbidden: removing what the record
does not vouch for; silence over a path left standing.

## Phase 1 - dimensions (from the code)

Grid A - record state, as `reclaimStrandedShields` classifies it before any path is touched:

- R1 no `bento-run-*` directories (or Glob error), :994
- R2 run directory, no `shields.record` (live run pre-record; killed mid-record leaving only `.tmp`)
- R3 run directory not a real dir, not 0700, or not this uid, :1101-1106
- R4 record not a regular file (symlink, FIFO, directory), :1108 / :1113
- R5 record file owned by another uid inside our 0700 dir, :1117
- R6 record ours, flock held by a live run (other process or same process), :1007
- R7 record ours, flock free, whole and well-formed (walked in Grid B)
- R8 truncated: no trailing NUL, or a zero-filled tail after power loss, :1068
- R9 empty entry or unknown kind byte, :1073-1078
- R10 well-formed but not something bento writes: relative path; same path as `d` in one record and `f` in another
- R11 record lost (reboot, tmpfiles sweep) between the kill and the next run
- R12 record released by a run that exited cleanly, in the window between `shieldRecord.Close()` (linux.go:157) and `cleanup()` removing runDir
- R13 record ours but with a loose mode (not 0600)

Grid B - for R7, what sits at a recorded path now, crossed with what removeCreatedShields does:

- P1 absent
- P2 bento's own empty artifact still standing (the case the record exists for)
- P3 an empty dir or zero-byte file the user created at the same path after bento's was gone
- P4 user content at the path (non-empty file, populated dir)
- P5 leaf replaced by a symlink
- P6 an intermediate component replaced by a symlink
- P7 kind swapped (recorded `f`, now a dir; recorded `d`, now a file)
- P8 path on a dead mount (host answer hangs) - inherited from teardown's bound verdicts

Reporting column (checked per cell): is silence emitted only when the path is really gone,
and is the record deleted (:1030) only then?

## Phase 2 - verdicts (first pass, by reading)

### Grid A

| Cell | Verdict |
|---|---|
| R1 | HANDLED shields.go:1025 returns before touching anything. |
| R2 | HANDLED openOwnRecord's OpenFile fails (:1108) -> nil -> skip. A kill between `.tmp` create and rename leaves the run dir forever (never deleted, nothing sweeps it); allowed direction, outside the checkout, same residual as teardown A3/T6. |
| R3 | HANDLED :1101-1106 (Lstat, IsDir, perm == 0700, uid). |
| R4 | HANDLED O_NOFOLLOW + O_NONBLOCK at :1108, IsRegular on the descriptor at :1113. |
| R5 | HANDLED :1117 uid on the descriptor. |
| R6 | HANDLED :1007 LOCK_NB fails. Same-process concurrent Run is also covered: the sweeper's OpenFile is a new open file description, and flock conflicts across descriptions even within one process. |
| R8 | HANDLED :1068 (last element must be empty). A zero-filled tail yields an empty entry, refused at :1073. |
| R9 | HANDLED :1073 / :1077. |
| R10 relative path | UNHANDLED - parseShieldRecord accepts any non-empty path; a relative one is resolved against the reclaiming process's cwd. Only a same-uid writer can produce it (bento writes paths from createdShields), so it is a hardening gap, not a reachable bento defect. Candidate for an `filepath.IsAbs` refusal beside the kind-byte refusal. |
| R10 kind conflict | HANDLED, over-reports: the path lands in both `dirs` and `files`; the file branch Lstats a dir, calls it left, and both records are kept and re-warned. Allowed direction. |
| R11 | HANDLED in the allowed direction, documented at :989-991: artifact stays, indistinguishable from user content. Not reported (nothing left to report from). |
| R12 | HANDLED: the paths were already removed by the owning run's defer, so reclaim sees P1 and deletes the run dir. If a concurrent live run in the same checkout has meanwhile re-created a mount point at that path, this is the race documented at :966-970 (accepted). |
| R13 | HANDLED by design: only the directory's mode is checked; a 0700 same-uid directory is the trust boundary, the record's own mode adds nothing another uid could use. |

### Grid B (R7)

| Cell | Verdict |
|---|---|
| P1 | HANDLED shields.go:682 absent is clean; record and run dir deleted (:1030). Nothing reported, correctly. |
| P2 | HANDLED file removed only if regular and zero bytes (:682-689), dir via rmdir (:693). |
| P3 | WRONG (forbidden direction) - the record proves bento created *a* node at this path once, not this one. A zero-byte file or empty dir the user made after bento's was gone is removed and nothing is said. Reachable wherever the record outlives the artifact: a kill after the owning run's teardown ran but before cleanup(), or an earlier reclaim that removed some paths and kept the record for another. The zero-length rule (:640-642) argues an empty file "holds nothing", but its existence is the content (a marker or placeholder). |
| P4 | HANDLED - kept and named (:684). But the record is then kept (:1029) and re-warned on every future run, forever, with text blaming a killed run for what is now user content. Contradicts the "self-limiting" claim at :980-981. Allowed direction; noise, not a violation. |
| P5 | HANDLED - file: Lstat sees a symlink, not regular, left and named. Dir: rmdir on a symlink fails ENOTDIR, left and named. The target is untouched. |
| P6 | UNHANDLED - os.Remove and syscall.Rmdir resolve intermediate components, and shieldLstat checks only the leaf. A recorded `<co>/.git/hooks` whose `.git` is now a symlink reaches an empty dir or zero-byte file outside the recorded tree. Same-uid only. Forbidden direction. |
| P7 | HANDLED - recorded `f` now a dir: not regular, left. Recorded `d` now a file: rmdir ENOTDIR, left. Both named. |
| P8 | HANDLED per teardown grid: one bound over all records (:1027), expiry reports every input path, no record deleted. |

Reporting column: silence is emitted for P1 (true) and for P3/P6 (the node is gone, but it was
not bento's - the second clause of the invariant holds literally, the first does not). No cell
found where a path left standing is reported as reclaimed.

Tally: 21 cells. HANDLED 18 (incl. allowed-direction notes on R2, R10-kind, R11, P4), WRONG 1
(P3), UNHANDLED 2 (P6, R10-relative). IMPOSSIBLE 0.

## Phase 2 - re-open pass

- 470317c / bv2-ntncf (closed, "reclaim reuses removeCreatedShields' own safety checks"). Fixed
  the teardown grid's T6 row for P2. The decision it records is the one refuted here: those checks
  were argued (shields.go:640-647) for a same-run teardown whose window is one run long, with the
  residual named as "a host process touching the path during the window the run occupied". Reused
  for a cross-run reclaim, the window becomes "any time until some later bento starts", and the
  leaf-only Lstat was never argued against a parent that changed. P3 and P6 are that row not
  carried.
- 286e705 (trust only our own records). Fixed R3/R4/R5 - who may have WRITTEN the record. The row
  not carried: what the record may SAY (R10 relative) and what the named path may have BECOME
  (P6). Owning the record proves where the string came from, not what node sits at it now.
- 265a790 / bv2-8jj3n. Ordering coupling only; no cell of this grid moved.
- bv2-t41ij / bv2-rgqms / bv2-0hy3m. The "never report a reclaim it did not do" clause. Carried
  into reclaim: residue flows through warnResidue (shields.go:1034) from both call sites. Holds in
  every cell; the only inaccuracy is the R10-kind over-report (a removed path reported as left).
- bv2-eq5cw (open). Is R11; verdict unchanged, allowed direction.

## Phase 3 - verification

Spikes in a throwaway `internal/linux/zz_spike_test.go` (runDirBase and checkouts under
t.TempDir), deleted afterwards.

| Cell | Result | Stamp |
|---|---|---|
| P3 | A zero-byte file created at a recorded path after the record was written is removed by reclaim, nothing printed. | VERIFIED BY SPIKE |
| P6 | Record names `<co>/.git/hooks` and `<co>/.git/config`; `<co>/.git` is a symlink to another tree. The empty dir and the empty file in the OTHER tree were both removed. | VERIFIED BY SPIKE |
| R10 relative | A record `drelspike\0` rmdir'd `./relspike` in the process cwd. Writer: only this uid (the run dir must be 0700 and ours, :1101-1106) - a same-user process, or a future bug in bento's own writer. Not another user. | VERIFIED BY SPIKE |
| P5 (dismissal, inverted) | Leaf symlinks to an empty dir and an empty file: targets untouched, both named as left. | VERIFIED BY SPIKE |
| P4 (dismissal + note) | Non-empty file kept; the same warning printed on two successive reclaims and the record kept - "re-warns forever" confirmed. | VERIFIED BY SPIKE |
| R10 kind (dismissal) | The dir was removed, yet named as left and both records kept: over-report, allowed. | VERIFIED BY SPIKE |
| R13 (dismissal) | A 0666 record in a 0700 dir is honored, as designed. | VERIFIED BY SPIKE |
| R3, R6, R8, P1, P2, P7-file | Existing TestReclaimStranded* and TestRemoveCreatedShields* pass. | VERIFIED BY EXECUTION |
| R2, R4, R5, R9, R11, R12, P7-dir, P8 | Traced only. R5 needs a second uid. | VERIFIED BY READING |

## Phase 4 - findings and rejections

Forbidden direction:

1. P6 - `removeCreatedShields` (shields.go:682-693), reached from reclaim at :1027, follows a
   symlinked intermediate component out of the recorded tree. Proposed bead: "linux: shield
   reclaim follows a symlinked parent out of the checkout". Fix direction: walk with
   O_NOFOLLOW per component (openat + unlinkat), or refuse a path whose parent does not resolve
   to itself.
2. P3 - reclaim removes an empty file or dir the user created at a recorded path after bento's was
   gone (shields.go:682-693 via :1027). Proposed bead: "linux: shield reclaim cannot tell its own
   empty artifact from a user's later one". bwrap creates the node after the record is written,
   so the node's identity is not in the record; a fix needs identity captured once the node
   exists, or a stated ceiling if that is not buildable.
3. R10 - `parseShieldRecord` (shields.go:1072-1080) accepts a relative path. Same-uid writers
   only. Proposed bead: "linux: parseShieldRecord accepts a relative path".

Allowed direction, worth a bead:

4. P4 - a recorded path now holding user content keeps the record forever and re-warns on every
   run, blaming a killed run; contradicts the "self-limiting" comment at shields.go:980-981.
   Proposed bead: "linux: shield reclaim re-warns forever over user content".

Rejected: R10-kind over-report (bento's writer cannot produce it; allowed direction). R13 (the
directory is the boundary). R12 race (documented at :966-970, accepted). R2 orphaned `.tmp` run
dir (teardown A3/T6 residual, outside the checkout).

Coverage gap: P5 (leaf symlink left alone) is held by no existing test.

Not walked: none. Deliberate cross-uid /tmp planting is routed to threat-model.
