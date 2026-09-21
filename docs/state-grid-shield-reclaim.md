# State grid: stranded-shield reclaim (record trust x path state)

Technique: `state-grid` (Phases 0-3). Tracker filing is the orchestrator's.
Scope: `recordCreatedShields` (internal/linux/shields.go:976), `reclaimStrandedShields`
(:1049), `parseShieldRecord` (:1125), `openOwnRecord` (:1158), `reclaimShieldPaths`
(:692), `parentResolved` (:748), and the two callers (internal/linux/linux.go:102/:150,
internal/linux/profile.go:109/:154). Dimensions derived from the code; git log and the
tracker were read only in the re-open pass, after every cell had a verdict.

## Phase 0 - fit call: ACCEPT

- A lifecycle axis with real branches: the record is published before the launch
  (linux.go:150) and removed only with the run directory by the sandbox cleanup
  (linux.go:943), so where the creating run died decides what the record claims versus
  what exists.
- A trust decision in code: `openOwnRecord` plus the flock decide whose record is acted
  on. That is the only WHO axis used.
- A mirror pair: the reclaim reuses the same-run teardown checks (`reclaimShieldPaths`)
  over an open-ended window instead of one run.

Invariant (one-sided), adopted as proposed:

> Reclaim may leave a stranded shield artifact behind; it must never remove, or modify,
> a path this tool did not create.

Out of scope, routed to `concurrency-audit`: two runs reclaiming at once (the flock
second-taker at shields.go:1063), a run starting while a reclaim is in flight
(documented at shields.go:1023-1027), and the Lstat-then-unlink window (shields.go:647).

Split along the real seam: grid A decides WHETHER a record's paths are acted on at all;
grid B decides WHAT happens to one path once they are.

## Grid A - record trust (does the record reach `reclaimShieldPaths`?)

| id | record state | verdict | where |
|----|--------------|---------|-------|
| A1 | no record (died before the :1000 rename, or a run with no shields) | HANDLED | shields.go:1167 open fails -> skip; the temp name is never globbed (:987 vs :1050) |
| A2 | own record, holder alive (lock held) | HANDLED | shields.go:1063 LOCK_NB fails -> skip |
| A3 | own record, holder dead (killed after the record) | HANDLED | proceeds to grid B, shields.go:1072-1090 |
| A4 | own record, clean exit | IMPOSSIBLE | run dir RemoveAll'd by cleanup (linux.go:943), deferred before the shield defer (linux.go:113 vs :154) so it runs last. Coupling gap: only defer order enforces it |
| A5 | run dir of another uid, not 0700, or not a dir | HANDLED | shields.go:1160-1166 |
| A6 | record is a symlink, FIFO, or another uid's file in an own dir | HANDLED | shields.go:1167 O_NOFOLLOW/O_NONBLOCK, :1171-1178 |
| A7 | truncated (no trailing NUL) | HANDLED | shields.go:1127 |
| A8 | unknown kind byte, empty entry, relative or unclean path | HANDLED | shields.go:1132-1138 |
| A9 | well-formed, own uid, names a path outside any checkout | UNHANDLED | no checkout binding in the record or the parse; any absolute clean path reaches :1090. Only author is this uid (A5/A6), so routed to threat-model |
| A10 | record lost (reboot, tmpfiles sweep) | HANDLED (allowed direction) | artifact left standing; shields.go:1040-1042 |

## Grid B - path state at reclaim time (record trusted, A3)

WHEN is folded into what the path holds: a run killed after the record but before bwrap
created the node leaves the path absent; a run killed mid-run leaves bento's empty node.
Either way what decides the outcome is what stands there at reclaim.

| id | path state | kind | verdict | where |
|----|------------|------|---------|-------|
| B1 | bento's untouched empty node | f | HANDLED | shields.go:720 Remove after :706-717 |
| B2 | bento's untouched empty node | d | HANDLED | shields.go:734 rmdir |
| B3 | gone (never created, or user deleted it) | f/d | HANDLED | shields.go:709 / :736, IsNotExist is clean |
| B4 | user content: non-empty file | f | HANDLED | shields.go:712 size -> kept |
| B5 | user content: non-empty dir | d | HANDLED | shields.go:737 ENOTEMPTY -> kept |
| B6 | now a symlink (last component) | f | HANDLED | shields.go:706 Lstat, not regular -> kept |
| B7 | now a symlink (last component) | d | HANDLED | rmdir on a symlink is ENOTDIR, shields.go:737 -> kept |
| B8 | kind flipped (record d / now file; record f / now dir) | f/d | HANDLED | shields.go:712 / :737 ENOTDIR |
| B9 | parent swapped for a symlink or a non-dir | f/d | HANDLED | shields.go:698 / :726 via parentResolved :748 |
| B10 | parent errs (EACCES, dead mount) | f/d | HANDLED | parentResolved default arm -> left, not kept; record retried, shields.go:1092 |
| B11 | Lstat errs other than ENOENT | f | HANDLED | shields.go:710 -> left |
| B12 | whole cleanup exceeds the bound | f/d | HANDLED | shields.go:743 all left, kept nil -> record kept for retry |
| B13 | **user's own EMPTY node, made after bento's was gone or never made** | f/d | **WRONG** | shields.go:712/:734 cannot tell it from B1/B2; removed, and not reported (not in left) |

Counts: HANDLED 20 (incl. A10 allowed-direction), IMPOSSIBLE 1 (A4), UNHANDLED 1 (A9),
WRONG 1 (B13). No cells left unwalked.

## Adversarial re-review of HANDLED

- B7: rmdir(2) does not follow a trailing symlink (ENOTDIR). Spike kept the link and
  its empty target dir.
- B9: parent check and remove are not atomic; an interleaving, routed.
- A4: holds only by defer order in linux.go and profile.go; no test named for it found.
  Coupling gap, not a defect.
- B12: `bounded` abandons rather than cancels the closure, so after an expiry it can
  still remove paths while the record is kept; the retry then finds them absent (B3).
  Allowed direction.

## Phase 3 - findings, ranked by blast radius

1. **B13 - WRONG, VERIFIED BY SPIKE.** Record written, run killed before bwrap made
   `hooks/` and `.envrc`; the user then `mkdir hooks` and `touch .envrc`; the next
   `reclaimStrandedShields` removed both (spike failed with ENOENT on both). No content
   is lost (the nodes are empty), but a path the tool did not create is removed and
   nothing is reported. The record proves bento made a node at that name, not this node,
   and the window runs until the next bento start.
2. **A9 - UNHANDLED, VERIFIED BY READING.** No checkout binding in the record; routed to
   threat-model.

Dismissals inverted: B4, B6, B7, B8 (record d, now an empty file) ran as one spike with
the user state in place; all survived. VERIFIED BY SPIKE. A5-A8 are covered by existing
tests (shields_test.go:1734, :1760, :1857); B9 by :1877. Spikes deleted.

## Re-open pass

- 470317c (introduced reclaim) carried the same-run checks B1-B8 into an open-ended
  window; that is where B13 came from - the row was not re-derived for the new window.
- 286e705 fixed A5/A6. a9a550c fixed B9. 65fef8e fixed B10 (left, not kept).
- B13 is already tracked as bv2-zlqjy (open, decision: record dev/inode after launch vs
  accept and document). A10 is bv2-eq5cw (open). No new cell beyond those.

## Routed

- threat-model: A9. Any process running as this uid (and a sandboxed target, if
  runDirBase `/tmp` is writable from inside the sandbox - not checked here) can create a
  0700 `bento-run-*` dir with a record naming arbitrary absolute paths, and the next
  bento start rmdirs empty dirs and unlinks empty files there with the user's rights.
- concurrency-audit: concurrent reclaimers, reclaim vs a starting run, the Lstat/unlink
  gap.
