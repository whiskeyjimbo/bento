# State grid: manifest trust flaws vs the frontends that act on a manifest

Base: detached worktree at `docs/state-grids` 7bc186f. Execution harness: a scratchpad
script built `bento` and ran approve, validate, validate --json, run --json (current and
stale stamp, with and without --allow-unapproved) over a manifest stamped in a 0700
directory and then `chmod 777` on that directory, with XDG_STATE_HOME in scratch. The
off-Linux consumer logic was fed the unlocated `trust.Manifest{}` on linux (the value
`Inspect` returns on `ErrLocationUnknown`, trust/trust.go:200-202) in a throwaway test;
`GOOS=darwin GOARCH=arm64 go vet ./trust ./cmd/bento` compiles. All spikes deleted.

## Phase 0 - fit

Good fit. Signals: one flaw computation (`Manifest.Flaws`, trust/trust.go:269, and its
location half `LocationFlaws`, :290) consumed by four frontends through three different
selectors (stampFlaws, LocationFlaws, Flaws-for-refusal), with two machine forms
(run --json, validate --json, profile --json) that each mirror a stderr form. The
platform stub is a sentinel that can be read as "nothing found".

Invariant (one-sided): every frontend that acts on or stamps a manifest surfaces every
flaw it computes in each output form it offers, and none reads ErrLocationUnknown, or a
flaw check it could not perform, as no flaws. Over-warning is allowed.

Out of the invariant by design, and not graded as findings: run and validate only warn
on a flaw, fatal or not (trustwarn.go:33-36); stampFlaws computes nothing for an
unstamped manifest (trustwarn.go:27-29), so there is no computed flaw to surface.

## Dimensions (from code)

Flaw sources:
- **L** location flaw on linux: directory holding it, a symlink, a fatal chain directory (trust.go:301-339).
- **M** manifest-file flaw: group/world-writable mode, foreign owner (trust.go:271-282). Only in `Flaws`, not `LocationFlaws`.
- **U** location unknown: off linux `manifestLocation` returns ErrLocationUnknown (trust_other.go:26), `Inspect` keeps `located=false`, `LocationFlaws` returns a fatal flaw (trust.go:295-299). `pathDirs` also returns it (trust_other.go:34), which reaches `InspectNew` as an error.
- **S** stamp gate: stampFlaws returns nil unless `Approves` is set (trustwarn.go:27).

Frontends and forms: run human, run --json (success, refusal); validate human, validate
--json; approve human (no --json); profile human, profile --json.

Platform matters only for U, and only where the frontend is reachable off linux: run and
profile call checkPlatform first (run.go:65, profile.go:96; platform_other.go:24), validate
and approve do not.

## Grid A - source x frontend x form (26 cells)

| Source | Frontend / form | Verdict | Where / what | Stamp |
|---|---|---|---|---|
| L | run human | HANDLED | run.go:90-91 warnUntrusted(stampFlaws) before any refusal | EXECUTION |
| M | run human | HANDLED | same call, Flaws includes file half (trust.go:271-283) | READING |
| L | run --json, target ran | HANDLED | run.go:93 notes.StampAtRisk, carried into writeRunResult (run.go:165) | EXECUTION |
| M | run --json, target ran | HANDLED | same slice | READING |
| L/M | run --json, refused after notes built | UNHANDLED | refuse (run.go:59) -> refuseStreamJSON (run.go:312-318) emits Reason/Report only; notes built at run.go:89-98 are dropped. Hits requireApproval (stale stamp, run.go:102), Resolve, ResolveEnv, backend.New | EXECUTION |
| L/M | run --json, hint | WRONG (minor) | run.go:93 carries f.Reason only; Hint and Fatal printed on stderr (trustwarn.go:39-41) have no JSON field | EXECUTION |
| U | run (any form) | IMPOSSIBLE | checkPlatform refuses first, run.go:65 / platform_other.go:24 | READING |
| S | run (unstamped, --allow-unapproved) | HANDLED (by design) | trustwarn.go:27, no flaw computed | READING |
| L | validate human | HANDLED | validate.go:65 warnStampAtRisk | EXECUTION |
| M | validate human | HANDLED | same | READING |
| U | validate human | HANDLED | Inspect keeps unlocated (trust.go:200), Flaws -> LocationFlaws fatal flaw (trust.go:295), printed via warnStampAtRisk | SPIKE |
| L | validate --json | UNHANDLED | stdout envelope has no flaw field (validate.go:69-78, policyJSON validate.go:439-515); flaw only on stderr | EXECUTION |
| M | validate --json | UNHANDLED | same | READING |
| U | validate --json | UNHANDLED | same; the "cannot be checked on darwin" flaw never reaches stdout, so a macOS CI gate reading stdout sees an approved manifest and no caveat | READING (consumer logic SPIKE; darwin binary not runnable here) |
| S | validate (unstamped) | HANDLED (by design) | trustwarn.go:27 | READING |
| L fatal | approve | HANDLED (refuses) | requireApprovableLocation approve.go:412-421, before shortcut and stamp | EXECUTION |
| L nonfatal | approve | HANDLED | approve.go:65 warnUntrusted(LocationFlaws) | READING |
| M fatal (foreign owner) | approve | HANDLED (refuses) | approve.go:413 iterates Flaws, not LocationFlaws | READING |
| M nonfatal (mode) | approve | HANDLED | not warned by design (trust.go:286-289); rewrite clamps and announces | READING |
| multiple fatal | approve | WRONG (minor) | approve.go:414-419 returns on the first fatal flaw; later fatal flaws are computed and never shown, so a fix-and-retry loop reveals them one at a time. Refusal still holds | READING |
| U | approve | HANDLED (refuses) | trust.go:295 fatal -> approve.go:414; approve does not call checkPlatform | SPIKE |
| L | profile human | HANDLED | profile.go:298 warnUntrusted(LocationFlaws) on existing or InspectNew location | READING |
| M | profile (any form) | HANDLED (by design) | profile rewrites and voids the stamp; LocationFlaws only | READING |
| L | profile --json | UNHANDLED | profileJSON (render.go:199-235) has no flaw field; flaws go to stderr only (profile.go:298) | READING |
| U | profile (any form) | IMPOSSIBLE | checkPlatform, profile.go:96; InspectNew would also refuse with ErrLocationUnknown (profile.go:294-296, trust_other.go:34) rather than read clean | READING |
| U | InspectNew consumer | HANDLED | error propagated to refuse, never swallowed (profile.go:294-296) | READING |

## Adversarial re-check of HANDLED

- No consumer calls `errors.Is(err, trust.ErrLocationUnknown)` outside trust.go:200; the
  sentinel is never mapped to an empty flaw list. The unlocated zero Manifest yields a flaw
  from stampFlaws, LocationFlaws and requireApprovableLocation (spike, inverted: each
  assertion would have failed on an empty result).
- approve's already-approved shortcut (approve.go:84) runs after both the refusal and the
  warning, so a current stamp cannot skip them.
- run and validate proceed with exit 0 on a fatal location flaw (EXECUTION: val=0, run=0
  in a 0777 directory). Advisory by stated design (trustwarn.go:33-36); validate --strict
  does not gate on it either. Recorded, not graded.

## Findings (forbidden direction first)

1. **validate --json omits every trust flaw from stdout** (L, M, U). VERIFIED BY
   EXECUTION on linux (stdout grep for the flaw: 0; stderr carries it). The off-linux
   cell is the sharpest: validate is the one command documented to run there, and its
   "cannot check" caveat is stderr-only.
2. **run --json refusal objects drop stamp_at_risk** (and approval_note) for any refusal
   after run.go:98. VERIFIED BY EXECUTION: stale stamp in a 0777 dir, stderr warns, stdout
   refusal object has no stamp_at_risk.
3. **profile --json envelope carries no location flaws.** VERIFIED BY READING (profile
   needs a sandbox run; not executed).
4. **run --json carries Reason without Hint/Fatal.** VERIFIED BY EXECUTION. Minor.
5. **approve surfaces only the first fatal flaw.** VERIFIED BY READING. Minor; refusal
   direction is correct.

## Rejections

- "run/validate should refuse on a fatal flaw": rejected, advisory by documented design.
- "unstamped manifests hide flaws": rejected, stampFlaws deliberately computes none.
- "approve hides the manifest-mode flaw": rejected, rewrite clamps it (trust.go:286-289).
- "off-linux run/profile read unknown as clean": rejected, checkPlatform refuses first.

## Re-open pass

Open beads:
- **bv2-ati60** duplicates finding 1 for L and M. U is the same defect, not a separate one:
  off linux, stampFlaws returns the unlocated flaw through the same warnStampAtRisk call
  (validate.go:65), so one stamp_at_risk-style field in policyJSON closes all three cells.
  The bead should name the U cell so its test covers `trust.Manifest{}`: that cell is where
  the gap costs most, since validate is the command documented to run off linux.
- **bv2-uzlc2** duplicates finding 3 (profile --json, L).
- **bv2-uyx1h** does not overlap. It is about exit codes for --relocatable, and no cell here
  covers that.

Landed work:
- **8422b26** (approval_note in validate --json) is outside this grid. It closes approval-grid
  cells F and J, which are about stamp notes, not trust flaws. It adds no carrier for flaws,
  so the validate --json L/M/U rows stay UNHANDLED.
- **0eacfd5** introduced stampFlaws and notes.StampAtRisk. It is in HEAD, so the run --json
  "target ran" rows above already describe it as landed. Finding 2 is refusals raised in
  RunE before enforce.Run, which go through refuseStreamJSON with no notes.
  Judgement on the acceptance for a stale-stamp refusal: **it holds**. On a stale stamp, the
  at-risk note devalues a stamp that run has already rejected. Nothing ran. The consumer's
  next step is approve, and approve refuses on the same fatal location flaws itself
  (approve.go:412-421, EXECUTION: appr=125 in the 0777 dir) or warns on the non-fatal ones
  (approve.go:65). So the flaw reaches whoever acts on the manifest next. The same holds for
  a current stamp refused by Resolve, ResolveEnv or backend.New. Finding 2 moves to
  **accepted**, and its row becomes HANDLED (accepted: pre-enforce refusal, stderr carries it).
  Finding 4 (Hint/Fatal missing from the JSON) is unaffected.

Approval grid beads (all closed by 8422b26):
- bv2-65id6 (unrecorded-stamp note) and bv2-mxvq6 (shared-journal note) have the same shape
  as finding 1: a stderr-only fact about how much the stamp is worth, missing from validate
  --json. They are a different fact (journal vs location), with a different carrier
  (approval_note vs no field yet). They are siblings, not duplicates, and the fix pattern
  carries over.
- bv2-7o2mm (reportApproval default arm) does not overlap.
