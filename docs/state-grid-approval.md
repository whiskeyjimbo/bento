# State grid: trust.ApprovalState vs its frontends

Base: worktree at main 924e291. The two json callout commits (e18da26, ef26c0a) live on
`docs/state-grids`, not main; that branch was read with `git grep`/`git diff` and its diff
does not touch run.go, journal.go, trust/, or the approval arms in validate.go.

## Phase 0 - fit

Good fit. Signals: an enum (3 constants, trust/approval.go:11-15) consumed in 9 switch or
compare sites across 5 files; mirror pairs (run's gate vs validate --strict, validate human
vs --json); a long fix history in approve/validate. Invariant is one-sided.

Invariant: run may refuse where validate says current, but must never proceed silently on a
state validate or approve reports as unapproved, stale, or unconfirmed-here. Every state has
an explicit arm; an unnamed value never lands on "approved". Additionally, validate --json
must carry every approval verdict validate human prints.

## Dimensions (from code)

The ApprovalState enum has no foreign-host or unreadable constant. Those states exist
elsewhere:
- **garbage stamp** (`approves: deadbeef`) is folded into Stale (approval.go:23).
- **unreadable manifest** is a loadDocument error before any approval check (validate.go loadDocument).
- **unrecorded stamp** (current stamp, no matching entry in this host's journal: copied,
  from another host, journal cleared) is journalVerdict journalAbsent/journalForeign
  (journal.go readApprovalRecord), surfaced via stampNote (journal.go:316).
- **shared journal** (journalUntrusted) is the same note path with a different sentence.
- **unnamed future value** is the arm each switch has or lacks for an int it does not name.

States: U unstamped, C current+journal matches, F current+unrecorded, J current+shared
journal, S stale (policy edit), G garbage stamp, P parse error, X unnamed future value.
Frontends: run, run --allow-unapproved, validate, validate --strict, validate --json,
validate --json --strict, approve (tty/no-tty), approve --yes.

Execution harness: scratchpad script built `bento` and ran every frontend over U, C, F, S,
G, P with XDG_STATE_HOME in scratch (VERIFIED BY EXECUTION below means that run). J was not
executed (needs a group/world-writable state dir); X cannot be constructed without editing
the enum.

## Grid A - state x frontend (64 cells)

| State | Frontend | Verdict | Where / what | Stamp |
|---|---|---|---|---|
| U | run | HANDLED | run.go:664 requireApproval, Unstamped falls to the refusal | EXECUTION |
| U | run --allow-unapproved | HANDLED (opt-out) | run.go requireApproval returns nil first; runs with no line naming the state. Documented flag | EXECUTION |
| U | validate | HANDLED | validate.go:194 "not approved" | EXECUTION |
| U | validate --strict | HANDLED | validate.go:228 error, exit 125 | EXECUTION |
| U | validate --json | HANDLED | approvalName -> "unapproved" (validate.go:410) | EXECUTION |
| U | --json --strict | HANDLED | same strictApprovalError, exit 125 | EXECUTION |
| U | approve (no tty) | HANDLED | full review, confirmApproval refuses non-tty (approve.go confirmApproval) | EXECUTION |
| U | approve --yes | HANDLED | stamps unreviewed; journal records reviewed=false | READING |
| C | run | HANDLED | proceeds, no note (stampNote journalMatches -> "") | EXECUTION |
| C | run --allow-unapproved | HANDLED | proceeds | EXECUTION |
| C | validate | HANDLED | "current" | EXECUTION |
| C | validate --strict | HANDLED | exit 0 | EXECUTION |
| C | validate --json | HANDLED | "current" | EXECUTION |
| C | --json --strict | HANDLED | exit 0 | EXECUTION |
| C | approve | HANDLED | shortcut "already approved" (approve.go:87, needs SharedWrite()==0) | EXECUTION |
| C | approve --yes | HANDLED | same shortcut | EXECUTION |
| F | run | HANDLED | proceeds with stderr note "this host holds no record..." (run.go:91) | EXECUTION |
| F | run --allow-unapproved | HANDLED | same note, proceeds | EXECUTION |
| F | validate | HANDLED | "current" plus the unrecorded note under it (validate.go:194 reportApproval) | EXECUTION |
| F | validate --strict | HANDLED (by design) | exit 0; stampNote documents a note never a refusal (journal.go unrecordedStamp comment) | EXECUTION |
| F | validate --json | HANDLED | `"approval":"current"` with `approval_note` carrying the unrecorded note (TestValidateJSONCarriesTheUnrecordedStampNote) | EXECUTION |
| F | --json --strict | HANDLED (by design) | exit 0, as human strict; same missing field as above | EXECUTION |
| F | approve | HANDLED | shortcut declined, re-review with "cannot confirm it was stamped here" (approve.go:154) | EXECUTION |
| F | approve --yes | HANDLED | same notice, stamps, records journal | EXECUTION |
| J | run | HANDLED | stampNote journalUntrusted -> sharedJournal note | READING |
| J | run --allow-unapproved | HANDLED | same | READING |
| J | validate | HANDLED | note under "current" | READING |
| J | validate --strict | HANDLED (by design) | exit 0 | READING |
| J | validate --json | HANDLED | `approval_note` carries the sharedJournal note (TestValidateJSONCarriesTheSharedJournalNote) | EXECUTION |
| J | --json --strict | HANDLED (by design) | exit 0 | READING |
| J | approve | HANDLED | readApprovalRecord -> untrusted, shortcut declined, writeJournalDiff names it | READING |
| J | approve --yes | HANDLED | same | READING |
| S | run | HANDLED | refusal naming stale (run.go requireApproval) | EXECUTION |
| S | run --allow-unapproved | HANDLED (opt-out) | runs; no line says the stamp is stale | EXECUTION |
| S | validate | HANDLED | "STALE" | EXECUTION |
| S | validate --strict | HANDLED | exit 125 | EXECUTION |
| S | validate --json | HANDLED | "stale" | EXECUTION |
| S | --json --strict | HANDLED | exit 125 | EXECUTION |
| S | approve | HANDLED | "approved before and its permissions have changed" + journal diff | EXECUTION |
| S | approve --yes | HANDLED | same notice, stamps | READING |
| G | all 8 frontends | HANDLED | identical to S (approval.go:23 default arm); run refuses, strict exit 125, json "stale" | EXECUTION |
| P | all 8 frontends | HANDLED | loadDocument error, every command exits non-zero before an approval check | EXECUTION |
| X | run | HANDLED | requireApproval falls out of switch to refusal (run.go ~676) | READING |
| X | run --allow-unapproved | HANDLED (opt-out) | runs | READING |
| X | validate | UNHANDLED (currently IMPOSSIBLE) | reportApproval switch has no default: prints no approval line at all, exit 0. Unreachable because CheckApproval returns only 3 values (approval.go:18-25); nothing would fail to compile if a 4th were added | READING |
| X | validate --strict | HANDLED | strictApprovalError trailing refusal | READING |
| X | validate --json | HANDLED | approvalName -> "unapproved" | READING |
| X | --json --strict | HANDLED | strictApprovalError | READING |
| X | approve | HANDLED | shortcut needs Current; writeReapprovalNotice default returns, full review | READING |
| X | approve --yes | HANDLED | same | READING |

(G and P rows collapse 8 cells each: 64 cells total.)

Secondary consumers, walked for the "no default into approved" half:
profile seedGrants (profile.go:1430) and mergeExisting (profile.go:1519) compare `!= Current`,
stampNote compares `!= Current`: all fail safe. warnStampAtRisk (trustwarn.go:22) keys on the
raw `Approves == ""`, so S and G get the at-risk warning like C - consistent. examples/embed
(main.go:130) re-implements the check on the raw string with an explicit default refusal -
a mirror outside trust.CheckApproval, currently in agreement. HANDLED, READING.

## Grid B - stamp content change x frontends (7 cells, one verdict per row: all frontends agree)

| Change after stamping | Resulting state | Verdict | Stamp |
|---|---|---|---|
| Any policy field edited (read/write/net/env/exec/limits/args/interpreter) | S | HANDLED, policy/fingerprint.go:39-69 hashes every Policy field | EXECUTION (read added) + READING (field list vs policy.go:28-57) |
| Entrypoint path changed | S | HANDLED, fingerprint.go:46 | READING |
| Entrypoint file body changed | C | HANDLED by design (fingerprint.go:29-32, attests policy not code) | READING |
| Line-injection collision (newline in a hashed field forging another field's line) | - | IMPOSSIBLE: Problems() screens paths/args (policy.go FirstUnsafeRune), env names, limits, port all reject newline | SPIKE (env, memory, cpu, port rejected; paths by READING) |
| blocked-hosts provenance edited or stripped | C | HANDLED by design, manifest.go:82-88 says the record is advisory and unauthenticated; stripping it drops run's and approve's callout without staling | READING |
| Formatting / set reordering / relative path relocation | C | HANDLED by design (fingerprint.go:14-19; hashed before Resolve, run.go:96) | READING |
| Manifest copied to another host or path | F | see Grid A row F; json gap applies | EXECUTION |

## Phase 2 re-open pass

- 45fc983 fix(approve): review a stamp this host never recorded. Carried to run (stampNote
  on stderr) and validate human (reportApproval), not to validate --json. That is the F/J
  --json cell.
- e18da26 / ef26c0a carried approve's callouts (self-write, tmp, broad) into --json. The
  approval-state row was not carried: `approval` stays the 3-value enum spelling and the
  stamp note has no field. d9cb161 (runtime-dir note into the envelope) is the precedent
  for carrying a note.
- 9f6a942 fix(validate): refuse an approval state --strict cannot name. Fixed the strict
  cell of row X; the non-strict human cell (reportApproval no default arm) was not carried.
- bb6ae75, 3e123ca, b046d17 (approve shortcut ordering) - checked, shortcut still requires
  Current + journalMatches + no shared write.
- bd open items matching approv|trust|stamp: only bv2-nm49f (isCheckout .git), unrelated.

## Dismissals, flagged for a human call

- run --allow-unapproved on S and U proceeds without naming the state (EXECUTION). The flag
  is the consent and its help text names stale, so not counted WRONG; but it is the one
  path where a stale stamp runs with no line saying so, while F under the same flag does
  get its note.
