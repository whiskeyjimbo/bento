# State grid: the exec record vs the consumers that present it

Area: `enforce/enforce.go` (`ExecRecord`, `ExecRun`), `internal/launcher/applied.go`
(`writeExecRecord`), `internal/launcher/launcher.go` (`runTarget`), `internal/launcher/execrecord.go`
(`superviseTraced`, `traceExecs`), `internal/linux/applied.go` (`parseApplied`, `parseExecRun`,
`execRecord`), `internal/linux/degraded.go` (`degradedExecRecord`), and the readers:
`cmd/bento/render.go` (`writeExecRecord`, `toExecRecordJSON`), `cmd/bento/run.go` (verdict and
failed paths), `examples/embed`, `examples/supervise`. Reviewed at 7bc186f.

## Phase 0 - fit

Partial fit. `TestWriteExecRecordSeparatesItsFiveStates` (render_test.go:1674) walks five
records through the human writer with real assertions, but it does not cross state with run
count (its partial case has exactly one run and asserts only "ends"), never touches
`toExecRecordJSON`, and never feeds the watched=false-with-runs record the launcher's
failed-recorder path produces. Not declined.

Invariant (one-sided): no consumer presents a truncated, partial, unavailable or absent record
as a complete one. "Executed nothing beyond the target" may only be said of a complete record.
Under-claiming is allowed.

## Phase 1 - dimensions (from the code)

Record states, as `execRecord`/`degradedExecRecord` can build them:

- S0 absent: not asked, `nil` (applied.go:362, degraded.go:331).
- S1 unavailable, structural: exec block (launcher.go:337) or degraded tier (degraded.go:334);
  watched=false, complete=true, runs empty.
- S2 unavailable, host refused attach: `rec.failed` before any trace (execrecord.go:79, 92);
  watched=false, complete=true, runs empty or seed only.
- S3 recorder failed mid-trace: `rec.failed` in `traceExecs` (execrecord.go:177, 188) returns
  `errTargetRan`, so `runTarget` still writes the section with the runs seen and the marker
  (launcher.go:363-366); watched=false, complete=true, runs = partial list.
- S4 no section: cancel, unreached target, short write before recorder line; recorder "" ->
  watched=false, complete=false (applied.go:367).
- S5 complete, one run (target only).
- S6 complete, many runs.
- S7 complete, zero runs (damaged: section with recorder yes and marker, no exec-ran).
- S8 partial (no marker or garbled), one run.
- S9 partial, many runs.
- S10 any watched record with an ArgvTruncated run.

Producer tier: full (linux.go:297/314/334/368 all stamp `a.execRecord`), degraded (all four
arms stamp `degradedExecRecord`). Degraded produces only S0/S1.

Consumers x form: H = `writeExecRecord` human (run.go:520 failed path, run.go:698 verdict path,
same function); J = `toExecRecordJSON` (run.go:439 failed event, run.go:622 verdict, same
function); E = examples/embed, S = examples/supervise; P = `bento profile`.

## Phase 2 - verdicts

### Human (both paths share one writer)

| Cell | Verdict |
|---|---|
| S0 H | HANDLED render.go:1712 (prints nothing) |
| S1 H | HANDLED render.go:1715 (reason, stops) |
| S2 H | HANDLED render.go:1715 |
| S3 H | HANDLED, under-claim: render.go:1715 says "nothing was watching... no execs were recorded" and drops the partial runs. Allowed direction, but the sentence is false (something did watch and did record). Noted, not a finding. |
| S4 H | HANDLED render.go:1715 |
| S5 H | HANDLED render.go:1734 |
| S6 H | HANDLED render.go:1737 |
| S7 H | HANDLED render.go:1729 |
| S8 H | **WRONG** render.go:1733-1735 then 1742: prints "the run executed nothing beyond the target itself:" for a record that never reached its marker, and only afterwards the "stopped before the run did" caveat. The forbidden sentence is said of a partial record. |
| S9 H | HANDLED render.go:1737 + 1742 ("executed these" is not a completeness claim, trailer marks it) |
| S10 H | HANDLED render.go:1721 |

### JSON (both paths share one converter)

| Cell | Verdict |
|---|---|
| S0 J | HANDLED render.go:1676 (key omitted, run.go:387 omitempty) |
| S1 J | HANDLED render.go:1669 (watched false always emitted) |
| S2 J | HANDLED render.go:1669 |
| S3 J | **WRONG** render.go:1679: emits `{"watched":false,"complete":true,"runs":[...partial...]}`. `complete:true` travels with a list the recorder stopped building mid-run; the type doc (enforce.go:296-298) says watched=false means nothing was recording, so the runs contradict it and `complete` is the field the degraded comment calls "trust what is here". |
| S4 J | HANDLED render.go:1673 |
| S5, S6 J | HANDLED render.go:1680 |
| S7 J | **UNHANDLED** render.go:1673: `runs` is omitempty, so a damaged record serializes as `{"watched":true,"complete":true}`, indistinguishable from a clean record with no runs. The human writer special-cases this (render.go:1726); JSON does not. Reachable only by a section the launcher does not write (the seed is always present on the watched path), so severity is low. |
| S8, S9 J | HANDLED render.go:1673 (complete false emitted) |
| S10 J | HANDLED render.go:1662 (argv_truncated emitted when true) |

### Producers

| Cell | Verdict |
|---|---|
| full tier, all four return arms stamp a record when asked | HANDLED linux.go:297, 314, 334, 368 |
| degraded tier, all four arms | HANDLED degraded.go:278, 292, 299, 309 |
| degraded tier, S3-S10 | IMPOSSIBLE degraded.go:334 (literal, no runs) |
| truncation marker round-trip | HANDLED launcher/applied.go:193, linux/applied.go:343 |
| exec-ran after marker | HANDLED linux/applied.go:158 (voids) |
| launcher failed-recorder writes complete marker with partial runs (source of S3) | **WRONG** launcher/applied.go:183-198 writes "no" + runs + marker, and linux/applied.go:215 sets complete from marker alone |

### Other consumers

| Cell | Verdict |
|---|---|
| examples/embed, any state | IMPOSSIBLE examples/embed/main.go never sets RecordExec (grep: no RecordExec in examples), so ExecRecord is always nil (applied.go:362); asserted in examples/embed/result_test.go:144 |
| examples/supervise, any state | IMPOSSIBLE same, examples/supervise/result_test.go:118 |
| bento profile | IMPOSSIBLE: only run.go:163 sets RecordExec in cmd/bento; profile never reads ExecRecord |

### Adversarial re-check of HANDLED

- S9 H: "executed these, in the order they ran" plus trailer - the trailer comes last, a reader
  of the head sees a list. Kept HANDLED: no completeness word before the caveat, unlike S8.
- S5 H with an ArgvTruncated target: "nothing beyond the target" stays true. Kept.
- S4 on the failed path: run.go:690-698 comment confirms unreached writes no section; S4 H/J hold.

## Phase 3 - findings, forbidden direction first

1. **S8 H WRONG** - partial record with one run prints "executed nothing beyond the target".
   VERIFIED BY SPIKE: `writeExecRecord` on `{Watched:true, Complete:false, Runs:[/bin/sh]}` printed
   "the run executed nothing beyond the target itself:" followed by the truncation caveat. The
   existing five-states test uses exactly this record and asserts only "ends". Reachable via a
   short write after the first exec-ran line (linux/applied.go:215 leaves complete false).
2. **S3 J WRONG (source: launcher/applied.go:183-198)** - recorder failed mid-trace yields
   watched=false, complete=true, partial runs. VERIFIED BY SPIKE on both halves: `parseApplied`
   over `exec-recorder no "..."` + two exec-ran + marker returned
   `{Watched:false Complete:true Runs:[2]}`, and `toExecRecordJSON` emitted it verbatim. That the
   launcher writes this shape after `traceExecs` fails: VERIFIED BY READING
   (execrecord.go:117-119 wraps as errTargetRan, launcher.go:361-366 writes the section);
   UNSPIKEABLE HERE end to end (needs a wait4 failure under a live tracer).
3. **S7 J UNHANDLED** - empty complete watched record serializes identical to a clean empty one.
   VERIFIED BY SPIKE: `{"watched":true,"complete":true}`. Low severity: requires a section the
   launcher does not write.

Rejections (dismissed and checked inverted):

- S3 H "nothing was watching" with runs present: under-claim, allowed direction. VERIFIED BY SPIKE
  (prints the reason and no runs).
- Degraded tier states beyond S1: IMPOSSIBLE by literal at degraded.go:334.
- Examples and profile: RecordExec never set outside cmd/bento/run.go:163. VERIFIED BY EXECUTION
  (grep over the tree).

Spikes deleted; `git status` clean.

## Re-open pass

- bv2-pf2n (3b14c98): fixed launcher cell S3 on the WATCHED column only. Both `traceExecs` error
  returns now set `rec.failed`, so the section reads `exec-recorder no`. The test
  (`TestALostTraceMarksTheRecordFailed`) asserts only the recorder line. Row not carried: the
  marker is still written and `parseApplied` still sets complete from the marker alone
  (linux/applied.go:215), so the host reports watched=false, complete=true over a partial list.
  Finding 2 is this row half-closed. The bead's own complaint was "watched and complete"; only
  watched moved. REOPEN.
- bv2-1y1v (closed not-a-bug, aeefb2c): fixed nothing in the grid; it narrowed a docstring after a
  spike showed execve resets dumpable before the exec stop is read. A blank-exe entry would
  still render as `""` under a complete record, but the bead's refutation covers the reach. No
  delta.
- bv2-38f6 (8cefbd3): fixed full tier default arm (linux.go:368) producing S0 instead of a record.
  Row carried: all four full-tier arms stamp `a.execRecord`. Holds.
- bv2-ax0w (12c33f0): fixed degraded cancel and default arms producing S0. Close reason says the
  nil-ProcessState arm stays nil; at 7bc186f degraded.go:292 stamps it too, so the row was
  carried further later. Holds.
- bv2-l2r3 (be81219): created the H and J columns. The failed-event J cell came later (0eacfd5),
  guarded by the parity test on `exec_record`. The S8 H and S7 J cells were never in its row.
- bv2-lx4i: design only (ADR 0011). No cell.

Deltas to Phase 3: finding 2 is a reopen of bv2-pf2n rather than new. Findings 1 (S8 human
"nothing beyond the target" on a partial record) and 3 (S7 JSON) have no closed bead: new.
Out of area, not graded: bv2-83kke, bv2-nobuv, bv2-8updn.
