# State grid: the `workdir` manifest key

Written 2026-09-20. Fit: **GOOD** - two strong signals (a mirror set, and six
one-at-a-time fixes in nine days).

## Phase 0 - fit, and the invariant, corrected

The nominated invariant was "a frontend may disclose or refuse a workdir that a run would
accept; it must NEVER pass a workdir that a run on the same host refuses."

**That is false as stated for `gate`, and true for `approve`.** `gate/gate.go:12-17` states
the opposite one-sidedness in so many words - "the narrowings are all in the direction of
missing a refusal rather than inventing one - a gate that refuses what a run accepts is
worse than one that passes something the run then stops" - and `workdirProblems` acts on it,
declining to answer the exists-but-ungranted case for exactly that reason.

So the invariant is **per answerer**, and that is the grid's shape, not a footnote:

| answerer | forbidden direction | where it is written |
| --- | --- | --- |
| `gate.Check` / `validate` report | refusing what a run accepts | gate.go:12-17; gate.go:160-164 |
| `validate --strict` | (inherits gate's, with teeth: it exits non-zero) | validate.go:438-450 |
| `profile` proposal | proposing what the run refuses at its first step | cmd/bento/clamp_refusal_test.go:15-17; profile.go:1071-1095 |
| `approve` stamp | stamping a policy that cannot run | policy/policy.go:168 note; approve.go:186-192 |
| run (`internal/linux`) | - it is the oracle | args.go:399-402 |

Per cell the test is: *if this answerer is wrong here, does a run die after being told ok,
or is a user refused a run that would have worked - and is that this answerer's allowed
direction?*

The area is split into two grids because the halves do not interact.

---

## Grid A - host state of the workdir x answerer

Answerers: **G** = `gate.Check`/`workdirProblems` (gate.go:153-207), **S** = `validate
--strict` (validate.go:438-450), **P** = `profile` (printUngrantedWorkdir profile.go:1096;
discoveryPolicy profile.go:1390; clampProposal profile.go:556), **A** = `approve` stamp
(approve.go:193-210 -> `gate.Refusals`), **R** = the run (linux.go:880, args.go:399-402).

| # | host state | G | S | P | A | R |
| --- | --- | --- | --- | --- | --- | --- |
| A1 | absent (`workdir:` unset) | HANDLED gate.go:189 (returns nil) | HANDLED | HANDLED profile.go:1097 | HANDLED | HANDLED args.go:400-403 falls back to `filepath.Dir(entrypoint)` |
| A2 | relative (embedder-built, unresolved) | **UNHANDLED** - `os.Stat` runs it against gate's own cwd; no precondition check | UNHANDLED (same) | IMPOSSIBLE for the CLI: `existingForMerge` calls `manifest.Resolve` at profile.go:1715 before the workdir reaches profile.go:159-161 | UNHANDLED (same) | HANDLED linux.go:879-882 refuses explicitly |
| A3 | absolute, exists as a directory | HANDLED gate.go:191-193 | HANDLED | HANDLED | HANDLED | HANDLED |
| A4 | exists but is **not** a directory | HANDLED gate.go:194 (ENOTDIR measured) | HANDLED | **WRONG** - silent, see F2 | **WRONG** - silent, see F1 | refuses in bwrap (late, after the namespace is paid for) |
| A5 | absent, write grant **at or beneath** it | HANDLED gate.go:198-202 (accepts; correct) | HANDLED | HANDLED profile.go:1108-1113 | HANDLED | HANDLED - the grant creates the mount point |
| A6 | absent, **ungranted** | HANDLED gate.go:204-206 | HANDLED | HANDLED profile.go:1114-1118 | **WRONG** - silent, see F1 | refuses in bwrap |
| A7 | absent, under a grant that merely **covers** it (read of the parent) | HANDLED gate.go:198-206 (refuses - the covering grant does not create it) | HANDLED | **WRONG** - profile.go:1109-1112 clears it, see F2 | **WRONG** (F1) | refuses in bwrap |
| A8 | **exists** as a directory, nothing granted at or beneath it | UNHANDLED **by design** - gate.go:178-182 names the case and declines it (answering needs the whole bind set) | UNHANDLED (same) | HANDLED profile.go:1114-1118 - this is the case profile owns | UNHANDLED (same) | refuses in bwrap |
| A9 | under a **home that is not on this host** | HANDLED-but-deliberately-over-refusing for a *profiling* run: gate.go:171-175 names the exception and keeps the refusal. This is the one cell where gate knowingly violates its own forbidden direction; the cost of fixing it is telling `workdirProblems` which mode it is predicting. | same | HANDLED - profiling covers HOME with an empty tmpfs, so the round starts (profile.go:1410-1415) | **UNHANDLED** (F1 - no workdir state reaches the stamp) | profiling run: starts. enforced run: refuses |
| A10 | inside a **DenyAll** shield | HANDLED gate.go:165-169, and the cross-file claim is pinned by `internal/linux` `TestAbsentDenyAllIsShieldedOnlyWhereAWriteGrantReachesIt` (17e3c01). An *absent* path gets a tmpfs only where a write grant reaches it; an *existing* one is shielded and the chdir lands in the empty tmpfs. | same | **UNHANDLED** - profile has no shield notion; the cell falls through to the grant test | **UNHANDLED** (F1) | shields.go:686-688 (`exists \|\| writable`) |
| A11 | at a grant's own root (`workdir` == a `write:` entry) | HANDLED - A5's accept path, `policy.CoversResolved` is reflexive | HANDLED | HANDLED | HANDLED | HANDLED |
| A12 | in the base image / `/tmp` | HANDLED by A3/A6 - gate does not distinguish the base image and does not need to: it stats the real host path | same | HANDLED profile.go:1101 quiets it | **UNHANDLED** (F1) | HANDLED - both exist in the sandbox unconditionally |

Cells: 12 states x 5 answerers = **60, all walked.**

- **HANDLED 45** (one of them, A9/G, is HANDLED *and* knowingly one-sided the wrong way - see F4)
- **WRONG 5** - A4/P, A4/A, A6/A, A7/P, A7/A
- **UNHANDLED 9** - A2/G, A2/S, A2/A (F3, 3 cells); A8/G, A8/S (documented-by-design,
  gate.go:178-182, 2 cells); A9/A, A10/A, A12/A (F1's blind column, 3 cells); A10/P (1 cell).
- **IMPOSSIBLE 1** - A2/P, mechanism at profile.go:1715.

45 + 5 + 9 + 1 = 60.

The R column is never a verdict about correctness: it is the oracle every other column is
judged against.

## Grid B - spelling / relocatability x consumer

| # | spelling | `manifest.Resolve` | `Fingerprint` | approve stamp | profile `rewrite` | validate `--relocatable` |
| --- | --- | --- | --- | --- | --- | --- |
| B1 | `""` | HANDLED manifest.go:426 (passes through) | HANDLED fingerprint.go:49-52 - omitted, so no older stamp is restamped | HANDLED | HANDLED profile.go:561 ("" passes through) | HANDLED - not pinned |
| B2 | `.` | HANDLED manifest.go:372-376 - anchored **like a grant**, so `.` is the manifest's dir, not the entrypoint's | HANDLED - hashed | HANDLED | HANDLED profile.go:556-561 re-relativises to `.` | HANDLED - not pinned |
| B3 | relative (`./out`) | HANDLED manifest.go:429 | HANDLED | HANDLED | HANDLED | HANDLED |
| B4 | absolute | HANDLED manifest.go:426 | HANDLED | HANDLED | HANDLED - `under()` re-relativises when it is inside the manifest tree | HANDLED validate.go:479-480 pins it |
| B5 | `~/x` | HANDLED manifest.go:423-424 expandHome | HANDLED - the **unexpanded** spelling is what is hashed (fingerprint runs on `doc.Policy`, approve.go:109) | HANDLED | HANDLED profile.go:536-541 writes `~/...` back | HANDLED validate.go:479 pins it (NonAnchoring covers `~`) |
| B6 | `~other/x` | HANDLED policy.go:214 `screenTilde` refuses at the parse gate, before any host is consulted | n/a | n/a | n/a | n/a |
| B7 | control / bidi / zero-width rune | HANDLED policy.go:168 - workdir is in the screened field list | n/a | n/a | n/a | n/a |

Cells: 7 spellings x 5 consumers = **35, all walked. HANDLED 27, IMPOSSIBLE 8** - the
`n/a` entries on B6 and B7 are IMPOSSIBLE, not unwalked: `policy.Validate` (policy.go:168,
policy.go:214) refuses both spellings at the parse gate, so no later consumer ever sees
them. Mechanism cited, per the skill's rule on that verdict.

This half is in good shape; the three relocatability fixes (`4dcade7`, `30a15a6`,
`2a8e259`) landed the whole row, not one cell.

---

## Findings, in the forbidden direction first

### F1 - `approve` stamps a manifest whose workdir the run refuses. `VERIFIED BY SPIKE`

*The counter-argument, read and rebutted.* `requireHonorableGrants`' own doc
(approve.go:168-192) contains two sentences that look like a defence of this. The first -
"A host that could not resolve the grants, or could not anchor the shields, stamps as
before. The verdict approve exists to give is a property of the manifest and must not start
depending on where it is checked" - is about the **unanswerable** case, not about a host
fact that answers cleanly: the same function refuses outright on four classes it reads off
the filesystem, so approve already makes the stamp depend on the host wherever the host can
be asked. The second - the credential-alias paragraph - excuses a refusal that "turns on
`--accept-alias`, a flag of the run, which no stamp can attest." The workdir has no such
excuse: it is manifest + filesystem, exactly like the four classes that do refuse. The one
honest argument the other way is that the workdir "is not a permission" (profile.go:1704)
and `gate.Refusals` is defined as a set of *grants*. That is a reason to widen the stamp
gate's input rather than a reason for `bento validate --strict` and `bento approve` to
disagree about the same manifest on the same host - which approve.go:168-171 says they must
not: "a stamp and a green gate over the same manifest have to mean the same thing".

`cmd/bento/approve.go:205` calls **`gate.Refusals`**, not `gate.Check`. `workdirProblems`
is appended inside `Check` (`gate/gate.go:134`) and is **not** part of `Refusals`, so no
workdir state reaches the stamp gate at all. `bento approve` prints the workdir as a note
(approve.go:275-276) and then stamps.

This is the forbidden direction for that answerer, and `gate.go:212-219` predicted the shape
of it: *"One function because every reader of it ... has to agree on the set, and a check
added to only one of them is how a manifest gets stamped for a permission that does not
exist."* The workdir is not a permission, which is presumably why it went into `Check`
instead - but it is the same class of fact (manifest + filesystem, no run flag involved),
unlike the credential-alias exception approve.go:186-192 justifies at length.

Spike: `gate.Refusals` returned `[]` while `gate.Check(...).Problems` named the problem, for
both `not-a-directory` and `absent-and-ungranted`. Cells A4/A6/A7 (and A9-A12) column A.

### F2 - `profile` stays quiet on two workdirs the enforced run refuses

Stamps, split by sub-claim, because the spike's oracle was gate and profile's oracle is the
run:

- *profile and gate disagree on these two states*: `VERIFIED BY SPIKE`.
- *the run refuses A4 (exists, not a directory)*: `VERIFIED BY READING` of gate.go:183-188,
  which records the ENOTDIR as **measured** against bwrap, and notes that nothing the
  sandbox binds turns a host file into a directory.
- *the run refuses A7 (absent, under a covering read grant)*: `VERIFIED BY READING` -
  args.go:399-402 passes the path to `--chdir`, bwrap does not create its chdir target, and
  a read grant binds the host tree as it is, so an absent child stays absent. Not spiked: it
  needs a real sandbox. `UNSPIKEABLE HERE` without bwrap and a host home.

`printUngrantedWorkdir` (profile.go:1096-1119) answers only "is anything granted here". It
misses two states `gate.workdirProblems` answers:

- **A7**, `profile.go:1109-1112`: a grant that merely **covers** the workdir clears the
  warning (`CoversResolved(grant, dir)`). Its doc claims "one COVERING it binds the tree the
  workdir sits in" - true for an *existing* workdir, false for an absent one. A read grant
  binds the host tree as it is; an absent child stays absent, which is precisely what
  `gate.go:198-206` refuses.
- **A4**: a workdir that exists as a regular file is never tested for `IsDir`.

Spike output: profile printed nothing and returned no note in both cases, while
`gate.Check` named the refusal. Same root as F1 - the workdir predicate lives in exactly one
place and neither of the two answerers whose contract forbids passing-the-unrunnable calls it.

### F3 - `gate.Check` silently answers an unresolved (relative) workdir. `VERIFIED BY READING`

Cell A2. `internal/linux/linux.go:879-882` refuses a non-absolute workdir with a named
error. `gate.Check` has the same precondition (gate.go:15-17, "Grants must already be
resolved to host paths") and nothing enforcing it: `os.Stat("out")` stats it against
whatever directory the embedder ran from. Both possible outcomes stay inside gate's
*allowed* direction, so this is a robustness gap rather than a contract violation - but it
is one `if !filepath.IsAbs` away from being closed, mirroring linux.go:880.

### F4 - A9 is gate refusing what a profiling run accepts. `VERIFIED BY READING`

Documented at gate.go:171-175 and accepted with a stated reason. Recorded here because it is
the only cell where gate knowingly violates gate.go:12-17, so a future reader should not
"fix" it without reading that paragraph.

## Dismissals, verified inverted

- **"An absent workdir with a write grant at or beneath it is correctly accepted."**
  `VERIFIED BY SPIKE` - asserted the safe behaviour directly: grant *at* it and grant
  *beneath* it both return no problem, and a grant merely *covering* it still returns one.
- **"The workdir does not restamp older approvals, and a set workdir is stamped."**
  `VERIFIED BY SPIKE` - `Fingerprint()` is identical with `Workdir: ""` and with the field
  absent, and differs once it is set.
- **"The workdir is relocatable."** `VERIFIED BY SPIKE` - the same manifest tree copied to
  two roots fingerprints identically *because* the hash is taken on the unresolved policy
  (`approve.go:109`, `trust/approval.go:21`). The **resolved** policy's fingerprint differs
  per checkout, so this claim rests entirely on no consumer ever fingerprinting a resolved
  copy - a coupling worth a test of its own.
- **"The DenyAll/shield row is `exists || writable`."** `VERIFIED BY EXECUTION` - held by
  `internal/linux`'s `TestAbsentDenyAllIsShieldedOnlyWhereAWriteGrantReachesIt` (17e3c01),
  which gate.go:167-169 now names.

## Handoff

F1 and F2 are one defect with two faces: `workdirProblems` is reachable only through
`gate.Check`. The smallest fix that closes both is to make the workdir predicate callable
beside `gate.Refusals` (or to fold it in and let approve and clampProposal inherit it), with
one regression test per WRONG cell - A4, A6, A7 in the approve column and A4, A7 in the
profile column. Grid A is small and finite: it wants to become a table-driven test rather
than stay prose.

---

# Phase 2 re-open pass (appended after the grid was written)

Run against the known-open list and the shipped-fix list handed over *after* the grid was
built, so none of it biased Phase 1's dimensions.

## New row: A13 - the workdir's existence cannot be determined

`bv2-cr6cs` ("nothing acts on pathresolve's Unreadable arm") lands squarely on this grid,
and it **is a genuine 13th host state** that Phase 1 missed. `internal/pathresolve`
distinguishes three outcomes - OK, Loop, **Unreadable** (pathresolve.go:31-36) - and
Unreadable means EACCES/EIO/ESTALE on an ancestor: *the path could not be placed, so nothing
about it was determined* (pathresolve.go:104). `gate/gate.go:201` discards it:

```go
lands, _ := pathresolve.Existing(resolved.Workdir)
```

This is the empty-because-clean vs empty-because-unasked collapse, on the axis Phase 1's
"absent" state silently merged.

| # | state | G | S | P | A | R |
| --- | --- | --- | --- | --- | --- | --- |
| A13 | ancestor unreadable (EACCES/EIO/ESTALE), workdir's existence undetermined | **WRONG** - see F5 | **WRONG** (same text, promoted to a non-zero exit) | **UNHANDLED** - profile.go:1100 discards the same arm | **UNHANDLED** (F1's blind column) | the oracle: the run's own uid meets the same barrier |

Revised Grid A: 13 states x 5 answerers = **65 cells.** HANDLED 45, **WRONG 7**,
**UNHANDLED 11**, IMPOSSIBLE 1, plus A13/R which is oracle. (45+7+11+1 = 64, +1 oracle cell
at A13/R = 65.)

### F5 - gate reports "does not exist on this host" for a workdir it could not read. `VERIFIED BY SPIKE`

Spike: a directory that **does exist**, behind a `chmod 000` parent.

```
pathresolve outcome = unreadable
workdirProblems = ["workdir \".../locked/wd\" does not exist on this host and no write
                   grant is at or beneath it, so the run cannot start there"]
```

Two distinct defects in one cell, and they point in **opposite** directions:

1. **The reason text is false.** The directory exists. `os.Stat` (gate.go:191) fails with
   EACCES and the code treats every `err != nil` as absence. A reader who trusts it creates
   the directory, or adds a write grant, and neither is the problem. This is the same class
   `docs/state-grid-report-corrections.md` covers, arriving on a new field.
2. **With a write grant lexically covering it, gate goes silent.** Verified in the same
   spike: `Write: [<the unreadable path>]` makes `workdirProblems` return nothing, because
   `pathresolve.Existing` handed back the caller's own input for *both* the workdir and the
   grant (its documented fail-closed cutoff) and `CoversResolved` then compares two
   unwalked strings. A lexical match over two paths neither side could resolve is not the
   containment `CoversResolved` is meant to assert.

Direction: (1) is gate **refusing** with a wrong reason - inside gate's allowed direction as
a verdict, outside it as a report. (2) is gate **passing** - allowed for gate (gate.go:12-17),
**forbidden for approve and profile**, which inherit the same silence.

`UNSPIKEABLE HERE`: that the enforced run also refuses. bwrap runs as the same uid and meets
the same barrier, so the verdict is almost certainly right even where the reason is wrong -
but that is `VERIFIED BY READING`, not measured.

## bv2-kxv8p - the workspace-derived shield half. Weak interaction, worth one line.

`gate.go:450-462` records that the gate passes **no workspace shields** - the half derived
per write grant from the checkout under it, which `internal/linux` computes off host facts
(this repo's CLAUDE.md names that split as the layering check's one exception).
`workdirProblems`' own shield paragraph (gate.go:165-169) reasons **only about the built-in
denylist shields**, so its claim is true of half the shield set and silent about the other.

Does it reach a workdir? `VERIFIED BY READING` (internal/linux/autoexec.go:57-132): the
grant-derived shields are **directories** - `.git/hooks`, `.husky`, `.husky/_`, a resolved
`core.hooksPath`. Under either shield shape a directory remains a directory at that path
(DenyAll gives an empty tmpfs dir, DenyWrite a read-only bind), so a workdir at or under one
still chdirs. **The verdict does not change; the reasoning is half-scoped.** Recorded as a
comment-accuracy item, not a WRONG cell - gate.go:165-169 should say "built-in" where it
says "a shield", or the row inherits kxv8p's missing mirror if a future derived shield is
ever file-shaped.

## bv2-ntncf - SIGKILL strands materialized shield artifacts. Does not touch this grid.

One line, as asked: ntncf is about artifacts surviving **after** a run; A7 is about what does
**not** get materialized **before** the sandbox exists. Opposite ends of the lifecycle, no
shared mechanism. Not related.

## Re-opening the shipped fixes, cell by cell

| commit | cell it fixed | was the row carried? |
| --- | --- | --- |
| `d2cad92` feat: add a workdir key | introduced the axis: A1, A3, B1-B5 | Yes for Grid B - it landed manifest.go, fingerprint.go, policy.go and linux/args.go together. It shipped **no gate and no cmd/bento**, which is why every row below exists. |
| `30a15a6` fix: carry the manifest workdir | B2/profile - a re-profile dropped the workdir | row carried (profile.go:1804 + the merge) |
| `4dcade7` fix: keep the workdir relocatable | B2/B4 profile `rewrite` | row carried - profile.go:556-561 spells the rule as Resolve's own |
| `ea9abba` feat: show the workdir in validate | disclosure, validate.go:883 | row carried to `--json` (validate.go:547) - `output_parity_test.go` enforces that |
| `5ff63c2` fix(gate): refuse a workdir this host has not | **A6/G** | **NO.** Files: `gate/gate.go`, `gate/workdir_test.go`, `cmd/bento/output_parity_test.go`. **Nothing in `cmd/bento/approve.go`.** |
| `905d683` fix(gate): refuse a workdir that is not a directory | **A4/G** | **NO.** Same file set - `gate/gate.go` + `gate/workdir_test.go` + render/clamp. Again no approve. |
| `025222f` fix(profile): name an ungranted workdir | A8/P | row carried within profile, but only for the grants-nothing case |
| `2a8e259` fix(profile): quiet on a carried workdir | A12/P (base image, /tmp) | this is the commit that **added** profile.go:1109-1112's covering-grant clause, i.e. it introduced A7/P |
| `f0a3990` test: pin which side the workdir comes from | B-row pin, 6 lines in `profile_converge_test.go` | pins the merge side only |
| `1d81b92` test: assert the workdir reaches the sandbox | A1/R, A3/R (args.go `--chdir`) | row carried on the run side |

**F1's shape is confirmed against the commits.** `VERIFIED BY EXECUTION` (`git show --stat`):
the two commits that built the workdir predicate, `5ff63c2` and `905d683`, both added it
**inside `gate.Check`** and neither touched `cmd/bento/approve.go`. Each added a test under
`gate/workdir_test.go` for its own cell, so each looks complete and green while the approve
column of its row was never walked. That is exactly "a fix that covered one cell and stopped,
hiding behind a green checkmark."

And `2a8e259` is the mirror-image case: a fix that **widened** a row. It quieted profile on a
workdir the sandbox carries (correct, A12), and the clause it used to do it -
`CoversResolved(grant, dir)` - also quiets A7, which the sandbox does **not** carry.

## Closing out the relocatability dismissal

The dismissal rested on "no consumer ever fingerprints a **resolved** policy". Every call
site, `VERIFIED BY READING`:

| site | input | resolved? |
| --- | --- | --- |
| `cmd/bento/approve.go:109` | `doc.Policy` | no - approve never resolves in place |
| `trust/approval.go:21` | `doc.Policy` | no |
| `cmd/bento/journal.go:192` | the same `p` approve passes down | no |
| `examples/embed/main.go:134` | `p` **before** `manifest.Resolve(p, ...)` at :145 | no, **and the ordering is named in the comment at :143-145** |
| `cmd/bento/validate.go` | resolves into a **copy** (`resolvedGrants`, :838-845) | n/a - never fingerprinted |

**The coupling holds today.** It is guarded by prose in two places - embed's :143-145 and
`gate.Check`'s own "Resolve into a copy: resolving an approved manifest's policy in place
makes it read as stale against its own stamp" (gate.go:116-117) - and by nothing executable:
reordering embed's two lines, or dropping `resolvedGrants`' copy, compiles and silently ends
relocatability for every manifest with a workdir, a `~` path or a relative grant.

Per this repo's CLAUDE.md ("a claim resting on another file, where deleting the other thing
still compiles while silently changing behaviour, needs a test named for it"), this is a
**missing-coverage item**, not a defect. The Phase 3 spike that proved it is the test: one
manifest tree at two roots, identical unresolved fingerprints, differing resolved ones. It
guards cells B2-B5 across the whole `Fingerprint` column, which nothing currently holds.
