# State grid: Marshal vs Parse over the manifest's fields

Area: `manifest/manifest.go` - `Parse`, `Load`, `Marshal`, `fromPolicy`, `toPolicy`,
`quoteUnlessItReadsBack`, `screenSource`, `screenProvenance`, `networkRule.UnmarshalYAML`,
and `Provenance`. The fields are `policy.Policy`'s ten and `Provenance`'s four. Reviewed at
0abf849.

## Phase 0 - fit

Partial fit, not declined. `FuzzManifestRoundTrip` (manifest_adversarial_test.go:158) has a
real oracle (`reflect.DeepEqual` over Marshal then Parse), but its Policy literal is a
hand-list: it varies 8 scalars (entrypoint, interpreter, one env, one read, one write, host,
port, memory, cpu, pids), never `InterpreterArgs`, never `Args`, always passes `Provenance{}`,
always uses exactly one element per list, and pins `Exec: policy.ExecNone` so the empty-exec
cell is out of reach by construction. Shape is what it never varies: nil vs empty vs
multi-element, order, duplicates, and total document size. That is the grid's job.

Invariant (one-sided): Marshal may refuse what `policy.Validate` accepts, but it must never
write a manifest Parse reads back as a different policy or provenance. Refusing to write is
allowed; writing something that reads back changed - or does not read back at all - is not.

## Phase 1 - dimensions (from the code)

Concerns per field:

- W = written by `fromPolicy` (manifest.go:520-543) / marshalled with `omitempty`.
- Q = quoting on write, `quoteUnlessItReadsBack` (manifest.go:481) as a
  `yaml.CustomMarshaler[string]`, so it covers every string scalar including slice elements
  and the provenance block.
- R = rebuilt by `toPolicy` (manifest.go:545-570).
- S = screening that can refuse the written document on the way back in: `screenSource`
  (manifest.go:262), `screenProvenance` (manifest.go:502), `utf8.Valid` and
  `maxManifestBytes` (manifest.go:151-166), `Problems` (policy.go:142).
- F = varied by `FuzzManifestRoundTrip`.

Shape dimensions the code distinguishes: nil vs empty slice (`omitempty` at manifest.go:49-57
collapses both), absent vs explicit zero (only `limits.pids`, manifest.go:113), element order
(sequences preserve it; `Fingerprint` sorts env/read/write/network anyway), duplicates, and
total size against `maxManifestBytes`.

## Phase 2 - verdicts

### Policy fields, value concern

| Cell | Verdict |
|---|---|
| Entrypoint W/R | HANDLED manifest.go:522, 547; required non-empty by policy.go:161 |
| Entrypoint Q (indicator-leading, `~`, `...`, `? 0`, quotes, colons) | HANDLED manifest.go:487-492 |
| Interpreter W/R | HANDLED manifest.go:523, 548 |
| Interpreter Q | HANDLED manifest.go:487-492 |
| InterpreterArgs W/R | HANDLED manifest.go:524, 549 (never varied by F) |
| InterpreterArgs Q, multi-element | HANDLED manifest.go:487-492, verified by spike |
| InterpreterArgs without Interpreter | IMPOSSIBLE policy.go:167 refuses before Marshal writes |
| Args W/R | HANDLED manifest.go:525, 550 (never varied by F) |
| Args Q, multi-element, order, duplicates | HANDLED manifest.go:487-492 + YAML sequence order |
| Args element `""` (legitimate, `sh -c ''`) | HANDLED policy.go:180 exempts args; round-trips |
| Env W/R | HANDLED manifest.go:526, 551 |
| Env Q | IMPOSSIBLE policy.go:225 `envNameRe` admits only `[A-Za-z_][A-Za-z0-9_]*`, none of which needs quoting |
| Read/Write W/R | HANDLED manifest.go:527-528, 552-553 |
| Read/Write Q (space, colon, `#`, `~`) | HANDLED manifest.go:487-492 |
| Read/Write element `""` | IMPOSSIBLE policy.go:183 refuses an empty grant |
| Network W/R | HANDLED manifest.go:534-536, 556-558 |
| Network Q / host+port shape | IMPOSSIBLE policy.go:482, 561 admit only hostname/wildcard/IP and numeric ports |
| Network scalar form on read (`UnmarshalYAML`) | IMPOSSIBLE from Marshal: manifest.go:535 always emits a mapping; the scalar branch (manifest.go:126) is reachable only from a hand-written file |
| Network order, duplicates | HANDLED sequence order preserved; `Fingerprint` sorts anyway (fingerprint.go:63) |
| Exec non-empty W/R | HANDLED manifest.go:529, 554 |
| Exec `""` | NORMALIZED, not a finding - see rejections |
| Limits zero | HANDLED manifest.go:538 omits the block, toPolicy leaves the zero value |
| Limits memory/cpu | HANDLED manifest.go:539, 566; values constrained by policy.go:600 |
| Limits PIDs 0 with memory set | HANDLED manifest.go:540 omits the key, toPolicy leaves 0 (manifest.go:567) |
| Limits PIDs explicit 0 on read | HANDLED manifest.go:192 refuses it; Marshal can never write it (manifest.go:540) |
| Limits PIDs only, memory/cpu empty | HANDLED writes `memory: ""`/`cpu: ""`, reads back identical; verified by spike |

### Shape concern

| Cell | Verdict |
|---|---|
| Any list nil | HANDLED `omitempty`, manifest.go:49-57 |
| Any list `[]string{}` (Args, Env, Read, Write, Network) | NORMALIZED to nil - see rejections |
| Multi-element list, every field | HANDLED, verified by spike |
| Document > `maxManifestBytes` | **UNHANDLED when walked, fixed in c02e561** manifest.go:161: Marshal had no size gate, Parse refuses at 1 MiB; Marshal now measures its rendered bytes against the same constant |
| Nesting depth of Marshal's output vs `maxNestDepth` | IMPOSSIBLE manifest.go:262-300: the written shape reaches 3 levels, cap is 32 |
| Marshal output containing a tag/anchor/alias token | IMPOSSIBLE in practice: quoting (manifest.go:487) keeps `!`, `&`, `*`-leading values quoted; verified over 50 indicator strings in 6 placements |
| Marshal output non-UTF-8 or carrying a control character | IMPOSSIBLE policy.go:155 and manifest.go:508 screen both sides on `FirstUnsafeRune` |
| Marshal output as a multi-document stream | IMPOSSIBLE `yaml.Marshal` of one value emits one document; Parse's second-document check (manifest.go:180) is read-side only |

### Provenance

| Cell | Verdict |
|---|---|
| GeneratedBy/GeneratedAt/Approves W/R | HANDLED manifest.go:476-478, 199-202 |
| Those three, Q | HANDLED manifest.go:487 (the custom marshaler is type-scoped, so it reaches nested struct fields) |
| Those three, deceiving runes | HANDLED manifest.go:473 on write, manifest.go:203 on read, same function |
| BlockedHosts multi-element, Q, order | HANDLED manifest.go:487, sequence order; verified by spike |
| BlockedHosts `[]string{}` with another field set | NORMALIZED to nil - see rejections |
| Provenance all-zero | HANDLED manifest.go:475 drops the key, Parse yields the zero value (manifest.go:199) |
| Provenance with only `BlockedHosts: []string{""}` | HANDLED `isZero` is false (manifest.go:96), block written and read back identical |
| Provenance in `Load` | IMPOSSIBLE by design manifest.go:355: `Load` discards it |

### Adversarial re-check of HANDLED

- The Q cells rest on `quoteUnlessItReadsBack` asking its question **context-free**: it
  marshals the scalar alone and unmarshals it alone. A value that reads back standalone but
  differs inside a sequence or mapping would slip through. Re-checked empirically: 50
  indicator-bearing strings across entrypoint, interpreter, interpreter_args, args, read,
  write and all four provenance fields, plus 1.8M fuzz executions over a widened tuple. No
  divergence. Kept HANDLED.
- `strconv.Quote` as the fallback spelling (manifest.go:492) is Go quoting, not YAML quoting.
  The two differ on escapes for control and invalid-UTF-8 bytes - which are exactly what
  `FirstUnsafeRune` has already refused on both sides, so the fallback only ever sees
  printable text. Kept HANDLED.
- `Marshal(nil, ...)`: `p.Validate()` runs before `fromPolicy` dereferences p, and
  `Problems` handles a nil receiver (policy.go:143). Kept HANDLED; the comment at
  manifest.go:462 says this ordering is deliberate.

## Phase 3 - findings, forbidden direction first

1. **Document > `maxManifestBytes` UNHANDLED when walked, fixed in c02e561 (bv2-jql08)** (manifest.go:161 vs manifest.go:455). Nothing
   caps the size of what Marshal writes, and no policy field is length-capped except the
   network host. A policy whose grants exceed 1 MiB of YAML is written happily and then
   refused by its own parser - the exact class of defect Marshal's doc comment says it was
   added to close ("Marshal used to write files Parse would then refuse").
   VERIFIED BY SPIKE: 300 read grants of 4 KiB each marshalled without error, and Parse
   returned `manifest: input is larger than 1048576 bytes, which is not a manifest`. Low
   severity - a profiling run does not produce a megabyte of grants - but it is the one cell
   in the forbidden direction, and it is invisible to `FuzzManifestRoundTrip` because that
   target's lists hold one element each.

No WRONG cells. No other UNHANDLED cells.

Rejections (dismissed, each checked inverted by running it):

- **Exec `""` reads back as `"none"`.** `Validate` accepts `""` (policy.go:457), `fromPolicy`
  omits the key, `toPolicy` fills in `ExecNone` (manifest.go:558). DeepEqual differs.
  Not a finding: `ExecMode.canonical` (policy.go:449) makes the two one mode and
  `Fingerprint` hashes the canonical form (fingerprint.go:66), so the approval stamp is
  unchanged and no grant moved. The fuzz target pins `ExecNone` for this reason and says so.
  VERIFIED BY SPIKE (the round trip does differ; the fingerprint does not).
- **`[]string{}` and `[]policy.NetworkRule{}` read back as nil** (all five list fields, plus
  `Provenance.BlockedHosts`). VERIFIED BY SPIKE. Same class: `omitempty` collapses empty and
  absent, `Fingerprint` emits one line per element so both hash identically
  (fingerprint.go:47-64), and the package doc says empty and nil both mean deny
  (policy.go:8). Normalization, not a changed policy.
- **Order and duplicates in every list.** VERIFIED BY SPIKE: preserved exactly, duplicates
  included, for args, read, write, env, network and blocked-hosts.
- **Quoting gaps in `Args`/`InterpreterArgs`/provenance**, the fields the fuzz target never
  varies. VERIFIED BY SPIKE and BY EXECUTION: 50-value table plus a temporary fuzz target over
  `(arg1, arg2, interpreter_arg, generated-by, generated-at, approves, blocked-host)` run at
  `-fuzztime=45s`, 1.81M executions, 330 corpus entries, PASS. The one-sided guarantee holds
  on these fields.
- **`networkRule.UnmarshalYAML`'s scalar branch.** Unreachable from Marshal's output
  (manifest.go:535 always writes a mapping); it is a read-side message for hand-written files
  and out of the round-trip invariant. VERIFIED BY READING.

Spikes deleted; `git status` clean.

## Handoff: table vs fuzz

The value dimension is open-ended and belongs in the fuzz target, not a table: widen
`FuzzManifestRoundTrip`'s argument list to carry two `Args` elements, one `InterpreterArgs`
element (with `Interpreter` non-empty, or policy.go:167 refuses every case) and the four
provenance fields. That is a 7-string widening and it passed 1.81M executions here, so it
costs nothing but closes the fields the current hand-list leaves entirely unexercised.

The shape dimension is finite and small - about a dozen cells - and belongs in an exhaustive
table test, because a fuzzer over a fixed tuple can never reach it: nil vs `[]T{}` vs one vs
many for each of the five list fields and `BlockedHosts`; `Limits` zero, pids-only, memory-only;
`Provenance` zero, partial, full. Note before writing it that the empty-slice and `Exec: ""`
rows read back normalized, so the table's oracle must be the fingerprint plus provenance
equality rather than `reflect.DeepEqual` on the policy - otherwise those rows fail for a
reason the format intends. That choice is also the argument for keeping them out of the fuzz
target, whose oracle is DeepEqual.

## Re-open pass

Beads:

- **bv2-zkyyz** (open, report the two goccy gaps upstream): maps to the Q column, every row of
  it. Asked whether the workaround is complete - as far as this grid can see, yes.
  `quoteUnlessItReadsBack` was introduced type-scoped (e15bec3 replaced `yaml.Marshal` with
  `yaml.MarshalWithOptions(..., yaml.CustomMarshaler[string](...))`), so it covers every string
  scalar in the document rather than the `interpreter` field that bit. That is a fix that did
  not stop at one field, and the grid confirms it empirically: 50 indicator-bearing values in 9
  string placements, plus 1.81M fuzz executions over a widened tuple, with no divergence.
  One caveat for the bead, which is a real delta: its closing instruction is to drop
  `quoteUnlessItReadsBack` once upstream ships both fixes, on the strength of the two committed
  seeds `1ec216c1df15d2f2` and `0de821a3490c4043`. Those seeds exercise the current target,
  which varies neither `Args` nor `InterpreterArgs` nor provenance. So the seeds do not tell you
  it is safe for the fields the workaround silently protects today. Widen the target (handoff
  above) before the workaround is dropped, not after.
- **bv2-uyx1h** (validate --relocatable exit 125): no cell. Exit-status shape of a command, not
  the Marshal/Parse pair. Out of area, not graded.
- **bv2-oq59k** (validate should note fields a host posture refuses): no cell. Same field list,
  a different concern - what the host will refuse at run, which docs/state-grid-validate-run.md
  F2 owns. Nothing here refutes it. Out of area, not graded.
- **bv2-8zsrd** (denylist-audit skips directives it cannot parse): unrelated. A shell script over
  firejail profiles, no shared code. The shape does not even rhyme in the direction claimed:
  that parser passes while skipping input, whereas this area's one finding is the inverse -
  Marshal writes a document loudly rather than quietly, and it is Parse that then refuses. Not
  graded.

Landed work, cell by cell (`git log --since=6.months -- manifest policy/fingerprint.go`):

- **e15bec3** introduced `quoteUnlessItReadsBack`. Row carried, not stopped: type-scoped, so all
  nine string placements are covered by the one change. Its own doc comment says a hand-list of
  broken prefixes would have caught one gap and not the other, which is the same reasoning.
- **6e99f95** introduced `maxManifestBytes`, inside a commit whose subject is "sanitize parse
  errors, reject non-text input" - read-side hardening. Nothing was added on the write side, and
  nothing since. That commit's scope is exactly where finding 1 comes from: one side of the pair
  gained a bound the other was never asked about.
- **f1cebae** (`maxNestDepth`) has the same one-sided shape, but the written document reaches
  three levels against a cap of 32, so the asymmetry is unreachable. No gap.
- **0c24177** "validate and screen on the Marshal side" is the commit that made Marshal run
  `Validate` and `screenProvenance`. It closed the two screens Parse applies and did not carry
  `maxManifestBytes` across with them - the same row, half done.
- **0b5c8c6** fingerprints an omitted exec mode as none, and **7099c41**/**178c30b** are
  validate-side. No round-trip cell.

Severity revision on finding 1. No caller bounds a policy's size before Marshal: the four
production call sites are cmd/bento/approve.go:114, cmd/bento/journal.go:187 and :391 (rendering
only, never written back as a manifest), cmd/bento/profile.go:332, and examples/supervise's
perms.go:440. `profile` marshals a proposal built from observed grants, with `clampProposal`
dropping shielded and broad paths but capping neither count nor length. `approve` looks safe
because its policy came through Parse and so fitted under 1 MiB - but it is the reachable path,
not the safe one: approve adds a provenance block (`generated-by`, an RFC3339 timestamp, a
64-character `approves`, the carried blocked-hosts) and the quoting can lengthen scalars, so the
output can exceed its input. A manifest sitting just under the cap therefore becomes a manifest
bento cannot read, written atomically over the original by writeManifestAtomically. So the cell
is not "unusual path only": it is reachable through the one command whose job is rewriting the
file in place, and it loses the original. Still gated behind a roughly 1 MiB manifest, so the
priority stays low; the severity is no longer cosmetic, because the failure destroys the input
rather than just refusing it. The fix stays one-sided in the allowed direction: refuse in
Marshal, before anything is written.
