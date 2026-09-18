# State grid: `trust.groupReach` and the facts built on it

## Phase 0 - fit call: ACCEPTED, with one correction to the nomination

**Two strong signals, one-sided invariant.**

- **Enum x call sites.** `groupReach` has three constants (`trust/accounts.go:18-24`) and is
  read at three sites plus written at two. Small, but the grid writes itself.
- **Degradation flag.** `groupUnknown` is the canonical empty-because-unasked value, and
  the package itself frames the question that way (`trust/accounts.go:19-21`,
  `trust/trust.go:41-43`). This is the weaker signal the skill names, but here it is the
  whole point of the type.

**Correction to the nomination.** `internal/linux/scopeattest.go` and
`internal/linux/limits.go` are **not** consumers of `groupReach`. They are cgroup-v2 code;
every "group" in them is a *c*group. `groupReach` is unexported and confined entirely to
package `trust`:

```
$ grep -rn 'groupReach\|groupUnknown\|groupPrivate\|groupShared' --include='*.go' .
  # trust/accounts.go, trust/trust.go, and the two test files. Nothing else.
```

So the grid's consumer axis is smaller than proposed - but it is not therefore a decline,
because the producer side is where the defect turned out to be. Grid shape changed
accordingly: the axis is *every site that reads or writes `fileFacts.group`*, producers
included, not "consumers outside the package".

**Invariant (one-sided).** A group nothing could be learned about must never present as one
proven to hold nobody. Over-warning (unknown treated as shared) is tolerated; under-warning
is always a bug. Restated to cover producers as well as consumers, since the producer is
what failed: **proof of sharing that the account database holds must never be reported as
`groupUnknown`, and `groupUnknown` must never be read as `groupPrivate`.**

## Phase 1 - the grid

Derived from the code only (`grep` for every read and write of `group` / `groupReach`), not
from git history or the tracker.

**Axis A - the reach value:** `groupUnknown` / `groupPrivate` / `groupShared`.

**Axis B - the site that produces or consumes it** (6, all of them):

| # | Site | file:line | Role |
|---|---|---|---|
| S1 | `accounts.reach` | `trust/accounts.go:39-69` | producer - the lookup itself |
| S2 | `withGroup` | `trust/trust.go:76-81` | producer gate - only looks up when `0o020` is set |
| S3 | `factsOf` | `trust/trust.go:46-58` | producer that deliberately never looks up (the manifest's own facts) |
| S4 | `fileFacts.sharedWrite` | `trust/trust.go:87-96` | consumer - drops the group bit iff `groupPrivate` |
| S5 | `dirFlaws` fatality switch | `trust/trust.go:379-398` | consumer - `groupShared` promotes to `Fatal` |
| S6 | render | `cmd/bento/trustwarn.go:32-39`, `cmd/bento/approve.go:401-411` | consumer - advisory stderr line vs. approve's refusal |

The output-form axis the nomination proposed collapses into S6: there is **no** `--json`
surface for trust flaws. `Flaws()` / `LocationFlaws()` have exactly three callers
(`trustwarn.go:25`, `approve.go:65`, `profile.go:298`) plus the approve refusal, all text.
`validate --json` carries `Approval` only, never a flaw.

3 x 6 = **18 cells. All 18 walked.**

## Phase 2 - every cell

| Cell | Verdict | Evidence |
|---|---|---|
| **Unknown x S1** (reach returns Unknown) | **WRONG**, fixed in e054f63 | `trust/accounts.go:43-46` - the early return on a gid `/etc/group` does not name discards `db.primary[gid]`, which the loop at `:60-64` would have read as proof. Finding 1. The line numbers here are the ones before the fix. |
| Private x S1 | HANDLED | `trust/accounts.go:68` - reached only after both loops found nobody and nothing was unresolved. |
| Shared x S1 | HANDLED | `trust/accounts.go:57,62` - a resolvable non-owner non-root member in either shape returns immediately. |
| **Unknown x S2** (no lookup performed) | HANDLED | `trust/trust.go:77` - the lookup is skipped only when `0o020` is clear, so `sharedWrite` has no group bit to decide about. Spike 7. |
| Private x S2 | HANDLED | `trust/trust.go:78` - lookup runs, keyed on the *owner's* uid, documented at `:66-75`. |
| Shared x S2 | HANDLED | same line. |
| **Unknown x S3** (manifest's own facts) | HANDLED | `trust/trust.go:57` returns `fileFacts` with no group; zero value is Unknown, so `sharedWrite` keeps the bit. Over-warn, the allowed direction. Rationale at `:51-56`. Spike 2. |
| Private x S3 | IMPOSSIBLE | `trust/trust.go:57` is the only construction of the manifest's own facts on the Inspect path and never calls `withGroup`; `InspectNew` at `trust/trust.go:250` likewise builds the literal with no group. `trust/trust.go:78` is the sole assignment to `fileFacts.group` in the package. **Coupling gap - see below.** |
| Shared x S3 | IMPOSSIBLE | same mechanism, `trust/trust.go:78` being the only assignment. **Coupling gap - see below.** |
| **Unknown x S4** | HANDLED | `trust/trust.go:92` - the strip requires `== groupPrivate`, so Unknown keeps `0o020`. Spike 2. |
| Private x S4 | HANDLED | `trust/trust.go:92-94` - bit dropped, and only when setgid is clear. |
| Shared x S4 | HANDLED | `trust/trust.go:92` - condition false, bit kept. |
| **Unknown x S5** | HANDLED | `trust/trust.go:387` - `groupShared` is required for the fatal promotion, so Unknown stays advisory. **This is HANDLED, not a mislabelled WRONG.** The invariant forbids Unknown presenting *as private*, and Spike 3 proves it does not: private is silent, Unknown is advisory, Shared is fatal. What Unknown falls short of is *ground truth*, not `groupPrivate` - and on every host where Unknown arises (LDAP or sss in `nsswitch.conf`, a compat `+` entry, unreadable files) it arises for *every* path, so promoting it to fatal would break `approve` everywhere on that host. That is the argument at `trust/trust.go:368-375`, and it is the design decision, not a gap. Spike 3. |
| Private x S5 | HANDLED | never reaches the switch - `sharedWrite` at `:92` already cleared the bit, so the `if shared != 0` at `:366` is false and no flaw is emitted. Spike 3. |
| Shared x S5 | HANDLED | `trust/trust.go:387-397` - fatal, with its own reason naming the proof and a hint that switches on ownership. |
| **Unknown x S6** | HANDLED | `cmd/bento/trustwarn.go:34` prints the generic `is group-writable` line; `approve.go:403` does not refuse. Distinguishable from both siblings. Spike 3. Since 50fee8d and 7327d57 the line is no longer the generic one - it names the unanswered question. |
| Private x S6 | HANDLED | nothing printed, nothing refused - correct, since the grant reaches a set of one. Spike 3. |
| Shared x S6 | HANDLED | `approve.go:403-407` refuses with the `holds other users` reason. Spike 3. |

### Second pass over the HANDLED cells

Three HANDLED cells were re-examined adversarially and stand:

- **Private x S5 emits nothing at all.** A proven-private group is *silently* clean while an
  unknown one is advisory. That is the right way round, but it means the rendering carries
  no "we could not check the group" line anywhere - unlike `located`, which has
  `ErrLocationUnknown` and an explicit fatal flaw (`trust/trust.go:148-152, 295-300`). See
  Finding 2, fixed in 50fee8d and 7327d57: the unknown line now names the unanswered
  question, though the private one is still silent, which is the right way round.
- **Private x S4/S5 under a foreign owner.** `withGroup` keys the lookup on the file's owner,
  not the observer (`trust/trust.go:78`). A directory owned by someone else whose group holds
  only them reads private, so no group flaw - but `foreignOwner` (`:401`) is fatal on its own.
  Spike 5 asserts that backstop.
- **Private + setgid.** `sharedWrite` exempts setgid at `:92` and `dirFlaws:381` promotes it
  to fatal, so a shared-project layout stays fatal even when the database calls the group
  private. Spike 6.

### Coupling gap behind the two IMPOSSIBLE cells. **VERIFIED BY READING**

Private x S3 and Shared x S3 are unreachable only because `factsOf` (`trust/trust.go:46-58`)
*declines to call* `withGroup`. Nothing enforces that non-call - it is a line that is absent,
not a guard that is present, and the package compiles and passes its tests if someone
"harmonises the inconsistency" so the manifest's own facts get the same group lookup the
directories get.

The consequence is load-bearing rather than cosmetic. With a lookup in place, a manifest at
0664 in a per-user private group would get `groupPrivate`, `sharedWrite` at `:92` would clear
`0o020`, and `Flaws()` at `:271` would stop emitting the group/world-writable flaw for it -
which is the *whole* flaw the manifest's own facts contribute. The only thing holding the
current behaviour is the prose comment at `trust/trust.go:51-56`, which argues the case
correctly (fstat carries no ACL, so the group bits are the mask a named entry is filtered
through, not a grant to the group). Worth reporting on its own even though the IMPOSSIBLE
verdicts are correct today.

## Phase 3 - findings, forbidden direction first

### Finding 1 - `reach` discards the proof of sharing that `/etc/passwd` holds when `/etc/group` does not name the gid. `trust/accounts.go:43-46`. **VERIFIED BY SPIKE**. Fixed in e054f63 (bv2-2duoj); line numbers below are the pre-fix ones

```go
members, named := db.members[gid]
if !named {
    return groupUnknown   // <- db.primary[gid] is never consulted
}
```

A gid that no `/etc/group` line names but that several users hold as their **login group** in
`/etc/passwd` is proven shared - `db.primary[gid]` holds exactly that proof, and the loop at
`:60-64` is written to read it. The early return at `:46` means it never runs. The doc
comment's own promise ("a gid the database does not name is not proof",
`trust/accounts.go:32`) is true only of a gid neither file names; here one of the two files
names it, with proof.

This is the forbidden direction. It is a producer bug, not a consumer one, but the harm is
exactly what the invariant forbids: the answer becomes `groupUnknown`, S5 declines to make it
fatal, and `approve` stamps a manifest in a directory two other real users can write. The
spike proves the first two links by execution; the last link - that a non-fatal flaw means
`approve` proceeds - is **BY READING** `cmd/bento/approve.go:402-410`, which returns an error
only for `flaw.Fatal`.

Spike (`trust/zzspike_test.go`, since deleted):

```
=== RUN   TestSpikeUnnamedGidWithPrimaryMembers
    gid 2000 is the login group of uid 1001 and 1002; reach = 0, want groupShared
    a directory two other users can write produced nothing fatal:
      [{/w, the directory holding it, is group-writable (0775), so anyone there can
        replace the manifest  false  chmod g-w /w narrows it, ...}]
--- FAIL
```

Note the second line: the user is shown the *correct remedy* (`chmod g-w`) as advisory noise
on a host where it should have been a refusal.

**Fix** is one line - `!named` should withhold `groupPrivate` at the end rather than return
early, so the primary scan still runs:

```go
members, named := db.members[gid]
unresolved := !named          // instead of `if !named { return groupUnknown }`
```

The named-member loop is then a no-op on the nil slice, the primary loop still proves
sharing, and an unnamed gid with no primary members still ends at `groupUnknown` via the
`unresolved` check at `:66`.

**Reachability - wider than the missing-group-line case.** `!named` is true not only for a
gid no `/etc/group` line mentions, but for every gid whose only line `parseAccounts`
*skipped*: `len(f) < 4` at `trust/accounts.go:119-121` drops a truncated line
(`users:x:100`, a hand edit that lost the trailing colon), and the `ParseUint` failure at
`:122-125` drops a line whose gid field is not a decimal number. Both leave the gid out of
`db.members` entirely while `db.primary[gid]` still holds the proof from `/etc/passwd`, so
both land in the same wrong answer. A malformed or truncated `/etc/group` line is materially
easier to hit than a gid with no line at all, and it is the more likely trigger in practice.
The one-line fix covers all three shapes.

This host has neither (`comm -23` of passwd gids against group gids is empty). Other real
shapes: a container image with a trimmed `/etc/group`, a `groupdel` while users still
reference the gid, and NFS/LDAP-exported gid maps written into a local passwd.

### Finding 2 - `groupUnknown` has no user-visible label, unlike its sibling `located`. `trust/trust.go:376-398`, `cmd/bento/trustwarn.go:34`. Severity: low. **VERIFIED BY SPIKE** (that the states are distinguishable) + **BY READING** (that they are unlabelled). Fixed in 50fee8d and 7327d57 (bv2-5c02s): the `groupUnknown` arm of `dirFlaws` rewords the same non-fatal flaw to say the question could not be established. Line numbers below are the pre-fix ones

The package makes the same empty-because-unasked distinction twice. For location it is
explicit to the user: `ErrLocationUnknown` produces a dedicated fatal flaw that says the
location "cannot be checked on this host, so nothing vouches for who else can replace it"
(`trust/trust.go:295-300`). For group reach it is silent: on a host where the account
database cannot answer at all (LDAP in `nsswitch.conf`, an unreadable `/etc/group`, a compat
`+` entry) *every* group-writable directory gets the same generic umask line it would get on
a host that simply had nothing to prove. The user cannot tell the check was declined rather
than passed, on a host where it is declined for every path.

This does not violate the invariant - the three reach values do produce three distinguishable
outputs (Spike 3: private silent, unknown advisory, shared fatal) - so it is a reporting gap,
not an under-warning. Recorded as a cell worth a decision rather than a bug.

### Dismissals, verified inverted

Each asserts the safe behaviour the dismissal takes for granted, so it fails if the
dismissal is wrong. All passed.

| Dismissal | Inverted assertion | Stamp |
|---|---|---|
| The manifest's own facts never getting a lookup is safe over-warning | zero-value `fileFacts` keeps `0o020` through `sharedWrite` | **VERIFIED BY SPIKE** (Spike 2, pass) |
| Unknown / private / shared are distinguishable at the render | private emits 0 flaws, unknown emits 1 non-fatal *without* the `holds other users` claim, shared emits 1 fatal *with* it | **VERIFIED BY SPIKE** (Spike 3, pass) |
| An unlocated `Manifest`'s zero-value dir (group Unknown, mode 0) cannot read as clean | `LocationFlaws` on a zero `Manifest` returns exactly one fatal flaw | **VERIFIED BY SPIKE** (Spike 4, pass) |
| A foreign-owned directory with a proven-private group is still refused | `dirFlaws` produces something fatal via `foreignOwner` | **VERIFIED BY SPIKE** (Spike 5, pass) |
| setgid overrides a proven-private group | setgid + `groupPrivate` + 0775 stays fatal | **VERIFIED BY SPIKE** (Spike 6, pass) |
| Skipping the lookup when `0o020` is clear is safe | `withGroup` on 0755 leaves Unknown and `sharedWrite` is 0 | **VERIFIED BY SPIKE** (Spike 7, pass) |
| `internal/linux/scopeattest.go` and `limits.go` consume `groupReach` | tree-wide grep for the four identifiers | **VERIFIED BY EXECUTION** - they do not; the nomination was wrong |
| No `--json` surface renders a trust flaw | enumeration of all four `Flaws(`/`LocationFlaws(` callers (`trustwarn.go:25`, `approve.go:65`, `approve.go:402`, `profile.go:298`) and of `warnStampAtRisk`'s two callers (`run.go:87`, `validate.go:65`) - all stderr text. `validate.go:65` runs *before* the `if asJSON` branch at `:69`, whose body carries `Approval` alone. | **VERIFIED BY EXECUTION** (the greps) + **BY READING** (`validate.go:58-78`). The `json:"reason"` tags at `run.go:331` and `render.go:65,173` are unrelated structs, not `trust.Flaw`. |

### Not walked

Nothing. All 18 cells carry a verdict.

Adjacent things deliberately **outside** this grid, named so they are not mistaken for
covered: the correctness of `nsswitchIsLocal` against the full nsswitch grammar and of
`hasCompatEntry` against NIS syntax are input-parsing questions over an unbounded space -
a fuzzing concern (`trust/accounts_fuzz_test.go` already exists), not grid cells. The
`withGroup`-is-owner-relative-not-observer-relative question is a design decision the
package argues out at `trust/trust.go:66-75` and turns on a caller that does not exist yet.

## Handoff

The grid is finite and small, so Finding 1's case belongs in `TestGroupReach`'s existing
table as a permanent row rather than as a fuzz seed:

```go
"a gid only passwd names, held by others, is shared": {2000, groupShared},
```

The unbounded axis here is the file *text*, which `accounts_fuzz_test.go` already covers;
the invariant above is the oracle for it.

---

# Re-open pass

Run after the known-open list was handed over, per the staging rule. The list did not
change any dimension; it changed one row's facts, and it caught a false dismissal.

## 0. Retraction: the "no `--json` surface" dismissal was WRONG. **VERIFIED BY EXECUTION**

The main grid above claims there is no `--json` surface for trust flaws and that
`validate.go:65` runs before the `if asJSON` branch. **That is false against the current
tree**, and the coordinator was right that it could not coexist with ef9e36a.

Cause: the worktree I gridded in was based on an older commit than `main`'s HEAD (0a45ddb).
Its `cmd/bento/trustwarn.go` was 39 lines and ended at `warnUntrusted`; the current one is
61 lines and carries `stampFlaws`, `flawJSON` and `toFlawsJSON`. Everything I concluded
about `cmd/` was read against a tree that predates f2d50d2 and ef9e36a.

**What actually exists today - three JSON surfaces, all through one converter:**

| Frontend | Field | Wiring |
|---|---|---|
| `run --json` | `stamp_at_risk` | `cmd/bento/run.go:92` -> `toFlawsJSON`, struct at `run.go:394-395` |
| `validate --json` | `stamp_at_risk` | `cmd/bento/validate.go:73` -> `toFlawsJSON`, struct at `validate.go:486-488` |
| `profile --json` | `location_flaws` | `cmd/bento/profile.go:396` -> `toFlawsJSON`, struct at `render.go:222-224` |

`validate.go:65` does run before the `asJSON` branch - but only because it is the *stderr*
call; `validate.go:73` sets `out.StampAtRisk` **inside** that branch. My reading saw the
first and, on a tree where the second did not yet exist, concluded there was none.

**What this does NOT change.** The `trust` package is byte-identical to what I gridded - I
re-read `accounts.go:39-48`, `accounts.go:119-126`, `trust.go:87-96` and `trust.go:385-390`
in the main checkout and every cited line matches. Cells S1-S5 (15 of 18) stand unchanged,
Finding 1 stands, and the last commit to touch either file is 23ad700, well before this pass.
Only the S6 row was read against a stale tree.

### S6 row, re-walked against the real tree

| Cell | Verdict | Evidence |
|---|---|---|
| Private x S6 | HANDLED | `stamp_at_risk` / `location_flaws` are `omitempty` and `sharedWrite` emitted no flaw, so the key is absent - the same answer as "nothing wrong", which is correct here because a set-of-one grant *is* nothing wrong. |
| Unknown x S6 | HANDLED | one `flawJSON` entry, generic `is group-writable` reason plus the `chmod g-w` hint. Present, so a consumer sees it. Since 50fee8d and 7327d57 the reason also names the unanswered question. |
| Shared x S6 | **HANDLED, with a carried-column gap** | one `flawJSON` entry whose reason names the proof (`and its group holds other users`). But `flawJSON` has only `reason` and `hint` - **`Fatal` is dropped**. See section 2. |

The three reach values remain distinguishable in JSON, but only by free-text `reason`, not
by any machine-readable field.

## 1. Finding 1, upgraded: the malformed-group-line shape, spiked. **VERIFIED BY SPIKE**

The coordinator asked me to spike the shape I ranked on rather than only the shape I first
found. Three shapes, one passwd proving gid 100 is the login group of uid 1001 and 1002:

```
=== RUN   TestSpikeMalformedGroupLine/truncated_group_line      ("users:x:100", no trailing colon)
    reach(100, 1000) = 0        want groupShared     nothing fatal
=== RUN   TestSpikeMalformedGroupLine/non-numeric_gid           ("users:x:0x64:")
    reach(100, 1000) = 0        want groupShared     nothing fatal
=== RUN   TestSpikeMalformedGroupLine/no_line_for_the_gid       (control)
    reach(100, 1000) = 0        want groupShared     nothing fatal
--- FAIL (all three)
```

All three produce the identical advisory flaw. The truncated line is dropped by
`trust/accounts.go:119-121` (`len(f) < 4`) and the non-numeric gid by `:122-125`
(`ParseUint`); both leave gid 100 out of `db.members`, so `!named` is true at `:44` and the
primary scan at `:60-64` never runs. **My ranking of the malformed line as the more likely
trigger is confirmed as a real, reachable shape** - it is not a different bug, it is the
same one-line defect reached from an easier direction.

**The decisive control** (Spike 9, **PASS**): a *well-formed* empty group line,
`users:x:100:`, for the same passwd, returns `groupShared` correctly. So the scan works and
the map lookup is the whole defect. That isolates the fix to `!named` and rules out any
reading in which the primary scan is itself at fault.

## 2. The closed decisions, re-opened cell by cell

### bv2-ati60 / bv2-uzlc2 (f2d50d2) and ef9e36a - did the row get carried?

**Yes, for the column those tickets were about.** ef9e36a's subject is "carry each trust
flaw's hint in --json", and the hint reaches all three frontends because all three go
through the single converter `toFlawsJSON` (`cmd/bento/trustwarn.go:57-63`) rather than each
building its own shape. That is the structural reason the row could not be half-carried, and
it is worth naming: the fix was made at the converter, not at the call site. Spike 11
(**PASS**) asserts the hint survives and that all three struct fields are `[]flawJSON`.

So the coordinator's hypothesis - one frontend fixed, a sibling left behind - is **not** what
happened. The contradiction was entirely my stale tree. Recorded as a rejection with its
reason, not a silent drop.

### The column that was NOT carried: `Fatal`. **VERIFIED BY SPIKE**

`trust.Flaw` has three fields; `flawJSON` has two.

```
stamp_at_risk = [
 {"reason":"/w, ... is group-writable (0775) and whether its group holds other users cannot
   be established, so anyone there may be able to replace the manifest",
  "hint":"chmod g-w /w narrows it"},
 {"reason":"/w, ... is group-writable (0775) and its group holds other users, so they can
   replace the manifest","hint":"chmod g-w /w narrows it"}
]
```

The advisory entry and the one `approve` would refuse over are **structurally identical** -
same keys, same hint, differing only in the free text of `reason`. A CI consumer gating on
`run --json` cannot ask "would approve refuse this?" without substring-matching English.

**This is not a violation of the invariant, and I am not filing it as one.** The direction is
the tolerated one: a consumer that treats any `stamp_at_risk` entry as a problem over-warns,
which is safe; only a consumer that deliberately ignores entries under-warns, and it would
have had to ignore them. The comment at `trustwarn.go:45-49` says both halves are carried
"so a consumer can act on it" - `Fatal` is the third half, and whether it belongs is a
product decision rather than a defect. Recorded so the next reader does not have to
rediscover that the omission was examined.

Adjacent, and it corroborates: **bv2-lr5wm** (P4, `run --json stamp_at_risk` has no
end-to-end test) is open against exactly this field. A surface with no end-to-end test is
the surface a stale reading is most likely to get wrong, which is what happened here.

### Was the rest of the row carried on the *trust* side?

The earlier grid (`docs/state-grid-trust-flaws.md`) and its fixes were about `Flaw`
production and rendering. Finding 1 sits one layer below them, in `reach`, and no closed
decision touches `trust/accounts.go:43-46` - the last commit to that file is 23ad700, a
language-features refactor. So Finding 1 is not a half-carried row; it is a cell nobody has
stumbled into, which is the case this technique exists for.

## 3. The other open board item

**bv2-nm49f** (P2, `isCheckout` trusts a `.git` name it never validates) is **not adjacent**
to any cell here. It concerns what counts as a checkout, not who a group reaches; no path
from it reads `fileFacts.group`. Named rather than dropped.

## 4. Net effect on the grid

- 15 of 18 cells unchanged and still correct.
- 3 cells (the S6 row) re-walked; verdicts unchanged (HANDLED) but their *evidence* was
  wrong and is now replaced. The Unknown x S6 and Shared x S6 cells now cite real JSON
  wiring instead of an absence.
- 1 dismissal retracted outright ("no `--json` surface"). **This is the false dismissal the
  skill warns about**: it passed a grep, it read as a conclusion, and nothing in the original
  pass would ever have re-examined it. It was caught only because the coordinator held a
  closed decision that contradicted it.
- Finding 1 unchanged in substance, strengthened in reachability, now with an isolating
  control.

**Process note worth more than any single cell:** a reviewer in a worktree must verify its
base against the branch it is reporting about. Every `cmd/` claim in the main grid above was
sound reasoning over the wrong bytes, and the stamps (`VERIFIED BY EXECUTION`) were honest -
the greps really did run and really did return nothing. A stamp certifies the method, not
the tree.

### Re-open pass stamps

| Claim | Stamp |
|---|---|
| Three `--json` surfaces exist and carry trust flaws | **VERIFIED BY EXECUTION** (grep + the four struct/wiring sites read) |
| `validate.go:73` sets `StampAtRisk` inside the `asJSON` branch | **VERIFIED BY READING** (`validate.go:58-78`) |
| The `trust` package is unchanged from what was gridded | **VERIFIED BY EXECUTION** (`git log -- trust/`, plus all four cited line ranges re-read) |
| A truncated or non-numeric group line reproduces Finding 1 | **VERIFIED BY SPIKE** (Spike 8, 3/3 FAIL as predicted) |
| A well-formed empty group line does *not* - the skip is the whole defect | **VERIFIED BY SPIKE** (Spike 9, PASS) |
| `Fatal` is dropped from every JSON flaw surface | **VERIFIED BY SPIKE** (Spike 10, PASS) |
| The hint reaches all three frontends via one converter | **VERIFIED BY SPIKE** (Spike 11, PASS) |
| bv2-nm49f is not adjacent to any cell | **VERIFIED BY READING** |
