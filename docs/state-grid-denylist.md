# State grid: the deny-list's declared fields against the rules that consume them

Area: `internal/denylist/denylist.go` (the rule tables and the three emitters - `Home`,
`Relocated`, `Runtime` - plus `Workspace`/`WorkspaceGitfile`, `Covers` and
`internal/denylist/index.go`) against `internal/shield` (`rules.go`'s `Assemble`,
`credentialLinks`, `linksUnder`, `Mount`/`target`; `verdict.go`'s `Contains`, `OptIns`,
`callerDenied`).

The backend is the boundary: `internal/linux` is cited where a verdict's consequence lands
there and is not gridded. One cell it holds is named on bv2-12pba rather than left silent -
`internal/linux/shields.go:391-398` dedups mounted rules on `{path, deny, dir}` and so
resolves `Source` deterministically while leaving `Holds` to arrival order, which is F5's
tie-break one package over.

Out of scope by instruction: whether the 2724 lines should split store-table data from
matching logic. That is answered at the end as a conclusion, not taken as an input.

Date: 2026-09-20, against `039629a`. Dimensions derived from the code, not from git
history or the tracker.

## Phase 0 - fit

**Good fit.** One strong signal of the best kind and one of the second kind:

- **A mirror pair.** `Rule` is a five-field declaration written in one package and obeyed
  in another. `internal/shield/rules.go:257` states the direction explicitly: "Which
  stores those are is the deny-list's declaration, not this package's inference... A store
  that should be walked and is not is a missing flag in denylist.go, never a case to add
  here." That is a contract, and a contract is a grid.
- **An enum times its call sites.** `Deny` (2) × `Verdict` (7) × `Kind` (2), consumed by
  five branch sites in `Contains` and by `Covers`/`Index.Covers` on the other side.

The blocker the bead names is gone: `bv2-5y7c0` (061ec2a) made expansion a function of one
declared field, so the per-rule invariant below is statable at all. Before it, expansion
was a switch on `Holds` in the consumer, and "what does this rule declare" had no answer.

**Invariant (one-sided).** *A consumer may shield MORE than a rule declares; it may never
shield less, and it may never describe a path differently from the rule that declares it.*
Concretely: a rule the deny-list emits with `ExpandLinks` must have its farm targets
shielded or the shortfall named in a channel; a rule's `Holds` must be the same noun
wherever the same store is reached; and a field a consumer ignores must be one no producer
sets. The allowed direction - a consumer shielding a store the rule did not ask to be
walked, or a report that over-names - costs launch time and refuses a grant that could have
been honored. The forbidden direction leaves a credential store reachable.

`Source` is outside the invariant's enforcement half by its own contract
(`denylist.go:129`: "Nothing about how a rule is enforced may read it"), so its cells are
judged against the report, not against what binds.

Caveats stated up front: the case-folding cells need a vfat/exfat/ciopfs mount or an ext4
directory with `+F`, which this session does not have. `internal/shieldcorpus`'s `Folding`
fake stands in for the verdict half of those cells - that is what the shipped fold tests
use - and the bind half is stamped `UNSPIKEABLE HERE`.

## Grid A - the five declared fields against the eleven places a rule is produced (55 cells)

A cell asks: does this producer set this field, and is what it sets what the consumers
will read?

| # | Producer | Deny | Dir | Holds | ExpandLinks | Source |
|---|---|---|---|---|---|---|
| 1 | `Home` dirGroups (`denylist.go:1269`) | HANDLED - `DenyAll`, all six groups | HANDLED - `true`, all six | HANDLED - per group, `denylist.go:561-566` | HANDLED - per group, and the three `false` groups are argued: bulk stores cost a recursive walk every launch (`denylist.go:112-117`), service sockets are not farm-managed | IMPOSSIBLE - anchor-relative rules have no variable; empty by construction |
| 2 | `Home` fileGroups (`denylist.go:1274`) | HANDLED - `DenyAll` | HANDLED - absent, so `false`; these are the stores that are genuinely one file (`denylist.go:1243`) | HANDLED - per group | IMPOSSIBLE - `credentialLinks` requires `Dir`, `rules.go:269` | IMPOSSIBLE - as row 1 |
| 3 | `Home` writeOnly / writeOnlyDirs (`denylist.go:1279,1282`) | HANDLED - `DenyWrite` | HANDLED - set on the dir list only | HANDLED - left `HoldsUnknown` deliberately: `Holds` is "set on DenyAll rules only" because a write shield cannot be lifted by a grant (`denylist.go:104`) | IMPOSSIBLE - not `DenyAll` | IMPOSSIBLE - as row 1 |
| 4 | `Relocated` XDG restatement (`denylist.go:1370-1373`) | HANDLED - copies the default rule whole (`r := d`), so every field rides along | HANDLED - same copy | HANDLED - same copy; this is the one relocation path that cannot disagree with its default | HANDLED - same copy. A farm-managed store moved by `XDG_CONFIG_HOME` still expands | HANDLED - overwritten with `b.env` |
| 5 | `Relocated` dirEnvs (`denylist.go:1389`) and dirSubEnvs (`denylist.go:1625`) | HANDLED - `DenyAll` | HANDLED - `true` | **HANDLED, newly pinned** - `HoldsCredentials` is written out literally rather than read off the default rule. Correct today only because every `dirEnvs.def` and every `dirSubEnvs` `def+sub` happens to sit in `credentialAnchorDirs`. Nothing joined the two tables; `TestARelocatedStoreDeclaresWhatItsDefaultDeclares` now does | **HANDLED, same pin** - `ExpandLinks: true` is literal for the same reason, and a row defaulting into `bulkStoreDirs` would have flipped a deliberately-unexpanded store into a per-launch recursive walk | HANDLED - `de.env` |
| 6 | `Relocated` single-file DenyAll blocks - dirFileEnvs, fileEnvs, fileDenyAllEnvs, HGRCPATH, CARGO_HOME's credential half (`denylist.go:1400,1456,1483,1503,1601`) | HANDLED - `DenyAll` | HANDLED - absent; these name one file | HANDLED - `HoldsCredentials`, except fileDenyAllEnvs which carries `fe.holds` per row, the history/credential split | IMPOSSIBLE - not `Dir` | HANDLED - the variable, per block |
| 7 | `Relocated` write-shield blocks - `addWriteShield`, GOPATH, writeOnlyDirEnvs (`denylist.go:1523,1650,1658`) | HANDLED - `DenyWrite` | HANDLED - `true` on the two directory emitters, absent on `addWriteShield` (the comment at `denylist.go:1654-1657` calls out that `addWriteShield` is the wrong emitter for the writeOnlyDirEnvs block, since it produces a file rule) | HANDLED - `HoldsUnknown`, as row 3 | IMPOSSIBLE - not `DenyAll` | HANDLED - the variable |
| 8 | `Runtime` (`denylist.go:1750-1765`) | HANDLED - `DenyAll` | HANDLED - `true` | HANDLED - `HoldsServices` | HANDLED - off, consistent with `serviceDirs` in row 1; a /run tree is not farm-managed | HANDLED - `XDG_RUNTIME_DIR` on the relocated rule only |
| 9 | `Workspace` / `WorkspaceGitfile` (`denylist.go:1846,1886`) | HANDLED - `DenyWrite` on every rule | HANDLED - set on `.git/hooks`, `.vscode`, `.idea` | HANDLED - `HoldsUnknown`, as row 3 | IMPOSSIBLE - not `DenyAll` | IMPOSSIBLE - not a relocation |
| 10 | `shield.linksUnder`'s expansion (`rules.go:325`) | HANDLED - `DenyAll` | HANDLED - `s.fs.IsDir(rp)`; see the dismissals for why an absent target getting `false` is the allowed direction | HANDLED - inherited from the store being walked | HANDLED - deliberately off, argued in place (`rules.go:323`): a target is shielded at its own path and never re-walked | **WRONG, rejected** - inherited from the store, so a farm target is reported under the variable that moved the store. Rejected as a finding; see the dismissals |
| 11 | Caller `extraDeny` (`rules.go:126-135`) | HANDLED - the caller's | HANDLED - the caller's | HANDLED - the caller's, read by `OptIns`... which excludes caller denies, so it reaches only `Contains`'s refusal | **UNHANDLED** - `Assemble` scrubs `Source` on a caller rule and leaves `ExpandLinks` to be silently ignored by `credentialLinks`, which iterates `base` only. Two declarative fields, one defensively cleared, one dropped on the floor. The consequence is written down (`rules.go:114-117`: "whatever it sets on the rule") and nothing tests it. F2 | HANDLED - cleared at `rules.go:131`, with the reason |

## Grid B - the eight consumers, and which declared fields each is entitled to read (8 cells)

| Consumer | Verdict |
|---|---|
| `Assemble`'s anchor pass (`rules.go:79-107`) | HANDLED - reads `Path` only, and records provenance by the deny-list's own spelling. `nestedAnchor` (`rules.go:239`) is keyed on where the rule CAME FROM, not on any field |
| `credentialLinks` (`rules.go:267`) | HANDLED - reads exactly `Deny`, `Dir`, `ExpandLinks`, and nothing else; pinned by `TestExpansionFollowsTheFlagNotTheBucket`. This is the cell `bv2-5y7c0` created, and it is clean |
| `Mount`/`target` (`rules.go:188,223`) | HANDLED - reads `Path` only. Note the ordering: `credentialLinks` runs over `base` BEFORE `Mount`, so a store whose own rule `target` drops still contributes its link rules. Allowed direction (more shielding, not less) |
| `Contains`, DenyAll arms (`verdict.go:111,113,129,172`) | HANDLED - reads `Deny` and the resolved path; `Rule.Path` and the `loc` spelling are asked alongside for the symlinked-home and farm shapes |
| `Contains`, DenyWrite arms (`verdict.go:144,189`) | **WRONG** - the fold question is asked of three of the four Deny×direction cells and not the fourth. See Grid C and F1 |
| `Contains`'s workspace slice (`verdict.go:147`) | **UNHANDLED** - `if r.Deny == denylist.DenyWrite` silently drops any other rule. True today because `Workspace` emits `DenyWrite` only, which nothing asserts: `TestWorkspaceShieldsEditorConfigDirs` checks `.vscode` and `.idea` individually and says nothing about the rest. Add a `DenyAll` rule to `Workspace` and nothing fails to compile and nothing fails to pass. F3 |
| `OptIns` (`verdict.go:328`) | HANDLED - reads `Deny`, `Path`, `Holds`; the `Holds` it carries out is the one the rule declares, which is what `OptIn`'s three-field struct exists to keep together (`verdict.go:300-305`) |
| `Covers` / `Index.Covers` (`denylist.go:1803`, `index.go:63`) | **UNHANDLED (contract)** - the doc specifies `Deny` and `Dir`, and declares `Source` and `Holds` unspecified in the returned rule. `ExpandLinks` postdates that paragraph (`bv2-5y7c0`) and is not mentioned, so a fourth field is undefined without saying so. `stricter` (`denylist.go:1825`) does not consider it either. Nothing reads it off a `Covers` result today - verified by grep - so this is a doc gap, not a bug. F4 |

## Grid C - the fold question across Deny × direction (4 cells)

A shield is one byte-exact bind, so where the directory holding it folds case the same
content is reachable under a second spelling. Three of these four cells say so in their own
comments. The fourth's silence is F1.

| | grant AT or UNDER the shield | grant ABOVE the shield |
|---|---|---|
| **DenyAll** | HANDLED - `InsideShield` via `covers`, which settles each differing component by asking the host (`verdict.go:195-245`). The comment at `verdict.go:99-104` argues the `~/.SSH/id_rsa` case explicitly | HANDLED - `FoldedShield` (`verdict.go:129`), refused on both tiers (`internal/linux/grants.go:101`, `gate/gate.go:437`) |
| **DenyWrite** | HANDLED - `UnderWriteShield` via the same `covers` (`verdict.go:144`). The comment at `verdict.go:136-141` names `~/.pyenv/SHIMS` against a shield at `~/.pyenv/shims` | **WRONG - F1.** `AboveWriteShield` (`verdict.go:189`) is fold-blind, and it is the one verdict the full tier does not refuse |

## Findings, forbidden direction first

### F1 - `AboveWriteShield` is fold-blind, and it is the verdict the bwrap tier honors
Verdict is fold-blind: `VERIFIED BY SPIKE`. The exposure that follows from it:
`UNSPIKEABLE HERE` (needs a vfat/exfat/ciopfs mount or ext4 `+F`, plus bwrap).

A write grant that CONTAINS a `DenyWrite` shield earns `AboveWriteShield`, and that verdict
is refused on the degraded tier ALONE (`internal/linux/degraded.go:61` via
`checkWriteNotAboveWriteShield`; declined by `checkGrants` at `internal/linux/grants.go:107`
and by the gate at `gate/gate.go:408`). The reason is recorded at
`internal/linux/grants.go:264-268`: "Under bwrap denyArgs re-binds the shield read-only
after the grant's bind and bwrap is last-wins, so the shield holds and `write: ~/.pyenv` is
a legitimate grant."

That reasoning is sound for a byte-exact filesystem and unsound where the grant's directory
folds case. The shield's ro-bind lands at `~/.pyenv/shims`; `~/.pyenv/SHIMS` reaches the
same directory and is inside the grant's read-WRITE bind, so the run plants shims on the
host on the tier that was supposed to be the safe one. This is not a new model: it is the
same model `foldsCase` (`verdict.go:249-270`) and the component walk in `covers` already
rest on, and it is the exposure the `UnderWriteShield` comment at `verdict.go:136-141`
already names with the same `.pyenv/SHIMS` example - reached by a grant that spells the
shim directory, where this is reached by a grant that merely contains it. Disputing this
cell means disputing three shipped ones.

**Severity caveat, raised in review and worth carrying.** Whether the bind is really
defeated is filesystem-dependent in a way nothing here can settle. ext4's casefold and vfat
fold in the dentry layer, so both spellings resolve to ONE dentry and a bind on it is hit
under either name; a FUSE overlay such as ciopfs presents two, and there the ro-bind covers
one of them. So "the plant lands on the host" is stated more confidently above than
`UNSPIKEABLE HERE` supports, and the honest form is: on at least the ciopfs shape it lands,
and on the dentry-folding shapes it may not. That does not weaken the cell, because the
finding is safe under either answer - if the model holds, `AboveWriteShield` needs the fold
check; if it does not, the three shipped fold cells beside it are over-refusing, which is
the larger finding. It does mean the fix must measure before it chooses, rather than
inheriting this paragraph's confidence.

Spike (deleted): `Assemble` over a home with `.pyenv/shims`, `shieldcorpus.FS{Folding:
true}` and `{Folding: false}`, asking `Contains(home+"/.pyenv", shield.Write, nil, nil)`.
Both returned `AboveWriteShield`, same rule. The fold changes nothing.

`FoldedShield` is the verdict that exists for exactly this shape and it is gated on
`a.Rule.Deny != denylist.DenyAll` (`verdict.go:125`). Filed as **bv2-c2abm**.

### F2 - a caller deny declaring `ExpandLinks` is silently ignored, and nothing pins it
`VERIFIED BY SPIKE`

`credentialLinks` iterates `base` (`rules.go:118`), which is the built-ins alone, so a
caller's `Rule{..., ExpandLinks: true}` walks nothing. The consequence is stated at
`rules.go:114-117` - "a `DenyAll` it puts on a farm-managed credential directory shields
that directory and nothing the farm points at, whatever it sets on the rule" - and that is
a claim about another file: delete the `base` argument's restriction and the sentence
becomes false while everything still compiles. `internal/shield/callerdeny_test.go` sets no
`ExpandLinks` at all. Per this repo's cross-file-prose rule the claim needs a test.

Spike (deleted): a caller deny on `/opt/creds` with `ExpandLinks: true` over a fake whose
`/opt/creds/k` links into `/home/u/farm/k`. `set.CredentialLinks()` came back `[]`.

The finding is the missing pin, not the behaviour - `Assemble` scrubbing `Source` two lines
below while leaving `ExpandLinks` to be dropped by a consumer is the asymmetry that makes it
worth pinning rather than the behaviour being wrong. Filed as **bv2-yybcq**.

### F3 - `Contains` silently ignores a workspace rule that is not `DenyWrite`
`VERIFIED BY READING`

`verdict.go:147-152` consults the runtime workspace shields under
`if r.Deny == denylist.DenyWrite`. Every rule `Workspace` and `WorkspaceGitfile` emit is
`DenyWrite` today, so the guard costs nothing - and nothing asserts that. A `DenyAll` rule
added to `Workspace` (a checkout-local credential store is the obvious next entry) would be
assembled, mounted by the enforcer, and never once refuse a grant, because no arm of
`Contains` looks at the workspace slice for anything else. The skill's coupling-gap shape
exactly: one condition in another file, nothing fails to compile if it moves.

Not the same as `Contains`'s deliberate "INSIDE direction only" for workspace rules, which
is argued at `verdict.go:78-86`. That argument is about direction; this is about `Deny`.
Filed as **bv2-3n3fa**.

### F4 - a store the expansion could not read WHOLE is not disclosed, where a store it could not walk DEEP ENOUGH is
`VERIFIED BY SPIKE`

`TruncatedStores` (`rules.go:181`) exists so that "a store that is shielded but only
expanded partway says so instead of under-covering its farm targets silently", and
`cmd/bento/render.go:2046` reports it to the operator. It is raised by one cause only: the
depth bound (`rules.go:294`). The OTHER way the walk covers less than the store - `ListDir`
returning `ok == false` - raises nothing. Both shapes reach it:

- A read that failed outright (`rules.go:302`) returns early, and the early return's comment
  dismisses it: what an unreadable store exposes is its links' targets, which cannot be named
  without reading the directory.
- A read that failed PART WAY returns real entries with `ok == false` and falls through to
  expand them. `FS.ListDir`'s own doc (`shield.go:57-61`) says those are "real entries a
  caller failing closed on the remainder must still cover" - and the remainder is neither
  covered nor named.

The dismissal is right about what can be BOUND and wrong about what can be SAID. The
partial-read case is the sharper half: the walk knows it did not finish, the channel for
saying so is three lines away, and the operator is told the store is expanded.

Spike (deleted): `Assemble` over a fake whose `~/.ssh` `ListDir` returns `ok=false`, once
with an entry and once empty. Both gave `TruncatedStores() == []`. Filed as **bv2-a4165**.

### F5 - `Covers`'s contract argues three of the five fields individually, and `ExpandLinks` is not one of them
`VERIFIED BY READING`. **Narrowed in review; the first draft of this finding overstated it,
and the overstatement is recorded rather than edited away because it is the same mistake the
grid exists to catch - a cell called UNHANDLED without opening the file twice.**

The first draft said `ExpandLinks` "is not mentioned" and is "undefined by omission", and
that `Index.Covers` inherits the same silence. Both are false. `denylist.go:1800` does
mention it - "nothing about how a rule is enforced reads Holds, which is why ExpandLinks is
declared per rule rather than derived from it" - and `index.go:63` says "only the returned
Deny and Dir are specified", which covers every other field at once.

What survives is narrower and still worth a line. `denylist.go:1803`'s doc specifies `Deny`
and `Dir` on the returned rule, then argues `Source` unspecified and `Holds` unspecified,
each in its own paragraph. `ExpandLinks` gets no such paragraph, and the sentence that does
name it is about why the field exists rather than about what the returned rule says - which
a reader arriving at that paragraph can take for the same kind of statement. `stricter`
(`denylist.go:1825`) tie-breaks on `Deny` and `Dir` only, so which rule's flag comes back is
slice order, exactly as for `Holds`. Nothing reads it off a `Covers` or `Index.Covers` result
today (grep over the tree), so this is the contract, not the behaviour. The reason to close
it rather than leave it: `Covers` is the shared answer the parity audit and the credential
hunt both use, and the next consumer that wants to know whether a store expands will read it
off the result. Filed as **bv2-12pba**.

## Dismissals, verified inverted

- **A farm target that does not exist yet gets `Dir: false`, and that is the allowed
  direction.** `VERIFIED BY READING`. `rules.go:325` sets `Dir: s.fs.IsDir(rp)`, so a
  dangling farm link produces a file-shaped `DenyAll` that `Index.dirs` never holds and
  that covers nothing below it. The contrast is deliberate on the other side -
  `Workspace`'s `.cargo/config.toml` rules are "shielded whether or not they exist yet,
  because an absent one is exactly what a plant creates" (`denylist.go:1866`) - but the
  shapes differ: a `DenyAll` file rule binds an empty file at the path, and nothing can be
  created UNDER a regular file, so the run cannot fill the absent directory in behind the
  shield. Degraded, not exposed. No action.
- **`Source` inherited onto an expanded link rule is not a misattribution.** `VERIFIED BY
  READING`. `rules.go:325` copies the store's `Source`, so `relocatedShields()`
  (`cmd/bento/render.go:2036`) reports a farm directory the variable never named under that
  variable. Rejected as a finding: unsetting the variable genuinely does undo those link
  shields, which is what the report's remedy line tells the operator, so the attribution is
  transitively true. Recorded because the cell is unobvious, not because it needs a fix.
- **`credentialLinks` running before `Mount` is the allowed direction.** `VERIFIED BY
  READING`. A store rule that `target` (`rules.go:223`) drops - one resolving onto a home -
  has already contributed its link rules, which are then mounted on their own merits. More
  shielding than the declaration asks for, never less.
- **The `dirGroups` `expand: false` groups are argued, not forgotten.** `VERIFIED BY
  READING`. `bulkStoreDirs` and `serviceDirs` are the two, and `denylist.go:112-117` gives
  the cost ("every launch pays a recursive walk of it and each link's target becomes an
  alias-scan root"). Row 1 of Grid A stands on that argument, and F-none follows from it.
- **`MaxWalkDepth` and `maxGitdirDepth` agree on the comparison, not just the number.**
  `VERIFIED BY READING`. Both are `depth > bound` (`rules.go:294`,
  `internal/linux/shields.go:275`), and `internal/linux/shields.go:359` reads the shield
  constant rather than repeating it. The profiler's clamp does repeat the number
  (`cmd/bento/clamp.go:262`) and that residual is already recorded at
  `cmd/bento/render.go:2054`. No new finding.

## The question the bead asked and did not pre-judge

**Should the 2724 lines split store-table data from matching logic?** On this grid's
evidence, no - and the grid is the argument rather than a preference. Every finding above is
a contract gap between a declared field and a consumer in ANOTHER package, and none of the
five would have been prevented by moving the tables into a file of their own: F1 is entirely
inside `internal/shield`, F2 and F3 are consumer-side guards, F4 is a disclosure channel,
and F5 is a doc paragraph. What the grid did find is that the file's highest-risk seam is
the pair of relocation emitters that write `Holds` and `ExpandLinks` out literally where the
default reads them off a table (Grid A row 5), and that is a JOIN between two tables in the
same file - a split would put the two on opposite sides of a package boundary and make it
harder to pin, not easier. The pin landed instead.

## Spike graduated

`TestARelocatedStoreDeclaresWhatItsDefaultDeclares`
(`internal/denylist/relocation_columns_test.go:99`) is the one spike that became a real
test, because the cell it pins - Grid A row 5 - is held today by nothing but two tables
happening to agree. Proved red by adding a `dirEnvs` row whose default lives in
`bulkStoreDirs`, which is the group that disagrees on BOTH fields at once
(`{HoldsPrivateData, false, ...}`, `denylist.go:562`), so one mutation exercises the whole
assertion:

```
dirEnvs/FAKE_MAIL_DIR: default .thunderbird holds private-data, but the relocation emits HoldsCredentials
dirEnvs/FAKE_MAIL_DIR: default .thunderbird does not expand links, but the relocation emits ExpandLinks
```

Reverted; green with the table restored. A `historyDirs` row trips the `Holds` arm alone -
that group expands - which is why the bulk-store row is the one recorded here.

The `Dir` arm was added in review, after the observation that the two assertions above both
pass for a row whose default is one of the `fileGroups` stores while the relocation binds a
whole tree where the default binds one file. Proved red on its own terms with
`{"FAKE_FILE_DIR", ".netrc"}`, which is `HoldsCredentials` and so leaves the `Holds` arm
silent:

```
dirEnvs/FAKE_FILE_DIR: default .netrc does not expand links, but the relocation emits ExpandLinks
dirEnvs/FAKE_FILE_DIR: default .netrc is a file rule, but the relocation emits a directory
```

Between the two mutations all three literal fields are shown load-bearing. Note what the
test cannot fail on today: with `credentialAnchorDirs` the only `HoldsCredentials` group and
that group expanding, `ExpandLinks` never fails alone. It is not decoration - it pins the
second literal independently, so a future `HoldsCredentials` group with `expand: false`
trips it by itself - but its red is currently only ever observed alongside another arm's.

## Spikes (deleted; Phase 4)

1. `internal/shield/spike_fold_above_test.go` - `Contains` over a `.pyenv/shims` home with
   the corpus folding fake on and off. Both `AboveWriteShield`. F1.
2. `internal/shield/zz_spike_grid_test.go` - two cases over a hand-built `shield.FS`: a
   caller deny with `ExpandLinks: true` (F2, `CredentialLinks()` empty) and a store whose
   `ListDir` returns `ok=false` with and without entries (F4, `TruncatedStores()` empty).

## Gates

One test file changed (`internal/denylist/relocation_columns_test.go`), no non-test source.
`GOWORK=off go test ./internal/denylist/ ./internal/shield/`, `make vet`, `make lint`,
`make layering`, and `GOOS=darwin GOWORK=off go vet ./...` - the crossbuild step, because a
test file changed.

## Cells not walked

None. Grid A 55/55, Grid B 8/8, Grid C 4/4. The weaker stamps are named where they sit: F1's
exposure half is `UNSPIKEABLE HERE`, and every Grid C cell's bind behaviour rests on the
model `foldsCase` states rather than on a folding mount this session could build.
