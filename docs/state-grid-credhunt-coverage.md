# State grid: credhunt's shape signals against denylist's coverage

> **Status, 2026-09-20 (fleet run).** U-1, U-2 and U-3 are FIXED, by the one shared remedy
> this document argued for: `Hunt` returns a fourth value, `[]Skip{Path, Reason}`, and
> `cmd/credhunt` prints `skipped` (c22d7aa, a10b898, 1b8fbd8). The dotfile-farm row is fixed
> separately for the UNVERSIONED case only (84eb583); a farm under git was never silent,
> being pruned whole by `isCheckout` and disclosed. `FuzzHuntNeverReportsAShieldedFile` now
> carries a canary with a constant oracle (a4cc548), so its five pre-existing assertions are
> load-bearing rather than vacuous against a nil return. H-8's pin was resolved differently:
> the assertion already existed - see that section. Still open: axis A needs its split (a
> row is missing for "sniffed, but only to `MaxFileSize`"), and sniff depth is measured from
> the home root rather than the farm root (bv2-c3z78).

Area: `internal/credhunt/credhunt.go` and `cmd/credhunt/main.go`, against
`internal/denylist/denylist.go` (`Home`/`Relocated`/`Runtime`, `Covers`, `Shieldable`),
`internal/denylist/index.go`, `internal/denylist/audit/audit.go`, and
`internal/shield/rules.go` (`Assemble`, `Mount`/`target`, `credentialLinks`).

Date: 2026-09-20, against `9a90f6a`. Dimensions derived from the code, not from git history
or the tracker. Inherits the verdicts of `docs/state-grid-denylist.md` rather than redoing
them; `Holds` vs `ExpandLinks` is settled there and is not re-litigated here.

## Phase 0 - fit: ACCEPT, and the earlier decline is superseded

**Q1 - the earlier decline ("one dimension, linear flow - ordinary review if anything")
was correct about credhunt in isolation and is superseded by the second axis.** Read alone,
`Hunt` is a `filepath.WalkDir` with a signal list; that is a list, not a grid. What makes it
a grid is that credhunt is one half of a **mirror pair**, which is the strongest Phase 0
signal there is:

- credhunt answers "is this path shielded?" with `denylist.Home + Relocated + Runtime`,
  fed through `denylist.Index.Covers`, **lexically and unresolved**
  (`credhunt.go:180`, `credhunt.go:210`; rule set built at `cmd/credhunt/main.go:116-119`).
- the run answers the same question with `shield.Assemble` -> `Mount`/`target`,
  **resolved**, **plus** the `credentialLinks` symlink expansion and minus the rules that
  mount nowhere (`internal/shield/rules.go:75`, `:186`, `:253`).

Two pieces of code answering one question that may disagree in exactly one direction. The
earlier decline was missing that second reader, and the fit turns on it. Recording this
plainly so the next sweep does not re-nominate credhunt on its own: **credhunt alone is not
a grid; credhunt x the applied shield set is.**

**Q2 - `FuzzHuntNeverReportsAShieldedFile` does NOT cover this grid; defer-to-the-machine
does not apply.** It is a strong oracle pointed the wrong way. Every assertion in its body
(`internal/credhunt/hunt_fuzz_test.go:57-88`) is quantified over `found`: the
`Covers`/`Index` DenyAll differential, signals-non-empty, private-mode-alone, sortedness,
dedup. **Nothing is quantified over planted-and-not-reported.** A `Hunt` that returned
`nil` for every input passes it. Its name is the allowed direction of the invariant
("never reports a shielded file"); the forbidden direction is asserted nowhere in the tree.
`internal/denylist/index_fuzz_test.go:48` (`FuzzCoversAgreesWithIndex`) is the same
differential one package over and has the same blind spot - it compares two coverage
oracles, never coverage against reality. `internal/denylist/audit/audit_test.go:1123` is
parity against corpora, which `audit.go:19` itself states is not completeness.
*(VERIFIED BY READING and, for the `nil`-passes claim, by the three failing spikes below,
which the fuzz target is green on.)*

**Invariant (one-sided, restated).** *credhunt may report a store the applied shield set
already covers - a redundant lead is noise, not a defect. It must never be SILENT about a
secret-bearing file that the applied shield set does not cover.* "Silent" is the strong
form: not listed as a finding, and not named in the `pruned` or `unreadable` channels
either. The allowed direction costs the operator reading time; the forbidden direction is
the failure the package doc (`credhunt.go:11`, `:36`) says the tool exists to prevent, and
is what `denylist.go:36`'s 2-of-21 recall baseline is measured against.

Caveat on scope: this grid judges credhunt's *silence*, not the deny-list's *completeness*.
A store the deny-list also misses is an UNHANDLED cell here only if credhunt does not name
it in any channel.

## The grid - 5 x 6 = 30 cells

**Axis A - whether credhunt's content sniff ever reaches the file.**

| A | state |
|---|---|
| A1 | a cheap signal fires (name token, suffix, editor-leaving, private mode) -> sniffed |
| A2 | no cheap signal, file sits directly at the home root -> sniffed (`shapesOf`'s `atHomeRoot`) |
| A3 | no cheap signal, file sits **below** the home root -> **never opened** |
| A4 | entry is not a regular file (symlink, socket, fifo) -> never examined, never named |
| A5 | entry is inside a subtree `Hunt` pruned -> never examined, root **is** named |

**Axis B - the coverage state of the file's path.**

| B | state |
|---|---|
| B1 | covered by a `DenyAll` **directory** rule |
| B2 | covered by a `DenyAll` **file** rule at its own path |
| B3 | covered by a `DenyWrite` rule only |
| B4 | covered only via `shield.credentialLinks`' `ExpandLinks` expansion - **invisible to credhunt** |
| B5 | a rule is in credhunt's set but `shield.Mount`/`target` drops it - **credhunt over-prunes** |
| B6 | not covered at all |

### Cells

Verdict key: H = HANDLED, W = WRONG, U = UNHANDLED, I = IMPOSSIBLE.

| | B1 DenyAll dir | B2 DenyAll file | B3 DenyWrite | B4 ExpandLinks only | B5 dropped by shield | B6 uncovered |
|---|---|---|---|---|---|---|
| **A1 cheap signal** | H-1 | H-8 | H-2 | H-3 (noise) | I-1 | H-4 |
| **A2 home root** | H-1 | H-8 | H-2 | H-3 (noise) | I-1 | H-5 |
| **A3 below root** | H-1 | H-8 | H-6 | H-3 (noise) | I-1 | **U-1** |
| **A4 non-regular** | H-1 | H-1 | **U-2b** | H-3 | I-1 | **U-2** |
| **A5 pruned** | H-1 | H-8 | H-7 | H-7 | I-1 | H-7 |

Counts: **HANDLED 22, WRONG 0, UNHANDLED 3, IMPOSSIBLE 5.** Every cell carries a verdict;
none were left unwalked. Behind them are two distinct findings - U-1 (one cell) and U-2
(two cells) - plus one coupling gap on an otherwise-HANDLED cell (H-8).

## Cell notes

**H-1 (B1, all A) - `credhunt.go:180`.** `shields.Covers(path)` plus
`r.Deny == DenyAll` plus `d.IsDir()` -> `fs.SkipDir`. Correct and in the allowed direction:
the subtree is genuinely shielded, so silence about it is silence about something covered.
*VERIFIED BY SPIKE* - planted `~/.ssh/id_rsa` with a PEM body; not reported.

**H-8 (B2 x A1/A2/A3/A5) - handled, but by coincidence rather than by agreement. This
cell was walked as WRONG first and the verdict was overturned by opening the backend;
recording the correction, because the wrong version is the plausible-looking one.**

`credhunt.go:180-186` tests `r.Deny == DenyAll` and then branches on `d.IsDir()` - **it
never consults `r.Dir`.** `Index.Covers` returns from its `exact` map at the path itself
"whatever its Dir flag" (`internal/denylist/index.go:32`). So a rule the deny-list declared
as a **file**, whose path is a **directory** on this host, prunes the whole subtree beneath
it. `denylist.Home` emits **128 DenyAll file rules**, every one such a prune point, and the
shape is ordinary - a tool turning a single-file config into a config directory
(`internal/denylist/denylist.go:752-755`'s linphone pair sits at the home root as exactly
this kind of rule).

*VERIFIED BY SPIKE* (credhunt half): planted `~/.linphonerc/secret.pem` (0600, PEM body,
three signals) -> `found=[]`. Control at `~/.acmerc-notarule/secret.pem` under no rule ->
reported. Rule confirmed as `{Path:.../.linphonerc Deny:0 Dir:false}`.

The reason this is not the forbidden direction is in the backend, not here.
`internal/linux/shields.go:709-724` (`shieldMount`) picks the mount shape **from what is on
disk, not from the declared `r.Dir`** - "~/.cert is a directory on one host, a file on
another" - so a file-declared DenyAll rule landing on a real directory gets `--tmpfs` and
the run hides the whole tree too. The two sides agree, so credhunt's silence is silence
about something genuinely shielded: the allowed direction. *VERIFIED BY READING*
(`internal/linux/shields.go:718-726`, and the same choice restated at `:809`).

**The coupling gap is the finding.** Both sides ignore `r.Dir` for the same *outcome* and
for entirely different *stated reasons* - credhunt because `Index.Covers` matches exactly
and the walk branches on `d.IsDir()`; the backend because handing bwrap a tmpfs-over-file
mount aborts the run. Nothing connects them, and nothing would fail to compile if
`shieldMount` started honouring `r.Dir`.

**Corrected after review (2026-09-20).** This section first said that honouring `r.Dir`
would leave those 128 trees readable while credhunt stayed silent. It would not: bwrap
refuses a file bound over a directory and the run aborts loudly (measured on this host -
`bwrap --ro-bind <emptyfile> <realdir> true` exits 1, "Is a directory"), which the
existing test's own comment already said. The silent variant needs a different edit -
dropping a kind-mismatched rule to dodge that refusal - and the same assertion catches it,
because the mount then comes back nil rather than `--tmpfs`. The coupling is real; the
failure mode named here was wrong.

**H-2 (B3 x A1/A2) - `credhunt.go:175-180`.** `DenyWrite` is deliberately not coverage, and
the comment says why. *VERIFIED BY SPIKE, inverted* - planted a 0600 token file under a
`DenyWrite` directory rule and asserted it **is** reported; it was.

**H-3 (B4) - allowed direction.** credhunt's rule set is `Home+Relocated+Runtime`
(`cmd/credhunt/main.go:116-119`); it never runs `shield.Assemble`, so the
`credentialLinks` expansion (`internal/shield/rules.go:253`) is invisible to it. A farm
target the run *does* shield is therefore reported as a lead. Noise, not a defect - exactly
the direction the invariant permits.

**H-4 / H-5 (B6 x A1/A2).** The tool working: a shape fires, or the home-root exception
opens the file, and an uncovered secret is reported. *VERIFIED BY SPIKE* for A2 - a 0644
`~/.env` holding a token assignment was reported.

**H-6 (B3 x A3).** Same mechanism as H-2 - no prune - so the file reaches `shapesOf` and is
judged on shape alone. Where it is silent, the cause is U-1's, not `DenyWrite`'s.

**H-7 (A5, B3/B4/B6) - `credhunt.go:196-215`, `cmd/credhunt/main.go:150-153`.** A pruned
subtree hides its contents, but `Hunt` returns every pruned root and `run` prints each one
individually and refuses to fold them into a count. That satisfies the invariant's
"named in a channel" clause: the operator is told exactly where the scan narrowed.
*VERIFIED BY SPIKE* - planted a real `.git` checkout with an uncovered `.npmrc` inside;
`found=[]` but `pruned=[.../work/repo]`.

**U-1 (A3 x B6) - `internal/credhunt/credhunt.go:274-278`. The second forbidden-direction
finding.** `shapesOf` runs `contentShapes` only when `len(signals) > 0 || atHomeRoot`. A
**world-readable file below the home root whose name trips no `nameToken` and no
`nameSuffix` is never opened at all.** The package's justification for that gate
(`credhunt.go:264-270`) reasons about **PEM only**: "a PEM block in a file with an ordinary
name and world-readable mode is a certificate, not a hunt result." That argument does not
transfer to `SignalToken`. A `"token": "<40 opaque chars>"` assignment in a 0644
`~/.config/<tool>/settings.json` is not a certificate - it is precisely the developer token
store class `credhunt.go:11` says the tool exists to reach, and that `denylist.go:36`
records the parity audit missing 19 of 21 of. The narrowing was reasoned about one signal
and silently applied to both.

*VERIFIED BY SPIKE*: four 0644 files holding `oauth_token: gho_...` -
`.config/acmecloud/settings.json`, `.config/acmecloud/config.json`,
`.local/share/acmecloud/db.json`, `.acmecloud/hosts.yml` - `Hunt` returned `found=[]`,
`pruned=[]`, `unreadable=[]`. Total silence. The identical content at the home root is
reported (H-5), which isolates the cause to the gate rather than to `tokenAssignment`.

The fix is a judgement call, not a one-liner: sniffing every file is the cost the gate
exists to avoid. The cheapest honest narrowings are to extend the `atHomeRoot` exception one
directory level deeper, or to sniff any file under a **dot**directory regardless of mode.
Both are bounded; neither is obviously right, which is why this is filed as a cell rather
than fixed here.

**U-2 (A4 x B6) and U-2b (A4 x B3) - `internal/credhunt/credhunt.go:222-224`.**
U-2b is the same silence: a `DenyWrite` rule hides nothing, so a link under one leads to a
target that is just as reachable as an uncovered one. Kept as its own cell because the
coverage state differs and the invariant is decided the same way in both. `if !d.Type().IsRegular()
{ return nil }` drops every non-regular entry with no record anywhere. A **symlink at the
home root pointing at an unshielded secret outside the home** is therefore invisible: not a
finding, not `pruned`, not `unreadable`. It is the same class `shield.credentialLinks`
exists to chase from the other side, unchased here.
*VERIFIED BY SPIKE*: `~/.acmerc` -> `/tmp/.../farm/creds` (0600, token body) ->
`found=[] pruned=[]`.
Smaller than U-1: a farm link usually points back inside the home, where the target is
walked under its own name. But a link *out* of the home is exactly the shape
`internal/shield/rules.go:253`'s expansion was written for, so the class is real. The cheap
remedy is naming it rather than following it - a symlink out of the home narrows the scan,
and by this package's own standard a narrowing belongs in a channel.

**I-1 (B5, all A) - credhunt cannot over-prune on a rule `shield` drops.**
`cmd/credhunt/main.go:106-119` passes the **same** `denylist.HomeAnchors()` slice to
`Relocated(home, homes)` and to each `Hunt{Home: h}`, so every rule in credhunt's set has
already passed `denylist.Shieldable(p, homes)` (`internal/denylist/denylist.go:515-538`),
which refuses any `p` equal to an anchor or enclosing one - no rule can prune a whole home.
`shield.target`'s extra drop is on the **resolved** path
(`internal/shield/rules.go:224-232`), so the only rules it removes and credhunt keeps are
ones whose *unresolved* path would have to be reachable in the walk to shadow anything -
and for that, a component of it must be a symlink, which `Hunt` never follows
(`credhunt.go:222`). The rule is inert in credhunt, which is the answer
`internal/denylist/denylist.go:500-506` already records for lexical readers, naming the
credential hunt explicitly. *VERIFIED BY READING* - not spiked, because constructing it
needs a home reachable by two spellings.

*Coupling note on I-1:* what makes this cell impossible is one predicate in another package
(`Shieldable`) plus one line in this one (`IsRegular`). Neither would fail to compile if the
other moved, and `denylist.go:500` is the only place the pairing is written down. That is
load-bearing cross-file prose with no test behind it, which this repo's CLAUDE.md asks for a
test or a bead on.

## Handoff

- **The forbidden direction has no executable assertion anywhere in the tree.** Everything
  green today is quantified over what `Hunt` returned. The cheap, high-value thing is a
  table test that plants secret-bearing files at known paths and asserts each **is** present
  in `found` - the inverse of `FuzzHuntNeverReportsAShieldedFile`. Rows of that test are
  already written and run (above). It cannot land green until U-1 and U-2 are fixed, so it
  belongs to those items: each should carry its own row as its regression test rather than
  the table landing as a standalone commit.
- **H-8 needs a pin, not a fix.** One test asserting that a DenyAll rule with `Dir:false`
  landing on a real directory is hidden by `shieldMount` too, named for the pairing, is
  what keeps credhunt's prune from silently becoming over-prune.
- **Corpus seeds** for `FuzzHuntNeverReportsAShieldedFile` once it grows the inverted
  assertion: a 0644 `.config/x/settings.json` holding a token assignment (U-1); a home-root
  symlink out of the home (U-2); `.linphonerc/secret.pem` (H-8's pairing).
- **fuzz-oracle handoff:** `FuzzHuntNeverReportsAShieldedFile` is a live example of the
  strong-oracle-pointed-the-wrong-way shape, worth a row in any future `fuzz-oracle` pass.
- Spikes were deleted after the run; their bodies are described in the cell notes in enough
  detail to rebuild each in a few lines.

---

# Phase 2 re-open pass

Added after the grid was walked, against the known-open list. Nothing here was used to
derive the dimensions above - that is the point of the staging.

## The reframing: silence is this package's systematic failure mode

`git log --oneline --since=1.year -- internal/credhunt cmd/credhunt` returns 41 commits.
**Eight of the fix commits are the same defect class**, each converting one silence into a
disclosure, one at a time:

| commit | the silence it closed |
|---|---|
| `e4d91a7` | an unwalkable home reported clean |
| `86a2ef7` | a home that is a symlink reported clean |
| `e270af2` | the scan root pruned as a store, reporting clean |
| `e55e90c` | a large file never sniffed, so its head was never read |
| `dbf260c` | the paths the scan could not read, uncounted |
| `afd60e9` | that count narrowed to only what the scan could not see |
| `1b223cb` | the VCS object-store prune, uncounted |
| `4cc59a2` | pruned and unreadable paths named rather than counted |

That is Phase 0's third signal - *repeated one-at-a-time fixes for the same underlying gap* -
and it is the strongest evidence in this document that the area warranted a grid. The
earlier "one dimension, linear flow" decline did not look at the history; had it, the
pattern was already eight commits deep.

**Which cell did each fix, and was the row carried?** None of the eight carried its row.
`4cc59a2` is the clearest: it built the `pruned` and `unreadable` channels and named their
contents individually - the right remedy - and then applied it to exactly two of the five
ways this scanner goes quiet. The other three (U-1's sniff gate, U-2's non-regular drop,
U-3's bounded read, all below) were left silent, and each has been silent since. A fix that
built the disclosure mechanism and then stopped at two call sites is precisely the shape
this technique exists to catch.

**U-3 is the third silence, and it is new - and it means axis A above was incomplete.**
*VERIFIED BY SPIKE.* A1 and A2 are both spelled "-> sniffed", which hides a sub-state:
*sniffed, but only as far as `MaxFileSize`*. Splitting A1/A2 by that would add a sixth row
and two more UNHANDLED cells. The grid is not rewritten here because the finding is the same
one either way and a renumbered table would invalidate the cell references above; recording
the omission instead, since a dimension found late is exactly what the Phase 1 rule about
collapsing the wrong axis is meant to surface.
`contentShapes` (`internal/credhunt/credhunt.go:312-316`) bounds the head read at
`MaxFileSize` and discloses the truncation nowhere. Planted a 0644 `~/.env` with ~11 KB of
filler and `aws_secret_access_key=...` after it, `MaxFileSize` 1 KB: `found=0 pruned=[]
unreadable=[]`. The same token inside the bound is reported (control passes). The read also
discards its error - `head, _ := io.ReadAll(...)` - and still returns `opened=true`, so a
file that opened and then failed mid-read is not in `unreadable` either. `cmd/credhunt`
runs with a 64 KB bound over shell and editor histories, which is the exact file class the
bound's own comment (`cmd/credhunt/main.go:26-29`) says grows past it.

Three silences with one mechanism between them makes the recommendation a package-level one
rather than three tickets: **every place this scanner declines to look needs a channel, and
the channels already exist.** `Hunt` returns `pruned` and `unreadable`, `run` prints each
path individually and refuses to fold them into a count
(`cmd/credhunt/main.go:150-157`). U-1, U-2 and U-3 are all "chose not to look", which is a
third concept the return signature does not yet have.

## bv2-cr6cs - can the existing `unreadable` channel carry U-2?

**Mechanically yes, semantically no, and the gap is one word wide.** *VERIFIED BY READING.*
The channel is a plain `[]string` on `Hunt`'s third return, appended at three sites
(`credhunt.go:167`, `:229`, `:236`) and printed per-path at `cmd/credhunt/main.go:156`.
Appending U-2's non-regular drops at `credhunt.go:222` is a two-line change and needs no new
plumbing at all.

What stops it is the contract, not the wiring: `Hunt`'s doc (`credhunt.go:139`) calls it
"the paths that could not be read", and `main.go` prints the literal word `unreadable`. A
symlink out of the home *can* be read - the scanner declined to follow it. Filing them under
`unreadable` would make the report say something false about every one of them, which in a
tool whose output a human reads to classify leads is its own defect.

So the cheap remedy is a **third channel with an honest name** (`skipped`, "a path the scan
saw and did not look into"), carrying U-2's non-regular entries and U-3's truncated reads,
printed the same way. That is strictly cheaper than it reads in the grid above, and it is
one change closing all three cells - which is the answer the systematic-silence reframing
predicts. cr6cs is the same family one layer over (an `Unreadable` arm nothing acts on) and
candidate 39 found it again in `gate/gate.go:201`; three independent sightings of "not
looked at is indistinguishable from not a secret" is a cross-cutting item, not three.

## bv2-lzcxk - the intersection with U-1, concretely

**Adjacent, not the same item, and the true intersection is narrower than it looks - but it
exists and neither bead names it.** *VERIFIED BY SPIKE.*

The non-expanding set, enumerated from `denylist.Home`: **70 `DenyAll` directory rules with
`ExpandLinks` false**, every one of them `HoldsPrivateData` - the `bulkStoreDirs` that
`denylist.go:115-117` deliberately leaves unexpanded because "every launch pays a recursive
walk of it". Mail spools, XMPP clients, browser profiles, and outside `.config` the wallets
and vaults: `/h/.ethereum`, `/h/.dashcore`, `/h/.1password`. **Zero `HoldsCredentials`
directory rules lack the flag**, so lzcxk's remainder is exactly the bulk-store class and
not the token-store class.

That matters for the intersection. A store in lzcxk's set is itself `DenyAll`, so credhunt
prunes it and is silent about it *correctly* (cell H-1). The gap lzcxk names is its **farm
target**, which carries no rule. So the question is whether those targets land in U-1's
blind spot, and the answer is: **only when the farm strips the leading dot and the name
carries no token.** Planted four targets, 0644, each holding `_authToken=<32 chars>`:

| planted farm target | reported? | why |
|---|---|---|
| `.local/share/chezmoi/private_dot_npmrc` | yes | `nameTokens` hit on "private" |
| `.local/share/chezmoi/dot_config/acme/private_settings.json` | yes | same |
| `dotfiles/npmrc` | yes | `nameSuffixes` hit on "rc" |
| `dotfiles/config/acme/settings.json` | **no** | no token, no suffix, 0644, below root |

The last row is the worst cell in this grid: **un-expanded by the deny-list AND un-sniffed
by credhunt**, so neither side sees it and neither bead currently names it. It is narrow -
chezmoi's own `private_` prefix rescues most of its output by accident, and a bare `stow`
farm keeps the dotfile names - but a farm laid out as plain `config/<tool>/<file>` defeats
both halves at once.

Recommendation: keep lzcxk and U-1 as separate items (one is deny-list coverage, the other
is scanner reach), and file the intersection row as its own seed against whichever lands
first, because closing either one alone leaves it open.

## bv2-agqg4 - the close reason

The Phase 0 section above states it plainly enough to stand as the bead's close reason; the
sentence to quote is *"credhunt alone is not a grid; credhunt x the applied shield set is."*
Sharpening it with what the re-open pass added: the bead's premise was right for a reason it
did not give. The second axis is what makes the grid decidable, **and** the eight-commit
silence pattern in the history is what makes it worth running - either alone would have been
a weaker case than the two together.

## Re-opened commits outside credhunt

- **`8fd4c1b` refactor(shield): share the walk bound with the git scan.** Cell: shield's
  `MaxWalkDepth` against `internal/linux`'s `maxGitdirDepth`. Row carried - the constant is
  read rather than repeated (`internal/shield/rules.go:19`), which is the shared-source
  fallback done right. **No credhunt equivalent exists**: credhunt's own bound is
  `maxFileSize` in `cmd/credhunt/main.go:26`, unshared and unreferenced by anything.
- **`e895fba` feat(doctor): report walk-truncated credential stores.** Cell: shield's
  expansion walk stopping short. Row NOT carried, and this is the sharpest confirmation of
  the reframing. `shield.Set` grew `truncatedStores` and `TruncatedStores()`
  (`internal/shield/rules.go:60`, `:176`) precisely so a walk that covered less than the
  store is disclosed rather than silent - the identical remedy this document asks for three
  times - and credhunt's own bounded read (U-3) got nothing. One package learned the lesson
  and the package next door, whose entire purpose is to not report a clean home falsely,
  did not.

## The H-8 pin - acceptance test body

H-8 is HANDLED by coincidence: credhunt ignores `r.Dir` because `Index.Covers` matches
exactly and the walk branches on `d.IsDir()`; `shieldMount` ignores it because bwrap aborts
on a tmpfs-over-file mount (`internal/linux/shields.go:715-724`). Same outcome, unrelated
reasons, nothing connecting them. The dismissal's safe assumption is *the run hides a
directory that a file-declared DenyAll rule lands on*, and this asserts it so the cell fails
if `shieldMount` ever starts honouring `r.Dir`:

```go
// TestFileRuleOnADirectoryIsHiddenBothWays pins the pairing credhunt's prune rests on.
// credhunt.go:180 prunes a directory on any DenyAll match without consulting r.Dir, which
// is only safe because shieldMount picks the mount from what is on disk. If that ever
// keys on r.Dir instead, the hunt goes silent about 128 paths the run leaves readable.
// ^ this last sentence is wrong; see the correction below the block.
func TestFileRuleOnADirectoryIsHiddenBothWays(t *testing.T) {
	dir := t.TempDir()
	r := denylist.Rule{Path: dir, Deny: denylist.DenyAll, Dir: false} // declared a FILE
	sb := sandbox{/* exists(dir)=true, isDir(dir)=true */}
	if got := shieldMount(r, sb); got[0] != "--tmpfs" {
		t.Fatalf("a file-declared DenyAll rule on a real directory mounted %v, not a tmpfs; "+
			"internal/credhunt prunes such a directory whole and is now silent about a readable tree", got)
	}
}
```

**Resolved differently, 2026-09-20 - do not add this test.** The assertion already exists.
`TestDenyAllShieldMatchesRealKind` (`internal/linux/shields_test.go`, the second block)
has always covered this cell: a file-declared `DenyAll` rule on a real directory must
return `--tmpfs`. Adding the function above would duplicate a live assertion one function
away. Measured: making `shieldMount` read `dir := r.Dir` alone turns exactly two tests red,
that one and `TestReportedShieldKindMatchesTheMount` - a direct guard, not collateral.

The `t.TempDir()` in the sketch above is decorative, which is what hid the duplication: the
body still hands `shieldMount` a constructed `sandbox`, so no real directory ever reaches
the code under test. The existing fake-fs test exercises the identical seam.

What was actually missing was the disclosure, not the assertion - the existing test named
only its own reason (bwrap aborts on a kind-mismatched mount) and said nothing about the
second consumer. Landed as a paragraph on that test's doc comment. No new test.

## Revised finding count

Four items, not three: **U-1** (sniff gate), **U-2/U-2b** (non-regular drop), **U-3**
(bounded read, found in this pass), **H-8's missing pin**. U-1/U-2/U-3 share one remedy - a
third disclosure channel - so they are one change and three regression rows, not three
independent fixes. Plus one seed against `bv2-lzcxk`: the farm target that strips the dot
and carries no token.
