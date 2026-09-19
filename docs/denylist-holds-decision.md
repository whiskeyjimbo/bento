# bv2-h7k3b: what `denylist.Holds` should mean

Evidence for one sitting. Worked from commit `09ddde4f6f41bfbc14799888a2fcb8e231c3ca1f`
(branch `docs/state-grids`, one commit ahead of `origin/docs/state-grids` = `a46dee2`).
`git checkout docs/state-grids` was refused in the worktree because the main checkout
holds that branch; fast-forwarded to the same SHA instead and confirmed with
`git rev-parse HEAD`. Every claim below is stamped. Spikes were run in
`internal/shield/zzspike_test.go` and deleted afterwards.

Nothing here changes semantics. No code was modified.

---

## 1. What `Holds` actually decides today

**It decides whether a store's symlinks expand.** VERIFIED BY SPIKE.

`internal/shield/rules.go:231-247`, `Set.credentialLinks`:

```go
	switch r.Holds {
	case denylist.HoldsCredentials, denylist.HoldsHistory, denylist.HoldsPersistence:
		out = append(out, s.linksUnder(r, r.Path, 0)...)
	case denylist.HoldsUnknown, denylist.HoldsPrivateData, denylist.HoldsServices:
		// No second spelling to chase: these buckets are directories of data and
		// sockets rather than the credential stores tools symlink into.
	}
```

The output is not advisory. `rules.go:107-120` puts it in `Set.links`, `Set.builtin` and
`Set.rules`, so it changes what bwrap binds, what a grant is refused over, and what the
alias scans walk (`Set.CredentialLinks` at `rules.go:172`, documented at `rules.go:157-162`
as an input to the alias scan). VERIFIED BY READING.

### What the doc says

`internal/denylist/denylist.go:122-126`:

> `Holds` names what a shielded path contains. The deny rules are all enforced the same
> way, so this exists purely for the sentence a reviewer reads while deciding whether to
> approve a grant that lifts the shield [...]

and the field, `denylist.go:103-106`:

> `Holds` is what the path contains, for the callouts that tell a reviewer what lifting
> the shield exposes. Set on DenyAll rules only [...]

"The deny rules are all enforced the same way" and "exists purely for the sentence" are
both false at HEAD: `credentialLinks` is enforcement, and it reads only `Holds`. The
contradiction the bead reports **still stands**. VERIFIED BY SPIKE (A, below).

Precision the bead overstated: the hard prohibition *"Diagnostic only. Nothing about how a
rule is enforced may read it"* (`denylist.go:118-119`) is on the **`Source`** field, not on
`Holds`. `Holds`'s own words are the softer "exists purely for the sentence". Still a
contradiction; the adjacent `Source` ban is the precedent this field was written against,
not a rule `Holds` itself states. VERIFIED BY READING.

### Spike A - the asymmetry, reproduced at HEAD

Temp home; `.ssh`, `.thunderbird` and `.config/gajim` each a real directory containing one
symlink to a file under `~/dotfiles`. Identical shape; only `Holds` differs.

```
SPIKE A .ssh (HoldsCredentials)          expanded=true  readGrantVerdict=1
SPIKE A .thunderbird (HoldsPrivateData)  expanded=false readGrantVerdict=0
SPIKE A .config/gajim (HoldsPrivateData) expanded=false readGrantVerdict=0
```

`0 = shield.Honored`, `1 = shield.InsideShield` (`internal/shield/verdict.go:19-24`).
VERIFIED BY SPIKE.

### Spike C - the inverted dismissal

"The farm target is covered anyway" is the thing a dismissal would take for granted.
Asserted directly:

```
SPIKE C read grant on <home>/dotfiles/prefs.js -> verdict=0 (Honored) rule="" holds=unknown
SPIKE C control read on <home>/dotfiles/id_ed25519 -> verdict=1 (InsideShield) rule=<that path>
```

A read grant naming the farm path of a `HoldsPrivateData` store's link is **fully honored**
- no rule, no warning, no opt-in sentence. The credential control is refused. The exposure
the bead's NOTES asserts is real. VERIFIED BY SPIKE.

### Spike B - the scale of it

Census of the assembled built-in set (`Set.Builtin()`), DenyAll rules by bucket:

```
bucket=credentials    denyAllRules= 169 expansionEligible= 169
bucket=history        denyAllRules=  34 expansionEligible=  34
bucket=persistence    denyAllRules=  41 expansionEligible=  41
bucket=private-data   denyAllRules= 103 expansionEligible=   0
bucket=services       denyAllRules=   4 expansionEligible=   0
DenyAll rules with HoldsUnknown: 0 []
```

107 DenyAll stores get no link expansion. 25 of the `bulkStoreDirs` entries are under
`~/.config` - precisely the tree stow, chezmoi and yadm manage wholesale - and their own
comments say what they hold: `.config/gajim` "saved account passwords", `.config/psi`
"account passwords and OTR keys", `.config/Mumble` "client certificate INCLUDING its
private key", `.config/kdeconnect` "device pairing RSA key". VERIFIED BY SPIKE (counts) and
BY READING (`denylist.go:2437-2600`).

---

## 2. `HoldsUnknown` per consumer: is unasked distinguishable from clean?

The headline result reframes this question. **`HoldsUnknown` is unreachable on any
expansion-eligible rule today.** Two independent reasons, both executed:

- Zero DenyAll built-in rules carry `HoldsUnknown` (Spike B). A test already enforces this:
  `internal/denylist/denylist_test.go:2084` `TestDenyAllRulesAreClassified` fails on any
  DenyAll rule left unclassified, relocations included. VERIFIED BY SPIKE + BY READING.
- Caller-supplied denies never reach the expansion at all. `rules.go:107` computes
  `links` from `base` only; `extraDeny` is appended afterwards at `:113-124`. Asserted
  both ways - Spike E:

```
SPIKE E caller DenyAll dir rule: expansionRan=false (CredentialLinks=0)
SPIKE E farm target <home>/dotfiles/token verdict=0 (Honored)
SPIKE E store itself verdict=2 (InsideCallerShield) rule=<home>/vault holds="unknown" noun="always-shielded path"
SPIKE E caller rule w/ HoldsCredentials: expansionRan=false
```

VERIFIED BY SPIKE. So the bead's stated mechanism - "a DenyAll directory rule added without
a classification silently loses its link expansion" - is a **latent hazard for a future
table entry**, not a live path. The live finding is the 107 classified-but-excluded stores.

Per consumer:

| Consumer | Reads `Holds` how | Unasked vs clean |
|---|---|---|
| **Shield rules** (`shield/rules.go:237`) | the switch above | Indistinguishable in principle - `HoldsUnknown` sits in the no-expansion arm beside two deliberate exclusions - but unreachable today (above). UNVERIFIED that it stays so under a future table edit; the `denylist_test.go` guard is the only thing holding it. |
| **Profiler clamp** (`cmd/bento/clamp.go:45-58`) | `drop()` returns `(r.Holds, bool)` | **Distinguishable, via the bool, not the value.** `HoldsUnknown` is also the sentinel returned alongside `ok=false` (`clamp.go:52`), so the value alone conflates "not shielded" with "shielded, unclassified". Only `dropped` entries carry a meaningful `Holds`, and for a caller deny that value is genuinely `HoldsUnknown` -> "always-shielded path". VERIFIED BY READING + SPIKE E. |
| **Parity audit** (`internal/denylist/audit`) | **does not read `Holds` at all** | N/A. Grep over the package: no `.Holds` reference. VERIFIED BY EXECUTION (grep). |
| **Credential hunt** (`internal/credhunt`) | **does not read `Holds` at all** | N/A. Same grep. It rediscovers credential shapes by content signal, independently of the bucket. VERIFIED BY EXECUTION. |
| **Callout prose** (`validate.go:775`, `approve.go:299`, `profile.go:1262`) | `Noun()` / `Exposure()` / `Code()` | Not distinguishable, **by design**: `HoldsUnknown` renders "always-shielded path" / "read what bento shields there", which is true of every shielded path. Working as documented. VERIFIED BY SPIKE D. |
| **Enforce boundary** (`enforce.ShieldedGrant.Holds`, string) | `Code()` / `HoldsByCode` | Not distinguishable, and lossy in a second way: `HoldsByCode("nonsense") == HoldsByCode("unknown") == HoldsUnknown`. A garbled code from a backend and a genuine unclassified rule read identically to a frontend. VERIFIED BY SPIKE D. |

---

## 3. The options

### (a) Keep the coupling; restate `Holds`'s doc as enforcement-bearing

Rewrite `denylist.go:122-126` to say that the bucket decides symlink expansion and what a
wrong classification costs; leave `credentialLinks` alone.

- **Breaks:** nothing at runtime. Behaviour byte-identical.
- **Tests that change:** none. `TestDenyAllRulesAreClassified` is already the guard and
  gains a reason in its comment.
- **Symlink expansion:** unchanged - the 107 `private-data`/`services` stores stay
  unexpanded, and Spike C's honored farm grant becomes documented behaviour rather than a
  defect.
- **Cost:** the `~/.config` exposure is then intended. That is a policy call this option
  makes silently by accepting the status quo, and the bead's NOTES argue it is wrong.

### (b) Decouple: an explicit per-rule field gates expansion; `Holds` goes back to prose

Add a `Rule` field (e.g. `ExpandLinks bool`), gate `credentialLinks` on it, and initialise
it in the `dirGroups` tables to exactly today's set (`credentials`, `history`,
`persistence`) so the first commit is a behaviour-preserving refactor. A follow-up bead then
sets it on the credential-bearing `~/.config` entries.

- **Breaks:** nothing, if initialised to reproduce today. Every rule-constructing site in
  `denylist.go` (the `dirGroups`/relocation tables, ~14 literal sites plus the group
  loops) must be swept - "finish the thought".
- **Tests that change:** none need to change for the behaviour-preserving step; the
  `internal/shieldcorpus` farm cases (`shieldcorpus.go:159-200, 273`) and
  `internal/shield/links_test.go` keep passing unchanged, which is the proof the step was
  behaviour-preserving. A new test pinning "the flag, not the bucket, gates expansion" is
  what makes it stick. The follow-up widening step changes `internal/shieldcorpus` and
  `cmd/bento/profile_test.go` expectations for whichever stores gain expansion.
- **Symlink expansion:** unchanged at step one; independently widenable at step two
  without relabelling a mail spool as a credential store.

### (c) Widen: expand links under every DenyAll directory rule

Delete the switch.

- **Breaks:** the price is already written down at `denylist.go:2426-2431` -
  `bulkStoreDirs` are "far too many files to enumerate on every launch" and "routinely
  hardlinked by the tools that manage them (mail sync deduplicates identical messages),
  which would trip the alias scan on a message rather than a credential". Adding 107 stores
  including mail spools and browser profiles to a per-launch recursive walk is a startup
  cost and an alias-scan false-positive source. UNVERIFIED how large - no benchmark was run;
  measuring it is the gate on this option.
- **Tests that change:** `internal/shield/links_test.go` gains cases; `internal/shieldcorpus`
  and `internal/linux/alias_test.go` expectations shift for bulk stores; the `credhunt`
  scale test (`hunt_scale_test.go`) is where a walk-cost regression would show.
- **Symlink expansion:** everywhere, including `/run` and `XDG_RUNTIME_DIR`
  (`HoldsServices`), where it buys nothing.

### Recommendation: **(b)**, in two commits

Take (b) with the flag initialised to today's exact behaviour. It is the only option that
satisfies "do not change semantics" in the same commit that makes the invariant statable,
and it is the only one that can later cover the farm-managed `~/.config` stores without
either relabelling a mail spool as a credential store or declaring Spike C's honored farm
grant intended (which (a) does). The bead's own NOTES reach the same answer from the
`.config/gajim` evidence; Spike C executes it.

The step-two widening is a separate decision on separate evidence and should be its own
bead. Settling this one does not require taking it.

---

## 4. What each option unblocks for a grid

- **(a):** *Every DenyAll directory rule whose `Holds` is credentials, history or
  persistence has its in-home symlink targets shielded at their own paths, and no other
  rule does.* Decidable per cell from the rule alone.
- **(b):** *Symlink expansion is a function of one declared per-rule field and of nothing
  else; `Holds` affects only prose.* Two independent grid dimensions instead of one
  overloaded one - the bucket axis becomes purely about callout wording, and the expansion
  axis becomes a boolean with a stated rationale per rule.
- **(c):** *Every DenyAll directory rule expands its in-home symlink targets.* The
  simplest invariant, and the one whose cells are all the same - but it moves the open
  question to the alias scan's hardlink behaviour, which is where the cost lands.

---

## Separate defects (independent of this decision)

1. **`HoldsByCode` collapses a garbled code and a genuine unknown.**
   `denylist.go:HoldsByCode` returns `HoldsUnknown` for any unrecognised string, so a
   frontend cannot tell a backend that sent nonsense from one that sent a real
   unclassified rule across the `enforce` boundary. Wrong under all three readings; the
   doc says "an unrecognized code reads as HoldsUnknown, whose wording is true of every
   shielded path", which is a defensible wording answer but not a diagnosability one.
   VERIFIED BY SPIKE D. Low severity - prose-only surface.

2. **Checked and clean, recorded so nobody re-derives it:** no non-DenyAll rule carries a
   bucket, so `Rule.Holds`'s "Set on DenyAll rules only" holds at HEAD.
   `SPIKE F non-DenyAll rules carrying a bucket: 0 []`. VERIFIED BY SPIKE.

3. **Not a defect, but load-bearing and undocumented at the call site:** caller-supplied
   denies never reach `credentialLinks` (Spike E). `rules.go:110-112` explains why the
   expansion derives from the built-ins ("the two sets are the same set"), which is the
   reason, but nothing states the consequence: an embedder's DenyAll on a credential
   directory gets no link expansion even if it classifies it. Worth a sentence.
