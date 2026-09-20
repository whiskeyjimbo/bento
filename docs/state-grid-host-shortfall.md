# State grid: host-shortfall disclosure (validate's note) vs what the run refuses on

Area: `cmd/bento/validate.go` (`hostPosture`, `writeHostPosture`, `policyJSON.HostUnenforcedLayers`),
`enforce/run.go` (`RequiredLayers`, `Options.admit`, the pre-run refusals in `Run`,
`admitRunID`), `enforce/report.go` (`StateOf`, `Disclosure`, `shortfall`),
`cmd/bento/doctor.go` (`gatedShortfall`, the anchor gate).

Companion grid: `docs/state-grid-admission.md` already gridded admit vs postRunShortfall vs
doctor (49 cells, all resolved). This grid does NOT redo those cells. `b5dbe59` added a
THIRD answerer - validate's per-layer host-shortfall note - after that grid was written, so
this is the unwalked column: does validate's PREDICTION cover what the run will refuse on?

## Phase 0 - fit

**Fit: accepted, as a grid of its own, not a correction to the admission grid.** The new
answerer is not a fourth row in Grid A: it answers a different question (what the host falls
short on, flag-free) against a different input (an unfiltered `Probe` report, not the
`forLayers`-filtered one), and it is the only answerer that runs BEFORE any Options exist.
The existing grid's HANDLED/IMPOSSIBLE calls are inherited unchanged.

Signals: mirror triple (validate note / admit / doctor), enum x call sites (`enforce.Layer`
x 3 answerers), and a one-sided invariant.

**Invariant (restated).** For a policy `p` on a host whose probe is `r`:

> `hostPosture(r, p)` may NAME a layer the run then enforces or waives (over-warning is
> safe, and is explicitly the documented ceiling at validate.go:352-362). It must never be
> SILENT about a reason `bento run` will refuse to start on this host, and when it does
> name a layer it must not describe that layer less fully than the other frontends do.

Forbidden direction = silence, or a named-but-understated layer. That second clause is not
padding: a note that names `filesystem: degraded` and drops the paragraph saying the tier
has no mount namespace has technically not been silent, and has still left the reader
believing a guarantee they do not have.

`FuzzParseAppliedNeverOverClaims` (internal/linux/applied_fuzz_test.go:80) was read before
claiming any cell: it pins the severity floor on the PARSE side (a corrupted applied report
may worsen a layer, never buy one back). It says nothing about validate's prediction and
walks none of the cells below.

## Phase 1 - dimensions (from the code)

The nominated `Layer x answerer x state` cross product collapses hard, and the collapse is
the first finding:

- **State does not partition `hostPosture`.** validate.go:374-377 branches only on
  `state == Enforced`; Degraded and Unavailable take the identical path and print the
  identical shape. The state axis is 2-valued (Enforced / not), not 3.
- **Layer does not partition it either.** The loop is over
  `enforce.RequiredLayers(p, enforce.Options{})` with no per-layer branch - no tier check,
  no report-only check, no limits special case. Every layer in the set is treated alike.

What actually partitions behaviour is three small grids:

- **Grid V1** - layer membership: is the layer ever in `RequiredLayers(p, Options{})` for
  some `p` a validator can see? 8 cells.
- **Grid V2** - refusal sources: every way `bento run` refuses on this host, against whether
  validate's note can see it. 10 cells. This is the yield.
- **Grid V3** - fidelity of a named layer: what the note says about a layer it does name,
  against what the report holds. 5 cells.

23 cells total.

Every cell also carries a **reachability** reading, because two of the findings below need
a report the shipped Linux probe cannot emit: *live* (an operator meets it today on
linux/amd64) or *latent* (reachable only through another `Enforcer`, or a probe that
duplicates a layer entry). Latent is not dismissed - it is the coupling gap the skill warns
about - but it files behind live.

## Grid V1 - layer membership (can validate ever name this layer?)

`hostPosture` inherits the layer set from `requiredLayers` (run.go:465), which is the
anti-drift seam `RequiredLayers` was exported for.

| # | Layer | In RequiredLayers for some p? | Verdict |
|---|---|---|---|
| V1.1 | LayerFilesystem | always (run.go:466) | HANDLED - named whenever not Enforced |
| V1.2 | LayerNetwork | iff `len(p.Network)>0` or a gate (run.go:467) | HANDLED for the policy half; the gate half is V2.6 |
| V1.3 | LayerExec | iff `p.Exec != ExecAll` | HANDLED |
| V1.4 | LayerExecStrict | iff `p.Exec == ExecNoneStrict` | HANDLED - pinned by TestHostPostureNamesOnlyTheLayersTheManifestNeeds |
| V1.5 | LayerLimitsMemory | iff `p.Limits.Memory != ""` | HANDLED |
| V1.6 | LayerLimitsPIDs | iff `p.Limits.PIDs != 0` | HANDLED |
| V1.7 | LayerLimitsCPU | iff `p.Limits.CPU != ""` | HANDLED |
| V1.8 | LayerAutoExecReport | never (report-only, run.go:434) | IMPOSSIBLE, correctly - `ReportOnly()` derives from the same `requiredLayers`, so it cannot drift. Nothing requires it, nothing refuses on it. |

Zero mismatches. The shared table does its job: there is no layer the run gates on that
validate's loop cannot reach.

VERIFIED BY SPIKE: a maximal policy (`ExecNoneStrict`, one network rule, all three limits)
against a report marking all 8 constants Unavailable produced exactly 7 notes -
filesystem, network, exec-block, exec-strict, limits-memory, limits-pids, limits-cpu -
with auto-exec-report absent.

## Grid V2 - refusal sources vs the note (THE YIELD)

Every way a `bento run` on this host is refused before the target starts, against whether
`hostPosture` can see it. Rows are refusal sources, not layers, because that is what
partitions: a refusal keyed on a required layer's state is always covered by V1, and every
gap is a refusal keyed on something else.

| # | Refusal source | file:line | Does the note see it? | Verdict |
|---|---|---|---|---|
| V2.1 | `admit` default: core layer < Enforced | run.go:512 | yes - the layer is required and not Enforced | HANDLED |
| V2.2 | `admit` default: requested limit not enforced | run.go:520 | yes | HANDLED |
| V2.3 | `admit` strict: ANY required layer not enforced | run.go:498 | yes - the note names every non-Enforced required layer | HANDLED |
| V2.4 | `admit` allow-degraded: core layer Unavailable | run.go:504 | yes | HANDLED |
| V2.5 | `Run`: network Unavailable on a non-degraded host, **read from the UNFILTERED probe** | run.go:162 | **NO** for a zero-rule, gateless manifest | **WRONG (forbidden direction)** - below |
| V2.6 | `Run` degraded tier + `opts.NetworkGate` | run.go:200 | no gate exists at validate time (`Options{}`, validate.go:373) | HANDLED for `bento run`, which sets no gate (cmd/bento/run.go:156-162). Embedder-only; outside validate's reach by construction. |
| V2.7 | `Run` degraded tier + `p.Network` / `opts.DenyPaths` | run.go:206, run.go:192 | partially - filesystem Degraded IS named, but the note's prose says "--allow-degraded accepts some" and here no posture runs it | **WRONG (understatement)** - below |
| V2.8 | `admitRunID`: run id with `p.Limits.IsZero()` | run.go:608 | no - no layer is involved at all | UNHANDLED but out of model: a mistake in the command line, not a host shortfall, and validate has no flags. Recorded, not filed. |
| V2.9 | `denylist.HomeAnchors()` failure - shields cannot be anchored | doctor.go:57; refused in the backend before any tier is chosen | **NO** - "no layer status carries that: newSandbox fails before any tier is chosen, so Probe never sees it" (doctor.go:52-54) | **UNHANDLED (forbidden direction), live** - doctor discloses it, validate does not |
| V2.10 | `backend.New()` fails - no usable backend on this host | validate.go:76-80 swallows the error; cmd/bento/run.go:135 refuses on it | **NO**, and by design: "Silent where the answer cannot be had rather than failing: validate is documented to run on a host bento cannot run anything on" | HANDLED by documented design - but it is the most complete silence in the grid, so it is worth saying out loud that the ONE case validate deliberately says nothing about is also the one where nothing runs at all. A one-line "no backend here; `bento run` will refuse" would cost nothing and is not a verdict. Recorded, low priority. |

### V2.5 - a silent host that refuses every run

`Run` reads `probed.StateOf(LayerNetwork)` on the UNFILTERED probe (run.go:162), precisely
so a zero-rule manifest cannot slip past on the grounds that it never asked for egress.
`hostPosture` reads the FILTERED set. So on an enforcer whose probe pairs an Enforced
filesystem with an Unavailable network, `bento validate` prints nothing and `bento run`
refuses under every posture, `--allow-degraded` included.

`docs/state-grid-admission.md` cell C2 recorded this shape from the admission side and
resolved it with the Linux probe's coupling (`networkLayer` and `filesystemLayer` turn on
the same `namespaceProbe`, probe.go:244/252, pinned by
`TestAnUnavailableNetworkLayerNeverLeavesFilesystemEnforced`). That coupling holds here
too, so on the Linux backend the note is not empty - it says `filesystem: degraded`.

It is still the forbidden direction, for two reasons the admission grid did not have to
weigh: (a) the note's contract is per-layer disclosure and it names the wrong layer - a
reader told the filesystem is degraded is not told the run is refused for want of a netns;
(b) `Run` deliberately does not rest on that coupling ("that is an invariant of one
backend's probe, and Run takes any Enforcer", run.go:152-156) while `hostPosture` silently
does. The asymmetry is the defect: the argument that made run.go read the unfiltered probe
applies verbatim to the validator and was not carried across.

**Reachability: latent.** The spike below had to hand-build a report the shipped Linux
probe cannot emit - `filesystemLayer` and `networkLayer` read the same `namespaceProbe`
(probe.go:244/252). So no operator meets this today; it arrives with a second Enforcer, and
it is the coupling gap rather than a live defect. It files behind V2.9 and V2.7.

VERIFIED BY SPIKE. With a fake Enforcer whose probe is `{filesystem Enforced, network
Unavailable}` and a bare policy:

    enforce.Run  -> refusing to run: this host has no network namespace to fence egress
                    into, and only the degraded tier substitutes a seccomp egress block
    hostPosture  -> []

### V2.7 - "depends on the flags it is given", when it does not

`writeHostPosture` (validate.go:395-397) prints, verbatim:

    Whether that refuses the run depends on the flags it is given:
    --strict refuses any shortfall, --allow-degraded accepts some.

For a manifest with `network:` rules on a host whose filesystem is Degraded that is false:
run.go:206 refuses under every posture, `--allow-degraded` included, because the degraded
tier has no netns to run the proxy in. The reader is sent to a flag that cannot help. Same
shape as the anchor message doctor already got right ("--allow-degraded does not help",
doctor.go:95).

The layer IS named, so this is the weaker half of the invariant - understatement, not
silence - but it is decidable from `p` and the probe alone: `len(p.Network) > 0 &&
report.StateOf(LayerFilesystem) == Degraded` is the whole predicate.

VERIFIED BY SPIKE. Degraded-filesystem probe, `AllowDegraded: true`, one network rule:

    enforce.Run  -> refusing to run: network rules cannot be honored by the degraded tier:
                    it has no network namespace to run the egress proxy in
    hostPosture  -> ["filesystem: degraded - no userns"]   (under the header above)

### V2.9 - the anchor refusal validate cannot see

doctor asks `denylist.HomeAnchors()` explicitly BECAUSE no layer carries it, and prints
"Runs are refused here until the shields can be anchored. --allow-degraded does not help"
(doctor.go:93-95). `hostPosture` asks only the probe, so `bento validate` on that same host
is silent and `runnable:` stays true. Third answerer, third answer.

VERIFIED BY READING (doctor.go:52-57 and :93-96 against validate.go:76-80). The host state
that makes `HomeAnchors` fail is UNSPIKEABLE HERE: it needs a passwd/HOME fixture the
validate command does not take.

## Grid V3 - fidelity of a layer the note DOES name

| # | What the report holds | What the note prints | Verdict |
|---|---|---|---|
| V3.1 | `State` | `fmt.Sprintf("%s: %s", l, state)`, from `StateOf` (most-severe-wins) | HANDLED |
| V3.2 | `Reason` | appended, from `slices.IndexFunc` - **first match** | **WRONG** with duplicate entries - below |
| V3.3 | `Consequences` | **dropped entirely** | **WRONG (forbidden direction)** - below |
| V3.4 | layer absent from the report | `StateOf` folds absence into Unavailable, no reason | HANDLED, and deliberately (validate.go:378-380) |
| V3.5 | Enforced layer carrying `Consequences` (exec-block's execveat seam, probe.go:158) | skipped by the `state == Enforced` continue | HANDLED - the note is about shortfall; doctor is the frontend that prints a standing seam |

### V3.3 - the note drops half of every degraded filesystem disclosure

`enforce.LayerStatus.Disclosure()` exists for exactly this (report.go:114-119):

> Disclosure is everything the layer has to say about itself, **for a frontend that
> describes it in full rather than pointing at one that does**. Every such frontend uses
> this rather than joining the halves itself.

The contract is conditional, so state the gap precisely rather than as a flat violation:
validate's note does **neither**. It does not print `Consequences`, and it does not point
the reader at the frontend that does. Every other frontend picks one side -
`enforce/run.go:692` and `:701` (a refusal, which prints the diagnosis and sends the reader
on), `cmd/bento/render.go:584` (doctor's per-layer notes, "the one place the two halves have
to appear together"), `:2162` and `:2179`. `hostPosture` (validate.go:381-383) joins the
halves itself and prints only `Reason`.

**Severity: deferred disclosure, not lost disclosure.** `render.go:2179` is the run-output
path, and it deliberately prints `Disclosure()` whole - "this path is a run that is
proceeding under --allow-degraded, so the consequences are what the user is about to
accept". So a reader who validates and then runs does get the paragraph, at `bento run`
rather than at `bento validate`. That is the thing the note was added to spare them, and
validate is the surface a reviewer reads without a host to run on - but nobody ends up
unaware, which drops this below V2.9 and V2.7.

Not hypothetical. The degraded filesystem layer is the commonest shortfall on a real host,
and it is the ONE layer whose disclosure deliberately splits (probe.go:232-236). Its
`Consequences` is the paragraph naming no mount namespace, no PID namespace, no network
namespace and the Landlock metadata gap (`internal/linux/probe.go:280-295`, pinned by
`TestDegradedConsequencesDiscloseEveryResidualRight` and
`TestFilesystemLayerSplitsConsequencesFromTheRemedy`, probe_test.go:372 and :75).
`bento validate` prints none of it.

The comment at report.go:114 is exactly the "cross-file prose needs a test or a bead" shape
this repo's CLAUDE.md names: it asserts a property about every frontend, nothing enforces
it, and a frontend added later broke it without anything failing to compile.

VERIFIED BY SPIKE. Status `{filesystem, Degraded, Reason:"rrr", Consequences:"ccc"}`:

    hostPosture          -> ["filesystem: degraded - rrr"]
    LayerStatus.Disclosure() -> "rrr ccc"

### V3.2 - state from one entry, reason from another

`Report.Add` appends without deduplicating (report.go:135); only `Set`/`SetStatus` replace.
`StateOf` -> `probedState` (report.go:196) takes the most severe among duplicates,
deliberately, "so this agrees with shortfall/Degradations". The reason lookup on the very
next line of `hostPosture` takes the first match instead. A report whose Enforced entry
precedes its Degraded one prints the severe state beside the benign entry's empty reason,
losing the account of what is broken.

Using `Disclosure()` does not fix this on its own; the fix is to select the status once
(the most-severe entry) and render it whole, which closes V3.2 and V3.3 together.

**Reachability: latent.** `internal/linux/Probe` emits each layer exactly once
(probe.go:73, :91, :93-95, :116-118, :119 - the two loops iterate distinct layers), so a
duplicate needs a probe bug or another Enforcer. `probedState`'s most-severe-wins rule
exists precisely because duplicates are not ruled out by type, and `hostPosture` is the one
reader that did not follow it - that is the finding, and it costs one line to close.

VERIFIED BY SPIKE. Report `Add(filesystem, Enforced, "")` then
`Add(filesystem, Degraded, "why it is broken")`:

    hostPosture -> ["filesystem: degraded"]      (reason lost entirely)

## Phase 2 re-open pass (second round - CORRECTIONS BELOW SUPERSEDE TWO CELLS ABOVE)

The first round re-opened only `b5dbe59`. A second round over the rest of the area's
history **retracts one WRONG cell and narrows another**, because two of my verdicts were
read off `b5dbe59`'s diff rather than off the current file. That is the re-open rule
working; the corrected tables are here and the sections above are left as written so the
retraction is visible rather than tidied away.

### 7d9b549 `fix(validate): word the host note as a note` - closes V2.7, halves V3.3

This commit landed twelve minutes after `b5dbe59` and rewrote both things I faulted.

- **V2.7 is RETRACTED - the cell is HANDLED.** The line I quoted
  ("`--strict refuses any shortfall, --allow-degraded accepts some`") no longer exists.
  The current text (validate.go:398-400) is "*Whether that refuses the run is `bento
  run`'s decision: some of these refuse under every flag, some run under none, and some
  turn on --strict or --allow-degraded*", which is true of the degraded-tier network
  refusal and of every other row in Grid V2. **VERIFIED BY READING** the current
  `writeHostPosture`; my spike's run-side half still stands, but it no longer contradicts
  anything the command prints.
- **V3.3 is NARROWED to the `--json` surface.** The same commit added
  "`bento doctor` reports this host in full" - which is exactly the second half of
  report.go:114's contract ("*rather than pointing at one that does*"). The **human**
  surface therefore satisfies the contract and V3.3 does not apply to it.
  `policyJSON.HostUnenforcedLayers` (validate.go:667-671) does not: it is the raw `notes`
  slice, so a machine consumer gets `Reason` alone, with no `Consequences` and no pointer
  to the surface that has them. **That is the un-carried half of this commit's row** - the
  wording fix reached the writer and not the JSON field beside it.
- It also introduced `probeHost` (validate.go:409-415), a package-level `var` seam, which
  moves my **V2.10** cite: the `backend.New()` call is no longer inline at validate.go:76-80.
  The cell's verdict is unchanged.

### b5dbe59 - membership inherited in full, disclosure not at all

The converse check the coordinator asked for: it inherited **membership** completely (via
the `RequiredLayers` it exported in the same commit - that is why Grid V1 is clean) and
inherited the **reason/consequence surface** not at all. `hostPosture`'s reason lookup and
the absence of `Consequences` are present in that commit's diff in exactly the shape they
have today. So **V3.2 and the JSON half of V3.3 originate in `b5dbe59` and are not later
regressions.** VERIFIED BY READING (`git show b5dbe59 -- cmd/bento/validate.go`).

### fba3fa7 `test(bento): probe the real host in doctor parity`

Touches `cmd/bento/output_parity_test.go` only. No cell moves. It is worth noting against
V3.3 that `writeHostPosture` is *exempt* from the parity table by its own row ("the fixture
host enforces every layer, so the writer prints nothing here"), so the parity machinery that
catches a fact present on one surface and missing on the other is switched off for precisely
the writer whose two surfaces now disagree.

### e895fba `feat(doctor): report walk-truncated credential stores` - strengthens V2.9

This is V2.9's shape again, and it makes it a trend rather than a one-off. doctor's JSON now
carries five host facts that no `LayerStatus` holds: `anchors`, `unshieldable_relocations`,
`nested_anchors`, `relocated_shields` and now `truncated_stores` (doctor.go:156-160,
:188-192). validate carries exactly one field, `host_unenforced_layers`, and none of these.
Every time doctor learns a host fact outside the layer model, the gap between the two
answerers widens and nothing notices. VERIFIED BY READING.

### b) The V2.5 coupling gap - nothing would fail to compile

Confirmed explicitly, as the skill asks. The only thing making V2.5 unreachable is that
`filesystemLayer` and `networkLayer` read the same `namespaceProbe` value
(internal/linux/probe.go:244, :252). Change `networkLayer` to report `Enforced` on a host
with no userns and **every package still compiles**: `hostPosture` never names
`LayerNetwork` for a zero-rule manifest, so there is no reference to break. The coupling is
held by one test's name (`TestAnUnavailableNetworkLayerNeverLeavesFilesystemEnforced`) and
by prose in three files. `enforce/run.go:152-156` says in so many words that it will not
rest on it; `hostPosture` rests on it without saying so. That is what makes a latent cell
worth filing. VERIFIED BY READING.

## Open decisions this grid bears on

**bv2-dnda5** (unsampled scope as its own State) - **the grid gives this evidence it
currently lacks, and points one way.** The cost of a new `State` constant is not spread
across the frontends: `hostPosture` is state-blind (it branches only on
`state == Enforced`, validate.go:374-377), and doctor renders whatever `String()` returns,
so **neither answerer needs an edit for a new state**. The whole cost lands in `enforce`'s
ordered comparisons - `probedState`'s `l.State > state`, `shortfall`'s `l.State >= atLeast`,
and the two call sites that pass `Degraded` and `Unavailable` as the bar (run.go:504, :512).
So the decision is a question about *where in the severity order* an unsampled reading sits
and nothing else, which is a much smaller decision than it currently reads as. My V3.2 and
V2.9 are the same shape one layer up - V3.2 is two entries folded into one answer with the
halves taken from different entries, V2.9 is a fact no state can carry at all - and both say
the same thing: **the failure mode is a can't-tell folded into a definite answer, and the
fix that has worked here each time is to keep the two apart at the source** (`probedState`
returning `(State, bool)` is the precedent, report.go:186-196).

**bv2-gsxl5** (SetTierPreset seaming effectiveABI) - **buys nothing for the unspikeable
cells in this grid.** V2.9 is a refusal that never reaches a `Report` at all
(`newSandbox` fails before a tier is chosen), so no tier or ABI seam can drive it; what it
needs is a seam on `denylist.HomeAnchors` in validate, not on the probe. And at the command
level the seam already exists: `probeHost` (validate.go:409) is an injectable `var`, so any
layer/state arm of this grid is spikeable today without `SetTierPreset`.

**bv2-9rqim** (default exec none on arm64) - orthogonal, confirmed. It changes which
`Layer` a policy requires by default, and Grid V1 derives membership from `RequiredLayers`
rather than restating it, so every cell holds unchanged whatever that decision is.

## Phase 2 re-open pass (first round)

`b5dbe59` is the only commit in this area. Re-opened cell by cell:

- It correctly inherited the layer SET from enforce (`RequiredLayers`, exported in the same
  commit). Grid V1 is clean because of that decision, and the drift the commit message warns
  about does not exist.
- It did not inherit the layer's DISCLOSURE (V3.3) or the unfiltered-probe reading (V2.5).
  Both are one-line facts in `enforce`/`internal/linux` that the new answerer re-derived and
  got wrong in the silent direction - the same class of gap the commit was written to close,
  one level down.
- `docs/state-grid-admission.md` Grid B's caveat ("Doctor does not gate on network; it
  relies on the Linux probe tying network Unavailable to filesystem non-enforced") was
  carried to doctor and not to validate. That is V2.5.

The tracker was deliberately not consulted during Phase 1, per the skill's isolation rule.

## Summary

**Revised after the second re-open round** (see the corrections section): 23 cells,
**17 HANDLED, 1 IMPOSSIBLE, 5 WRONG/UNHANDLED** (V2.5, V2.8, V2.9, V3.2, V3.3-json).
V2.7 is retracted - `7d9b549` had already fixed it - and V3.3 applies to the `--json`
surface only, because the same commit gave the human writer its pointer to doctor.

Ranked by reachability first, then by how far the cell falls in the forbidden direction:

**Live on this host today**

1. **V2.9** - silent on the anchor refusal doctor discloses. Nothing runs on that host and
   validate says nothing at all; `runnable:` stays true. `cmd/bento/validate.go:76-80` vs
   `cmd/bento/doctor.go:57`. VERIFIED BY READING; UNSPIKEABLE HERE.
2. **V3.3 (`--json` half only)** - `policyJSON.HostUnenforcedLayers`
   (`cmd/bento/validate.go:667-671`) carries `Reason` alone: no `Consequences`, and none of
   the "`bento doctor` reports this host in full" pointer the human writer got in
   `7d9b549`. A machine consumer gets the truncated half of every degraded-filesystem
   disclosure. VERIFIED BY SPIKE (`hostPosture` -> `["filesystem: degraded - rrr"]` while
   `Disclosure()` -> `"rrr ccc"`; the JSON field is that slice verbatim).
   ~~V2.7~~ **RETRACTED** - already fixed by `7d9b549` before this review began.

**Latent - needs another Enforcer or a probe bug**

4. **V2.5** - silent on the run.go:162 network refusal for a zero-rule manifest, resting on
   a one-backend coupling `Run` itself refuses to rest on. `cmd/bento/validate.go:373` vs
   `enforce/run.go:162`. VERIFIED BY SPIKE; unreachable with the shipped Linux probe.
5. **V3.2** - state and reason read from different entries of a duplicated layer, against
   `probedState`'s deliberate most-severe rule. `cmd/bento/validate.go:381`.
   VERIFIED BY SPIKE; needs a duplicating probe.

**Out of model, recorded not filed**

V2.6 (a gate is embedder-only), V2.8 (a run id with no limits is a command-line mistake,
not a host fact), V2.10 (no backend at all - deliberate silence, worth one line but not a
defect), V3.5 (Enforced-with-consequences is doctor's job).

## Proposed exhaustive test

Grid V1 is small, finite and pure: `TestEveryRequirableLayerCanReachTheHostPostureNote` -
loop every `enforce.Layer` constant, build the policy that requires it, assert `hostPosture`
names it when the report is not Enforced, and reuse the missing-constant guard from
`TestARequirableLayerIsNeverReportOnly` so a new layer forces an edit. Grid V3 is four
assertions over one helper. Grid V2 stays prose: its rows are refusal sources in another
package and V2.9 needs a host fixture.

### Landed

`TestEveryLayerFrontendDisclosesOrPointsAtOneThatDoes`
(`cmd/bento/disclosure_test.go`) is the table report.go:114 has been asking for since it
was written: a row per frontend surface - doctor (its table and summary together, since
they are one invocation), the run's degradation notice, validate's host note - each given a
Degraded filesystem status carrying both halves, each required to print the consequences OR
name `bento doctor`. Whitespace is collapsed before matching because every one of these
wraps to the terminal width.

Proved it detects the defect rather than the code: deleting "`bento doctor`" from
`writeHostPosture` turns the validate row red with the full output attached, and restoring
it turns it green. VERIFIED BY EXECUTION.

It does NOT cover the `--json` surface, which is the one still failing the contract
(V3.3-json above). Adding that row is the acceptance test for that cell's fix, not
something to land red now.

`TestTheHostNoteReadsOneLayerEntryNotTwo` was written for V3.2 and deliberately **not
landed**: it failed then, and V3.2 was a cell to file rather than a fix to smuggle in under a
review. **Now landed** (`cmd/bento/validate_test.go`), green, with V3.2 closed: `hostPosture`
selects the status once through the new `enforce.Report.StatusOf` - the same most-severe
entry `probedState` reads - and both surfaces render that one entry. This note claimed the
test body was written out in the V3.2 section above; it never was, so the landed body was
written from that section's spike instead.
