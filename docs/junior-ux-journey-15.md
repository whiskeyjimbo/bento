# Bento UX Journey — Junior Engineer, Round 15

Picking up after `junior-ux-journey-14.md`. Fresh `/tmp/jr-journey15`
workspace, same three scripts:

- `list_releases.py` — `urllib.request` to api.github.com, writes JSON
  to `$OUT` (default `./releases.json`). Repo via `$REPO`, count via
  `$COUNT`.
- `summarize.sh` — `set -euo pipefail`; reads `$OUT`, shells out to
  `python3 -c` and `date`; appends a row to `$SUMMARY` (default
  `./summary.txt`).
- `ping` — Go ELF, takes URLs as `os.Args[1:]`, prints a JSON status
  array. No filesystem writes.

**TL;DR:** Round 14's three findings all landed. `bento validate`
now downgrades unset-allowlist-vars from ISSUE to NOTE and exits zero
(#1); the run-time advisory consolidates the two `--env` blocks into
one and prints the full corrected invocation with every missing var
(#3); and the bash manifest's `read:` block carries a parity comment
even when the profiler logged no individual read paths (#2). The
"smaller observation" about the re-profile advisory guessing `IN=`
also landed — the failed-profile advisory now correctly suggests
`--env OUT=...` derived from the script source. The python and ELF
flows are now genuinely first-try clean. The bash flow regressed for
one specific reason: the new **Quick-apply fix (a)** block hardcodes
`OUT` as the env var name, and `summarize.sh`'s output env var is
`SUMMARY`, not `OUT`. Following the manifest's own scaffold verbatim
produces a tmpfs failure on the second run. Two findings this round,
both centered on the bash flow's script-scraping; the headline
finding is that the Quick-apply scaffold has good shape but
hardcodes a variable name that's only right for one of the three
journey scripts.

## What worked great

- **Round-14 Finding #1 is fully fixed.** After applying the Quick-apply
  fix (uncomment `env: - OUT`, uncomment `write:`), `bento validate`
  printed:
  ```
  manifest: ... — ok (1 note(s) — see end of output)
  ...
  NOTES:
    - env: OUT is in allowlist but not set in current shell — pass
      `--env OUT=VALUE` to `bento run`, or export it before running
  ```
  Note, not ISSUE; exit zero. The recipe and the validator no longer
  contradict each other.
- **Round-14 Finding #3 is fully fixed.** Running `summarize.manifest.yaml`
  unmodified printed exactly one consolidated block instead of two
  overlapping ones — and the corrected command listed both `--env
  OUT=...` AND `--env SUMMARY=...`, not just one of them. Single
  paste, both vars covered. Matches the Round-13 profile-side fix.
- **Round-14 Finding #2 landed as a placeholder.** The bash
  manifest's `read:` block now carries:
  ```yaml
  # this trial: no individual read paths surfaced by the profiler — `.` below
  # is the conservative default (grants the manifest's directory). If you know
  # which paths the script reads, list them explicitly to tighten the grant.
  read:
      - .
  ```
  Tells me whether the missing-detail is intentional vs. a tool gap.
  Cheap fix, correct framing.
- **Round-14 "smaller observation" about `IN=` is fixed.** When
  `summarize.sh` failed reading `./releases.json` during profile,
  bento now suggests:
  ```
  bento profile --allow-exec --env OUT=/tmp/jr-journey15/releases.json ./summarize.sh
  ```
  Correctly named `OUT` from script source (the script reads `$OUT`,
  not `$IN`). Pasting the suggested line just works.
- **ELF path is unchanged and still the cleanest.** `bento profile
  ./ping <urls>` → manifest with args baked in → `bento run` succeeds
  first try; passing a new URL on the CLI gives a clean argv
  replacement note and a clean `DENY cloudflare.com:443` advisory.
- **Tmpfs cross-reference is still excellent.** The
  `↳ the script's output above mentions 'summary.txt' — that print
  referred to a discarded path.` line removes any "wait, did it work?"
  ambiguity for a script that prints "appended row to ./summary.txt"
  even though the row never landed on the host.

## Finding #1 — Quick-apply scaffold hardcodes `OUT`, which is the wrong env var name for `summarize.sh`

`summarize.manifest.yaml`'s scaffold block reads (verbatim):

```
# ── Quick-apply fix (a) ─ uncomment the `write:` block below AND uncomment
#    `- OUT` under the `env:` comment above. Then run with:
#       bento run --env OUT=/tmp/jr-journey15/<file> <this manifest>
# write:
#   - /tmp/jr-journey15
```

Two things are off:

1. **There is no `- OUT under the env: comment` to uncomment** —
   `env:` is already an active block containing `- OUT` because the
   profile-time `--env OUT=...` taught the profiler about it. So the
   first half of the instruction ("uncomment `- OUT` under the `env:`
   comment above") refers to something that isn't there.
2. **`OUT` is the wrong var for the lost write.** The manifest's own
   WARNING block, ten lines above, says:
   ```
   # Lost writes:
   #   - /sandbox/summary.txt
   ```
   `summary.txt` is the file `summarize.sh` writes from `$SUMMARY`,
   not `$OUT`. (`$OUT` is the *input* path the script reads.) So a
   junior who follows the scaffold verbatim runs:
   ```
   bento run --env OUT=/tmp/jr-journey15/releases.json summarize.manifest.yaml
   ```
   …and gets the exact same tmpfs-lost-write failure they were
   trying to escape:
   ```
   [bento] script wrote to paths not declared in `write:`:
     /sandbox/summary.txt
   ```

The python case happened to work because `$OUT` *is* the output env
var name in `list_releases.py` — pure coincidence. The scaffold's
"OUT" reads as a placeholder for "the env var that controls the
output path" but is rendered as a literal name in the recipe text,
so a junior reading both manifests assumes "OUT" is the convention.

Reasoning chain that's available to the profiler but not used:

- The lost-write basename is `summary.txt`.
- The script's source contains `SUMMARY="${SUMMARY:-./summary.txt}"`
  and writes to `"$SUMMARY"`.
- Therefore the env var that controls the lost path is `SUMMARY`,
  not `OUT`.

Three ways out, increasing scope:

- **Cheap: name every env var the script reads in the scaffold,
  not just one.** For `summarize.sh`, the script source has
  references to both `OUT` and `SUMMARY`. The scaffold could say
  "uncomment whichever of these correspond to the lost paths above:
  `- OUT`, `- SUMMARY`" and "Then run with `bento run --env OUT=...
  --env SUMMARY=... <manifest>`". Lets the junior decide instead of
  guessing wrong on their behalf.
- **Medium: correlate the lost-write basename to script env refs.**
  Same heuristic the profile-failure advisory already uses ("script
  reads `$OUT` → suggest `--env OUT`"); just apply it during
  manifest generation when there's a lost write to scaffold for.
  Single-var case: `bento run --env SUMMARY=/tmp/jr-journey15/summary.txt`.
- **Higher: drop "Quick-apply fix" framing when the inference is
  weak.** If the profiler can't confidently name the right var,
  the scaffold's certainty ("Quick-apply", with copy-pasteable
  command) is over-promising. A weaker "the script appears to read
  `OUT` and `SUMMARY` — figure out which one corresponds to the
  lost `/sandbox/summary.txt`" would be more honest.

Compared to Round 14, this is a regression from "costs me 30
seconds of confusion" back to "costs me a debug-and-retry loop" —
the first run after the scaffold fails identically to the first run
before the scaffold, and only the explicit junior-checks-the-warning
loop recovers it.

## Finding #2 — bash manifest's `env:` allowlist is single-var even though the script reads two

The python manifest carries a candidate-env comment block:
```
# env:
#   - REPO
#   - COUNT
#   - OUT   ← required for the Quick-apply fix below
```
…populated by scanning the script source for `os.environ.get(...)`
calls. Three vars; one flagged as load-bearing for the scaffold.

The bash manifest, by contrast, has:
```
env:
    - OUT
```
…and no comment block listing other candidates, even though
`summarize.sh` plainly references `${SUMMARY:-./summary.txt}` on
its third line. The profile-time `--env OUT=...` taught it about
`OUT`; nothing taught it about `SUMMARY`.

A junior reading both manifests side-by-side asks: "did bento decide
SUMMARY wasn't needed, or did it not look?" The answer is the
latter — bash script-scraping for env reads is weaker than python's,
which is invisible to the user.

This is the root cause of Finding #1: if `SUMMARY` had been listed
as a candidate (commented or active) and `summarize.sh` is read by
the profiler the way `list_releases.py` is, the scaffold's "OUT"
problem self-corrects.

- **Cheap: scrape bash for `${VAR}`, `${VAR:-default}`, `${VAR:=default}`,
  `$VAR` outside single quotes.** Standard bash idioms; one regex
  pass over the script gets `OUT` and `SUMMARY` both.
- **Cheap+: at minimum, list every var the bash script's
  `${VAR:-...}` defaults reference in the candidate-env comment**,
  even if not auto-added to `env:`. Closes the asymmetry with python.

## Smaller observations

- **`SUMMARY` doesn't appear anywhere in the run-time advisory either.**
  When I ran `bento run summarize.manifest.yaml` with only `OUT`
  declared in `env:`, the Round-14 consolidated note correctly listed
  both vars *if both were in the allowlist* — but since the bash
  manifest only ships with `OUT` (per Finding #2), the consolidated
  note only mentioned `OUT`. The advisory's coverage is bounded by
  what the manifest declares, which is bounded by what the profiler
  scrapes. Same root cause as Finding #2; same fix.
- **The bash manifest's `read:` got a placeholder annotation but
  no `write:` annotation at all (in the scaffold variant).** When the
  bash trial run lost its write to tmpfs, the manifest only carries
  a *commented-out* `write:` block under the Quick-apply scaffold —
  no "this trial actually touched (write): /tmp/jr-journey15/summary.txt"
  comment like the round-14-and-prior bash manifests had once the
  write was successful. Since the trial failed, there's nothing to
  annotate from observation — fine. But the scaffold could borrow
  the same "this trial *intended* to write" framing from the lost-
  writes list above, e.g.:
  ```
  # the trial intended to write (but lost to tmpfs):
  #   - /sandbox/summary.txt   ← rename to host path via --env SUMMARY=...
  ```
  Connects the WARNING block to the scaffold below in one place.
- **`go.mod` left behind by `go build` inside the workspace.** Not
  bento's responsibility, but the journey produced four artifacts
  (`go.mod`, `ping`, manifests) before any bento step ran. A junior
  who chose `go run ./ping.go` instead of `go build -o ping` would
  have hit "no main package" or similar and never gotten to bento.
  Not actionable for bento; noting only because the ELF path's
  "cleanest of the three" status depends on the junior knowing to
  produce a binary in the first place.
- **`network.rules` renders `port: "443"` as a quoted string.**
  Cosmetic, but yaml-aware editors highlight it differently from
  integer ports a junior might add by hand. Trivial.
- **Re-profiling the python script with the Quick-apply fix already
  applied would be a nice sanity step that doesn't exist.** Right
  now there's no `bento profile --re-check <manifest>` that does a
  trial run against the current manifest and tells you "yes, this
  would have worked" before you commit. The validate+run loop
  approximates it but `validate` doesn't execute.

## Suggested ordering for the maintainer

1. **Finding #2: scrape bash scripts for env var references the same
   way python is scraped.** Underlies Finding #1; one regex pass
   probably closes both. Biggest leverage per line of code.
2. **Finding #1: when scaffolding the Quick-apply fix, derive the
   env var name from the lost-write basename + the script's env
   references, instead of hardcoding `OUT`.** Falls out naturally
   once #2 is in place — if both `OUT` and `SUMMARY` are known, the
   scaffold can match `summary.txt` ↔ `SUMMARY` by substring or by
   default-value parsing.
3. (later) "this trial intended to write" framing on the lost-writes
   list inside the manifest, so the WARNING block and the Quick-apply
   block reference the same paths in the same vocabulary.

The trajectory is still good — every prior round's headline has
been retired by the next, and the failure mode this round is one
hardcoded string in a template that hadn't been generalized to the
case where the output env var isn't named `OUT`. Closing Finding #1
+ #2 would make the bash flow as first-try clean as the python and
ELF flows already are.
