# Internal audit, round 4 - 2026-08-08

Fourth adversarial audit of `internal/`, run through the `audit-loop` formula. Eleven
parallel opus subagents: ten package scopes split by non-test line count, plus the
cross-package seams slot. 52 beads filed under the label `audit-internal-2026-08-08`.

Prior rounds: `docs/audit-internal-2026-08-05.md` (round 3, 37 beads),
`audit-internal-2026-08-04` (round 2, 31 beads). The 07-25 and 07-26 reports no longer
resolve in this checkout; the 08-05 report was still untracked when this round started and
is committed in 68409e4.

## Method

Split by non-test LOC, not by directory - `internal/linux` is 6053 non-test lines and took
four agents; `landlock` + `seccomp` + `shield` (2411 combined) fit in one.

| agent | scope | non-test LOC |
|---|---|---|
| 1 | linux/alias.go, linux/probe.go, i386 | 1498 |
| 2 | linux/linux.go, autoexec.go, degraded.go | 1430 |
| 3 | linux/args.go, limits.go, profile.go | 1581 |
| 4 | linux/shields.go, grants.go, applied.go | 1578 |
| 5 | denylist/denylist.go, index.go | 2233 |
| 6 | denylist/audit, shieldcorpus, credhunt | 1677 |
| 7 | launcher | 2155 |
| 8 | observe | 1635 |
| 9 | proxy, pathresolve, grantrefusal | 1480 |
| 10 | landlock, seccomp, shield | 2411 |
| 11 | cross-package seams | - |

The brief method that worked in round 3 was carried forward and extended. Open beads with
full bodies, plus the 43 closed round-3 beads under an explicit "already fixed, in the tree
today" heading - and this round with their **close reasons** attached, not just their
titles. That change paid for itself: three of the four incomplete-fix claims below are
arguments against a close reason's stated rationale, which nobody can construct from a
title. Zero staleness false positives again.

Two additions worth keeping:

- A `SETTLED - do not re-derive` section carrying round 3's three spiked results (the
  seccomp ACTION_ONLY s32 cast, NNP propagation under TSYNC, and `RunOptions.Degraded`'s
  revisit triggers). Every agent whose scope touched them honoured it.
- The seams agent alone got the `audit-non-internal-2026-08-07` bead list, with its scope
  narrowed to seams *between internal packages*. Round 3's seams agent spent its P2/P3 on
  `cmd/bento/`; this round's stayed inside and produced a genuinely compositional P1.

## Verification

Four claims were spiked. All four confirmed.

**Write grant above a DenyWrite shield.** `shield.Assemble` over `shield.Host()`,
`homes=/home/u`:

    write /home/u/.pyenv             -> Honored
    write /home/u/.local/share/mise  -> Honored
    write /home/u/.local             -> AboveShield   (caught by an unrelated DenyAll at .local/share/gh)
    control: write /home/u/.pyenv/shims -> not Honored

The control arm matters: it proves the DenyWrite rules exist, so the above-direction result
is a real gap and not an absent rule set. It also corrected one auditor - `~/.local` was
offered as an instance and is not one.

**Entrypoint re-bind over a built-in shield.** `compile` with `interpreter: /usr/bin/cat`,
`entrypoint: ~/.ssh/id_ed25519`, `read: /home/u`:

    shields applied: [{Path:/home/u/.ssh Kind:hidden}]
    last --tmpfs /home/u/.ssh          at argv[19]
    last --ro-bind .../id_ed25519      at argv[21]
    command: /usr/bin/cat /home/u/.ssh/id_ed25519

**A spike that fails on its control arm is the spike working.** This one needed two
corrections before it meant anything. Run 1: with no grant reaching the store, `shieldNeeded`
correctly drops the shield, so the ordering assertion would have passed vacuously - while
the key was bound in and read all the same. Run 2: the fake sandbox needed `/home/u/.ssh`
itself in its `existing` set before the shield was emitted. Round 3's memory recorded the
inverse trap (a spike that *passes* for the wrong reason); the same discipline - assert the
artifact exists before asserting what beats it - catches both.

**classifyUnshare.** `bwrap: execvp true: Permission denied` and a bind-mount refusal both
classify as `namespacesBlocked`, the tier-*downgrading* verdict, with the reason "cannot
create an unprivileged user namespace". Control arm: a genuine userns refusal also reaches
`namespacesBlocked`, so the assertion is not vacuous.

**Relocated CARGO_HOME.** `CARGO_HOME=/srv/cargo`: control arm `/home/u/.cargo/bin` is
`{DenyWrite, Dir:true}`; `/srv/cargo/bin` is absent.

Two claims were checked and came back **not settled**, recorded as such on their beads:

- The `bv2-asq7` parity-gate claim. The structural half (the unset loop is absent from the
  test's call site) is confirmed by reading. Running the gate ambient and again with
  `ZDOTDIR`/`GNUPGHOME`/`CARGO_HOME` set passed both times - those relocations did not
  happen to cover an upstream candidate on this host. The masking effect is undemonstrated.
- The observe `EINTR`/`ERESTART` finding. Its write-up visibly contradicted itself
  mid-paragraph on which branch is taken. The mechanism is re-derived on the bead; the
  consequence half is marked for re-derivation before anyone acts on it.

## Incomplete fixes found in closed beads

Four, which is the highest-value output this loop produces and the reason close reasons
belong in the brief.

- **bv2-d3vv** added ~30 PATH-resident shim directories and never applied the package's own
  "Adding a tool" checklist item 3, env-var relocations. Eleven shielded directories have a
  first-class relocation variable and none is in any table - `GOBIN` is named in the comment
  directly above the rule that ignores it. Its close reason enumerates the residuals as
  globs only, so the class was never considered. The `CARGO_HOME` instance is spike-confirmed
  and filed separately as the proof of shape.
- **bv2-asq7** unset the relocation variables in `cmd/denylist-audit`'s `run()`. There are
  two triggers of `audit.Audit` and `report()`'s own comment says so; only the CLI got the
  loop. See the caveat above - structurally confirmed, effect undemonstrated.
- **bv2-r9u8** fixed a hand-counted numeral in `grantrefusal`'s package doc. The doc says
  "twenty-one call sites for ten sentences"; it is 24 and 11. The incompleteness is
  structural - a restated hand count re-rots by construction, and did so within one round.
- **bv2-51jy** swept the off-Linux stubs and left `RestrictExecAllowlist` out of
  `landlock_other.go`. Latent: the only caller is linux-tagged, so the crossbuild passes.

**bv2-0taz is NOT incomplete, and the distinction is the interesting part.** It closed the
caller-`DenyPaths` entrypoint case, and its close reason correctly states that `extraDeny` is
only ever `Options.DenyPaths` and never the built-in Home/Runtime shields. That sentence is
true - and is exactly why the same last-wins ordering is still open for the built-ins. A
correct close reason that scopes itself honestly is what let this round find the sibling
instead of re-litigating the original.

## Findings

| pri | bead | finding |
|---|---|---|
| P1 | bv2-1r33 | denylist: a relocated CARGO_HOME drops .cargo/bin, and both the code and the test comment claim it mirrors the defaults |
| P1 | bv2-b7a9 | observe: a FAILED execve sets Execed, which profile turns into exec: all and removes the exec-block filter |
| P1 | bv2-pf2n | launcher: a traceExecs error leaves rec.failed nil, so a truncated exec record is written as watched and complete |
| P1 | bv2-gmae | proxy: handle's writeStatus calls have no write deadline, so a client that never reads pins a handler slot for the whole run |
| P1 | bv2-fm00 | linux: the entrypoint re-bind lands after a BUILT-IN shield too, so a manifest reads a credential the report says is hidden |
| P1 | bv2-3hce | shield: a write grant ABOVE a DenyWrite shield is Honored, and the degraded tier then writes it for real |
| P2 | bv2-h2wb | linux: the degraded exposure report labels a fully writable path 'read-only' |
| P2 | bv2-1wrm | proxy: classify returns on the first matching NAT64 prefix, so a multi-Pref64 site's verdict depends on DNS answer order |
| P2 | bv2-mvq1 | launcher: applied.go's 'mutually exclusive by construction' claim is refuted by runTarget's own block path |
| P2 | bv2-ab5w | observe: the existence decoder's errno skip-set omits EINTR and the ERESTART pseudo-errnos |
| P2 | bv2-3jto | observe: a group-stop is restarted with its own SIGSTOP reinjected, so a self-stopping target livelocks the profiler |
| P2 | bv2-1y1v | launcher: PR_SET_DUMPABLE(0) blanks the exec record's image and argv, and the record still attests complete |
| P2 | bv2-pd6v | linux: parseApplied accepts exec-ran lines appended after EXEC-RECORD and still reports the record complete |
| P2 | bv2-v2dl | denylist-audit: the corpus floors leave ~90 and ~300 entries of silent slack, and neither parser counts what it dropped |
| P2 | bv2-1fdc | denylist-audit: bv2-asq7 unset the relocation vars in the CLI only, so the in-tree parity gate still reads the developer's shell |
| P2 | bv2-tafl | layering: scripts/layering.sh cannot see denylist.Rule composite literals, so the grant-derived shield family is unguarded |
| P2 | bv2-hmio | seams: the degraded guard covers NetworkGate and not network: rules, and the report attests LayerNetwork Enforced |
| P2 | bv2-iye6 | linux: classifyUnshare reads any 'Permission denied' as a userns refusal, and that is the tier-DOWNGRADING verdict |
| P2 | bv2-eokb | denylist: bv2-d3vv's PATH-shim shields were never given their relocation variables |
| P3 | bv2-5v0f | shield: maxLinkDepth is named and documented as a link bound but implemented as a directory-recursion bound |
| P3 | bv2-weg6 | proxy: halfClose's fallback aborts both directions, and the doc says it half-closes |
| P3 | bv2-8jx7 | linux: any symlink under .git/modules or .git/worktrees hard-refuses the run |
| P3 | bv2-6f8h | linux: createdShields has no rule dedup while denyArgs does, over the same rule set |
| P3 | bv2-fwaa | linux: degradedSystemPaths bypasses the sb.exists seam, so the /nix branch is unreachable in tests |
| P3 | bv2-wd0s | linux: autoexec.go claims every source of core.hooksPath is fixed for the run; false for a grant that is not a checkout |
| P3 | bv2-ozv6 | observe: the initial wait bypasses the waitTracee seam, so the one pre-EXITKILL error return is untestable |
| P3 | bv2-xmth | observe: ENOTDIR is skipped as 'not there', but enforcement answers ENOENT instead |
| P3 | bv2-50em | denylist: the XDG block in Relocated is the only one with neither a shieldable nor a covered guard |
| P3 | bv2-9qkw | denylist: HomeAnchors' doc says an anchor cannot be dodged, and on a passwd-less host it can |
| P3 | bv2-1qzq | denylist: five concrete credential stores whose sibling is already covered, none visible to the firejail ratchet |
| P3 | bv2-qvr4 | denylist-audit: DormantKeywords is an unratcheted permanent suppression of the ratchet that exists to notice silence |
| P3 | bv2-ldpw | denylist-audit: an AcceptedWeaker skip swallows a co-occurring Narrowed, and the reporter has a branch for that pair |
| P3 | bv2-ajhw | shieldcorpus: no test file of its own, and every symlinked-subdirectory case names a path that does not exist |
| P3 | bv2-f6cx | credhunt: the VCS-object-store prune is the one narrowing that is not counted |
| P3 | bv2-lxok | proxy: idleTimeout is a package var a test mutates while other tests' tunnels read it |
| P3 | bv2-xbkl | linux: nothing in the package ever sets sb.applied, so three compile branches are unreached |
| P3 | bv2-rzvh | linux: Profile's limits gate is coarser than Run's, and refuses naming controllers the manifest never requested |
| P3 | bv2-aj4a | linux: runScopeProbe returns success without creating a scope when the limits are zero |
| P3 | bv2-phow | linux: observeHomeTmpfs guards against / and /tmp before Clean, so both get through |
| P3 | bv2-8axf | launcher: permittedStdioDevice's justification is bwrap-only but the check is shared with the degraded tier |
| P3 | bv2-zliz | launcher: enforce.Process.AllowNetworkStdio is silently inert on the degraded tier |
| P3 | bv2-nq73 | launcher: RunDegraded validates every argv-supplied path except Scratch |
| P3 | bv2-yqra | shield: foldsCase flips only the shield's own basename, so ext4 per-directory casefold is detected one level up and nowhere else |
| P3 | bv2-50ny | landlock: 'deliberately NOT best-effort, and stays that way' sits eight lines above a BestEffort() call |
| P3 | bv2-vhi2 | landlock: RestrictExecAllowlist has no off-Linux stub, so bv2-51jy's stub sweep missed one |
| P3 | bv2-o0sk | seccomp: the foreign-arch and x32 kill arms are untested in egress and terminal, and tested twice in strict |
| P3 | bv2-krr5 | linux: acknowledgementRoots suggests --accept-alias trees that checkAcknowledgementScope then refuses |
| P3 | bv2-ckdr | observe: a stranded drops key on a LIVE tracee silently suppresses every later drop at that call site |
| P3 | bv2-vuov | observe: execImage validates a shebang interpreter for absoluteness but not a PT_INTERP |
| P3 | bv2-yfc6 | grantrefusal: bv2-r9u8's fix was a restated hand count, so the package doc has already re-rotted |
| P3 | bv2-b8u7 | linux: homeContainers is duplicated and has diverged, and the copy missing /export/home backs a refuse-if-too-broad guard |
| P3 | bv2-wgjn | linux: ChangedAutoExec is computed on the cancel path and discarded by every frontend |


## Dismissals carried forward

Two dismissals were re-derived independently by two agents each and should not be spiked
again:

- `internal/linux/degraded.go:107`'s auto-exec snapshot ordering (the comment says "after
  prepareWriteDirs", the code is before). Both the linux.go agent and the seams agent traced
  it and both rate it behaviourally inert, because `prepareWriteDirs` creates only the grant
  root and no `autoExecNames` entry is ever the grant root. Comment fix only.
- `internal/i386`'s `INT $0x80` register clobber. Dismissed by disassembling the seccomp test
  binary rather than by reasoning: the compiler emits `XORPS X15, X15` / `MOVQ FS:0xfffffff8,
  R14` at every ABI0 call site, so the caller restores both special registers itself.

One dismissal is left **unresolved between two auditors** and is recorded on its bead rather
than silently resolved: whether the degraded tier's exposure report actively misleads. The
shields/grants agent read `shieldsApplied`'s `DenyWrite -> "read-only"` mapping as naming
the protection that is absent; the shield agent treated the entry's mere presence in
`exposedShields` as adequate disclosure. It turns on what `cmd/bento/render.go` prints,
which neither agent read.

## Scope

Every non-test file under `internal/` was assigned to an agent and read. Test files were
read in full only where a coverage claim depended on it; several agents state explicitly
that their "no test reaches this" claims rest on function-name enumeration plus grep, not a
line-by-line read - those are marked on the beads.

Not covered: `cmd/`, `enforce/`, `policy/`, `gate/`, `profile/`, `examples/` except where an
internal finding's blast radius had to be traced into them. Those were audited on 2026-08-07
under `audit-non-internal-2026-08-07`.

Every agent had an advisor this round.
