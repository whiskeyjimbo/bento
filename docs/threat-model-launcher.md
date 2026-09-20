# Threat model: internal/launcher and the fences it verifies

Scope: `internal/launcher`, plus the enforcement points it depends on in
`internal/linux` and `internal/landlock`. Date: 2026-09-17. Tree at `0abf849`
(head of `docs/state-grids`).

This is a package-level companion to `docs/threat-model.md`, not a replacement.
That document states the system boundary and its non-goals; among the things it
trusts rather than defends is "the kernel and bubblewrap". This one starts from
the observation that `internal/launcher/verify.go` does **not** fully trust
bubblewrap, and asks how far that partial distrust reaches. Its own comments say
why it exists: the flags that ask for the sandbox "go through the same
PATH-resolved bwrap that would be doing the lying". Four fences are checked from
inside against the kernel's own answer. The rest of the argv is not, and the
delta is the deliverable here.

Spikes ran, under the subagent carve-out only: in-process calls against fixtures
this run planted in its own temp directories. No process was spawned to attempt a
crossing, because no user was reachable for the Phase 5 consent gate. Two
throwaway `zz_spike_test.go` files were written into the checkout to reach
unexported symbols and were deleted; `git status --porcelain` is empty.

Row grades: 25 rows - 3 `evidenced` (the code executed against a fixture this run
planted), 22 `read`, 0 `spiked` against a live sandbox.

Attacker list (proposed, not confirmed - see "Attackers" below):
`same-uid`, `content-supplier`, `local-user`.

## Findings, worst effect first

### F1. Everything the host attests about a run is attested by a binary named through PATH, and the channel it reports on is unauthenticated

`VERIFIED BY SPIKE` (both halves, in-process), with the escalating variant
`UNSPIKEABLE HERE`.

**RESOLVED** in `internal/linux/probe.go:525`. The resolution is unchanged -
`exec.LookPath` still finds the binary, because a fixed list of system
directories would refuse NixOS - but `trustLauncherPath` (`:566`) then refuses
any path, or symlink target, one of whose components this uid may write. Both
launch sites and the probe go through it, so a plant in a granted `bin`
directory refuses the next run instead of unconfining it.

bwrap is no longer the only binary under that check. Under resource limits the
outer process the host execs is a `systemd-run` scope runner, which inherits fd
3 and the bridge liveness pipe in bwrap's place; `resolveScopeRunner`
(`internal/linux/limits.go:89`) holds it to the same refusal, and
`preflightLimits` (`limits.go:230`) is the gate every wrapped launch reaches
(e607a3b). `trustLauncherPath` therefore takes a `role` naming which binary
it is ruling on, and its refusals are worded about running with a binary rather
about building a sandbox with one.

The report's half is closed by the same check and not by anything on the
channel. Nothing in the report's bytes can authenticate its writer: whatever the
host launches inherits the argv and environment along with fd 3, so a nonce or a
shared secret is handed to the forger too. Provenance of the binary is the only
unforgeable thing, which is recorded at `internal/linux/applied.go:23`.
`checkLauncher` (`linux.go:976`) was NOT the home, despite looking like it: it
rules on `sb.bentoPath`, which already comes from `os.Executable()`, and two of
its three callers run no bwrap at all.

`internal/linux/linux.go:97` resolves the sandbox builder with
`exec.LookPath("bwrap")`. Nothing verifies the image it finds:
`checkLauncher` at `internal/linux/linux.go:976` looks like that check and is
not one - `launchGuard` is `nil` in production by its own comment at
`internal/linux/linux.go:950`, and the seam exists so the test suite can
intercept a launch.

A process holding that name decides what the sandbox is, and it also inherits
the descriptors the host passed: the applied-layer report at fd 3
(`internal/linux/applied.go:23`) and the bridge liveness pipe at fd 4. It need
never exec bento's launcher at all, so none of `verify.go` runs. What it writes
on fd 3 is what the host reconciles into the run's report.

Spike, in-process against `parseApplied`: a report consisting of the three lines
`exec-filter strict`, `landlock yes`, `APPLIED` parses as
`complete=true execFilter="strict" landlock="yes"`. There is no nonce, no
sequence, no authenticator - the marker is the whole proof, and the marker is
three ASCII characters. The second half spiked the same way: with a file named
`bwrap` planted in a directory this run created and that directory prepended to
`PATH`, `exec.LookPath("bwrap")` returns the planted path. Neither spike executed
anything.

**Effect, split, because the two halves are not the same row.** For a
`same-uid` attacker who can already set `PATH` on the invocation, the gain is a
*false attestation* and nothing more: they hold the user's privileges and could
read the credential directly without a sandbox in the way. Say that plainly
rather than counting it as an escape.

The escalation is one specific shape. The sandboxed target writes a file named
`bwrap` into a directory it has a write grant for that also sits on the user's
`PATH` - a project's `node_modules/.bin`, a `./bin` or `.venv/bin` a direnv
profile adds, a tool wrapper directory. The *next* run then builds no sandbox,
runs the target against the real host, and reports every layer Enforced.
`internal/linux/autoexec.go:32` reports changes to a fixed set of auto-executing
project files and `autoexec.go:63` to three directories whose every entry runs;
a `bin` directory on the user's `PATH` is on neither list, and the report's own
documentation (`docs/threat-model.md` section 4.2) says it is a hint rather than
a fence. Nothing else in the run names such a plant.

What bounds this row: bwrap is already trusted by name in
`docs/threat-model.md` section 3, and the honest reading of `verify.go` is that
it narrows that trust rather than removing it. What is new here is that the
narrowing covers six fences out of the argv's fifteen-odd, and that the
attestation channel a shim controls is the one artifact the user reads afterwards
to decide whether the run was confined.

The `PATH` the resolution reads is the invoking user's. `internal/linux/linux.go:210`
builds the launch command and sets only `Stdin`, `Stdout`, `Stderr` and
`ExtraFiles`; it never assigns `cmd.Env`, and nothing in `cmd/bento` or
`internal/enforce` sanitizes or pins `PATH` before the enforcer runs. Worth
saying because one name looks like it covers this and does not:
`shadowedPathDirs` (`cmd/bento/run.go:608`) reports the PATH directories that
were *not* carried into the sandbox, which is a usability diagnostic about the
target's own lookups. Nothing reports a host PATH directory that shadows
`/usr/bin/bwrap`.

What would settle the escalating variant: a spike that spawns `bwrap` from a
shimmed `PATH` under a real `bento run` and checks whether the report comes back
Enforced. That spawns a process to attempt a crossing, so it stayed unrun.

One real ceiling, and it is the reason this is not worse. `parseApplied` is
monotone past the marker: `internal/linux/applied.go:152` accepts only a
`target-unreached` line after `APPLIED`, once, and
`internal/linux/applied.go:157` voids the whole report for anything else in a
closed exec-record section. A forger can make the report claim *more*, never
retract a layer, so the direction that matters is the one that is open.

### F2. Terminal detachment is the fifth fence with no second leg, and only one of the two tiers enforces it

`PARTIAL`. `VERIFIED BY READING`, with the runtime observation
`UNSPIKEABLE HERE`.

**RESOLVED** in `internal/linux/args.go:528` and `internal/linux/probe.go:607`.
`--new-session` was hoisted out of `baseFlags` into a shared `sessionFlags`, the
way `namespaceFlags` and `pseudoFSFlags` are shared, so `canUnshare` exercises
the same flag the run does. The canary then proves from inside that it took, by
reading a nonzero session id from the namespace-local procfs - a session leader
outside the PID namespace is invisible in it and reads back as 0, so nonzero says
the sandbox's own session leader is inside the sandbox, which only `setsid()`
produces. Measured both ways on a working host: 1 with the flag, 0 without. A
missing proof lands on the `unknown` verdict, which refuses the run rather than
offering the degraded tier over an unverified fence. The reading is namespace-local
and therefore vacuous against a host `/proc`, so the probe is one leg of two: the
other is `internal/launcher/verify.go`'s `verifyPidNamespace`, which refuses at
launch the only shape that satisfies the probe vacuously.

The degraded tier treats terminal injection as fatal: `degraded.go:120` refuses
a run whose host cannot supply `seccomp.TerminalInjectionSupported`, and
`degraded.go:226` refuses if `blockTerminalInjection` will not install. The bwrap
tier installs no such filter. It relies entirely on `--new-session` in
`internal/linux/args.go:519`, which calls `setsid` and leaves the target with no
controlling terminal, because `TIOCSTI` is refused on a terminal that is not
yours.

That flag lives in `baseFlags` rather than `namespaceFlags`, so the pre-run probe
(`canUnshare`) never exercises it, and `verify.go` never asks the kernel whether
it took. Every other fence the tier leans on with no second leg is checked from
inside; this one is not.

Effect: a sandboxed program pushes characters into the user's terminal that the
shell reads back as typed input after the run exits. That is arbitrary host
command execution as the user, which outranks anything else in this document -
what keeps it below F1 is that it takes a lying or absent `--new-session`, where
F1 takes only a name on `PATH`.

Existing coverage, which is better than a spike would leave it:
`internal/linux/newsession_test.go` builds a probe that asserts detachment
through `open("/dev/tty")` and also attempts `TIOCSTI` directly, and its header
comment names exactly this gap. So the guarantee is walked on every CI run. What
is not walked is the runtime: a shim that drops the flag on a real host passes
the test suite, because the test suite does not resolve bwrap through the
attacker's `PATH`.

The fix shape is the one `verify.go` already uses four times, and the spike
confirms the primitive is the cheap one. In-process `open("/dev/tty")` returned
`ENXIO` in this run's own environment, which is what a detached process sees.
This run cannot distinguish that from a positive result because it was already
detached, so the check is `feasible` rather than `demonstrated`.

### F3. The Landlock backstop confines writes only, so it cannot backstop any read fence, and it warns rather than refuses

`VERIFIED BY READING`. This is the Phase 6 composition finding, not a row.

`internal/landlock/landlock_linux.go:102` is the bwrap tier's whole backstop:
`Restrict(writable)` is `RestrictTo([]string{"/"}, writable)`. It read-grants the
entire visible filesystem and constrains writes to the named set. Two things
follow, each defensible alone.

First, no read fence has a *backstop*: Landlock grants read of `/` whatever the
mounts are, so nothing underneath catches a dropped read fence. The credential
shields are `--ro-bind` of an empty file over a path a broader grant exposed
(`internal/linux/args.go:318`, `internal/linux/shields.go`), and a shim that drops
one shield's argument pair would expose that store for the run's whole length under
a report saying the filesystem layer was enforced.

**RESOLVED**, not by a backstop but by a verify. `launcher.Config` now carries the
run's hidden and read-only shield sets, and `verifyShields`
(`internal/launcher/verify.go:197`) confirms each from inside the sandbox - the
sixth in-sandbox verify, and the first to cover a read fence. It checks shapes
rather than deny rules: hidden means nothing readable is left at the path,
read-only means a write there is rejected. The composition finding stands as the
reason that verify has to exist.

Second, `applyLayers` in `internal/launcher/launcher.go:312` warns and proceeds
when the backstop cannot be applied, which is documented and correct on its own
terms: failing would make bwrap's confinement contingent on the backstop and
invert the relationship. `BY-DESIGN`, with the comment as the cite.

Together they are the two halves that would each have backstopped the other. The
write fence has a backstop that is allowed to be absent; the read fence has none
at all. Neither is a defect; the pair is the shape worth naming.

One narrowing that keeps this honest, and it is the single most load-bearing fact
in the whole shim row set: **bwrap's root is a fresh tmpfs and its mounts are
additive**, so a shim that *omits* an ordinary bind exposes nothing - the path is
simply absent, and the target finds less than the policy granted. Only two edits
gain anything: omitting a **shield**, which is a bind over a path some broader
grant already exposed, and **adding** a mount the argv never asked for. Under
default-deny with narrow grants there is no broader grant for a dropped shield to
uncover, so this row's effect is conditional on the run carrying a broad read
grant - the case `docs/threat-model.md` section 4.2 exists for.

### F4. `/dev` was unverified, and statfs could not settle it - FIXED

`VERIFIED BY SPIKE` (the negative result), then closed by `verifyDevMount`
(`verify.go:134`), which reads the directory listing instead of the filesystem
type. Two spikes under bento's own `baseFlags` put bwrap's `/dev` at 14 entries
without a controlling terminal and 15 with one, against this host's 216. The extra
name is `/dev/console`, which bwrap binds from the *invoking* process's controlling
tty; `--new-session` only `setsid()`s the child and does not suppress it, so
`bwrapDevNodes` carries `console` unconditionally. The paragraphs below record why the
obvious single-syscall fix does not work, since that is the reusable part.

`internal/linux/args.go:513` asks for `--proc /proc`, `--dev /dev` and
`--tmpfs /tmp` as one list that the probe and the real run must exercise
identically. `verify.go` confirms one of the three directly and one by
consequence:

- `/tmp` is confirmed by `verifyFreshTmp` (`verify.go:31`).
- `/proc` is confirmed by consequence. A procfs inherited from the host keeps
  showing host pids, so `verifyPidNamespace` (`verify.go:61`) fails on it, and
  `/proc/net/dev` would then describe the host stack and fail
  `verifyEmptyNetns` (`netns.go:29`). `internal/launcher/netns_test.go` and
  `verify_test.go` both drive those refusals.
- `/dev` is confirmed by `verifyDevMount` (`verify.go:134`), by listing rather
  than by statfs - see below.

The obvious fix does not work, which is what the spike bought over reading. On
this host `statfs("/dev")` reports `0x1021994`, which *is* `TMPFS_MAGIC` - the
same answer `verifyFreshTmp` accepts for `/tmp`. So the one-syscall trick that
settles `/tmp` cannot distinguish bwrap's `/dev` from the host's. Verifying it
means enumerating the device set or asserting the absence of specific nodes, which
is a denylist of the kind this codebase declines to build elsewhere.

Effect, and it is modest, which is why this sits here rather than at F1: a host
`/dev` in the sandbox offers `/dev/kvm`, `/dev/mem`, `/dev/net/tun`. As the
invoking uid with an empty capability bounding set (`verify.go:322` confirms the
set is empty), `/dev/mem` at `0600 root` and `/dev/kvm` at `0660 root:kvm` are
reachable only where the user is already in those groups. `/dev/net/tun` is
commonly `0666`, and an interface created through it lands in the sandbox's
verified-empty netns with no route out. So the gain is real but host-dependent
and mostly not an escape.

### F5. The remaining unverified namespace flags

`VERIFIED BY READING`. Named for completeness, ranked last because their effect
is small.

`--unshare-ipc`, `--unshare-uts` and `--unshare-cgroup`
(`internal/linux/args.go:501`) have no in-sandbox check. Their absence gives the
target the host's SysV IPC and POSIX message queues, the host's hostname, and the
host's cgroup view. `--unshare-user` is likewise unchecked, but its principal
consequence is capability-shaped and `verifyEmptyCapBound` covers that.
`--die-with-parent` and `--chdir` are unchecked; the first is backstopped
host-side by the run's deadlines and cancellation, and the second is bounded by
both exec paths refusing a relative `argv[0]` (see the sibling pair below).
`--clearenv` (`internal/linux/args.go:662`) is unchecked, but the launcher
independently drops the proxy variables it cares about at
`internal/launcher/launcher.go:241`, so the specific redirection that would
matter is closed on bento's own authority rather than on bwrap's.

### One sibling pair that did not diverge

Worth recording because the shape usually does. Both exec dispatch paths refuse a
relative `argv[0]`: the supervise path at
`internal/launcher/launcher.go:1040` (`startTarget`), and the exec-block path,
which does not go through it, at `internal/seccomp/seccomp_linux.go:157`
(`seccomp.Exec`). `startTarget`'s comment claims every path refuses one; the
claim checks out. `internal/launcher/launcher_test.go:25` covers the first.

## Boundaries (proposed)

Slugs are taxonomy rung 6 throughout: three packages and eight crossings collapse
rung 5 onto three repeated slugs. `Run` exists in both `launcher` and `linux`,
so the launcher's is suffixed.

| slug | inside / outside | who controls the outside | crossing |
|---|---|---|---|
| `lookpath-bwrap` | the host enforcer / the binary that builds the sandbox | anyone who can write a `PATH` directory, or set `PATH` | `internal/linux/probe.go:525` (`resolveBwrap`), reached from `linux.go:102`, `probe.go:592`, `profile.go:65` |
| `run-launcher` | the in-sandbox stage / the namespace it woke up in | whatever built that namespace | `internal/launcher/launcher.go:108` |
| `decodelaunch` | the in-sandbox stage / its own argv | whatever exec'd it | `internal/launcher/reexec.go:61` |
| `parseapplied` | the host's report / fd 3 | whatever inherited fd 3 | `internal/linux/applied.go:109` |
| `refusenetworkstdio` | the sandbox's egress fence / fds 0-2 | bento's parent process | `internal/launcher/launcher.go:566` |
| `rundegraded` | the no-bwrap stage / the host it runs directly on | the host, and its own argv | `internal/launcher/degraded.go:139` |
| `decodelaunchdegraded` | the no-bwrap stage / its own argv | whatever exec'd it | `internal/launcher/degraded.go:284` |
| `restrict` | the filesystem backstop / the set it is given | `--rw` off the launch wire | `internal/landlock/landlock_linux.go:102` |

## Flows, with the receiving side's assumption

The assumption column is where the rows came from.

| what crosses | direction | the receiving side assumes |
|---|---|---|
| the bwrap argv (15-odd flags) | host to sandbox builder | the builder honors every flag; four of them are checked afterwards |
| the launch invocation (`--rw`, `--socket`, `--applied-fd`, `--exec`) | builder to launcher | the fd numbers are the host's, the paths absolute, the exec mode one of three |
| the mount set the namespace carries | builder to launcher | the launcher assumes the shields landed; nothing confirms it |
| the applied-layer report | launcher to host, on fd 3 | a report reaching `APPLIED` proves the fences were installed |
| fds 0, 1, 2 | bento's parent to the target | a socket, a directory, a device or a namespace handle on stdio is a channel past every fence |
| every other inherited fd | bento's parent to the launcher | nothing revokes an open description, so they must be dropped |
| `/proc`, `/proc/net/dev`, `/proc/self/status`, `statfs("/tmp")` | kernel to launcher | the kernel's answer is the one leg that is not the suspect's word |
| `TMPDIR`, `HTTP_PROXY` and friends | policy to target | first occurrence wins in glibc `getenv`, so bento's value must be the only one |

## Attackers (proposed; unconfirmed, no user was reachable)

- `same-uid` - code running as the invoking user. This is *the* attacker: the
  sandboxed target is attacker-chosen code by design, and it shares the user's
  uid. It can already read everything the user can, so every row's effect column
  has to name something beyond that. Two variants matter and are kept apart
  throughout: the target of *this* run, confined; and a plant the target leaves
  behind that influences the *next* run, unconfined.
- `content-supplier` - a checkout or manifest the user obtained. It chooses the
  interpreter (`internal/linux/linux.go:763` resolves it with `exec.LookPath`),
  the grants, the target argv, and the environment a policy declares.
- `local-user` - a different uid on the same host. Kept only for the `/tmp` row,
  because `verifyFreshTmp`'s own comment names it: a host `/tmp` left in place is
  writable to the target and exposes every other user's scratch files.

Dropped, with reasons: `remote-unauth` and `remote-auth` (no listener in this
scope; the egress proxy's own surface is `internal/proxy`, modelled by
`docs/threat-model.md` section 4.4). `upstream` and `downstream` (the launcher
dials only a bind-mounted unix socket on loopback inside a verified-empty
netns). `insider` (indistinguishable from `same-uid` here). A root-level
attacker is dropped by `docs/threat-model.md` section 3: a compromised host is
out of scope, and every row would otherwise be attackable, which says nothing.

## The matrix

Enforcement: `ENFORCED` needs a `file:line` that rejects this row.
Grade: `read` reasoned from code, `evidenced` the code executed against a
planted fixture, `spiked` attempted against the real thing.

| id | attacker | enforcement | effect | detection | grade | evidence |
|---|---|---|---|---|---|---|
| `lookpath-bwrap/identity-forged` | same-uid | `ENFORCED` | a launcher any component of whose path this uid may write is refused, and the run with it | `LOGGED-ONLY` (the refusal names the writable component) | evidenced | `internal/linux/probe.go:566` (`trustLauncherPath`); `launchertrust_test.go`. Not `checkLauncher` at `linux.go:976`: that seam rules on `sb.bentoPath`, which comes from `os.Executable()`, and two of its three callers have no bwrap at all |
| `lookpath-bwrap/check-bypassed` | same-uid | `PARTIAL` | six fences are re-checked from inside; ten flags are not | `LOGGED-ONLY` (the six refusals name what they saw) | read | `verify.go:31,61,134,197,322`, `netns.go:29` against `args.go:511,549,693,388` |
| `lookpath-bwrap/search-path-hijacked` | same-uid (next run) | `ENFORCED` | a granted `bin` directory is by construction writable by this uid, so a `bwrap` planted in it refuses the next run instead of unconfining it | `LOGGED-ONLY` | evidenced | `internal/linux/probe.go:566`; `TestRunRefusesAUserWritableLauncher`. The auto-exec report still names neither shape (`autoexec.go:32,63`), which no longer matters for this row |
| `lookpath-scoperunner/identity-forged` | same-uid | `ENFORCED` | under limits the scope runner is the outer process, inheriting fd 3 and the liveness pipe; one this uid may replace is refused, and the run with it | `LOGGED-ONLY` (the refusal names the writable component) | evidenced | `internal/linux/limits.go:89` (`resolveScopeRunner`), gated at `limits.go:230` (`preflightLimits`); `scoperunnertrust_test.go`. The probes' own canaries are the next two rows, not this one: they are executed before any preflight rather than wrapping the launch |
| `probecanary/identity-forged` | same-uid (next run) | `ENFORCED` | the probes execute their canaries before any preflight, so a planted `sh` or `true` is code execution as this user rather than a forged verdict; one this uid may replace is refused and each probe falls closed (scope unanswered, controllers unknown, namespaces unknown) | `LOGGED-ONLY` (the refusal names the writable component) | evidenced | `internal/linux/limits.go:506` (`trustedProbeBinary`), reached from `measureScope` (`limits.go:132`), `measureDelegatedControllers` (`limits.go:400`) and `canUnshare` (`probe.go:666`); `probetrust_test.go`. The conventional path is preferred over PATH so an ordinary user-level shell (a Nix profile, a mise shim) is never the one resolved |
| `probecanary/systemd-run-unchecked` | same-uid (next run) | `ENFORCED` | the probes' own `systemd-run` goes through the same provenance check as their canaries, so a planted one is refused before it runs rather than executed as this user; `measureScope` leaves no verdict and `measureDelegatedControllers` reports the set unknown, both the fail-closed direction. Absence stays the ordinary "limits cannot be enforced" verdict and is still cached | `LOGGED-ONLY` (the refusal names the writable component) | evidenced | `internal/linux/limits.go` (`scopeProbeRunner`), reached from `measureScope` and `measureDelegatedControllers`; `TestProbesDoNotExecuteAnUnvouchedScopeRunner` in `probetrust_test.go` asserts non-execution rather than the reason text, since the harm here is execution and the verdict half was already closed |
| `lookpath-bwrap/privilege-inherited` | same-uid | `ENFORCED` | the descriptors are still inherited, but only by a launcher whose provenance was established first | `SILENT` | read | `internal/linux/probe.go:525` gates every launch that passes them; `internal/linux/applied.go:23` records why the channel's origin is rooted there and not in its bytes |
| `parseapplied/identity-forged` | same-uid (as the shim) | `ENFORCED` (by provenance, not by content) | a forged report still parses, but only a launcher `resolveBwrap` vouched for can write one | `SILENT` | evidenced | `internal/linux/probe.go:525`; the residual is documented at `internal/linux/applied.go:23`. No authenticator on the bytes can close this: whatever the host launches shares its argv and environment, so a nonce reaches the forger too |
| `parseapplied/state-mutated` | same-uid | `ENFORCED` | a post-marker edit voids the report rather than being accepted | `LOGGED-ONLY` | read | `internal/linux/applied.go:152,157` - monotone: claims can grow, never retract |
| `parseapplied/path-traversal` | local-user | `ENFORCED` | a substituted file at the path cannot reach the read | `SILENT` | read | host holds the descriptor from before the child started; `internal/linux/applied.go:109`, `:90` (0600 in a 0700 per-run dir) |
| `parseapplied/log-forgeable` | same-uid | `ENFORCED` | a newline in a detail cannot forge a record | n/a | read | `internal/launcher/applied.go:133` quotes every detail with `%q` |
| `parseapplied/resource-unbounded` | same-uid | `ENFORCED` | an unbounded argv would lose the section, not just lengthen a line | n/a | read | `internal/launcher/applied.go:75` caps at 4096 and marks the cut |
| `run-launcher/state-mutated-netns` | same-uid, as the shim | `ENFORCED` | a host network stack is refused before the target runs | `LOGGED-ONLY` | read | `internal/launcher/netns.go:29`; `netns_test.go:68` |
| `run-launcher/state-mutated-tmp` | local-user | `ENFORCED` | a host `/tmp` (read and write, since `/tmp` is in the writable set) is refused | `LOGGED-ONLY` | read | `internal/launcher/verify.go:31`; `verify_test.go:37` |
| `run-launcher/state-mutated-pidns` | same-uid, as the shim | `ENFORCED` | the host process table and its `/proc` are refused | `LOGGED-ONLY` | read | `internal/launcher/verify.go:61`; `verify_test.go:91` |
| `run-launcher/state-mutated-capbound` | same-uid, as the shim | `ENFORCED` | a non-empty bounding set, which would let the read-only binds be remounted rw, is refused | `LOGGED-ONLY` | read | `internal/launcher/verify.go:322`; `verify_test.go:236` |
| `run-launcher/state-mutated-terminal` | same-uid | `ENFORCED` | a bwrap that did not put the sandbox in a session of its own refuses the run | `LOGGED-ONLY` | evidenced | fatal in the degraded tier at `degraded.go:120,226`; the bwrap tier now probes it from the shared `args.go:528` (`sessionFlags`) and proves it from inside at `internal/linux/probe.go:607` (`sessionProof`, a nonzero session id in the namespace-local procfs). The probe's reading is namespace-local, so it is vacuous against a host `/proc`; what refuses that shape is `internal/launcher/verify.go` (`verifyPidNamespace`) seeing the host process table at launch, so the two legs together are the fence. Tests: `newsession_test.go` end to end over a real pty, and `TestTheNamespaceProbeProvesTheNewSessionTook` on every host |
| `run-launcher/state-mutated-dev` | same-uid | `ENFORCED` | any `/dev` name neither bwrap's `--dev` nor this run's own grants account for is refused, a single injected bind included | `LOGGED-ONLY` (the refusal names the nodes it saw) | evidenced | `statfs("/dev")` is `TMPFS_MAGIC` on this host, so the `/tmp` trick does not transfer; `verifyDevMount` (`verify.go:134`) lists `/dev` against the closed set bwrap's `--dev` creates plus `Config.GrantedDevNames`, the top-level `/dev` names `internal/linux` derived from the run's resolved grants. A policy may grant a path inside `/dev` (`checkGrantNotManagedMount` refuses only the whole root) and that grant binds after `baseFlags`, so a legitimate `/dev/dri` or `/dev/net/tun` run puts a name there `--dev` never creates - the grant set is what tells those from an injected one. This previously asked the kernel whether the name was a mount of its own, which could tell neither a shim's `--dev-bind /dev/mem /dev/mem` (a mount too) nor a host `/dev` assembled from per-node binds the way a rootless container runtime builds one; `ownMountUnderDev` is deleted and both residuals close with it. Tests: `verify_test.go`'s `TestRunRefusesTheHostsDev`, `TestRunAcceptsAGrantInsideDev` and `TestRunRefusesADeviceNodeNoGrantNamed` |
| `run-launcher/state-mutated-shields` | same-uid | `ENFORCED` | a dropped `--ro-bind` or `--tmpfs` shield argument is refused before the target runs, rather than exposing that credential store for the run's length | `LOGGED-ONLY` (the refusal names the path and the shape it expected) | read | `args.go:318` builds them; `verifyShields` (`verify.go:197`), the sixth in-sandbox verify, confirms each from inside - hidden means nothing readable is left at the path, read-only means a write is rejected there, and `internal/linux` decides which shape from the same `shieldMount` that built the argv (`shieldChecks`), so a shield whose shape is host-dependent is compared against what was actually mounted. The Landlock backstop is no second layer here: `landlock_linux.go:102` read-grants `/`, which is the whole reason this needed its own verify |
| `run-launcher/privilege-inherited` | same-uid (bento's embedder) | `ENFORCED` | every leaked descriptor is CLOEXEC-marked before the bridge or the target | `SILENT` | read | `internal/launcher/launcher.go:217` (`dropInheritedFDs`); `launcher_test.go:230` |
| `run-launcher/internal-disclosed` | same-uid (the target) | `ENFORCED` | `/proc/<launcher>/fd` would reopen dropped fds by path and disclose host paths | `SILENT` | read | `PR_SET_DUMPABLE` at `internal/launcher/launcher.go:252`, and its comment on why bwrap alone is not the guarantee |
| `refusenetworkstdio/check-bypassed` | same-uid (bento's parent) | `ENFORCED` | an inherited socket, directory, device or nsfs handle on stdio walks past every fence | `LOGGED-ONLY` on the waived path | read | `launcher.go:579,639,767,836`; `stdio_socket_test.go:22,365`. Both tiers: `launcher.go:200`, `degraded.go:177` |
| `decodelaunch/input-unvalidated` | same-uid, as the shim | `ENFORCED` | a relative `--rw` would confine the target to a tree the policy never granted | `LOGGED-ONLY` | read | `launcher.go:125`; degraded sibling at `degraded.go:148`, plus scratch membership at `:164` |
| `decodelaunch/input-reinterpreted` | same-uid, as the shim | `ENFORCED` | an unknown exec mode is refused rather than defaulting to the weakest | `LOGGED-ONLY` | read | `reexec.go:135` (`parseExecMode` default arm), and `reexec.go:114` panics rather than silently disarming; `reexec_test.go:93,103` |
| `decodelaunch/privilege-inherited` | same-uid, as the shim | `ENFORCED` | an fd flag naming a standard stream would write the report into the target's stdio and close it | `LOGGED-ONLY` | read | `launcher.go:134,143`, `internal/launcher/applied.go:122`; `stdfd_test.go:19` |
| `restrict/default-permissive` | same-uid | `BY-DESIGN` | the bwrap-tier backstop grants read of `/` and confines writes only | `SILENT` | read | `internal/landlock/landlock_linux.go:102-104`; the degraded tier names its read set explicitly (`degraded.go:35`) because there it is the only fence |
| `rundegraded/fail-open` | same-uid | `ENFORCED` | every fence in the tier is fatal, so a marker-bearing report is itself the proof | `LOGGED-ONLY` | read | `degraded.go:120,209,216,226,232`, and the seam list at `degraded.go:103` explaining why each is pinned |
| `rundegraded/confinement-partial` | same-uid | `ENFORCED` | the tier refuses rather than running with a missing fence | `LOGGED-ONLY` | read | `degraded.go:120`; `degraded_prereq_test.go:23,128` |

## Not spiked

**Covered by an existing test or fuzz target - walked on every CI run, which is
better than one spike would leave it.** All three suites pass at `0abf849`
(`GOWORK=off go test ./internal/launcher/... ./internal/landlock/...
./internal/linux/...`, 1.8s / 5.4s / 70s).

- the four `verify.go` fences: `verify_test.go:36,90,131`, `netns_test.go:68`
- terminal detachment as a property: `internal/linux/newsession_test.go`
- the stdio descriptor screen, family by family and kind by kind:
  `stdio_socket_test.go:22,365`, `stdfd_test.go:41`
- the launch wire codec, including the modes that must not round-trip:
  `reexec_test.go:15,58,93,103`, `reexec_fuzz_test.go`
- the report's tamper stance: `internal/linux/applied_test.go`,
  `applied_fuzz_test.go`
- the degraded tier's refusals: `degraded_prereq_test.go`
- the exec-block fail-closed path: `installfilter_test.go:74`,
  `applied_test.go:94`

**Not attempted because nothing this run could do reaches it.** These are gaps
in this document's evidence, not in the code.

- a real `bwrap` shim under a real `bento run`: spawns a process to attempt a
  crossing, and no consent gate was available (`UNSPIKEABLE HERE`). This is what
  would settle F1's escalating variant and every `lookpath-bwrap` row.
- a dropped `--new-session` and an actual `TIOCSTI` into the invoking terminal:
  same reason, and this run has no controlling terminal to inject into
  (`open("/dev/tty")` returned `ENXIO`).
- a dropped shield under a broad read grant: needs a sandbox stood up
  (`UNSPIKEABLE HERE`).
- applying a Landlock ruleset to observe what `Restrict` actually denies: the
  package's own comment at `landlock_linux.go:300` says why nobody does this in
  process - the restriction is irreversible and would Landlock the test binary.
  `backstopRules` exists precisely so the granted set is assertable without
  applying it.

## Dropped rows

- every `S` row against `decodelaunch` and `run-launcher` other than the ones
  above: nothing downstream depends on who sent the invocation, only on what it
  says. The identity question is `lookpath-bwrap`'s, where it is kept.
- `action-unattributed` scope-wide: the run's report and the exec record are the
  attribution surface and are `internal/linux`'s to model; the launcher writes
  what it installed and the host reconciles it.
- `oracle-timing`, `compare-non-constant`, `rotation-absent`: no secret is
  compared or held in this scope. The launcher handles a socket path, not a
  credential.
- `resource-unbounded` and `lock-held` against `run-launcher`: the outside does
  not choose the size of anything here, and the bridge's own bounds
  (`launcher.go:1159,1180,1257`) are availability engineering rather than a
  crossing. `blocked-availability` likewise: the four verifiers refuse loudly,
  which is the declared behavior, and the cost lands on a run that was already
  lying to itself.
- every parser row (`depth-unbounded`, `type-confused`,
  `decompression-amplified`, `entity-external`): the report format is
  line-oriented with a fixed key vocabulary and no nesting.
- `destination-unscreened`, `redirect-followed`, `tls-unverified`,
  `rebind-dns`: the launcher's only outbound destination is a constant
  (`proxyAddr`, `launcher.go:35`) inside a verified-empty netns. The screening
  lives host-side in `internal/proxy`.
- `query-injected`, `template-injected`, `shell-injected`: no query language, no
  template, and no shell - both exec paths take an argv slot.
- `secret-in-argv`, `secret-at-rest`, `secret-logged`: the launch wire carries
  paths, fd numbers and an exec mode. No credential crosses it.
- every row whose only attacker is root: dropped per `docs/threat-model.md`
  section 3.

## Handoffs

Kept at their grades above and counted once; listed because someone else should
walk them.

- `state-grid`: `run-launcher/state-mutated-terminal`. Two tiers that must agree
  on a fence, where one enforces it fatally and the other relies on a flag.
  `docs/state-grid-degraded-tier.md` grids the tier pair but along the layer
  axis; the terminal fence is a cell that axis does not name.
- `state-grid`: the flag-versus-verification delta as its own grid - fifteen
  bwrap flags by "checked from inside / backstopped host-side / neither". This
  document lists it as prose in F4 and F5; it is really a grid, and it is the
  artifact that would keep a new flag from arriving unverified.
- `concurrency-audit`: not a row here, but noted. `docs/threat-model.md` section
  5 describes the alias scan as a snapshot with a window that stays open through
  the tree walk. That is a check-to-use interleaving, which this skill cannot
  see.
- `fuzz-oracle`: `parseapplied`. `internal/linux/applied_fuzz_test.go` exists;
  whether its oracle asserts the monotonicity property F1's ceiling rests on, or
  only that the parser does not panic, decides how much that row's `ENFORCED`
  is worth.

## Teardown

Two `zz_spike_test.go` files (one in `internal/launcher`, one in
`internal/linux`) were written into the checkout to reach unexported symbols, run
once each, and deleted. `git status --porcelain` is empty. No process was
started, no port bound, no tracked file modified. Nothing is left running.
