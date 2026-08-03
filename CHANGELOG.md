# Changelog

Notable changes to Bento. Because Bento is a sandbox, every entry is written to
answer one question without reading the diff: did the boundary move, and in
which direction? See [SECURITY.md](SECURITY.md) for how versioning treats a
boundary change.

Each entry lists the changes since the previous tag. The 0.1.0 entry is the
exception: it describes the boundary as it first shipped, not the 380-odd
commits that built it - none of them were ever in a release.

## 0.2.1 (2026-08-03)

A patch bump: nothing about the boundary moved. These are all fixes to what
bento tells you - one report that claimed more than it enforced, and several
failures that said what was wrong without saying what to do about it.

### Boundary Reporting

- **`doctor` no longer reports the exec block as total**: the exec-block layer
  denies `execve` and never `execveat`, which the launcher itself needs to reach
  the target. `bento validate` said so over a manifest that blocks exec; doctor
  claimed `enforced` and stopped there. The layer now carries that seam even when
  it holds, as a note under doctor's table and a `consequences` field on the
  enforced row of `doctor --json` and `run --json`. The boundary did not move -
  what moved is how much of it the report admits to.

### What a Run Tells You

- **Exit 127 from a shell now explains itself**: unless the manifest passes
  `PATH` through, the sandbox uses its own, and a bare command name is only
  looked for in those two directories. The shell just says it could not find the
  command, so you never learn where it looked. `run` now prints that path along
  with the three ways out: grant the tool's directory, allowlist `PATH` in
  `env:`, or call the tool by absolute path. Only shells get this, since other
  languages are free to use 127 for whatever they like.
- **The 127 and missing-`HOME` notes now check what the sandbox actually got**:
  they used to check the manifest's `env:` list, which can name a variable the
  host never set. If `HOME` was allowlisted but unset, the note stayed quiet
  when it should have fired. Both now look at the environment the sandbox was
  handed.
- **`run` stops suggesting `--allow-degraded` when it would fail**: on a host
  that cannot enforce resource limits, the refusal offered that flag even under
  `--strict`, which rejects the two together. Under strict you now get the one
  fix that works - drop `limits:` from the manifest - and only when limits are
  the whole problem, since dropping them does nothing for a degraded filesystem
  tier.
- **Ownership warnings say what to do**: when the manifest or its directory
  belongs to another uid, which is normal in a container that checks out sources
  as one user and runs the job as another, bento reported the problem and left
  it there. Root now gets the `chown`; everyone else is told to move the
  manifest somewhere they own, rather than a command that would just fail.

### Profiling (`bento profile`)

- **A shell that cannot find a command gets its own warning**: the usual advice
  is "fix the run and profile again", but that goes nowhere here. Looking up a
  bare name is all existence probes, which the observer drops by design, so
  nothing gets recorded and the next round comes out the same. That case now
  gets its own message with the sandbox PATH and the absolute-path fix. If
  something was exec'd, the target does get recorded, so the usual advice stands
  and this message stays out of the way.
- **`PATH` still stays out of discovery**, with the reasoning now written down:
  bento cannot pass it without also recording it, and a manifest carrying `PATH`
  resolves bare commands against whoever's shell ran the profile, so it stops
  naming the same programs on every machine.

### Documentation

- `examples/embed` covers driving bento from another language over the
  subprocess contract.
- The README spells out the shared-kernel boundary, and lists crossbuild among
  the gates.

## 0.2.0 (2026-08-02)

A minor bump because `bento run --json` changed shape - see the breaking section
at the end. Pre-1.0 that is what a breaking change earns; see
[SECURITY.md](SECURITY.md).

### Boundary Hardening

- **Off-Linux is a refusal, not a crash**: every command that would enforce
  something refuses on a non-Linux host before it does any work. `version`,
  `help` and shell completion still answer, since they enforce nothing and a
  build identifier is the first thing a bug report needs. Bento's guarantees are kernel
  features that only exist on Linux, so a build that ran anywhere else enforced
  nothing while looking like it did. The refusal stays inside the `--json`
  envelope, so a machine consumer reads it as a refusal rather than a crash.
- **`validate` predicts the grants the run refuses**: a write grant naming an
  existing file, and a read or write grant whose symlinks loop, aborted the run
  at sandbox setup while `bento validate` said nothing. Validate now reports both
  in the same words the run refuses them in, and `validate --strict` fails on
  them, so a CI gate and the run agree on what is grantable.
- **`supervise` no longer prompts for the walk down to the script**: the example
  supervisor asked about each directory on the path to the script it was told to
  run. The boundary moved tighter - a routine "yes" to one of those prompts
  granted a recursive read several levels above anything the script named
  (`~/src` and up).
- **Grant and shield paths are cleaned before they are compared**: a `.` or `..`
  segment on either side of a containment test - a grant, a denylist query, a
  record awaiting judgement - was compared literally, so a path that resolved
  inside a shield could read as outside it. Both sides are cleaned now.
- **An unexpanded `~` is refused at enforcement**: a `~` that reached the
  enforcer without being expanded was treated as a literal directory name.
  It is refused instead, and a nil policy is answered rather than assumed
  expanded.
- **A grant that lifts a shield is raised before the stamp**: `validate` and
  `approve` now resolve grants against the shields the way `run` does, refuse
  the ones `run` refuses, and call out an exact-shield opt-in - including on the
  already-approved shortcut, which previously returned early. A manifest stamped
  by an earlier bento no longer reads as approved for permissions the run
  refuses.
- **A run whose in-sandbox setup never attested is refused**: `enforce` refuses
  rather than reporting an outcome for a stage that never said it got there, the
  backend refuses a `New()` that never dispatched, and an undispatched re-exec
  stage panics rather than continuing as the parent.
- **`approve` refuses a non-terminal stdin**: a stamp nobody read is now
  something a caller asks for with `--yes`, not something the absence of a
  terminal decides. The example supervisor's `run` refuses the same way.
- **The shared-write warning proves group membership without NSS**: the check
  for "somebody else can write this" read routes that `LD_PRELOAD` could put
  back under the caller's control, and warned on a private group holding only
  its owner. It now resolves members through the same pure-Go path the shields
  anchor on, and a member passwd cannot resolve is not taken as proof.
- **`profile` proposes less**: unix socket grants are withheld entirely, the
  entrypoint's ancestor chain is no longer proposed as a read grant, and a host
  that cannot sandbox is refused before anything is observed rather than after.
- **A shebang's interpreter arguments reach the exec policy**: an interpreter
  line carrying arguments (`#!/usr/bin/env -S python -u`) had them dropped, so
  the policy attested an exec the run did not make.
- **The example supervisor's trial is read-only**: the trial run no longer
  writes, and no longer trims `/tmp` workspaces it did not create.

### `approve` is a review step, not a stamp

`approve` printed four numbered steps whose last command printed one line, which
made typing it the path of least resistance over reading the policy. It now
prints the permissions it is about to stamp, calls out the entries that deserve a
second look, and asks before writing - `--yes` for scripts and CI.

- It resolves the entrypoint the way `run` does, so the reviewer sees what will
  actually execute.
- It says when nobody reviewed and when the stamped policy has drifted, with the
  drift notice after the callouts rather than buried above them; an unattested
  run is worded as unknown rather than as unrun, and a stale stamp says why it
  has no diff to show.
- Egress a profiling run reached and the guard refused is recorded on the
  manifest as `blocked-hosts` and called out here. The record is provenance, not
  permission: it does not shift the approval fingerprint and it does not widen
  anything.

### Profiling (`bento profile`)

- **`--json`**: the draft, the notes and the refusals come out as one document,
  with probed-versus-resolved carried through the envelope so a consumer can tell
  a path the target opened from one bento resolved for it.
- **Manifests are written in the relocatable form**: a path under the manifest's
  own directory is emitted `./`-relative and one under your home `~/`-prefixed,
  so the result can be committed and used by someone else. A path under neither
  stays absolute and names this machine.
- **`/tmp` grants are disclosed as the target's request**: a proposed grant under
  `/tmp` reaches the draft because the name exists on this host, which is the
  only way a real workspace there can be told from the sandbox's own scratch - so
  a target opening guessed names can steer what lands in the proposal. It is now
  named as such rather than presented as an observation.
- **The interpreter comes from the script's shebang**, not its extension, with
  the interpreter the run actually used merged back into the draft and its
  argument cost stated. A whole-workdir grant is called out, a granted write
  directory is created the way `run` creates it, and a merge into an existing
  manifest says what it changed.
- **The run is honest about its own shape**: the target's stdout passes through
  rather than being swallowed, every converge round runs under the base
  invocation, and a run that ended before the rounds converged says so instead of
  presenting the last draft as settled.

### What a Run Tells You

The boundary did not move for any of these; what a user can see about it did.

- **Denials name the manifest field that caused them**: `bento run` prints a
  legend mapping a denial's errno to the grant that would have permitted it -
  "Read-only file system" to `write:`, "Operation not permitted" to `exec:`.
  This is new output on runs that previously said nothing, including runs that
  exit 0.
- **A degraded refusal leads with its remedy**: a refusal on a host that cannot
  fully enforce a core layer opened with what is broken and the command that
  fixes it, then buried it under a tier-consequence enumeration identical on
  every degraded host. The run refusal now carries the diagnosis and points at
  `bento doctor` for the rest; `doctor` still prints every fact it printed
  before. `enforce.LayerStatus` gained a `Consequences` field and a
  `Disclosure()` method for embedders that describe a layer in full, plus
  `Report.AddStatus`/`SetStatus` for forwarding a status whole. No disclosure was
  dropped, only relocated.
- **A userns refusal in a container names the flags that lift it**: the probe's
  reason now spells out the `docker run --security-opt` flags rather than leaving
  the reader to find them in the README.
- **A file-shaped write grant says what it will actually do**: a `write:` entry
  that does not exist yet and is spelled like a file (`./out/log.txt`) becomes a
  *directory* under that name, so the script's own write to it fails with "is a
  directory". `validate` and `run` both say so before the run rather than leaving
  the reader to infer it from the failure.
- **A death by SIGSYS names the filter that caused it**: the filters bento
  installs kill only on a foreign-architecture syscall, and a withheld permission
  is refused with EPERM instead - so the run says the signal is most likely that
  guard rather than a grant the reader can add.
- **Exit 126 under a blocked exec is explained**, with the hint worded for a
  manifest that omitted the `exec` line and gated on the block actually landing.
  A non-zero exit points at `bento profile`.
- **`HOME` inside the sandbox is stated up front**: it is not passed through, so
  `~` expands somewhere else and a script resolving `~` itself misses grants
  matched against host paths. The note repeats when a run trips it.
- **A rule covering an egress the guard refused is noted** by `validate` and
  `run` - the destination resolved to loopback, private space or cloud metadata,
  and this run refuses it the same way rather than the rule widening it.
- **A killed run says it was killed**, without guessing who did it, naming the
  signal, and blaming limits only for a cgroup kill.
- **A usage mistake answers in the `--json` envelope**: a bad flag, an unknown
  subcommand and a size-spelling error come back as a refusal with usage and a
  hint rather than as bare cobra output, with every spelling of `--json` read
  during the scan and unknown refusal shapes rejected at every depth.
- **A manifest reports every bad field in one pass** instead of one per parse.
- **`run --json` carries a missing read grant, denied egress and a flag
  conflict**, and discloses the alias scan a degraded tier skips.
- **A limits refusal names the way past it**: it said the limits could not be
  enforced without saying whether to waive the tier or drop the `limits:` block.
  `enforce.Refusal` gained a `Waivable` field carrying which one applies.
- **The shared-write warning is quiet where no stamp is at stake**: `run`,
  `validate` and `profile` warned that somebody else could edit an unapproved
  manifest, which is true and beside the point - nothing was attested to drift
  from. `approve` still refuses.
- **`doctor` reports its own limits more plainly**: it names the platform and
  flags one whose enforcement is unverified. A degraded line now leads with the
  real cause in plain language rather than a semicolon-joined fragment or raw
  bwrap output, oversized detail moves below the table, and the exit code is the
  same with `--json` as without.
- **The sandbox probe is more useful when it fails**: it says how to install
  bwrap, spells out the `docker run --security-opt` flags a userns refusal in a
  container needs, reads a refused base mount honestly, and says why the shield
  probes skipped.
- **`bento version` answers on every install path**: a `go install` or plain
  `go build` binary reports the module version Go recorded - a release tag for
  `@latest`, a pseudo-version for a checkout - instead of `dev`. `make build`
  stamps the commit and build time it derives from the source, and now derives
  the version too rather than carrying a literal that goes stale at every tag.
- **Paths printed back are quoted** by the credential hunt, error text drops its
  package prefix, and passing a script where a manifest belongs names the
  manifest bento expected.

### Platform and Embedding

- **`validate` and `approve` answer off Linux**; every other command refuses
  before doing any work, names the architecture, and keeps the refusal inside the
  `--json` envelope. The Linux-only tree is behind build tags and the no-backend
  stub is tagged `darwin`, so a macOS build produces a working binary rather than
  failing to compile. Linux and macOS are the only targets that compile at all.
- **`enforce` reports how far in-sandbox setup got** and exposes the caller's
  deny paths on the enforced run, so an embedder can tell a target that failed
  from a sandbox that never reached it - which `examples/supervise` now reports.
- **`internal/observe` distinguishes a probed path from a resolved one** and
  treats only ENOENT as "nothing was there", carrying `Probed` on the non-Linux
  `Access` too.
- **`policy` exports the path-coverage predicate** that grant and shield
  comparison use, so an embedder tests containment the way the enforcer does.

### Performance

Shield rules are resolved once per invocation rather than per grant, the
credential hunt indexes the deny rules before walking a home directory, and
`policy.CoversResolved` no longer allocates.

### Breaking: `bento run --json` is now a stream

The boundary did not move. What changed is the machine contract: `run --json`
put one indented JSON document on stdout at the end of a run, with the script's
whole output carried in its `stdout` and `stderr` fields. It is now a stream of
JSON objects, one per line, written as the run happens.

Every object carries an `event` field, which is what a consumer switches on:
`stdout` and `stderr` for chunks of the script's own output as it arrives, then
exactly one `verdict`, `refusal` or `failed` object last. The verdict is the
old envelope minus the two stream fields; `refusal` is what `refused: true`
used to say. Chunk bytes are base64, because a script is untrusted and can
print anything - the old string fields silently replaced invalid UTF-8 with
U+FFFD, so a script emitting binary had its output corrupted with nothing to
say so.

Two things this answers that the document could not. A run no longer costs
memory proportional to what the script printed: measured peak RSS was ~1x the
output volume (12.5 MB at 1 MB of output, 75.2 MB at 64 MB) and is now flat at
~11-12.7 MB across the same range. And the two streams are labelled as they
arrive - the old shape copied both undistinguished onto bento's stderr for
progress, so nothing could tell them apart until the run had ended.

There is no compatibility mode. Two output shapes behind one flag is the thing
to avoid, not the compromise; a consumer of the old envelope pins the previous
release until it reads the stream.

`bento profile --json`, `validate --json` and `doctor --json` are unchanged -
they answer with a single document, and a refusal from `profile` still carries
`refused: true`.

## 0.1.1 (2026-07-29)

### Boundary Hardening

- **Refused network stdio**: The launcher now refuses execution if `stdin`, `stdout`, or `stderr` are network sockets, regardless of manifest egress grants. This closes socket-inheritance bypasses where a sandboxed process could communicate over pre-opened network file descriptors without passing through the host proxy.
- **Refused `write: /`**: Manifest validation now rejects a write grant of the root directory (`write: /`) outright.
- **Fail closed on non-amd64 architectures**: The seccomp filter now explicitly refuses execution on non-amd64 architectures rather than quietly skipping the seccomp architecture guard.
- **Fail closed on proxy & NAT64 failure**: The HTTP CONNECT egress proxy fails closed (refuses connection) when NAT64 prefix discovery cannot answer, when RFC 6052 address layout is invalid, or when NAT64 translation fails to derive a target.
- **Fail closed on unwalkable credential paths**: Credential alias resolution and home directory traversal fail closed when directory walking cannot complete due to permission errors or unreadable paths.
- **Expanded default shields**: Added `.claude.json.backup` to default credential denylist shields and ensured relocated `XDG_RUNTIME_DIR` paths are shielded across all user anchors.
- **Normalized proxy hostnames**: Trailing DNS root dots (e.g. `example.com.`) in HTTP CONNECT targets are stripped before matching against manifest host rules.

### Boundary & Information Disclosure Fixes

- **Proxy refusal privacy**: Proxy refusal bodies no longer disclose resolved destination IP addresses to the sandboxed caller.
- **Embedder observer protection**: Embedder observer panic handling prevents proxy panics from disrupting host enforcement.
- **Standardized guard refusal**: Guard-blocked connection attempts return standard dial failure responses rather than disclosing internal gate errors.

### Profiling & Observability (`bento profile`)

- **Entry-stop syscall decoding**: Syscall pathnames and `execve` events are now decoded at entry stops rather than exit stops, preventing missed system calls (such as `execveat`) and eliminating false phantom drop counts.
- **Thread probe accounting**: Fixed probe leak and drop accounting during thread termination, `execve` thread retirement, and root exit.
- **Credential alias scanning in profiling**: `bento profile` now executes credential alias scanning to detect foreign-home credential stores during profiling runs.

### Operator Surface & Platform Refinements

- **Surfaced guard blocks**: Operator and supervisor summaries now report destinations blocked by network guards.
- **Landlock degraded tier**: Added `resolve_unix` handling to Landlock's degraded tier and stopped requesting ungranted Landlock rights.
- **Shield mount cleanup**: Shield mount points created during a sandbox run are explicitly reclaimed upon exit.

## 0.1.0 (2026-07-27)

First release. Linux (amd64) is the enforced platform; arm64 and macOS are not
yet supported.

### Enforcement

- Deny-by-default filesystem: only manifest-granted paths are visible inside the
  sandbox. Reads are bound read-only, writes are bound per-directory (so
  save-via-rename keeps working), and the sandbox root is remounted read-only.
- Egress denied by default via an unshared, empty network namespace. Declared
  `host:port` rules are routed through a host-side HTTP CONNECT proxy reached
  over an isolated unix socket, with hostname validation and IP pin checks.
- Subprocess execution blocked by a seccomp filter. `exec: none-strict`
  additionally blocks `fork`/`clone` on amd64.
- Memory, CPU, and PID limits enforced through a transient systemd scope on
  cgroup v2 controllers.
- Landlock rules applied as a best-effort second filesystem layer behind the
  mount namespace.

### Shielded by default

A mandatory denylist covers these even under a broad grant such as `read: ~`,
and covers paths that do not exist yet so a sandboxed program cannot create
them:

- Credentials and secret stores: SSH keys, cloud CLI tokens, GPG keyrings, OS
  keyrings, crypto wallets, environment-relocated secret directories, and shell
  histories.
- Persistence vectors: `.git/hooks`, `.vscode`, `.idea`, and shell startup files
  such as `.bashrc` and `.zshrc`.
- Host control sockets under `/run` and `/var/run` - the Docker daemon socket,
  `gpg-agent`, the session bus, and similar.

The shields anchor on both `$HOME` and the running uid's passwd entry, so a
caller-chosen environment cannot relocate them off the real credential stores:
under `HOME=/` those stay shielded rather than the shields moving to `/.ssh`,
`/.aws` and so on. Two limits: where the uid has no passwd entry at all (an
LDAP host whose module is not loaded, an unmapped container uid) `$HOME` is the
only anchor left, and the passwd lookup must not route through libc NSS, which
`LD_PRELOAD` would put back under the caller's control - the shipped build is
static and tagged `osusergo`, which keeps it in pure Go. `$HOME` still decides
where a `~` grant points and which spellings count as a deliberate shield
opt-in; see the threat model.

A write grant that covers a shielded path is refused outright - including a
grant above a home directory that is itself a symlink, where the shield's
resolved location leaves the granted tree while the symlink inside it stays
writable. A read grant naming an exact shield path is honored as a deliberate,
warned exception.
`make audit` checks the denylist against upstream firejail reference definitions.

### Workflow

- `bento profile` observes a program under default-deny and drafts a manifest.
  It reads syscall registers via ptrace rather than opening host files, so a
  hostile program cannot use profiling to probe secrets. Egress is recorded but
  still blocked.
- Manifest paths resolve against the manifest's own directory, and a leading `~`
  expands to the invoking user's home - so a `read: "~"` grant means home and is
  shielded accordingly, rather than naming a file beside the manifest. Another
  user's home (`~operator/...`) is refused rather than guessed at. Because the
  fingerprint attests the manifest as written, a `~` grant resolves against
  `$HOME` at run time; see the threat model.
- `bento validate` parses a manifest, rejects malformed fields, and prints the
  requested permissions and resource limits (`--json` for machine output). Under
  each grant it also prints what that grant lands on for the host it is run on,
  following symlinks as well as `~` and relative prefixes, so a reviewer can see
  what the grant reaches before approving it - a `~` grant whose `.ssh` is a link
  elsewhere would otherwise read as a path under `$HOME`. `--json` carries the
  same answer as `resolved_read`/`resolved_write`, and `run --json` carries
  `shielded_grant_targets` for an opted-in shield, so a CI gate reads what the
  human summary shows rather than the spelling alone. The literal `read`/`write`
  are unchanged: they are what the fingerprint attests.
- The refusals a manifest can earn without consulting the host are raised by
  `validate` and `approve`, not left for `run`: a `~operator/...` path, and a
  write grant of the home directory itself (whatever `$HOME` is, the credential
  stores sit inside it, so such a grant would make their parent writable). Both
  were already refused at run, so on an ordinary host the gate simply moved
  earlier. The one manifest this newly stops is `write: ["~/.."]` on a host
  whose home directory is itself a symlink, which the enforcer accepted and
  should not have. The same grant spelled absolutely (`write: /home/u`) still
  needs `$HOME` to recognize and is still refused at run.
- `bento approve` stamps a fingerprint over the policy fields. `bento run`
  refuses an unapproved or since-edited manifest unless `--allow-unapproved` is
  passed, and re-checks the fingerprint at run time rather than trusting an
  earlier `validate`.
- `bento doctor` reports which isolation layers this kernel actually enforces.

### No quiet degradation

When a hardening layer is unavailable, Bento reports the shortfall instead of
falling back silently, and `--strict` makes `bento run` refuse to execute under
degraded enforcement.

### Embedding

The Go API (`backend`, `enforce`, `manifest`, `policy`) is importable for
in-process enforcement, including a `NetworkGate` callback that lets a host
application decide undeclared egress at connect time. See `examples/embed` and
`examples/supervise`. Pre-1.0, this API may change between minor versions.
