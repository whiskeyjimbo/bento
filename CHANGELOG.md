# Changelog

Notable changes to Bento. Because Bento is a sandbox, every entry is written to
answer one question without reading the diff: did the boundary move, and in
which direction? See [SECURITY.md](SECURITY.md) for how versioning treats a
boundary change.

Each entry lists the changes since the previous tag. The 0.1.0 entry is the
exception: it describes the boundary as it first shipped, not the 380-odd
commits that built it - none of them were ever in a release.

## Unreleased

The largest cycle so far. The boundary moved inward in a lot of small places -
around a hundred new shielded paths, a network fence on the degraded tier, a few
grants that used to slip past a shield - and a run says much more about what it
did and what this host could not do for it.

### Boundary Hardening

- **The egress guard takes the strictest NAT64 verdict, not the weakest.** A
  synthesized IPv6 is re-checked against the IPv4 each discovered Pref64 decodes
  out of it, and the per-prefix verdicts were folded with `max()` over the class
  enum - which is not ordered by strictness. An address a `/96` decoded to
  `169.254.169.254` and a `/64` decoded into RFC1918 came out private, so a
  manifest naming that IPv6 literal reached the cloud metadata endpoint. Inward,
  on a host publishing more than one Pref64. ISATAP and IPv4-translated addresses
  are decoded too, and a partial-Pref64 decode no longer falls through to a guess.
- **A manifest can no longer lift a deny path its caller supplied.** Both
  consumers of the read opt-in matched a bare resolved path with no record of
  which rule set it came from, so a caller denying `~/.aws` had its shield
  skipped entirely by a manifest granting `read: ~/.aws` - nothing mounted, the
  real store bound read-only, nothing said. Inward, for runs that pass
  `DenyPaths`.
- **A shield that resolves onto the home is dropped, not mounted over it.** The
  guard compared unresolved paths, so on a host whose `/home` is a symlink,
  `GNUPGHOME=/home/u` arrived as a tmpfs over the entire home.
- **Around eighty more shielded paths, and a dozen more relocation variables
  followed.** Write-denied: the `$PATH`-resident shim directories (`~/go/bin`,
  `~/.pyenv/shims`, `~/.asdf/shims`, `~/.bun/bin`, `~/.local/share/pnpm` and
  more), where a plant runs under a bare command name the user already types; the
  shell plugin roots past `~/.oh-my-zsh`; the files an rc sources by name
  (`~/.p10k.zsh`, `~/.fzf.zsh`); `~/.config/zsh`, the conventional `ZDOTDIR`,
  which no shell exports; the VS Code forks and JetBrains trees; dbus service
  files and GNOME Shell extensions. Hidden outright: credential files no upstream
  corpus lists - `~/.authinfo`, `~/.hgrc`, `~/.curlrc`, `~/.dbt/profiles.yml`,
  `~/.config/borg/keys` and siblings. `GOOGLE_APPLICATION_CREDENTIALS`,
  `REGISTRY_AUTH_FILE`, `AWS_WEB_IDENTITY_TOKEN_FILE`, `TF_CLI_CONFIG_FILE`,
  `ANSIBLE_CONFIG`, `PGPASSFILE` and `WGETRC` move the shield with the file they
  point at. The cost: `go install`, `pyenv install` and the like no longer run
  in-sandbox, since a write grant naming one of those trees is refused.
- **Three more paths the host runs code from are shielded**: `~/.bash_completion`
  (sourced by every interactive shell),
  `~/.local/share/bash-completion/completions` (sourced on the first tab-complete
  of that command), and `~/.selected_editor`
  (`sensible-editor` runs it at the next `git commit` on a host with no
  `$EDITOR`). Write-denied, not hidden - reads stay allowed, a plant does not.
- **mise's trust record, the settings that bypass it, and pre-commit's hook cache
  are write-denied.** mise gates an in-tree `mise.toml` behind a per-host trust
  record, so denying the record covers every workspace config at once. Only the
  shims directory was shielded, so a run under a home write grant could author
  its own trust and have the config execute at the developer's next `mise` call.
  The bypasses go with it: `trusted_config_paths`, `yes`, and the three configs
  mise reads with no trust check (`MISE_GLOBAL_CONFIG_FILE`,
  `MISE_SYSTEM_CONFIG_FILE`, `MISE_ENV_FILE`). `~/.cache/pre-commit` holds the
  hook repositories the host executes at the next commit - the `.git/hooks` entry
  point was shielded, the code it runs was not. Two costs: `pre-commit
  install-hooks` cannot populate its cache in-sandbox, and an untrusted
  `mise.toml` has to be trusted by exporting `MISE_TRUSTED_CONFIG_PATHS` for the
  run, which grants nothing on the host.
- **`DIRENV_CONFIG`, `PRE_COMMIT_HOME` and the `MISE_*` directories move their
  shields with them.** Relocation could only follow a hidden directory or a
  single file, so on a host setting one the shield sat where the tool no longer
  reads. `DIRENV_CONFIG` was the sharpest: `direnv.toml`'s `[whitelist]` skips
  the allow check, so relocating it disarmed the allow-record shield beside it.
- **A credential a dotfile farm keeps outside its store is shielded where it
  really lives.** stow, chezmoi and yadm leave `~/.ssh` a real directory of
  symlinks into `~/dotfiles`: the shield binds over `~/.ssh`, and the file the
  link named was covered by no rule and read in full under a grant of `~`. Rules
  are emitted on the link, not the target, so a planted link to `/` cannot shield
  the whole grant. The alias scan also reaches caller deny paths, link-target
  directories and the exec paths now, runs on the degraded tier, and sniffs the
  head of a large file rather than only small ones (BOM-marked UTF-16 included).
- **A grant is refused where a case-folding filesystem would let it around a
  shield** - `read: ~/.SSH` is a different string and the same directory. Settled
  per path component against the host's own answer, on both the read and write
  sides.
- **An entrypoint inside a shielded path is refused.** bwrap is last-wins and the
  entrypoint re-bind is emitted after the deny list, so `entrypoint:
  ~/.ssh/id_ed25519, interpreter: cat` bound the key back over its own shield and
  read it out.
- **The degraded tier fences TCP.** The Landlock-only tier leaned entirely on the
  seccomp egress filter, which governs socket creation and so cannot revoke a
  socket the target already holds - SCM_RIGHTS fd-passing was a documented
  residual. Landlock's ABI 4 hooks are on `bind` and `connect` and judge the
  calling task, so a passed unconnected AF_INET fd now buys nothing. Still
  partial: an already-connected fd, UDP, raw, AF_PACKET and MPTCP rest on the
  filter killing them at `socket`. The tier also refuses a manifest with
  `network:` rules rather than running it under a blanket block while reporting
  the destinations as allowed, and a host with neither fence is refused outright.
- **The launcher screens what it inherits on stdio.** An nsfs handle, an
  anon-inode, a netlink socket and a writable kernel pseudo-file are refused - a
  writable `/sys/kernel/uevent_helper` alone runs a program of the writer's
  choosing as root. A procfs descriptor passes only if world-readable and
  read-only. A terminal is recognized by whether it answers `TCGETS` rather than
  by a table of device majors, which was wrong in both directions: it passed idle
  host serial ports and refused `bento run` on real consoles.
- **A manifest is bounded at 32 levels of nesting.** The YAML decoder is
  superlinear in depth - 16k nested flow sequences take 209ms, 100k exhaust
  memory - and the 1MB source cap does not bound that. No real manifest passes
  four levels.
- **`enforce.Run` refuses an environment carrying a name the manifest does not
  declare.** Build it with `enforce.ResolveEnv`, or add the name to `env:`.
- **The credential-alias scan no longer walks the system package trees.** `/usr`,
  `/bin`, `/sbin`, `/lib`, `/lib64`, bento's own `/etc` binds and the Nix store
  were walked on every launch whose credentials carry an extra link - but a
  hardlink there needs write on a root-owned directory, and root reads the
  credential without an alias. It was not free: on a cold CI image the scan blew
  its 30s bound and refused the run. Outward by the width of a root-planted
  hardlink; a same-tree scan went from 0.70s to 0.05s warm, and from a timeout to
  instant cold. Runtime prefixes under the home are still walked, and the mount
  scan still catches a bind of a store onto any of these paths.

### What a Run Tells You

- **`run --record-exec` prints every command the run executed**, in order, led by
  the target, and as `exec_record` in the JSON envelope. It takes ptrace away
  from everything in the sandbox - `strace`, `gdb`, `rr` and a harness attaching
  to its own child stop working - so it is off unless asked for. A run that
  cannot have a recorder (the degraded tier, `exec: none`, a host whose yama
  `ptrace_scope` refuses the attach) says nothing was watching, and why. A record
  that ended early is marked truncated rather than passed off as whole.
- **The limits a run asked for are attested against the cgroup the kernel
  enforced.** systemd-run accepts a `MemoryMax` for an undelegated controller and
  silently ignores it, and the report read a pre-run probe's verdict memoized for
  the process lifetime. The scope's `memory.max`, `pids.max` and `cpu.max` are
  now sampled from the parent while the target is alive - `--collect` removes the
  cgroup about a millisecond after the wrapper exits - each layer is gated on its
  own controller, and a requested limit that went unenforced faults the run.
  Refused before the run rather than at the dial: `limits.memory: 0` (systemd
  applies it and the kernel OOM-kills the target), an explicit `pids: 0`, and the
  spellings systemd's parser rejects or ignores - a lowercase size suffix, a CPU
  quota past `21474836.47%`.
- **A run names the PATH directories the box does not carry.** With `PATH` passed
  through, only the directories something brought into the box are there, so a
  bare command name resolves to whatever the box does have: a different build of
  the same tool, no denial, exit code zero. That once read as bento corrupting
  repositories, when the lane's `git` and the host's were different versions. The
  run now says `docker resolves to /usr/bin/docker in the box, not
  /snap/bin/docker`, and carries `shadowed_path_dirs` in the JSON verdict and the
  `failed` event. Quiet about `/usr` and its kin, about directories the host does
  not have, and about ones whose commands have no counterpart in the box - which
  is what keeps the line off every run on a stock Ubuntu host.
- **A run reports the auto-executing files it changed.** A `package.json`'s
  install scripts, a `conftest.py`, a `build.rs`, an `eslint.config.js`, a
  `.pre-commit-config.yaml`, a `.github/workflows` entry: each runs on the host
  later without anyone reading it, and each is a file an agent doing ordinary
  work must be able to edit, so none can be denied. Named on stderr and as
  `changed_auto_exec` now, on the failure path too, along with a redirected
  `core.hooksPath`. Two limits: a fixed list checked at the root of each write
  grant, so a nested `package.json` in a monorepo is missed, and the comparison
  is size and mtime rather than content.
- **`run` and `validate` say when `XDG_RUNTIME_DIR` is outside every shield.** It
  holds the container `auth.json`, the gpg-agent socket and the session bus. The
  shield follows it, but not when it is relative or at or above a home anchor -
  and the rule count there reads exactly like a healthy host's. Only `doctor`
  said so. `validate --json` carries `unshieldable_runtime_dir`.
- **Same for every other relocation variable pointed where no shield can
  follow.** `GNUPGHOME=$HOME` leaves the keys unshielded while `~/.gnupg` keeps
  its default rule, so the rule set, count and exit code read like a host that
  set nothing. Named in the run summary and `doctor`, and carried as
  `unshieldable_relocations`. The refusals were right; only their silence was not.
- **The denial legend reaches the failing run, and names `exec:` and `network:`.**
  The mapping from `EROFS`/`ENOENT`/`EPERM` back to the field that produced them
  printed only after a clean exit, so the run holding `Read-only file system` in
  its own traceback got the generic note that the sandbox denies silently - which
  is that mapping withheld. A manifest with
  no egress rules has no proxy to observe a refusal, so `network:` was absent
  from both legend and summary: the summary says `no network: rules` now, and the
  legend maps `Network is unreachable` and an unresolvable name to it. The legend
  also names the two shapes that raise no errno at all - a shielded directory
  stats as an empty tmpfs, a shielded file reads as zero bytes.
- **A shielded file says what it holds, the way a directory already did.** Every
  single-file shield was stamped `credentials`, so the sentence before approving
  a grant called `~/.bash_history`, `~/.viminfo` and `~/postponed` credential
  stores, and the same path answered differently depending on how it was reached.
  `holds` now reports `history`, `private-data`, `persistence` or `services`
  where that is what is behind the shield - new codes on fifty-six paths, among
  them `~/.rhosts` and `~/.shosts`, which name hosts allowed in without a
  password rather than holding a secret. Nothing shielded changed.
- **Breaking: `shielded_grants` says what each lifted shield held, and absorbed
  `shielded_grant_targets`.** Every surface called what came out of a lifted
  shield a credential store, but the shields also cover history, session layout
  and service sockets. Each entry is an object now: `path` as the manifest
  spelled it, `holds`, and `on_host` where the grant bound elsewhere - which is
  what `shielded_grant_targets` carried, so that field is gone. `validate --json`
  reports the same shape minus `on_host`, which `resolved_read` answers. In Go,
  `enforce.Result.ShieldedGrants` is `[]enforce.ShieldedGrant`,
  `ShieldedGrantTargets` is gone, and `CredentialAlias` stays as it was for
  `AcceptedAliases`.
- **`profile --json` withholds a shielded read as `read-shielded`, not
  `shielded-credential`**, matching its `write-shielded` sibling, with the bucket
  in a new `holds` field. One code to match, and a withheld history store is
  distinguishable from a withheld key.
- **`profile` no longer proposes a rule for a host the run could not reach.** A
  destination the allowlist permitted and the dial then failed on was reported
  like an established tunnel, so a re-profile against a flaky host produced a
  wrong manifest rather than a smaller one. A gate admission that then failed to
  dial is still an admission - the supervisor's yes is egress past the declared
  manifest whether or not a packet followed. Egress the profiler cannot name is
  counted and warned about instead of failing the run, and a PATH search miss no
  longer lands in the proposal.
- **The proxy reports every connection exactly once**, and a failed dial, a gate
  denial, an allowlist refusal, an untunnelable request, a crash-looping gate and
  a refusal at the connection limit each read as themselves. Faults in a handler
  or observer are reported rather than eaten, a tunnel whose upstream never
  speaks is bounded, `Accept` retries the recoverable errnos instead of ending
  `Serve`, and a NAT64 blackout is counted per lost connection.
- **A cancelled run says so, with its own exit status.** Ctrl-C cancels the run
  so cleanup happens instead of leaving the sandbox behind, and the report keeps
  the run's egress and shield fields on the cancel path. Ctrl-C also interrupts
  the `approve` and `profile` prompts, and a cancelled prompt is reported as
  cancelled rather than as a no.
- **A refusal raised before anything was probed no longer reports a clean
  posture.** An empty report answered `fully_enforced: true`; it answers `false`
  now, matching what the `failed` event already said. Host facts that belong to
  the host rather than the run are disclosed separately instead of weighing on a
  run's enforcement verdict.
- **`doctor` names all three Docker restrictions at once.** Lifting the seccomp
  and AppArmor flags it named produced a second refusal over the `/proc` mask
  docker applies by default. One cycle instead of two.
- **An undispatched stage exits 125 with one line, not a panic.** An embedder
  skipping `backend.DispatchReexec()` gets a re-exec stage that would run its own
  program - a fork bomb the guard has always cut short, by panicking: which
  buried the one useful sentence under a goroutine dump, exited 2, and could be
  resumed past by a `recover()` in the embedder's `main()`.
- **`bento version` names the platform and what it can enforce there.** A
  `GOOS=darwin` cross-build compiles clean and then refuses `run`, `profile` and
  `doctor` at startup - including doctor, the command that would have explained
  why. `version` answers on every build: the GOOS/GOARCH pair, plus a line for a
  build with no backend, an unverified Linux architecture, or a libc NSS build.

### Running Under a Supervisor

- **`run --run-id <id>` makes a run reapable as a tree.** Under `exec: all` the
  target has children, so a supervisor holding bento's own pid could report a job
  dead while a test runner it spawned still held the checkout. The id names the
  transient scope `bento-run-<id>.scope`, which `systemctl --user kill` ends and
  `systemctl --user show -p ControlGroup` resolves. The caller picks the id
  before the run starts, so there is no window where the target runs and the
  handle is unknown. A run id needs a scope to name, so a manifest with no
  resource limits - or a host that cannot create a scope - is refused rather than
  run without a handle, and that refusal stands under `--allow-degraded`.

### Reviewing a Manifest

- **The credential-alias scan is bounded, and says when it stopped short.** On a
  host carrying any hardlinked shielded credential - a `cp -al` snapshot, a Nix
  store, an `rsync --link-dest` backup - `gate.Check` walked every granted tree
  whole, and it is on `validate`'s default path: one hardlinked key in `~/.ssh`
  took validate from 40ms to 1.14s over a 287k-entry module cache. It stops after
  50,000 directory entries now (1.14s to 0.23s) and reports the answer as
  partial, in the summary and as `credential_aliases_partial`, so an empty list
  cannot read as a tree checked to the end.
- **`approve` names the permissions that changed since the last approval.** The
  stamp is a sha256 over the policy, so a drifted manifest could say only that
  something changed, and finding the added grant meant diffing git revisions by
  hand. `approve` records the shape it stamped under
  `$XDG_STATE_HOME/bento/approvals/` and prints added and removed lines in the
  manifest's own spelling, with when the last stamp went on and whether anyone
  answered the prompt. The record is deliberately not in the manifest: anything
  stored there is unauthenticated, and a forged prior shape yields a diff naming
  one innocuous addition and invites a skim of a policy nobody approved. So where
  the journal cannot answer - no record, a record describing a different
  approval, or a journal somebody else can write - it says which case applies and
  sends the reader over the whole policy. The boundary moved once, inward:
  `~/.local/state/bento` is write-denied to every run, wherever `XDG_STATE_HOME`
  points, since a script that could write a record could make the next reviewer's
  diff lie. It stays readable. `approve` also fails when the approval cannot be
  recorded, calls out a grant over a linked entrypoint, and refuses every grant
  `run` refuses rather than only the shielded ones.
- **`validate --strict` fails on a host that cannot anchor its shields.** Such a
  host builds no credential shields, so `newSandbox` refuses every run on both
  tiers - and `--strict` exited 0, because it keyed on the refusal set, which is
  exactly what that host cannot answer. A CI gate reading the exit code green-lit
  a manifest the host runs none of. `--json` already carried `shields_unknown`
  and `doctor` already exited non-zero, so the two gates agree now.
- **That host no longer answers `unknown` to the questions it did answer.** A
  missing entrypoint, an interpreter off PATH, a read grant naming nothing and a
  write grant spelled like a file do not depend on the shields, and were all
  dropped for "this host could not answer". Only the grant half is unknown now:
  `grants: unknown` in the summary, `shields_unknown` in `--json`, refusal fields
  absent because they could not be answered rather than because there was nothing
  to say.
- **`validate --relocatable` refuses a manifest whose paths pin it to one
  location.** The stamp attests the manifest as written and `run` checks it
  before resolving paths, so an all-relative manifest keeps one approval across
  every checkout it is copied into - which is what lets a fleet approve one
  manifest per agent class and reuse it in every worktree. A single absolute or
  `~` path ended that silently. The flag reports the entrypoint and grants that
  do not anchor to the manifest's own directory and exits non-zero; `--json`
  carries `relocatable` and `pinned_paths`. Opt-in, because a manifest meant for
  one machine is not wrong. An absolute interpreter is fine - `/usr/bin/python3`
  means the same everywhere - but a `~` one is reported.
- **A grant this host refuses is reported as a refused grant, not an unrunnable
  manifest.** `runnable:` answers whether this host can start what the manifest
  names, and a write into a shielded path, a symlink loop or a write grant that
  is already a file was folded into it - so a manifest whose entrypoint and
  interpreter both resolve was sent after a problem that was not there, twice on
  one screen. It prints once now, beside the grant, under its own `grants:`
  verdict; `--json` carries `refused_grants`, and `runnable` stays true where
  nothing is unstartable, so a gate reading fields must check both. Every refusal
  kind is marked beside its grant, not only the shielded ones.
- **`validate` answers more of what a run would ask**: the allowlisted env vars
  this host has not set, what an unset allowlisted `HOME` becomes, the
  interpreter resolved the way `run` resolves it, a grant naming a whole tree,
  the relocations `Shieldable` dropped (`dropped_relocations` in `--json`), the
  grant checks the gate skipped, and an approval state `--strict` cannot name.
- **A write grant inside a credential shield is refused in its own words.** Both
  kinds shared one sentence offering the read opt-in, which is read-only by
  construction - so an author following it added a `read:` line and met the same
  refusal again. The write refusal now says there is no opt-in for a write, and
  why: it would grant exactly the plant the shield is held for.

### Building and Installing

- **`make install` installs to `/usr/local/bin`, not `GOPATH/bin`.** It honours
  `PREFIX`, `BINDIR` and `DESTDIR`, and installs the binary `make build`
  produced rather than building a second time. The default usually needs root;
  pass `PREFIX=$HOME/.local` for the old rootless behaviour.
- **`LDFLAGS` is a pass-through, not the stamp itself.** Anything passed is
  appended to the version stamp, so `make build LDFLAGS=...` can no longer
  silently produce a binary that misreports its own version. `CGO_ENABLED` stays
  0 on purpose: the shields anchor on the uid's passwd entry, and libc NSS would
  put that lookup back under caller control.
- **`make check` runs `make vuln` and needs network**, so a dependency with a
  known advisory stops the merge that introduces it. `make fuzz` keeps going
  after a target fails and names the package with each failure.

### Verifying a Release

- **The signature file is now `checksums.txt.sigstore.json`**, not
  `checksums.txt.bundle` - same keyless cosign signature over the same file, but
  the name matches the Sigstore bundle convention consumers look for. A script
  fetching the old name will 404.
- **Releases carry SLSA build provenance** as `bento.intoto.jsonl`, covering
  every published archive. The signature says a tagged run of this repo produced
  the artifacts; the provenance says how, and `slsa-verifier` can check an
  archive against it. See [SECURITY.md](SECURITY.md).

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
