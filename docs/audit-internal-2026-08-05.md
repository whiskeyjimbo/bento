# Adversarial audit of internal/, 2026-08-05

Third round. Ten parallel opus reviewers, read-only, live files (no diff): nine
package scopes split by non-test line count, plus one cross-package seams agent.
Prior-art brief was built from open beads plus the 31 closed round-2 beads with
the status column spelled out explicitly - the fix for the round-2 method error
that produced ~10 false "already fixed" claims.

Findings as reported. Verification status per finding is recorded here and
restated on each filed bead; nothing below is verified except where it says so.

Two agents (observe, seams) had no advisor available, so their findings had no
second read.

## Scope split

| Agent | Scope | Non-test LOC |
|---|---|---|
| 1 | linux/args.go | 1846 |
| 2 | linux/alias.go + pathresolve | 838 |
| 3 | linux/linux.go + applied.go | 1013 |
| 4 | linux probe/degraded/profile/limits + i386 | 1592 |
| 5 | denylist | 1614 |
| 6 | launcher + grantrefusal | 1590 |
| 7 | observe | 1405 |
| 8 | proxy | 1178 |
| 9 | seccomp + landlock + credhunt | 1727 |
| 10 | cross-package seams | - |

## Group A - the enforced run leaks something policy denied

### A1. Entrypoint/interpreter re-bind lands after the deny-list (P1)
`internal/linux/args.go:272-291`, `internal/linux/linux.go:437-520`

`compile` appends `denyArgs(...)` and then unconditionally
`--ro-bind sb.entrypoint sb.entrypoint` and `--ro-bind sb.interpreter
sb.interpreter`. bwrap is last-wins. Nothing compares `sb.entrypoint` against
`sb.extraDeny` on any route.

A manifest with `interpreter: /bin/cat`, `entrypoint: <a caller DenyPaths file>`
and no grants reads that file to the target's stdout. The report shows no shield
lifted, no `ShieldedGrants`, no `Exposed`.

The in-tree comment at args.go:262-270 defends the ordering, and is sound for the
CLI frame (the operator typed the entrypoint). `Options.DenyPaths` exists for the
embedder frame - `examples/supervise` passes it to the profiling trial, which is
exactly where untrusted code runs.

Status: reported by seams agent, traced not executed.

### A2. Workspace shields are anchored at the write-grant root (P1)
`internal/linux/args.go:660-674`, `internal/denylist/denylist.go:1096`

`Workspace(dir)` joins its rules relative to the grant: `dir/.git/hooks`,
`dir/.git/config`, `dir/.vscode`. `shieldRules` calls it with each resolved write
grant and nothing else.

`write: <repo>/.git` therefore emits shields at `<repo>/.git/.git/hooks` and
leaves the real `<repo>/.git/hooks` writable. `checkWriteNotAboveShield` and
`checkWriteNotUnderReadOnlyShield` consult only `alwaysShields`, never the
workspace set, so nothing refuses it. A planted `pre-commit` runs on the host at
the developer's next commit.

No test poses it: `persistence_fuzz_test.go:172` hard-codes `writes :=
[]string{root}` and varies only what is planted under the checkout, never the
grant's depth.

Status: reported by args.go agent, traced not executed.

### A3. Stdio inheritance check screens only S_IFSOCK (P2, claims bv2-dy50 incomplete)
`internal/launcher/launcher.go:510`

`refuseNetworkFD` returns nil for anything that is not a socket. The property it
exists for - no fence bento installs revokes what an inherited descriptor carries
- is not socket-specific. `openat(0, "rel/path", ...)` resolves from the inode
the dirfd names, walking outside the mount namespace entirely; in the bwrap tier
the Landlock backstop is `RestrictTo([]string{"/"}, writable)`, so there is no
read fence at all. Same for a character device (`/dev/net/tun`, `/dev/kvm`) on
fd 0.

Status: reported by launcher agent, traced not executed.

### A4. Symlink inside a DenyAll directory anchor leaves the real path unshielded (P2)
`internal/linux/alias.go:529-534` + `internal/denylist`

Anchors are resolved as whole paths, so a symlinked file anchor is chased. A
symlink *inside* a directory anchor is not - `hostFileIDs` drops every
non-regular entry, and nothing in `internal/denylist` enumerates a Dir rule's
children. On a stow/chezmoi/yadm dotfile farm (`~/.ssh` real, `~/.ssh/id_rsa ->
~/dotfiles/ssh/id_rsa`) the shield binds over `~/.ssh` while
`~/dotfiles/ssh/id_rsa` is covered by no rule and is read under `read: ~`. It
also contributes nothing to the alias scan, so no alias of it is ever detected.

Status: reported by alias agent. Alias-scan half certain by reading; the
"readable under read: ~" half not executed.

### A5. Landlock's scoped set is never used (P2)
`internal/landlock/landlock_linux.go:45,71`

Both tiers call `Config.RestrictPaths`, which go-landlock explicitly zeroes
`scoped` and `handledAccessNet` in. `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` and
`LANDLOCK_SCOPE_SIGNAL` (ABI 6) are never requested. On the degraded tier with
no netns, a target can connect to an abstract socket (`\0/tmp/dbus-XXXX`,
systemd-resolved). `egress_linux_amd64.go:28-33` asserts this is unavoidable
because "classic BPF cannot tell abstract from pathname at socket(2)" - true of
seccomp, false of Landlock; the comment reasons about the wrong layer and
concludes an irreducible hole where a mechanism exists two ABI levels earlier.

Consequence at ABI >= 9: `ResolveUnixRestricted()` drives `unixSocketClause`, so
the newest kernel is the one whose run report stops disclosing the residual it
still has.

Status: reported by seccomp/landlock agent, from source reading plus vendored
library reading; not executed.

## Group B - the report or the proposed manifest lies

### B1. Cancelled context reported as a clean run (P2)
`internal/linux/linux.go:178,214-225`, same shape `degraded.go:197-202`

`exec.CommandContext` SIGKILLs on `ctx.Done()`, which lands in the `isExitError`
branch: code 137, signaled, and `Run` returns a nil error with a full Enforced
report. `ctx.Err()` is never consulted in `linux.go`, `degraded.go`, or
`enforce/`. A supervisor that cancels on timeout cannot distinguish its own abort
from an OOM kill by the scope.

### B2. Existence-syscall filter drops every negative return (P2)
`internal/observe/observe_linux_amd64.go:1059`

The held-open branch 20 lines above tests `ENOENT`/`ENOTDIR` specifically and
documents why ("a file can exist and still refuse to open"). `recordHeldExistence`
then drops every `rax < 0`. `access` returning `EACCES`, `stat` returning
`EACCES`/`ELOOP`, `getxattr` returning `ENODATA` (the normal answer for an
existing file), and `name_to_handle_at` returning `EOVERFLOW` (the documented
first call of its two-call protocol) all read as "not there": path unrecorded,
`Dropped` stays 0, manifest silently short.

### B3. ELF and `#!` interpreters are never observed (P3)
`internal/observe/observe_linux_amd64.go:923-938`

The kernel opens `/lib64/ld-linux-x86-64.so.2` (and `/bin/sh` for a script) via
`open_exec` - no syscall, no stop. Every profile of a dynamically linked target
omits its interpreter and `Dropped` is 0. Adjacent to open bead bv2-jdrh but not
the same thing.

### B4. `execveat(fd, "", AT_EMPTY_PATH)` records no access and counts no drop (P3)
`internal/observe/observe_linux_amd64.go:936,1352`

`readString` returns `("", true)`, `add` skips the empty path. The launcher itself
uses this call shape.

### B5. `drops` is the one per-stop map never swept per tid (P3)
`internal/observe/observe_linux_amd64.go:653`

`held` and `lastOp` are swept on exit and on exec-retire; `drops` is keyed on the
same reusable `stopKey` and swept nowhere. A key that outlives its pair makes a
later real drop uncounted.

### B6. Entry-stop read is still TOCTOU and the comment denies it (P3)
`internal/observe/observe_linux_amd64.go:863-869`

ptrace freezes the stopped thread, not the address space; a `CLONE_VM` sibling
runs between `readString` and the kernel's `copyin`. The existing sibling-plant
test is airtight only because it uses `newfstatat`, where the success filter
discards the planted path. `openat`, `rename*`, `unlink*`, `chmod*`, `execve*`
have no filter by design, so a planted path is attributed to a call that never
touched it - over-attribution silently widens the consent surface.

### B7. `clampShieldedGrants` matches DenyAll shields literally (P2)
`cmd/bento/profile.go:1661-1727` vs `1737-1779`

The DenyWrite sibling twelve lines below resolves each rule with
`EvalSymlinks`, with a comment naming exactly this hazard (stow/home-manager). The
enforcer resolves too (`args.go:1156`). So with `~/.gnupg` symlinked into a
dotfiles checkout, the profiler drafts a grant that `run` hard-refuses, and the
only remedy the refusal offers is a *broader* grant.

Outside internal/, reported by the seams agent.

### B8. `bento validate` mirrors three of nine grant checks (P3)
`cmd/bento/validate.go:304-308` vs `internal/linux/args.go:1090-1121`

`checkGrantNotManagedMount`, `checkGrantNotProcess`,
`checkWorkspaceShieldNotRedirected`, `checkWriteNotRoot` are not predicted
anywhere. `read: /tmp` validates green, approve stamps it, run dies at first
step - the exact failure `render.go:471-473` says the mirror exists to prevent.

Outside internal/, reported by the seams agent.

### B9. `reconcile` overwrites the probe's accurate reason (P3)
`internal/linux/applied.go:193-196`

`blockWanted` omits the `seccompSupported()` term that `compile` applies, so on a
seccomp-less host reconcile replaces the true reason with "the sandbox reported
installing no exec-block filter though the policy asked for one". State right,
explanation wrong, and `Set` replaces rather than merges. `TestAppliedReconcile`
asserts only `StateOf`, never the reason string.

## Group C - test and gate weaknesses

### C1. Egress fence tests pass vacuously on a host with no route out (P2)
`internal/linux/netfence_test.go:93-145`

The tests dial `1.1.1.1:443` from inside the sandbox and assert BLOCKED. The two
controls only prove the probe works against a loopback listener; nothing
establishes the host can reach `1.1.1.1` unsandboxed. On an offline or
egress-firewalled runner, `ENETUNREACH` is returned with or without
`--unshare-net` - and the substring hint matches too. Deleting `args.go:232`'s
`--unshare-net` keeps CI green there. The file's docstring claims "If the kernel
fence ever stops holding, CI fails here before anything ships"; on that host
class the claim is false.

The sibling `TestDegradedConfinesFilesystemAndEgress` does it right by asserting
a seccomp `SOCKET_BLOCKED`, which is host-network-independent.

### C2. Resolve fuzzer cannot reach the branches that matter (P3)
`internal/linux/resolve_fuzz_test.go:52-99`

`buildSymlinkTree` creates flat siblings under one root - no nested directories,
so no symlink target routing through another symlink's subdirectory. `start` is
always absolute, so `Existing`'s relative-path/`os.Getwd` branch (the one bv2-25tc
fixed) has zero fuzz coverage. No node loses its x-bit, so the readlink-error
branches are unreachable. ~1/3 of generated nodes are regular files, making a
large fraction of inputs vacuous.

## Group D - completeness (denylist)

Filed as one bead per category rather than one per path.

### D1. $PATH-resident shim/bin dirs (P2)
`internal/denylist/denylist.go:702-717`. The bin-dir block is firejail-derived;
the whole non-firejail half is missing: `~/go/bin`, `~/.pyenv/{bin,shims}`,
`~/.rbenv/{bin,shims}`, `~/.asdf/shims`, `~/.local/share/mise/shims`,
`~/.bun/bin`, `~/.local/share/pnpm`, `~/.volta/bin`, `~/.krew/bin`,
`~/.ghcup/bin`, `~/.dotnet/tools`, `~/.sdkman/candidates/*/current/bin`,
`~/.opam/default/bin`, `~/.config/composer/vendor/bin`, `~/.foundry/bin`,
`~/.pub-cache/bin`, `~/.mix/escripts`. `~/go/bin` and `~/.config/mise` are
present on this host.

### D2. Shell plugin/framework roots (P2)
`denylist.go:638-641`. Missing `~/.zprezto`, `~/.zplug`, `~/.zinit`/`~/.zi`,
`~/.p10k.zsh`, `~/.fzf.zsh`, `~/.fzf.bash`, `~/.tmux/plugins`. `~/.fzf.zsh` is
present on this host and is sourced verbatim by a line fzf's installer appends to
the rc - the rc is DenyWrite, the sourced file is shielded by nothing.

### D3. Credential files (P3)
`denylist.go:304-404`. `~/.authinfo(.gpg)`, `~/.hgrc` + `~/.hgrc.d/`, `~/.curlrc`,
`~/.wgetrc`, `~/.ansible.cfg` + `~/.ansible/`, `~/.config/pypoetry/auth.toml`,
`~/.bunfig.toml`, `~/.dbt/profiles.yml`, `~/.config/borg/keys/`,
`~/.subversion/config`.

### D4. Desktop/session exec surfaces (P3)
`denylist.go:1499`. `~/.local/share/dbus-1/services` (Exec= lines, bus-activated -
the direct analog of the already-covered `.local/share/applications`) and
`~/.local/share/gnome-shell/extensions`.

### D5. IDE trees (P3)
`denylist.go:633-634,673-676`. `~/.config/Cursor`, `~/.config/Code - Insiders`,
`~/.config/VSCodium`, `~/.vscode-server`, `~/.vscode-oss`, and JetBrains entirely
(`~/.config/JetBrains/<IDE>/options/*.xml`, plus `c.kdbx`, a credential file).
Note `Workspace` already shields `.idea` per-repo, so the global half being absent
is an inconsistency.

### D6. HISTFILE and ZDOTDIR relocation shields are mostly dead (P2)
`denylist.go:850,899`. `Home` reads these with `os.Getenv`, but both are *shell*
variables, not exported ones. The standard `ZDOTDIR` idiom sets it in
`/etc/zsh/zshenv`, so bento launched from anything but zsh sees it unset, and
`~/.config/zsh/.zshrc` matches no rule at all. Fix shape: shield
`~/.config/zsh` unconditionally, as `.config/fish` already is.

### D7. GOOGLE_APPLICATION_CREDENTIALS not in fileEnvs (P2)
`denylist.go:809`. Canonical, always-absolute, genuinely exported pointer to a
service-account private key. The table already follows `KUBECONFIG` and the AWS
file vars, and `CLOUDSDK_CONFIG` for the directory. Same shape:
`REGISTRY_AUTH_FILE`, `AWS_WEB_IDENTITY_TOKEN_FILE`, `TF_CLI_CONFIG_FILE`,
`ANSIBLE_CONFIG`.

### D8. bv2-cpt9's fix is incomplete (P2)
`denylist.go:1024`, `cmd/bento/render.go:1557`. The bead's fix direction said the
prediction has to be where validate/run see it; what landed is a `doctor`
paragraph. Second, the warning is gated on `rd != ""`, but `RuntimeDir()` returns
`""` for a *relative* `XDG_RUNTIME_DIR` as well as an unset one - so that value
takes the same branch and gets neither shield nor warning.

### D9. AliasAnchors ignores every relocation (P3)
`denylist.go:1150`. With `GNUPGHOME=/srv/keys` the store is shielded but does not
anchor the alias scan, so a second readable name for those keys is undetectable.
Same for `PASSWORD_STORE_DIR`, `DOCKER_CONFIG`, `CLOUDSDK_CONFIG`,
`GH_CONFIG_DIR`, `AZURE_CONFIG_DIR`.

### D10. `Audit` builds its rule set from the ambient environment (P3)
`internal/denylist/audit/audit.go:641`. `Runtime`'s doc says it takes a resolved
parameter so the completeness audit "does not vary with the environment of
whoever runs it" - but the next expression is `denylist.Home(home)`, which reads
~25 env vars. `make audit` on a box with `GNUPGHOME` or `KUBECONFIG` set produces
a different rule set than CI, and any of those rules can cover a firejail
candidate and turn a real gap green.

## Group E - smaller, latent, and drift

- `internal/linux/args.go:1216-1239` - `checkWriteNotUnderReadOnlyShield` excludes
  workspace shields wholesale; a write grant strictly inside one is neither
  refused nor honored (EROFS at runtime, reported as honored). P2.
- `internal/linux/args.go:733-766` - `gitDirShields` skips symlinked entries, so
  `checkWorkspaceShieldNotRedirected` has no rule to test; one copy of the
  symlinked-shield fix landed, the sibling did not. P3.
- `internal/linux/args.go:825-828` - `denyArgs` drops a resolved-unshieldable
  rule but the three grant checks carry only the `"/"` skip, not the
  `Shieldable` one, so a relocation env var symlinked onto a home hard-refuses
  every run over a shield that was never applied. P3.
- `internal/linux/linux.go:97,110,142` - all cleanup is defer-based and the CLI
  installs no signal handler, so SIGINT leaves bwrap-created shield mount points
  in the user's own write-granted tree, permanently, accumulating per run. P2.
- `internal/linux/applied.go:208` - `reconcile` treats `landlock absent` as
  never-a-shortfall using a bwrap-tier argument, applied verbatim on the tier
  that has no bwrap. Latent (RestrictDegraded cannot currently emit absent). P3.
- `internal/linux/applied.go:99-133` - `parseApplied`'s tamper stance is
  asymmetric across the marker: post-marker garbage discards the report,
  pre-marker garbage is silently skipped, and the docstring claims the former for
  both. Defence-in-depth drift. P4.
- `cmd/bento/run.go:163-169` vs `internal/linux/degraded.go:186` - the `--json`
  terminal-object-last contract rests on "no WaitDelay set" and names setting it
  as what would break it; `degraded.go` sets `WaitDelay = 2s`. P3.
- `enforce/report.go:149-168` - `Set` upgrades as readily as it worsens while
  four call-site comments claim "it only ever worsens". `noteDeadListener`
  unconditionally sets Degraded. Unchecked invariant, no live host state found.
  P4.
- `internal/linux/degraded.go:54` - `runDegraded` never calls `preflightGrants`,
  so the alias/credential scan is skipped on that tier, and the degraded
  disclosure names the adjacent loss but not this one. Documented at
  linux.go:334-340 but unfiled. P3.
- `internal/linux/limits.go:43-57` - `cacheProbe` deliberately does not memoize a
  non-verdict, and `measureScope` returns unknown when the delegated-controller
  set is unreadable, so on containerized/nested/hybrid-cgroup hosts every
  `canCreateScope()` re-spawns two transient scopes: up to ten per invocation.
  A `0::`-less `/proc/self/cgroup` is a permanent fact being treated as
  transient. P3.
- `policy/policy.go:600-633` - `limits.memory: "0"` validates (the sibling
  `cpu: "0%"` is rejected explicitly), then fails as an opaque
  "systemd could not apply the requested resource limits". P4.
- `internal/launcher/launcher.go:144-153` - `AllowNetworkStdio` is family-blind,
  so an opt-in meant for socket activation also waives AF_NETLINK and AF_PACKET.
  The error already carries `e.domain`; the waiver never consults it. P3.
- `internal/launcher/launcher.go:184` - the proxy scrub misses
  `ALL_PROXY`/`all_proxy`/`FTP_PROXY`. P3.
- `internal/launcher/launcher.go:109` - `BridgeLivenessFD` has no
  standard-stream floor, unlike `AppliedFD`, whose doc explains exactly this
  failure. P3.
- `internal/launcher/launcher.go:302` - `ObserveFD` likewise, and
  `Config.ObserveFD`'s doc claim that it "is not inherited across exec" is false
  for fds 1 and 2. P4.
- `internal/launcher/launcher.go:238` - `Run` does not require `cfg.Writable`
  absolute while `RunDegraded` does, and the Landlock failure there is the file's
  one fail-open branch. P4.
- `internal/launcher/launcher.go:656-707` - comment says the bridge is not
  reaped; `reapUntil` reaps it and discards the status. P4.
- `internal/grantrefusal/grantrefusal.go:7-8` - "thirteen call sites for five
  sentences" is now seven sentences and fifteen call sites, and the count is the
  package's whole justification. P4.
- `internal/linux/alias.go:618-628` - `identify`'s `d.Info()` is a second lstat
  that `WalkDir`'s error parameter does not cover; on failure both callers drop
  the entry silently. `hostFileIDs`' own docstring calls this fatal: it turns
  "could not look" into a proof that no hardlink exists, and `linked == false`
  skips the entire granted-tree walk. Reachable by an ordinary credential
  rotation race. P2.
- `internal/linux/alias.go:663-668` - `hostStatID` Lstats the mountpoint path
  whose *ancestors* the device filter never screened, so a bind under a dead
  hard-mounted NFS hangs every launch - the exact failure the filter's docstring
  says it prevents. P3.
- `internal/linux/alias.go:663-668` - the same line silently shortens the mount
  list, contradicting both the function docstring and the `mountpoints` seam
  contract, which each say a partial list is the dangerous shape. No reachable
  leak found. P3.
- `internal/pathresolve/pathresolve.go:82-87` - every `os.Readlink` error is
  treated as "real file or not-yet-existing", conflating ENOENT with EACCES,
  ENAMETOOLONG, EIO; the lexical `..` popping at :78 rests on the invariant that
  conflation can break. Largely defused (EACCES needs a parent the sandbox cannot
  traverse either). P3.
- `internal/linux/alias.go:392` - a case-insensitive mount makes a credential an
  alias of itself and refuses the run. Fail-closed noise. P4.
- `internal/proxy/proxy.go:520-527` - `recoverableAccept` omits ENOMEM/ENOBUFS,
  which `accept(2)` returns under socket-buffer pressure; the same host-caused
  self-clearing class bv2-alba was filed for, reaching the same
  dead-socket-for-the-rest-of-the-run outcome. P3, claims bv2-alba incomplete.
- `internal/proxy/proxy.go:715-734` - `net.Dialer` returns the *first* address's
  error, so a guard block on the second address is discarded and the connection
  is reported `Allowed`. Refusal still correct; the operator signal that
  `GuardBlocked`'s doc calls "the only place the distinction survives" is lost.
  P4.
- `internal/proxy/proxy.go:926-938` - `canonicalPort` accepts `"0"`, which is not
  a port but the kernel's pick-one sentinel; it reaches the observer's recorded
  destination set and seeds a proposed manifest. P4.
- `internal/proxy/proxy.go:630` - `handle`'s blanket `recover()` is fully silent,
  while `report()` and `callGate()` each recover for a named reason and explain
  why a silent drop is unacceptable. P4.
- `internal/seccomp` S1 - on arm64 `BlockExec` calls `blockForeignArch`, which
  returns an error unconditionally off-amd64, while `Supported()` is
  architecture-independent. Every default run passes admission with the exec
  layer reported present and dies at the launcher. bv2-f030 fixed this shape for
  `BlockIoUring` (a profiling path) and left the sibling every run traverses.
  No arm64 artifact ships (`.goreleaser.yaml:42` has it commented out) but
  `make crossbuild` compiles it. P3, claims bv2-f030 incomplete.
- `internal/seccomp/seccomp_other.go` - the `!linux` build omits
  `StrictExecSupported`, `BlockExecStrict`, `BlockIoUring`,
  `BlockTerminalInjection`; it compiles only because nothing references them. P4.
- `internal/seccomp/seccomp_linux.go:188` - `Exec` manufactures an error
  unconditionally with no `if errno != 0`. P4.
- `internal/landlock/landlock_linux.go:396-403` - `degradedRules` routes `exec`
  through `existing()` and would grant recursive execute on a directory; the
  sibling `execAllowFiles` refuses exactly that and says why. Latent (only
  regular files reach it today). P4.
- `internal/landlock/landlock_other.go:13` - `RestrictDegraded` returns nil
  having restricted nothing, justified by a caller gate that is not at the call
  site. P4.
- go-landlock appends a `read_dir` grant on `/proc/$PID/task` when ABI < 8 and
  cgo is on, so `make race` (CGO_ENABLED=1) does not build the shipped degraded
  ruleset. Undocumented. Informational.
- `internal/credhunt/credhunt.go:166-168` - an unreadable directory narrows the
  scan and the `pruned` counter that exists to disclose narrowing does not count
  it, so the output is indistinguishable from a clean subtree. The swallow is
  deliberate; the missing disclosure is not. P3.
- `internal/credhunt/credhunt.go:300-304` - `contentShapes` justifies its
  read-and-split over `bufio.Scanner` with a minified-JSON case the sniff still
  misses (and which a test pins as a deliberate trade a hundred lines away). The
  Scanner argument is valid; the example is wrong. P4.
- `internal/credhunt` - UTF-16LE, base64-armoured, and gzipped credentials evade
  the content sniff, and a mode-0644 `~/.env` in UTF-16 surfaces on nothing. P4.
- `internal/credhunt/credhunt.go:218` - `MachineStores` matching is exact-string
  with no cleanliness contract on an exported field, unlike `Home`. P4.
- Comment/doc drift, `bv2-xu4s` incomplete: `(design 6.2)` at
  `internal/linux/probe.go:174` and `internal/launcher/degraded.go:23`; `(yz3.2)`
  at `internal/linux/linux.go:351`, `args.go:262,1012,1203`; `ADR-0008` at
  `internal/landlock/landlock_linux.go:111` and
  `internal/landlock/internal/probe/main.go:64`; `bv2-2k6y` at
  `internal/denylist/audit/audit.go:26`. The project rule forbids all of these.
- `internal/linux/probe.go:86-88` - comment says limits are gated on the
  namespace probe; there is no `nsOK` on that path and the next docstring says
  the opposite outright. P4.
- `internal/linux/args.go:441` - "the exec filter blocks only execve/execveat" is
  backwards; `execveat` is open by construction and documented as a residual.
- `internal/denylist/denylist.go:1030` - `Covers`' lede ("an exact match wins")
  contradicts its own loop, where an enclosing DenyAll beats an exact DenyWrite.
  The paragraph below it is correct. P4.

## Dismissals re-derived (claims that were checked, not passed through)

- `RunOptions.Degraded` revisit triggers: independently re-derived by two agents
  (probe/limits, seams). `Layer.Tier()` yields exactly two core layers and
  `probe.go` emits `LayerNetwork` as only Enforced or Unavailable pre-run; the
  two Degraded writes are strictly post-run. Neither trigger is met. Not filed.
- bv2-m7hp (register hazard): swept the whole observe decoder for a second
  instance. Every dirfd is narrowed with `int32`, and the open-flag masks are
  immune because every `writeFlags` bit is in the low 32. No second instance.
- bv2-hbzh: parity now comes from `PTRACE_GET_SYSCALL_INFO`'s `op`, never from
  `rax`. No remaining path infers the entry/exit distinction from a return value.
- bv2-ojzp: the fd is retained and `parseApplied` seeks rather than re-opening,
  pinned by `TestParseAppliedReadsTheRetainedDescriptorNotThePath`.
- bv2-m7wk and bv2-62tp: both closed as claimed; the size bound is on the
  `io.LimitedReader`, not `info.Size()`.
- DNS rebinding in the proxy: settled from the Go source rather than by
  reasoning. `netFD.dial` calls `ControlContext` on the same fd that then
  `connect()`s to the same `raddr`; there is no second resolve, and multi-A is
  vetted per candidate.
- Proxy IP classification: every class checked (127/8, 0/8, 240/4, 198.18/15,
  100.64/10 boundary, multicast, fec0::/10, ::/96, ::ffff:0:a.b.c.d, 6to4,
  ISATAP, RFC 8215 at every carve length). Every gap found is over-refusal.
  Teredo is undecoded and says so in its own doc comment.
- seccomp argument filters: every arg-inspecting filter reads a scalar, never a
  pointer. `clone3` is forced to ENOSYS rather than inspected, which is the
  correct handling for a pointer-argument syscall under seccomp.
- Landlock ABI pinning: `compatibleWithConfig` runs against the undowngraded
  config, and only `refer` collapses to v0, which makes `withRefer`'s ABI gate
  load-bearing and `withIoctlDev`/`withResolveUnix` safe ungated.
- Degraded-tier environment is the sanitized policy env, not the host
  environment (`degraded.go:186` sets `cmd.Env`). This was one agent's top P1
  hypothesis and it is false.

### Dismissal ranked top by blast-radius-if-wrong

NNP propagation under TSYNC. `installPolicy` sets `PR_SET_NO_NEW_PRIVS` on the
calling thread only, and `Exec` may run on a different thread. The agent cleared
it on kernel behaviour (`seccomp_sync_threads()` propagates no_new_privs to every
synced thread) and said plainly the claim comes from kernel knowledge rather than
from anything in this tree. If it is wrong, the exec'd target runs without NNP
and the exec-path filters are bypassable via setuid. This is the round's
highest-blast-radius unverified clearance.
