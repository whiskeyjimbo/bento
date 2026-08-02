# Bento threat model

This is what Bento defends, who it defends against, what it assumes, and what it
deliberately leaves open. Read it before you trust the sandbox with a secret. The
non-goals in section 5 matter as much as the defenses in section 4 - a boundary
you've misjudged is worse than one whose edges you know.

Some of what follows is built and checked against the code; some is still being
built. The text says which as it goes, rather than pretending the target and the
present are the same thing.

## 1. What Bento is

Bento runs a program - a build script, a CLI tool, an agent's shell command -
against your real project while keeping it away from your credentials, your host,
and the open network. The program sees the files you granted and nothing else,
and reaches the hosts you granted and nothing else. The default at the boundary
is deny; access is an explicit grant you can read back.

## 2. What we're protecting

- **Credentials and secrets**: SSH keys, cloud tokens, GPG keyrings, password
  stores, the OS keyring - anything under `$HOME` a build tool has no business
  reading.
- **Host integrity**: the ability to plant something that runs on the host later
  - a git hook, an editor task, a line in a shell rc.
- **Host services**: the docker/podman daemon, the session bus, gpg-agent, the
  display server. Their control sockets are host power.
- **The network**: reaching anything off-box, which is how everything above
  leaves.
- **Secrecy during discovery**: profiling an untrusted program to learn what it
  needs must not hand it a secret in the process.

## 3. The adversary, and what we trust

Assume the sandboxed program is hostile. It might be outright malicious or a
benign tool with a compromised dependency; it makes no difference. It will go
looking for credentials, try to leave something behind on the host, reach for
host services, and ship anything it finds out over the network.

A few things Bento trusts rather than defends:

- **The host and its kernel.** Bento protects the host from the program, not the
  other way around. A compromised host is out of scope.
- **The kernel and bubblewrap.** Filesystem and network isolation rest on
  unprivileged user namespaces, bind mounts, and `--unshare-net`. The behavior
  we rely on is checked on kernel 6.8 and bwrap 0.9.0. An older or unusual kernel
  is an assumption we don't yet enforce - see section 5.
- **The base image and the Nix store.** The read-only base (`/usr`, `/bin`,
  `/lib`, the CA bundles) is mounted readable inside the sandbox, and when the
  program's interpreter comes from Nix, so is the store. Note the scope: not that
  interpreter's closure but `/nix/store` *whole*, because a store path's shared
  libraries are themselves separate store paths and binding only the interpreter's
  prefix leaves it unable to load. Their integrity is part of the boundary, and
  none of it shows up on the consent surface.

  Integrity here rests on the host's Nix, not on anything Bento checks, and it is
  worth being precise about what that does and doesn't buy. Standard store paths
  are *input*-addressed: the hash names the derivation that produced the path, not
  the bytes sitting there now. So the path hash cannot be recomputed to detect
  tampering the way a content hash could - what protects the store is that it is
  immutable and root-owned, plus whatever trust the host placed in the substituter
  it fetched from. Bento binds it read-only, so a sandboxed program cannot alter
  what the next run executes, but it does not re-verify the store and should not:
  that is `nix store verify`'s job and the host's business, and a compromised host
  is already out of scope. A poisoned store means a poisoned interpreter, and no
  sandbox survives that.
- **Your own grants.** An explicit grant is caveat emptor. Grant `read: ~/.ssh`
  and you get a warning, then Bento takes you at your word. What it defends
  against is a *broad* grant pulling in a secret you didn't think about - not a
  deliberate handover.
- **`$HOME` at the time of the run, for grant *spelling*.** The shields
  themselves no longer move with the environment: they are anchored on the union
  of `$HOME` and the running uid's passwd entry, so `HOME=/` adds `/.ssh`,
  `/.aws` and so on without dropping the real ones (verified: a `read: /` grant
  under `HOME=/` reads a private key before that change and refuses it after).
  What the environment still decides is where a `~` grant *points*, since the
  fingerprint attests the manifest as written and not the environment it runs
  in - a harness with a caller-chosen environment can retarget the grant, though
  the shields inside whatever it lands on stay engaged. The same lever also
  decides which spellings count as a deliberate shield opt-in, since a read grant
  is matched against the shield paths `$HOME` produces: pointing `$HOME` at a
  symlink to the real home makes a grant of `<link>/.ssh` an honored, warned
  opt-in where the same manifest is refused otherwise. It changes the spelling
  that opts in, not what is reachable - a caller who can set `$HOME` can name the
  store directly instead - so it is a review-surface problem rather than an
  escalation, and both `validate` and the run warning name the store the grant
  lands on. It is not closable at the boundary: a caller aliasing the home and a
  host whose home is legitimately a symlink produce the same shape, and refusing
  it would break `read: ~/.ssh` everywhere homes are symlinked.

  Two configurations return the original lever in full. Where the passwd entry is
  missing entirely (an LDAP host whose module is not loaded, an unmapped container
  uid) `$HOME` is the only anchor left. And where the binary is built against libc
  NSS rather than the pure-Go resolver, `LD_PRELOAD` can make the passwd lookup
  fail and drop that anchor - the shipped build is static and tagged `osusergo`,
  which is what keeps that out of the caller's reach; a `go build` without it is
  not the shipped configuration and does not carry this property.

## 4. The defenses

### 4.1 Filesystem

The sandbox root is a tmpfs, remounted read-only after everything else is in
place (`--remount-ro /` goes on last, so `/tmp`, `/dev`, `/proc`, and the paths
you granted stay writable). The program wakes up in an almost-empty world: the
read-only base and, for a Nix interpreter, the store from section 3, plus the
paths you granted, and nothing more. The shields below still apply on top of the
base mounts. There's no route from "not listed" to "readable."

### 4.2 Credential and persistence shields

The denylist (`internal/denylist`) is a set of paths that stay shielded no matter
what a policy grants, so a broad `read: /` or `read: ~` can't reach them.

The precedence is fixed and does not depend on how the grant is written: no read
grant that merely *covers* a shielded path lifts it. What does lift one is a grant
naming the shielded store exactly - `read: ~/.ssh`, not `read: ~` - which is the
deliberate handover of section 3, and it warns. It has to be the store itself: a
shield covers a whole directory and cannot be partly lifted, so `read:
~/.ssh/id_rsa` is refused outright rather than honored under the shield - opting
one file in means naming the directory and taking the rest with it. Only the
hidden-outright shields are opt-in-able at all; the read-only ones have nothing to
grant but the write they exist to refuse, and a write grant under one is refused
outright.

Credential stores are shielded as whole directories, not named files. Shielding
`~/.ssh/id_rsa` by name leaves `~/.ssh/my_deploy_key` sitting there, and does
nothing about a file the program creates itself - so the whole directory goes.
When a tool relocates its store with an env var (GNUPGHOME, KUBECONFIG, the AWS_*
file vars), the shield follows to the new location.

Config a tool legitimately reads - `.gitconfig`, shell rc - is shielded
write-only: readable, so the tool works, but not writable, so it can't become a
persistence foothold. Config whose main content is a plaintext credential is
hidden outright, which also takes its exec knobs (msmtp's `passwordeval`, mutt's
source-pipe) off the table.

Inside a repo you've granted write access to, `.git/hooks`, `.git/config`,
`.vscode`, and `.idea` are read-only, so a program that can write your project
can't leave something that fires the next time you open it.

Keeping the list complete is a repeatable audit against firejail's disable-common
list, not a matter of remembering. Under default-deny, ungranted paths are inaccessible
by default; the denylist serves as an additional safety net carving out sensitive locations
even if broad read grants (like `read: ~`) are declared.

### 4.3 The runtime socket shield

`/run` and `/var/run` are shielded whole. A unix socket is a two-way channel no
matter how it's mounted: the kernel only refuses writes through a read-only bind
for regular files, so `connect()` still goes through a `--ro-bind` (checked on
6.8). Hand out `/run` and you've handed out the docker daemon, which has host
networking and can mount the host root. Like the credential shields, it lifts
only for an explicit `read: /run`, never for a broad grant that happens to cover
it.

### 4.4 Network egress

The `--unshare-net` namespace is the fence. With no routes in it, the kernel
answers any outbound dial with ENETUNREACH - even a static Go binary that brings
its own resolver has nowhere to go. There's no pasta and no nftables in the
default path; the empty namespace does the work.

Per-host allowlisting rides on a host-side HTTP CONNECT proxy on a bind-mounted
unix socket, with the sandbox pointed at it through `HTTP_PROXY`/`HTTPS_PROXY`.
The client names its target in the CONNECT line, so the name we check is the name
we dial - the SNI-spoofing and domain-fronting tricks don't apply, because a name
never gets separated from its connection. The proxy resolves host-side and checks
the resolved IP again at connect time. Loopback, link-local, and the
169.254.169.254 metadata address are refused flat out, even if a rule names the
literal IP; RFC1918 and CGNAT ranges (including NAT64-embedded forms) are refused
unless a rule names the literal address. A program that ignores the proxy doesn't
slip out - it fails.

### 4.5 Watching without reading

The ptrace observer pulls the path argument of an attempted open straight from
the tracee's registers and memory, and never looks at what the syscall returned.
So it records the exact path a program wanted even when that path isn't mounted
and the open ENOENTs, and it never touches file content. That's what lets
profiling report the real host path a program is after without ever binding it.

### 4.6 Profiling as a consent surface

Profiling runs a program under the same default-deny sandbox as a real run, recording what it *tries* to touch without mounting host secrets. The draft manifest lists what the code requested so access can be granted intentionally ("this reads `~/.ssh`" is surfaced for explicit review rather than quietly allowed), keeping untrusted tools isolated during discovery.

Because profiling runs under default-deny, a program that branches on a missing file hits ENOENT and may take an early error path before revealing subsequent access needs. Converging on a complete manifest for branching programs requires iteratively granting discovered paths and re-profiling until the run completes.

## 5. Non-goals and known gaps

These are deliberate edges, not oversights.

**Service sockets outside `/run`.** A socket a distro puts somewhere else (MySQL
in `/var/lib/mysql`, say) or one a host process opens partway through the run is
only reachable if a grant exposes its directory - but no fixed list can name them
all. They're covered when they sit inside a shielded store, and a residual
otherwise.

**Secrets built into the Nix store.** The store is bound readable whole, on the
premise that it holds world-readable package content and no user data. That
premise is Nix's own model, and it holds for anything built normally - but a
derivation that embeds a secret (reading a key file at build time, or passing a
token as a build argument) lands that secret in a world-readable store path. It
is a known Nix anti-pattern rather than a Bento one, and on a host that has done
it, every sandbox with a Nix interpreter can read it. Bento cannot tell such a
path from any other package, so it does not try: keep secrets out of derivations.
The same reasoning applies to the read-only base - a credential someone parked in
`/usr` is readable too.

**Datagram `sendmsg` to a socket.** Putting sockets on the consent surface via a
`connect()` hook is a usability win, not a control: a datagram `sendmsg` skips
`connect()` entirely. Runtime safety here comes from the filesystem `/run`
shield, which does cover it. Don't mistake the consent surface for the
enforcement boundary.

**A shield protects a path, not the content behind it.** The credential shields
are bind mounts over specific paths. A second readable path to the same content
inside a granted tree - a hardlink (same inode), a bind alias, a reflink - is not
covered by the shield itself. The sandboxed program can't set this up itself
(inside the sandbox the credential path is empty, so it never sees the real inode
to link), so it takes a host-created alias - but a user granting `read: ~/project`
would not expect a hardlink there to expose `~/.aws/credentials`.

Bento refuses such a run before the target starts, naming both the granted path
that reaches the content and the credential it reaches, since the alias is
host-made and the user is the one who can remove it. Two mechanisms find it,
because the two alias kinds leave different traces:

- *Hardlinks* are found by identity. A hardlink needs a second directory entry
  pointing at the credential's inode, so `nlink == 1` on every credential *proves*
  no hardlink to any of them exists anywhere on the host. Bento stats the credential
  set first - tens of files - and only when that gate fires does it walk the granted
  trees to find where the alias is. On an ordinary run the walk is provably
  unnecessary and does not happen. Below the walk root it does not descend into a
  filesystem none of the credentials live on, since a hardlink cannot cross a device
  boundary; the root itself is always walked, because a grant of `/` starts on the
  rootfs while the credentials may live on a separate `/home`, and pruning there
  would end the walk before it began.
- *Bind aliases* bump no link count, so the gate correctly skips the walk for them.
  They are read instead from `/proc/self/mountinfo`, at O(mounts). Only the
  mountpoint is used, never the mount's recorded source: the kernel reports a source
  relative to its own filesystem, so with `/home` on its own partition a bind of
  `~/.ssh` reports `/u/.ssh`, and a btrfs subvolume layout reports `/@home/u/.ssh`.
  Bento asks what is actually *at* each mountpoint instead, and only for mountpoints
  on a device some credential lives on - which also reaches a filesystem mounted
  under a directory the granted-tree walk pruned.

The credential set is built from the deny-list itself rather than from the shields
a given run engaged: a credential no grant reached is still reachable through an
alias that a grant *did* reach. It covers `DenyAll` shields under `$HOME` - a
read-only shield's file is readable by design, and the non-home hidden shields are
host service directories like `/run`, which it would be wrong to enumerate. A
credential's own path being explicitly opted into the sandbox drops it from the
scan: its shield never engages, so there is no shield for an alias to defeat.

Among the hidden *directories*, only the key-bearing ones anchor the scan - private
keys, tokens, keyrings, wallets. Every hidden directory is shielded just as hard;
this narrower set is only about which files can *identify* a credential. It is an
inclusion list because the deny-list grows with privacy and persistence entries far
more often than with new key formats, and an exclusion list would silently re-admit
each one. It also keeps the bulk stores out: `~/.mail`, `~/Mail`, `~/.thunderbird`
and the browser profile trees hold tens of thousands of files, so anchoring on them
would mean enumerating a mail spool on every launch - and mail sync tools (mbsync,
notmuch) hardlink duplicate messages routinely, which would trip the scan on a mail
file rather than a credential. A saved mail password inside one of those trees is
therefore not an anchor, and that is a deliberate residual; the tree stays shielded.

Two narrowings keep the refusal honest. A symlinked credential's *target* is not
followed - a store that deduplicates identical files by hardlinking them (Nix) gives
every linked dotfile an extra link by design. And VCS object stores inside a
credential directory are not used as identity anchors: `~/.password-store` is a git
repo by design and `git clone --local` hardlinks every object into the clone, so
anchoring on a blob would refuse a run because the user's own clone sits in a
granted tree, while the store stays shielded either way.

Two residuals are accepted rather than engineered against:

- a *reflink* shares content without sharing an inode, so identity comparison never
  sees one; catching it would mean hashing the contents of every file in every
  granted tree;
- the scan is a *snapshot*, so a host actor can create an alias after it runs. The
  window is not instantaneous: it opens when the credential set is stat'd and stays
  open through the tree walk, so an alias created in an already-walked directory is
  missed - seconds, on a large grant whose gate fired. Between the scan and the
  launch, a policy that sets resource limits also does a systemd round-trip, which
  widens it slightly further;
- the **degraded tier does not run this check at all**. It confines with Landlock,
  which is path-hierarchy based, so an alias inside a granted tree is readable there
  for the same reason it would be past a shield - and the exposure report cannot
  name it, since that list holds shield paths and an alias path is not one. Running
  under `--allow-degraded` therefore proceeds where the full tier refuses.

Both are bounded by the same fact: the actor who could exploit either already holds
the user's privileges and could read the credential directly without an alias. What
the mechanism delivers is naming an alias the user did not intend, not blocking
someone who needs no alias.

**An alias you know about is yours to accept.** A snapshot tool that hardlinks
against the live file - `cp -al`, or a whole-tree deduplicator - puts a second name
for every credential under its backup root, and that refusal is correct but not
useful. `--accept-alias <tree>` acknowledges the aliases inside a tree you name and
proceeds. It takes a tree rather than a path because those tools rotate: today's
snapshot directory is dated and tomorrow's is not, so acknowledging exact paths
would go stale daily. An alias outside the named tree still refuses, so this stays
far narrower than the alternative of granting read access to the credential store
itself. Whatever it admits is listed in the run's result and warned about on every
invocation, because a run that reads past a shield must not look clean; and it is an
invocation flag, never a manifest field, since an alias is a fact about one host's
filesystem and a manifest is portable and fingerprinted.

An acknowledgement wide enough to contain a credential store is refused outright,
because it would accept every alias of that store rather than the ones you meant.
That verdict is reached against every store the scan anchors on, not against the
aliases the current run happened to find - the flag is pasted into a command line
that outlives the run that suggested it, so one judged only against today's aliases
would silently accept whatever is planted under it tomorrow, and one typed on a run
that found nothing would never be judged at all.

`bento profile` runs the same scan and takes the same flag. The profiled target is
untrusted by construction - that is what it is being profiled to find out - so an
alias inside a discovery grant reads past the shield there exactly as it would
under a real run, and `--allow-network` would forward what it read.

Note that `rsync --link-dest` does *not* trigger this: it hardlinks each snapshot to
the previous snapshot rather than to the source, so the live credential keeps a link
count of one. Its snapshots are byte-identical copies, which is the content residual
above, not an alias.

**Access you grant is yours to grant.** An explicit grant to a shielded path
warns and proceeds. Bento won't second-guess a deliberate opt-in.

**Shooting yourself in the foot.** Point an env-relocation var at a path that has
to stay writable, or at `/`, and you get a loud refusal or a bwrap abort, not a
quietly wrong run. The failure is safe, not convenient, and Bento doesn't try to
guess what you meant.

**Transparent proxy mode doesn't exist yet.** Only the cooperative path
(`HTTP_PROXY`) is built. A transparent TPROXY mode to catch programs that ignore
the proxy env is designed but unimplemented - until it's real, such a program
fails closed instead of being transparently allowed. If it does get built, the
proxy has to own name-to-IP resolution itself; treating SNI as an allow-signal
would put the spoofing back.

**Kernel and runtime drift.** The isolation primitives are checked on specific
versions. An older kernel is an assumption we don't currently enforce with a
startup check.

**`exec:none` is a soft block.** It stops `execve` via seccomp filters (and `none-strict` also blocks `fork`/`clone` on amd64), but does not block `execveat`, the one real subprocess path left open. `io_uring` is a separate gap of a different kind: it dispatches file and socket I/O the exec filter never sees, not process creation. The bwrap enforced tier installs no `io_uring` block, so a ring is a file/socket surface there bounded by the same VFS enforcement as everything else; the degraded tier does block it, since without a netns its socket ops would be an unfenced egress path. So `exec:none` is an execution-policy convenience rather than a complete system-call boundary. What still holds either way is the filesystem: a spawned image is confined by the same bind mounts and Landlock rules as its parent.

**Out of scope entirely**: a malicious host, kernel 0-days, side channels, and
resource-exhaustion DoS.

## 6. Fail closed

The rule the whole design bends toward: every ambiguity resolves to denial. A
path nobody listed is unreadable, not readable. A program that ignores the proxy
fails instead of leaking. A misconfigured shield aborts the run loudly instead of
degrading open. Under default-deny, an ungranted path breaks a tool instead of exposing a secret.

## 7. Where this is going

The boundary we're building toward:

- Default-deny is the credential defense, not the denylist. The list stays, but
  as a warn-and-carve layer over an already-safe default; a forgotten entry fails
  closed instead of open.
- Completeness maintains itself - gaps surface from upstream references and real
  usage instead of someone remembering to look.
- Every escape we know about is a regression test, and the Linux and macOS
  backends are proven to enforce the same thing rather than assumed to.
- The version facts we lean on become startup preconditions that fail loud, and
  the build and everything it binds in readable have an audited supply chain.
- An operator can watch the boundary engage and tell when a tool is failing
  closed because it was denied something it needed.
- An outside security review of the isolation and permission model before anyone
  calls it hardened.

Until that's done, Bento is a careful, fail-closed sandbox in the middle of that
transition - not yet something to leave guarding an irreplaceable secret
unattended. This document is meant to close the gap between what it claims and
what it does, and to keep being honest about it as that gap shrinks.
