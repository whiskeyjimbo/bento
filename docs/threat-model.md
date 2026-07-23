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
- **The base image and interpreter closure.** The read-only base and the nix
  closure of the program's interpreter are mounted readable inside the sandbox.
  Their integrity is part of the boundary. They aren't user data and don't show
  up on the consent surface.
- **Your own grants.** An explicit grant is caveat emptor. Grant `read: ~/.ssh`
  and you get a warning, then Bento takes you at your word. What it defends
  against is a *broad* grant pulling in a secret you didn't think about - not a
  deliberate handover.

## 4. The defenses

### 4.1 Filesystem

The sandbox root is a tmpfs, remounted read-only after everything else is in
place (`--remount-ro /` goes on last, so `/tmp`, `/dev`, `/proc`, and the paths
you granted stay writable). The program wakes up in an almost-empty world: the
read-only base and interpreter closure from section 3, plus the paths you
granted, and nothing more. The shields below still apply on top of the base
mounts. There's no route from "not listed" to "readable."

### 4.2 Credential and persistence shields

The denylist (`internal/denylist`) is a set of paths that stay shielded no matter
what a policy grants, so a broad `read: /` or `read: ~` can't reach them.

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

A cheap partial mitigation now converts this from *silent* to *flagged*: when a
run's grant engages a home credential shield, bento stats that credential (walking a
directory shield for its interior files) and warns if any has more than one
hardlink - "these shielded credentials have extra hardlinks; a grant that exposes
another name for the same file would leak it past the shield". It is
necessary-not-sufficient, and its residuals are deliberate:

- it says an alias *exists*, not where, and over-warns on a harmless backup hardlink;
- the walk covers only *engaged* shields, so an alias whose credential path no grant
  reached (its shield never engaged) is not detected;
- it covers only shields under `$HOME`; the non-home hidden shields are host service
  directories (`/run`), not credential files, and walking them would descend into
  removable media and FUSE mounts and flag their unrelated backup links;
- a credential that *resolves* outside `$HOME` (a symlinked store) is skipped for the
  same reason, and a symlinked credential's *target* is not followed at all - a
  store-deduplicated target (Nix, which hardlinks identical files by design) would
  otherwise false-warn on every home-manager-linked dotfile;
- it does not cover bind aliases or reflinks, which share content without sharing a
  link count.

The full fix remains inode-aware shielding (walk each granted tree, match inodes
against every shielded credential), a separate and more expensive design.

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

**`exec:none` is a soft block.** It stops `execve` via seccomp filters (and `none-strict` also blocks `fork`/`clone` on amd64), but does not block `execveat` - it is an execution policy convenience rather than a complete system call boundary.

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
  the build and its bound-in closure have an audited supply chain.
- An operator can watch the boundary engage and tell when a tool is failing
  closed because it was denied something it needed.
- An outside security review of the isolation and permission model before anyone
  calls it hardened.

Until that's done, Bento is a careful, fail-closed sandbox in the middle of that
transition - not yet something to leave guarding an irreplaceable secret
unattended. This document is meant to close the gap between what it claims and
what it does, and to keep being honest about it as that gap shrinks.
