# Changelog

Notable changes to Bento. Because Bento is a sandbox, every entry is written to
answer one question without reading the diff: did the boundary move, and in
which direction? See [SECURITY.md](SECURITY.md) for how versioning treats a
boundary change.

Later releases will list changes since the previous tag. This first entry
describes the boundary as it ships, not the 380-odd commits that built it -
none of them were ever in a release.

## Unreleased

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
