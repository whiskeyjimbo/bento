# Changelog

Notable changes to Bento. Because Bento is a sandbox, every entry is written to
answer one question without reading the diff: did the boundary move, and in
which direction? See [SECURITY.md](SECURITY.md) for how versioning treats a
boundary change.

Later releases will list changes since the previous tag. This first entry
describes the boundary as it ships, not the 380-odd commits that built it -
none of them were ever in a release.

## 0.1.0 (unreleased)

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

A write grant that covers a shielded path is refused outright. A read grant
naming an exact shield path is honored as a deliberate, warned exception.
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
  so a reviewer can see which directory `~` or a relative path means before
  approving it.
- The refusals a manifest can earn without consulting the host are raised by
  `validate` and `approve`, not left for `run`: a `~operator/...` path, and a
  write grant of the home directory itself (whatever `$HOME` is, the credential
  stores sit inside it, so such a grant would make their parent writable). Both
  were already refused at run; the gate moved earlier, so no manifest that used
  to run stops running. The same grant spelled absolutely (`write: /home/u`)
  still needs `$HOME` to recognize and is still refused at run.
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
