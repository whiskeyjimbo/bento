# probe: a script for exercising the sandbox by hand

`probe.py` runs *inside* bento and reports what the box actually permits, one
line per probe:

```
RESULT <group>.<name> <ALLOWED|DENIED|SKIPPED> <detail>
```

ALLOWED means the operation succeeded, DENIED means it was refused, SKIPPED
means the probe could not run at all. None of the three is inherently a pass -
you read the outcome against what the manifest granted. Each manifest here
documents the outcomes it should produce.

Results flush as they are produced and a successful run ends with
`PROBE-COMPLETE`. If that sentinel is missing the probe was killed partway (a
cgroup limit is a SIGKILL, not a catchable error) and every line before it still
counts.

## Five-minute quick start

Four runs, in order. Each one establishes something the next depends on.

```sh
go build -o bento ./cmd/bento
cd examples/probe
export PATH="$PWD/../..:$PATH"
export BENTO_PROBE_HOME="$HOME" BENTO_PROBE_CANARY=must-not-leak
```

**1. The floor** - what the sandbox denies with no grants at all.

```sh
bento run deny-all.manifest.yaml --allow-unapproved
```

Every read, write, and network probe comes back DENIED. The handful that do not
are each worth understanding, because they are the sandbox's own floor rather
than anything the manifest granted:

- `read.cwd-listing` - the entrypoint has to be visible to run at all.
- `read.home-listing` - ALLOWED, but only a couple of entries: a skeleton mount
  for the path down to the working directory, not a readable home.
- `write.sandbox-tmpfs` - a private tmpfs, discarded with the box.
- `exec.fork` - plain `exec: none` blocks `execve`, not `fork`; step 4 covers it.
- `env.passthrough` / `env.sandbox-injected` - the manifest does allowlist
  `BENTO_PROBE_HOME`, and `PATH`/`HOME` are injected by bento.

The run ends in `PROBE-COMPLETE`.

**2. Grants work, and don't over-block.**

```sh
bento run grants.manifest.yaml --allow-unapproved
```

`read.granted` and `write.granted` flip to ALLOWED while `read.ungranted`
(`./secret`) stays DENIED. The one to look at is `write.save-via-rename`:
ALLOWED, because bento grants directories rather than files, so `os.replace`
and git-style atomic saves keep working.

**3. The headline claim** - a grant over all of `$HOME` does not lift the shields.

```sh
bento run broad-home.manifest.yaml --allow-unapproved
```

`read.home-listing` should report a count close to `ls -A ~ | wc -l`, proving
home really is mounted, while all four `read.shield-*` probes stay DENIED. The
closing line names how many paths were shielded; it should be dozens, not a
handful - the exact number is host-dependent. If the count is small, the
grant reached nothing and the DENIEDs mean nothing - see below.

**4. Egress, then the hardening tier.**

```sh
bento run network.manifest.yaml --allow-unapproved
bento run strict.manifest.yaml --allow-unapproved
```

The declared host returns `HTTP 200` through the proxy; the undeclared one is
refused at the CONNECT with a 403; `direct-socket` and `dns` fail because they
bypass the proxy. Then `strict` shows `exec.fork` DENIED (that is `none-strict`
doing what plain `none` did not) and the pid and memory caps biting - the memory
probe ends the process partway, so that run has no `PROBE-COMPLETE` by design.
Bento closes that run by naming the signal and the caps the manifest declared,
rather than reporting it as a script failure.

Run `bento doctor` first if step 4 looks too permissive; the hardening tier
needs host support that a container or an old kernel may not have.

## Running

```sh
go build -o bento ./cmd/bento     # from the repo root

cd examples/probe
export BENTO_PROBE_HOME="$HOME"       # see below
export BENTO_PROBE_CANARY=must-not-leak

bento run grants.manifest.yaml --allow-unapproved
```

`--allow-unapproved` keeps the loop short while you are editing manifests. Drop
it and run `bento approve <manifest>` to exercise the fingerprint path too - that
is worth doing at least once, since the approval check is what an unattended
`bento run` depends on.

The two environment variables:

- **`BENTO_PROBE_HOME`** - bento rewrites `HOME` to `/tmp` inside the sandbox and
  does not bind `/etc/passwd`, so the probe cannot find the real home directory
  on its own. Without this the shield probes report SKIPPED rather than guessing.
  Exporting it is only half: env does not cross into the sandbox unless the
  manifest names it, so every manifest here allowlists it in `env:`. A manifest
  `bento profile` drafts does not, which is why the shield probes skip under the
  root README's quick start and run under this tour.
  It doubles as the witness for `env.passthrough`: `PATH` and `HOME` are injected
  by bento itself, so only an explicitly allowlisted host variable shows that
  passthrough works.
- **`BENTO_PROBE_CANARY`** - deliberately *not* allowlisted. `env.canary-leak`
  should always come back DENIED; ALLOWED means the env allowlist leaked.

## The manifests

| Manifest | What it establishes |
|---|---|
| `deny-all` | The floor. No grants, so anything ALLOWED here is allowed by the sandbox itself rather than by policy. |
| `grants` | Narrow read/write grants work, including save-via-rename into the granted directory. |
| `broad-home` | A read grant over the whole home directory does not lift the credential shields. |
| `network` | One declared host reaches the internet through the proxy; everything else, including any direct socket, does not. |
| `strict` | The hardening tier: `exec: none-strict` blocks fork as well as execve, and the memory cap kills the process. |

## Two things that will mislead you

**A DENIED shield probe usually proves nothing.** If home was never mounted,
`~/.ssh/id_rsa` is missing because nothing is there, not because a shield held -
and the four `read.shield-*` lines look reassuring under every manifest,
including `deny-all`. That is what `read.home-listing` is for: it reports how
many entries of the home directory the sandbox can see. Compare it against
`ls -A ~ | wc -l` on the host. Under `broad-home` it should roughly match; under
`grants` it comes back ALLOWED with a couple of entries, which is a skeleton
mount for the path down to the working directory and not a real grant. **Only
read the shield results as meaningful when that count is close to the host's.**

YAML contributes to this trap: an unquoted `~` is the null tag, not a path, so
`read: [~]` decodes to an empty grant. Bento refuses that outright, but the
manifest reads as a home grant either way - quote it, as `broad-home` does.

**Egress is proxy-mediated.** The network namespace is unshared and DNS is
resolved host-side, so a program that ignores `HTTP(S)_PROXY` cannot reach an
allowlisted host either. The `net` group separates the two: `allowed-host` and
`denied-host` go through the proxy (expect a 200 and a refused CONNECT), while
`direct-socket` and `dns` bypass it and should fail under every manifest.

## Adding a probe

Probes are grouped in the `GROUPS` dict at the bottom of `probe.py`, and the
manifest's `args:` list selects which groups run. Use `attempt()` for anything
that raises `OSError` on refusal; call `report()` directly when the verdict comes
from inspecting state rather than from an exception. Keep `exec` and `limits`
last - they are the ones that can end the process.
