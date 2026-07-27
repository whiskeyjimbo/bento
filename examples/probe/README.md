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
  It is allowlisted in the manifests' `env:`.
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
| `broad-home` | A read grant over the whole home directory does not lift the credential shields. **Edit the path first** - see below. |
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

Bento contributes to this trap by not expanding `~` in manifest grants: a
`read: ["~"]` grant resolves to a nonexistent path next to the manifest, grants
nothing, and says nothing about it. `broad-home.manifest.yaml` uses an absolute
path for that reason - edit it if you are not running as the user who wrote it.

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
