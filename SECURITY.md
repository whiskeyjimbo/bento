# Security policy

Bento is a sandbox. Its whole value is the boundary it draws, so a hole in that
boundary is not an ordinary bug - it is the product failing at the one thing it
claims. This document says how to report one and how versioning treats it.

## Supported versions

Bento is pre-1.0. Until a 1.0 exists, only the latest release and the `main`
branch are supported: fixes land on `main` and ship in the next tag, and nothing
is backported to an earlier one.

## Reporting a vulnerability

Report privately through GitHub's private vulnerability reporting on the
[Bento repository](https://github.com/whiskeyjimbo/bento) - the **Security** tab,
**Report a vulnerability**. Please do not open a public issue for a boundary
failure until a fix exists.

Useful in a report: the manifest, the host (distro, kernel, whether bubblewrap
and unprivileged user namespaces are available), the output of `bento doctor`,
and the smallest program that demonstrates the escape.

This is a personal project with no staffed rotation, so there is no response-time
guarantee. What is promised: a boundary report is triaged before feature work.

## What counts as a vulnerability

In scope - any of these is a security bug, even without a working exploit:

- A **hidden** shield leaks: a path that should be invisible becomes readable,
  writable, or plantable from inside the sandbox. These are the credential and
  runtime-socket shields (`~/.ssh`, cloud tokens, GPG and OS keyrings, password
  stores, and the runtime socket directory) - the sandbox replaces each with an
  empty stand-in, so any read of the real content is a failure.
- A **write** shield is written or planted through: the persistence shields
  (`.git/hooks`, `.git/config`, editor task files under `.vscode` / `.idea`) are
  deliberately left readable so a build can consult them, but a write or a planted
  file that reaches the real path is a failure. Reading these is by design, not a
  bug.
- A grant exposes more than it names - a sibling directory, a symlink target
  outside the granted tree, a parent. (A host-created hardlink or bind alias into
  a granted tree is a documented residual, not a bug; see threat model section 5.)
- Network egress reaches a host the manifest did not allow, or bypasses the
  proxy allowlist.
- A subprocess runs under `exec: none` through any path other than the documented
  `execveat` limitation. (`io_uring` is a separate documented gap - it dispatches
  I/O, not process creation - so an `io_uring` file or socket operation reaching
  past enforcement is in scope, but "a subprocess spawned via `io_uring`" is not a
  thing it can do.)
- **A layer degrades silently**: the host cannot enforce something and Bento
  reports it as enforced, or `--strict` runs instead of refusing. Silent
  degradation is the defect class Bento exists to eliminate, so it is treated as
  a boundary failure in its own right, not as a reporting cosmetic.
- Approval or fingerprint checking can be bypassed, so a policy runs unreviewed.

Out of scope - these are documented non-goals, and
[`docs/threat-model.md`](docs/threat-model.md) section 5 explains each. Reports
of these are welcome as issues, but they are not vulnerabilities:

- A secret embedded in a Nix store path, or parked in `/usr`. Both are bound
  readable by design; keep secrets out of derivations.
- A service socket outside the shielded runtime directory that a grant exposes.
- Self-image replacement via `execveat` under `exec: none-strict`, which blocks
  concurrent process creation, not replacing the current process.
- A denial-of-service against the host by a sandboxed program that was granted
  the resources to do it.
- Anything that requires the host, the kernel, the bubblewrap binary, or the
  Bento binary itself to already be compromised. Those are trusted inputs; see
  threat model section 3.
- A kernel 0-day or a hardware side channel used to escape confinement. An
  unprivileged sandbox cannot defend against a bug in the kernel it runs on;
  these are out of scope entirely, matching threat model section 5.

If you are unsure which side of that line something falls on, report it
privately and let the triage decide.

## Verifying a release

The threat model trusts the Bento binary itself. Verification is how you earn
that trust for the copy you downloaded, so do it before running one.

Release archives are built by a tagged run of
[`.github/workflows/release.yml`](.github/workflows/release.yml). That run
publishes `checksums.txt` covering every archive and SBOM, and signs the
checksum file with [cosign](https://github.com/sigstore/cosign) keyless - there
is no long-lived key, so the certificate names the workflow, repository, and tag
that produced the artifacts. Verify the signature first, then the archive
through the checksum file:

```sh
# 1. The checksum file really came from a tagged release run of this repository.
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --new-bundle-format \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp \
    '^https://github\.com/whiskeyjimbo/bento/\.github/workflows/release\.yml@refs/tags/v'

# 2. The archive you downloaded is the one that file vouches for.
sha256sum --ignore-missing -c checksums.txt
```

Pin the identity to an exact tag rather than the `refs/tags/v` prefix if you
want to accept exactly one release:
`...release\.yml@refs/tags/v0.1.0$`.

A failure at step 1 means the artifact was not produced by this repository's
release workflow, whatever the filename says. Report it privately as above.

The release also carries SLSA build provenance as `bento.intoto.jsonl`, which
records how the artifacts were built rather than only who signed them. Check it
with [slsa-verifier](https://github.com/slsa-framework/slsa-verifier):

```sh
slsa-verifier verify-artifact bento_0.2.0_linux_amd64.tar.gz \
  --provenance-path bento.intoto.jsonl \
  --source-uri github.com/whiskeyjimbo/bento
```

Builds are reproducible, so you can check the artifacts against the source
rather than trusting the release run. The binary is stamped from the commit's
own timestamp, not the clock of the machine that built it, and paths are
trimmed. Check out the tag and rerun the same build:

```sh
goreleaser build --clean --single-target -o ./bento
```

That reproduces the published binary byte for byte. `make build` will not: it
stamps a different version and a short commit hash, which is a different binary
by design, not a reproducibility failure.

## Versioning and the boundary

Semantic versioning here is about the **boundary**, not just the Go API. A
manifest that ran safely must not silently run less safely after an upgrade.

- **A boundary regression is breaking severity.** A previously shielded path
  becoming exposed, a grant widening, or a layer that used to be enforced
  becoming unenforced is a breaking change regardless of how small the code
  change was. Pre-1.0 that means a minor bump (`0.x` → `0.x+1`) and an explicit
  note; after 1.0 it means a major bump. It is never a routine patch.
- **Adding a shield is not breaking**, even though it can stop a manifest that
  used to run. Tightening the boundary is the point, so it ships in a normal
  release with the newly shielded paths named in the notes. A manifest that
  breaks this way was reaching something it should not have been.
- **Removing or narrowing a shield requires the same scrutiny as a
  vulnerability fix**, because it re-exposes whatever the shield covered. The
  reason belongs in the release notes, not just the commit.
- **Degradation-reporting changes are boundary changes.** A layer that starts
  reporting `Enforced` where it previously reported a shortfall alters what
  `--strict` refuses, so it is versioned as a boundary change even if no
  enforcement code moved.

Every release note should let a reader answer one question without reading the
diff: did the boundary move, and in which direction?
