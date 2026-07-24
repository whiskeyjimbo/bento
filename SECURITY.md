# Security policy

Bento is a sandbox. Its whole value is the boundary it draws, so a hole in that
boundary is not an ordinary bug - it is the product failing at the one thing it
claims. This document says how to report one and how versioning treats it.

## Supported versions

Bento is pre-1.0 and unreleased; there are no tags yet, and the build stamps
itself `0.1.0-dev`. Until a 1.0 exists, only the `main` branch is supported.
Fixes land there and nothing is backported.

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

- A shielded path becomes readable, writable, or plantable from inside the
  sandbox. The credential and persistence shields (`~/.ssh`, cloud tokens, GPG
  and OS keyrings, password stores, `.git/hooks`, editor task files, and the
  runtime socket directory) are the core promise.
- A grant exposes more than it names - a sibling directory, a symlink or hardlink
  target outside the granted tree, a parent.
- Network egress reaches a host the manifest did not allow, or bypasses the
  proxy allowlist.
- A subprocess runs under `exec: none`, through any path other than the
  documented `execveat` and `io_uring` limitations.
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

If you are unsure which side of that line something falls on, report it
privately and let the triage decide.

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
