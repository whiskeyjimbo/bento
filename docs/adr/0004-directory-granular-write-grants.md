# [ADR-0004] Directory-Granular Write Grants and Shield Protection

* **Status:** Accepted
* **Date:** 2026-07-14

## Context and Problem Statement

Granting write access to individual files inside container/namespace sandboxes breaks common file updating workflows. Text editors, version control systems (`git`), and standard runtime APIs (e.g. Python `os.replace`, Go `os.Rename`) modify files by writing to a temporary file in the same directory and renaming it over the destination. A single file bind-mount prevents creating temporary files or replacing inodes in that directory.

Additionally, broad write grants (e.g. `write: ~`) could potentially overwrite shielded credential paths (such as `~/.ssh` or `~/.aws/credentials`).

## Decision Drivers

* Supporting standard atomic file save-via-rename operations.
* Protecting sensitive credential directories from being overwritten or used as persistence footholds.
* Clear, deterministic rules for manifest validation.

## Decision Outcome

Chosen Option: **Directory-Granular Write Grants with Strict Shield Parent Refusal**.

1. `write:` manifest entries must name directories, not individual files. Bento creates missing directories before starting the sandbox.
2. A write grant naming an existing single file is refused at validation time.
3. Write grants containing a shielded credential directory (e.g., `write: ~` enclosing `~/.ssh`) are strictly refused by manifest validation, prompting the user to grant a narrower target directory.
4. Read grants over broad trees are allowed; built-in denylist bind-mounts continue carving out shielded credential stores inside read-only trees.

### Positive Consequences

* Full compatibility with atomic file write/rename workflows (`os.replace`, `git`, editors).
* Eliminates key-planting and secret-overwriting vectors by refusing write grants over parent directories of shielded stores.

### Negative Consequences / Trade-offs

* Sandboxed programs gain write access to all non-shielded files within a granted directory, rather than a single file.
