# [ADR-0001] Machine-Owned Manifests and Fingerprinted Approvals

* **Status:** Accepted
* **Date:** 2026-07-14

## Context and Problem Statement

Hand-edited YAML manifests introduce syntax errors, inline comment formatting bugs, duplicate top-level keys, and fragile parser error rewriting. Crucially, asking humans to hand-edit permission manifests risks unreviewed permission modifications during automated runs (CI/CD pipelines or autonomous AI agents).

## Decision Drivers

* Eliminating the entire class of hand-editing YAML syntax errors.
* Supporting safe unattended execution without runtime interactive prompts.
* Ensuring permission policy changes require explicit human review and attestation.

## Decision Outcome

Chosen Option: **Machine-Owned Manifests with SHA-256 Approval Fingerprints**.

1. Manifests are generated and updated by `bento profile`. Hand-editing is supported but is no longer the required primary workflow.
2. `bento approve` stamps a SHA-256 fingerprint over the policy fields (`entrypoint`, `interpreter`, `args`, `env`, `read`, `write`, `network`, `exec`, `limits`) into `provenance.approves`.
3. `bento run` refuses to execute unapproved or modified manifests unless `--allow-unapproved` is passed for development profiling loops.

### Positive Consequences

* Structurally deletes YAML parsing error handling subsystems built around hand-editing mistakes.
* Prevents unreviewed permission creep in CI/CD and automated agent workflows.
* Changing executable script code does not invalidate an approval—the fingerprint attests the *policy boundary*, not the binary implementation.

### Negative Consequences / Trade-offs

* Requires an explicit `bento approve` step before executing in strict or unattended mode.
