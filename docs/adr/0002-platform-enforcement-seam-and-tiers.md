# [ADR-0002] Platform Enforcement Seam and Capability Tiers

* **Status:** Accepted
* **Date:** 2026-07-14

## Context and Problem Statement

Cross-platform sandboxing engines often enforce materially different security guarantees on different operating systems. Silent degradation—where missing host kernel features result in a warning while execution proceeds under weaker isolation—creates a dangerous false sense of confinement.

## Decision Drivers

* Strict fail-closed security philosophy: no silent degradation to weaker sandboxes.
* Clean separation of platform-independent domain models from OS-specific kernel backends.
* Honest capability reporting across Linux kernel features (bubblewrap, seccomp, Landlock, cgroups).

## Decision Outcome

Chosen Option: **Decoupled Enforcer Seam & Tiers with Loud Degradation Reporting**.

1. **Enforcer Seam:** Abstract `Enforcer` interface (`Probe` + `Run`) in the `enforce` package. No platform-specific types (e.g., bubblewrap flags or syscall constants) appear in core signatures.
2. **Capability Tiers:**
   - **Core Tier:** Baseline guarantees expected across platforms (filesystem tmpfs ro-root, network isolation via empty netns, credential shielding).
   - **Hardening Tier:** Linux-specific layers (seccomp exec-blocking, systemd cgroup resource limits, Landlock LSM backstop).
3. **Fail-Closed Execution:** `bento doctor` and `bento run` explicitly report degradation. Passing `--strict` causes `bento run` to refuse execution if any required policy guarantee cannot be fully enforced by the host kernel.

### Positive Consequences

* Prevents false confidence: users know exactly what isolation mechanisms their host kernel enforces.
* Host capability checks are performed dynamically before execution.
* Platform backends can be developed and tested behind the clean `enforce` interface.

### Negative Consequences / Trade-offs

* Strict mode fails on systems missing optional kernel features (e.g., unprivileged cgroup v2 delegation or seccomp support).
