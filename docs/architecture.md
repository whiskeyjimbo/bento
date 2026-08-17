# Bento - Architecture Overview

Bento runs a program on Linux under manifest-declared permissions, denying anything the manifest does not grant. This document describes how it is put together: package boundaries, execution flows, and enforcement seams. For what it defends against, see [`docs/threat-model.md`](threat-model.md); for why particular structures were chosen, see [`docs/adr/`](adr/). For what Bento is for, see the [README](../README.md).

---

## 1. System Overview

Three commitments shape the layout that follows:
1. **Machine-owned manifests.** Permissions are proposed via profiling, reviewed by humans, and stamped with cryptographic approval fingerprints. This is what `manifest`, `policy`, and `profile` exist to serve.
2. **Platform-decoupled seams.** Policy logic, manifest processing, and domain models are decoupled from platform backends, which is why kernel *enforcement* is confined to `internal/linux`, reached through the `enforce.Enforcer` interface.

   A second boundary rides the same check: `internal/shield` assembles the built-in half of a run's shield set, so a new package cannot start building shield rules of its own. The grant-derived half - a checkout's git hooks and editor task files - is assembled in `internal/linux`, which is where the host facts it needs are, and `make layering` names that exception with its reason rather than leaving it implicit.

   The confined thing is the kernel's isolation primitives - seccomp filters, Landlock rulesets, the in-sandbox launcher, the ptrace observer - which only the platform backend and each other may import. Raw syscalls in the ordinary sense are not confined and should not be: `cmd/bento` reads terminal state and signal constants, resolves grants with `stat`/`openat`, and fingerprints manifests with xattrs; `internal/proxy` and `internal/pathresolve` classify errnos. None of those decide what a run is allowed to do, which is the property the boundary exists to protect. `make layering` checks the import-level claim on every platform the tree builds for, so it fails when the boundary moves rather than when someone rereads this paragraph.
3. **No silent degradation.** Host kernel capabilities are reported in explicit tiers rather than fallen back through, which is why tier reporting sits in `enforce` alongside the enforcer interface rather than inside the platform backend (`internal/linux`).

---

## 2. Component Architecture

The codebase is organized into decoupled layers:

```mermaid
graph TD
    CLI["cmd/bento (CLI Entrypoint)"] --> Backend["backend (Platform Selection & Synthesis)"]
    CLI --> Manifest["manifest (YAML Load/Marshal & Provenance)"]
    
    Backend --> Enforce["enforce (Enforcer Interface & Tier Reporting)"]
    Backend --> Policy["policy (Domain Model & Fingerprinting)"]
    Backend --> Profile["profile (Observed Run Synthesis)"]
    
    Enforce --> LinuxBackend["internal/linux (Bubblewrap, Seccomp, Landlock)"]
    LinuxBackend --> Launcher["internal/launcher (In-Sandbox Stage)"]
    LinuxBackend --> Observer["internal/observe (Ptrace Open Profiler)"]
    LinuxBackend --> Proxy["internal/proxy (Host HTTP CONNECT Proxy)"]
    LinuxBackend --> Denylist["internal/denylist (Mandatory Credential Shields)"]
```

### Package Responsibilities

| Package | Purpose |
|---|---|
| `cmd/bento` | CLI subcommands (`profile`, `validate`, `approve`, `run`, `doctor`). |
| `policy` | Platform-independent `Policy` model, path matching, and SHA-256 fingerprinting. |
| `manifest` | Serializes YAML manifests and tracks generation/approval provenance. |
| `enforce` | Core `Enforcer` interface (`Probe` + `Run`), degradation reporting, and capability state matrices. |
| `backend` | Platform backend selector and profiler wrapper. |
| `internal/linux` | Linux bubblewrap backend, seccomp filters, Landlock LSM rules, systemd cgroups, and namespace setup. |
| `internal/proxy` | Shared host-side HTTP CONNECT proxy over isolated Unix domain sockets for network egress control. |
| `internal/denylist` | Platform-independent list of mandatory credential and persistence shields (`~/.ssh`, `.git/hooks`, `/run`). |
| `profile` | Turns a profiling run's observations into a proposed policy for a human to review. |
| `gate` | Answers what this host will refuse about a policy without building a sandbox - the verdict `bento validate` reports, reachable as a library. |
| `trust` | Whether a manifest's stamped fingerprint still matches its policy, and who besides the observing identity can rewrite the file it is stamped on. |
| `internal/shield` | Assembles the built-in shield set and answers "does this grant land inside a shielded path" for the backend, the validate gate, and the profiler's clamp, so the three cannot diverge. Rule data stays in `internal/denylist`. |
| `internal/credhunt` | The pre-run scan for host-made aliases (hardlinks, bind mounts) that reach a credential through a granted tree. |
| `internal/pathresolve` | Resolves a host path the way a write through it lands, including through components that do not exist yet. Shared by `internal/linux` and `profile` so the two cannot disagree about where a grant goes. |

---

## 3. Workflow & Execution Lifecycle

Bento executes in a 4-step lifecycle: **Profile → Validate → Approve → Run**.

```mermaid
sequenceDiagram
    autonumber
    actor User as User / CI / Agent
    participant CLI as Bento CLI
    participant Profiler as Ptrace Profiler
    participant Fingerprint as Fingerprint Engine
    participant Sandbox as Linux Sandbox (Bubblewrap)
    participant Proxy as Host Egress Proxy

    rect rgb(240, 248, 255)
        note over User, Profiler: Step 1: Profile
        User->>CLI: bento profile ./script.py
        CLI->>Sandbox: Launch under default-deny tmpfs
        Sandbox->>Profiler: Attach ptrace syscall observer
        Profiler-->>CLI: Synthesize observed paths into draft manifest
    end

    rect rgb(255, 250, 240)
        note over User, Fingerprint: Step 2 & 3: Validate & Approve
        User->>CLI: bento validate script.manifest.yaml
        User->>CLI: bento approve script.manifest.yaml
        CLI->>Fingerprint: Calculate SHA-256 over policy fields
        Fingerprint-->>CLI: Stamp provenance.approves
    end

    rect rgb(240, 255, 240)
        note over User, Proxy: Step 4: Enforce & Run
        User->>CLI: bento run script.manifest.yaml
        CLI->>Sandbox: Verify approval fingerprint & host capabilities
        Sandbox->>Proxy: Route allowlisted egress through Unix socket
        Sandbox-->>User: Execution Output / Stream Envelope
    end
```

---

## 4. Security Tiers & Degradation

Capabilities are structured into **Core** (baseline guarantees) and **Hardening** (platform-specific layers) tiers:

```mermaid
flowchart LR
    subgraph CoreTier ["Core Tier (Baseline Guarantees)"]
        FS["Filesystem Isolation (tmpfs ro-root)"]
        Shields["Credential & Socket Shields (~/.ssh, /run)"]
        NetFence["Empty Net Namespace (--unshare-net)"]
        ProxyEgress["Egress CONNECT Proxy"]
    end

    subgraph HardeningTier ["Hardening Tier (Linux Hardening)"]
        Seccomp["Seccomp Subprocess Blocking"]
        Cgroups["Systemd Scope Resource Limits"]
        Landlock["Landlock LSM Backstop"]
    end

    CoreTier --> DoctorCheck{"bento doctor Check"}
    HardeningTier --> DoctorCheck
    DoctorCheck -->|All Intact| CleanRun["Clean Enforced Execution"]
    DoctorCheck -->|Hardening Missing & --strict| RefuseRun["Refuse Execution (Fail Closed)"]
```

---

## 5. Architectural Decision Records (ADRs)

Detailed technical rationale for core design choices are documented in [`docs/adr/`](adr/):

- [`0001-machine-owned-manifest-workflow.md`](adr/0001-machine-owned-manifest-workflow.md): Machine-owned manifests and fingerprinted approvals.
- [`0002-platform-enforcement-seam-and-tiers.md`](adr/0002-platform-enforcement-seam-and-tiers.md): Decoupled enforcer seam and explicit capability tiers.
- [`0003-host-side-connect-proxy-egress.md`](adr/0003-host-side-connect-proxy-egress.md): Unix domain socket HTTP CONNECT proxy for network egress.
- [`0004-directory-granular-write-grants.md`](adr/0004-directory-granular-write-grants.md): Directory-level write bind mounts for save-via-rename compatibility.
- [`0005-ptrace-open-register-observation.md`](adr/0005-ptrace-open-register-observation.md): Register-level syscall tracing for zero-content profiling.
- [`0006-no-exec-gate-on-seccomp-user-notif.md`](adr/0006-no-exec-gate-on-seccomp-user-notif.md): Why the exec block stays a blind filter rather than an interactive gate.
- [`0007-cross-language-service-surface.md`](adr/0007-cross-language-service-surface.md): Cross-language service surface (proposed).
- [`0008-no-exec-allowlist-on-landlock.md`](adr/0008-no-exec-allowlist-on-landlock.md): Why Landlock's execute right is not used as an exec allowlist (rejected).
- [`0009-exec-broker-for-dynamic-toolchains.md`](adr/0009-exec-broker-for-dynamic-toolchains.md): Why there is no exec broker for dynamically linked toolchains (rejected).
- [`0010-shields-deny-vs-surface.md`](adr/0010-shields-deny-vs-surface.md): Whether a shield records authorization, denies, or surfaces.
- [`0011-exec-record-under-enforcement.md`](adr/0011-exec-record-under-enforcement.md): Exec-only ptrace recording what an enforced run actually ran.
- [`0012-untagged-shield-seam.md`](adr/0012-untagged-shield-seam.md): One shield verdict behind an untagged seam.
