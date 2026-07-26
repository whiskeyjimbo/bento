# Bento - Architecture Overview

Bento is a lightweight, fail-closed sandbox for Linux that executes untrusted programs (build scripts, CLI tools, AI agent actions) under strict, manifest-declared permissions.

This document outlines the architecture, package boundaries, execution flows, and enforcement seams of Bento. For threat model details, see [`docs/threat-model.md`](threat-model.md). For historical design decisions, see [`docs/adr/`](adr/).

---

## 1. System Overview

Bento is designed around three core principles:
1. **Machine-Owned Manifests:** Permissions are proposed via profiling, reviewed by humans, and stamped with cryptographic approval fingerprints.
2. **Platform-Decoupled Seams:** Core policy logic, manifest processing, and domain models are decoupled from platform backends (`internal/linux`).
3. **No Silent Degradation:** Host kernel isolation capabilities are reported in explicit tiers. Missing hardening layers surface loudly rather than quietly falling back to a weaker sandbox.

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
    LinuxBackend --> Launcher["internal/linux/internal/launcher (In-Sandbox Stage)"]
    LinuxBackend --> Observer["internal/linux/internal/observe (Ptrace Open Profiler)"]
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
