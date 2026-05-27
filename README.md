<p align="center">
  <img src=".github/assets/bento-gopher.png" width="25%" alt="Bento Gopher Logo" />
</p>

# Bento

A polyglot script sandbox for Linux and macOS. Declare a script's permissions in a declarative YAML manifest, and execute it under secure, kernel-enforced isolation.

`bento` leverages native OS sandboxing primitives (`sandbox-exec` on macOS, `bubblewrap` on Linux) coupled with local proxy network filtering. It isolates untrusted Python, Node.js, Bash, Go, or other compiled/interpreter-driven scripts without container overhead and without requiring root privileges.

> **Pre-1.0**
> The public API (`bento.Run`, `bento.Doctor`, options, manifest types) is stable and unlikely to break in incompatible ways before 1.0. The macOS path compiles cleanly and parity with Linux is the design intent. Contributions and feedback are welcome.

---

## Key Capabilities

* 🔒 **Filesystem Isolation:** Deny-by-default environment; bind-mounts exactly the explicit paths the script declares.
* 🌐 **Network Control:** Strict, per-host domain allowlists enforced via local proxies and kernel barriers (Landlock or network namespace isolation).
* 🚫 **Subprocess Interception:** A custom seccomp filter prevents untrusted scripts from spawning external shells or running arbitrary commands.
* 🛡️ **Mandatory Deny-List:** Automatic, unbypassable shielding for SSH keys, cloud provider credentials, shell profiles, and Git hooks.
* ⚡ **Zero Container Overhead:** Instant execution using host runtimes directly inside isolated OS namespaces.
* 📊 **Resource Constraints:** Control maximum memory limits, CPU quotas, and thread counts using cgroups.

---

## Installation

### 1. Build the Binary
```bash
# Clone the repository and compile
git clone https://github.com/whiskeyjimbo/bento
cd bento
make build                             # Builds the CLI launcher and shims
```

### 2. Verify Your Environment
Run the built-in diagnostic tool to ensure your system supports the sandboxing prerequisites:
```bash
./bin/bento doctor
```
If `bento doctor` reports missing configurations (e.g. user namespace restrictions in modern Ubuntu), run the automated configuration setup:
```bash
sudo ./bin/bento setup
```

### 3. Install System-Wide (Optional)
```bash
sudo install bin/bento /usr/local/bin/
```
*Note: If you skip installing system-wide, run all examples below using `./bin/bento` instead of `bento`.*

---

## Quick Start

The fastest way to sandbox a script is using `bento profile`. This records a single run, logs its accesses, and writes a tailored manifest you can review and enforce.

### 1. Profile a script
Run `profile` to observe file writes and outbound network targets during a test execution:
```bash
$ bento profile ./fetch.py
[bento] profiling "./fetch.py" (permissive network)...
[bento] observed network:
  Host                              Port    Count
  api.example.com                   443     2
[bento] observed filesystem writes:
  /tmp/fetch-out.json
[bento] wrote fetch.manifest.yaml — review and trim before running
```

### 2. Inspect the generated Manifest
Verify the boundaries Bento will enforce:
```bash
$ bento validate fetch.manifest.yaml
manifest:    /tmp/fetch.manifest.yaml — ok
interpreter: python3  →  /usr/bin/python3
script:      /tmp/fetch.py
read:        [ /tmp ]
network:     [ api.example.com:443 ]
exec:        blocked (no subprocesses allowed)
```

### 3. Run under sandbox
Run your script with full kernel-enforced sandboxing activated:
```bash
$ bento run fetch.manifest.yaml
```

---

## Declarative Manifest Example

Manifests are simple, declarative YAML files. A typical configuration looks like this:

```yaml
interpreter: python3
script: ./fetch.py
read:
  - /tmp/input-data
write:
  - /tmp/results
network:
  rules:
    - host: api.example.com
      port: "443"
limits:
  memory: "128M"      # Caps memory allocation
  cpu: "100%"         # Limits CPU usage
  tasks: 32           # Caps maximum concurrent threads/processes
```

---

## CLI Usage Reference

```bash
# Run a script with a manifest
bento run manifest.yaml

# Run an ELF binary directly (no interpreter)
bento run ./my-binary

# Run a quick script with zero-config (no network, read-only script dir)
bento run script.py

# Inject environment variables to the sandbox
bento run --env API_TOKEN=xyz --env ENV=prod manifest.yaml

# Run with interactive prompting to allow-list misses dynamically
bento run --prompt manifest.yaml
```

---

## Comprehensive Documentation

For advanced usage, architecture deep dives, and integration guidelines, check out the specialized guides:

* **[Manifest & Conventions Reference](docs/manifest-reference.md):** Complete manifest YAML specification, common patterns, and critical sandbox gotchas (stripped environment, username maps, subprocesses).
* **[Technical Architecture & Internals](docs/architecture.md):** Details on Landlock and namespace bridge network backends, filesystem mounts, seccomp filters, and host validation security.
* **[Go Library Integration Guide](docs/go-library.md):** How to import and use Bento inside your Go applications, API structure, and error handling behaviors.
* **[Platform Support & Development](docs/platform-support.md):** Compatibility matrices (Linux and macOS support details), installation prerequisites, Ubuntu/AppArmor setups, and testing instructions.
