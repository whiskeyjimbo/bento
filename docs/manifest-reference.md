# Manifest Reference & Sandbox Conventions

This document provides a detailed reference for the Bento manifest structure, common configurations, and critical sandbox conventions that developers must keep in mind when running sandboxed scripts.

---

## Sandbox Conventions

Because Bento runs scripts under strict OS and kernel isolation, environments inside the sandbox differ significantly from the host. Understanding these conventions up front will save hours of debugging.

### 1. Environment Variables are Stripped by Default
The host environment is **not** inherited. All host environment variables (like `$USER`, `$LANG`, `$PATH`, `$AWS_PROFILE`, and `$NODE_ENV`) are stripped by default.
* A script relying on `$DATABASE_URL` will see an empty string and fail silently or crash.
* **Solution:** Explicitly permit host variables to pass through using the manifest `env:` allowlist, or inject key-value pairs at runtime using `bento run --env KEY=VALUE` or `bento.WithExtraEnv`.
* Bento prints a `[bento] note` in the logs if a manifest requests an `env:` variable that is not currently set on the host.

### 2. The Sandbox User is `sandbox` (Not your host user)
Bento mounts a synthetic `/etc/passwd` inside the namespace to allow standard libc username lookups (`getpwuid`, `os.getlogin`, `whoami`, etc.) to succeed without leaking real user details.
* Any user lookup returns **`sandbox`**, regardless of your actual login.
* `$USER` and `$LOGNAME` are stripped and cannot be overridden using `--env`.
* If downstream tools require your real host username, pass it under a different name:
  ```bash
  bento run --env HOST_USER=$USER script.yaml
  ```
* Bento inspects script source code and prints warnings if it spots `$USER`, `$LOGNAME`, `whoami`, or `id -un` calls.

### 3. File Execution Path and `$HOME`
The script inside the sandbox is bind-mounted at `/sandbox/script` and executed there.
* The working directory (`cwd`) inside the sandbox is set to `/sandbox`.
* The `$HOME` variable inside the sandbox is overridden to `/sandbox`.
* Python `__file__` and standard traceback reports will reference `/sandbox/script` rather than the script's absolute path on the host.
* *Note:* For multi-file packages (`from utils import x` / `require('./utils')`), Bento automatically prepends the script's original directory to `PYTHONPATH` or `NODE_PATH` so local sibling imports succeed automatically.

### 4. Zero-Config Subprocess Interception
By default, the seccomp execution filter blocks all standard subprocesses (`execve`).
* Using `subprocess.run()`, backticks, or `os.system()` will fail with an "Operation not permitted" (EPERM) error.
* **Solution:** To allow subprocess spawning, set `allow_exec: true` in your manifest (or use the profiling flag: `bento profile --allow-exec ./deploy.sh`).
* **Note:** `exec: [...]` is a deprecated legacy list field. If Bento sees a non-empty `exec:` list, it warns the user and treats it globally as `allow_exec: true` (per-binary path lists are not enforced).

### 5. `set -euo pipefail` Gotcha in Bash
If you run a Bash script that uses command substitution (e.g. `val=$(whoami)`), and the execution gets blocked by the seccomp filter:
* Bash does **not** trigger `set -e` aborts on subshell execution substitution failures.
* The script will continue running with `val` silently set to an empty string. If your script yields empty outputs without failing, check the subprocess permissions.

---

## Manifest Schema Reference

A Bento manifest is a standard YAML file describing the interpreter, paths, and limits. Below is a fully commented layout:

```yaml
# 1. Interpreter and Script (Required)
interpreter: python3        # Evaluated via $PATH, or absolute path to bin.
script: ./fetch.py          # Relative path (to manifest) or absolute path.
args: ["--verbose"]         # List of default arguments forwarded to the script.

# 2. Environment (Optional)
env:                        # Host env vars allowed to pass into the sandbox.
  - LANG
  - AWS_DEFAULT_REGION

# 3. Filesystem Permissions (Optional)
read:                       # Read-only paths (bind-mounted --ro-bind)
  - /etc/hostname
  - .                       # Directory of the manifest/script

write:                      # Writable paths (bind-mounted --bind; implies read)
  - /tmp/output             # Targets must exist on host (unless parent is writable)

# 4. Network Allowlist (Optional)
# If omitted or set to null/empty, all outbound network access is blocked.
network:
  rules:
    - host: api.example.com
      port: "443"
    - host: .github.com     # Suffix match (matches all subdomains of github.com)
      port: "443"
    - host: "*"             # Wildcard host
      port: "8000-9000"     # Matches any port within the range

# 5. Process Restrictions (Optional)
allow_exec: false           # Set to true to permit scripts to spawn subprocesses.
                            # Default (false) blocks execve with EPERM.

# 6. Resource Controls (Optional - Linux cgroups via systemd-run)
limits:
  memory: "128M"            # systemd MemoryMax syntax (e.g., 64M, 1G)
  cpu: "100%"               # systemd CPUQuota syntax (e.g. 50%, 200%)
  tasks: 32                 # systemd TasksMax (process/thread ceiling)
```

---

## Common Configurations & Patterns

### 1. Minimal Sandbox (Formatter, Analyzer, Pure Script)
Zero-config layout. Blocks network, write, and subprocesses.
```yaml
interpreter: python3
script: ./format.py
read:
  - .
```

### 2. Workspace Updater (Linter / Sync tool)
Requires read and write access to the workspace folder, and access to a specific domain (like GitHub).
```yaml
interpreter: node
script: ./sync.js
read:
  - .
write:
  - .
network:
  rules:
    - host: api.github.com
      port: "443"
```

### 3. Static Binary Web Server
For ELF binaries, omit the `interpreter` field. Bento will run the binary directly.
```yaml
# No interpreter: Bento executes the compiled binary directly.
script: ./my-server
network:
  rules:
    - host: "*"
      port: "8080"
limits:
  memory: "64M"
  tasks: 16
```

### 4. Interactive Development Profiling
If you are developing a manifest for a script with complex, branch-specific access patterns:
* **Merge manifest inputs manually:** `bento profile` records only the code path traversed during that single execution. It will overwrite the manifest. Profile different options separately and combine lists.
* **Use Interactive Prompting:** Run the sandbox with `--prompt` to dynamically allow-list filesystem or network misses interactively as the script executes:
  ```bash
  bento run --prompt my-script.yaml
  ```
