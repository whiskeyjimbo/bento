# Go Library Integration Guide

Bento can be embedded directly into Go applications as a library. This guide details how to integrate Bento into your codebase, along with its API surface and error handling models.

---

## Basic Integration

To add Bento to your Go project:

```bash
go get github.com/whiskeyjimbo/bento
```

Below is a complete example of configuring and running a Python script under Bento's sandbox:

```go
package main

import (
    "context"
    "log"
    "os"
    "time"

    "github.com/whiskeyjimbo/bento"
)

func main() {
    // 1. Declare the sandbox manifest
    m := &bento.Manifest{
        Interpreter: "python3",
        Script:      "./fetch.py",
        Read:        []string{"/etc/hostname"},
        Write:       []string{"/tmp/results"},
        Network: &bento.NetworkPerm{
            Rules: []bento.NetworkRule{
                {Host: "api.example.com", Port: "443"},
                {Host: ".github.com", Port: "443"},
            },
        },
        Limits: &bento.Limits{
            Memory: "128M", 
            CPU: "100%", 
            Tasks: 32,
        },
    }

    // 2. Run the sandbox context
    code, err := bento.Run(context.Background(), m,
        bento.WithLogger(log.New(os.Stderr, "[bento] ", log.LstdFlags)),
        bento.WithTimeout(30*time.Second),
        bento.WithExtraEnv(map[string]string{"DEPLOY_ID": "abc123"}),
    )
    if err != nil {
        log.Fatalf("Sandbox execution failed: %v", err)
    }

    os.Exit(code)
}
```

---

## API Reference

### Core Types
```go
type Manifest struct {
    Interpreter string       `yaml:"interpreter"`
    Script      string       `yaml:"script"`
    Args        []string     `yaml:"args"`
    Env         []string     `yaml:"env"`
    Read        []string     `yaml:"read"`
    Write       []string     `yaml:"write"`
    Network     *NetworkPerm `yaml:"network"`
    AllowExec   bool         `yaml:"allow_exec"`
    Limits      *Limits      `yaml:"limits"`
}

type NetworkPerm struct {
    Rules []NetworkRule `yaml:"rules"`
}

type NetworkRule struct {
    Host string `yaml:"host"`
    Port string `yaml:"port"`
}

type Limits struct {
    Memory string `yaml:"memory"` // systemd MemoryMax syntax
    CPU    string `yaml:"cpu"`    // systemd CPUQuota syntax
    Tasks  int    `yaml:"tasks"`  // systemd TasksMax
}

type NetworkMode int
const (
    NetworkModeAuto NetworkMode = iota
    NetworkModeLandlock
    NetworkModeBridge
)
```

### Library Entrypoints
```go
// Run executes the sandbox given a manifest configuration and options.
// Returns the script's exit code and any configuration/runtime error.
func Run(ctx context.Context, manifest *Manifest, opts ...Option) (int, error)

// Doctor runs readiness checks on the host and writes diagnostics to the writer.
// Returns true if the host is ready to enforce all standard protections.
func Doctor(w io.Writer, opts ...CheckOption) bool

// Checks evaluates host capabilities and returns details of individual probes.
func Checks(opts ...CheckOption) []CheckResult
```

### Execution Options (`Option`)
* `WithLogger(Logger)`: Sets custom logging for warning and lifecycle outputs.
* `WithStdin(io.Reader)` / `WithStdout(io.Writer)` / `WithStderr(io.Writer)`: Configures custom I/O streams for the sandboxed process.
* `WithTimeout(time.Duration)`: Enforces execution deadlines.
* `WithExtraEnv(map[string]string)`: Appends environment variables directly to the sandbox environment.
* `WithNetworkMode(NetworkMode)`: Forcefully overrides auto-selection to use `NetworkModeLandlock` or `NetworkModeBridge`.

### Doctor Options (`CheckOption`)
* `WithSkipNetwork()`: Bypasses network interface check.
* `WithFailFast()`: Aborts checks on the first diagnostic failure.
* `WithCheck(CustomCheck)`: Registers user-defined pre-flight validation rules.

---

## Error Handling & Degraded Modes

Bento distinguishes fatal environment/manifest configuration errors from warnings about **degraded modes**:

### 1. Hard Errors (`Run()` returns `err != nil`)
These are unrecoverable setup configurations that cause execution to immediately fail:
* Required binary (`bwrap` on Linux, `sandbox-exec` on macOS) is not found on the host system.
* The manifest's `interpreter` cannot be resolved.
* The targeted `script` file does not exist.
* The sandbox proxy fails to bind to its port.
* Symlink-escape is detected on a requested write path.

### 2. Degraded Modes (Process proceeds, warning is logged)
These indicate that Bento cannot enforce specific optional layers but continues execution in a slightly less isolated state. If a logger is configured via `WithLogger`, warnings will be printed:
* **`libproxychains.so` missing:** SOCKS5 interception (`LD_PRELOAD` layer) is disabled. (TCP Landlock or Bridge mode still blocks static binaries).
* **Landlock TCP unavailable in `auto` mode:** Automatically degrades to the network namespace Bridge mode.
* **`systemd-run` missing:** Resource limits (Memory, CPU) are not enforced.
* **Launcher extraction failure:** The seccomp subprocess exec block is disabled.

*Note: Bento does not make assumptions about your security posture. It is up to the caller to treat specific warnings as fatal if desired.*
