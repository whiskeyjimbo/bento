// Package bento runs polyglot scripts under kernel-enforced isolation.
//
// A script's permissions are declared in a [Manifest]: which files it
// can read or write, which hosts and ports it can talk to, which
// subprocesses it can spawn, and what resource ceiling it runs under.
// [Run] executes the script under bubblewrap (Linux) or sandbox-exec
// (macOS).
//
// # Quick start
//
//	m := &bento.Manifest{
//	    Interpreter: "python3",
//	    Script:      "./check.py",
//	    Read:        []string{"/etc/hostname"},
//	    Network: &bento.NetworkPerm{
//	        Rules: []bento.NetworkRule{
//	            {Host: "api.example.com", Port: "443"},
//	        },
//	    },
//	    Limits: &bento.Limits{Memory: "128M", CPU: "100%"},
//	}
//	exitCode, err := bento.Run(context.Background(), m)
//
// # Linux composition
//
// On Linux, bento layers several mechanisms to provide rootless
// per-host network filtering and exec control:
//
//   - bubblewrap for mount namespacing and filesystem isolation
//   - a local HTTP CONNECT proxy that filters HTTP/HTTPS by host
//   - a local SOCKS5 proxy fronted by LD_PRELOAD proxychains so
//     non-HTTP traffic from dynamically-linked binaries is filtered
//   - Landlock TCP rules to block raw connect() from statically-linked
//     binaries (requires kernel ≥ 6.7)
//   - seccomp via a launcher shim that blocks execve when the
//     manifest's Exec slice is empty
//   - systemd-run cgroups for CPU/memory/task ceilings
//
// On macOS, all of the above collapses into a single sandbox-exec
// profile (SBPL).
//
// See docs/DESIGN.md in the repo for the full design history, the
// gaps that remain, and the friction encountered while building this.
//
// # Environment requirements
//
// Linux: kernel ≥ 6.7 (Landlock TCP), bwrap, proxychains4, systemd-run.
// Ubuntu 24.04+ requires an AppArmor profile for bwrap (the package
// installer should handle this; see testdata/bwrap.apparmor).
//
// macOS: ships with everything needed.
//
// Run [Doctor] or [Checks] to verify the environment.
//
// # Error handling policy
//
// bento distinguishes hard errors (the sandbox cannot run at all) from
// degraded modes (the sandbox runs with reduced enforcement):
//
//   - HARD ERROR — [Run] returns a non-nil error. Cases: required
//     core tool missing (bwrap on Linux, sandbox-exec on macOS);
//     manifest interpreter not found; script file missing; proxy bind
//     failure.
//
//   - DEGRADED MODE — [Run] proceeds and returns the script's exit
//     code. A warning is emitted via the [Logger] (prefix "[warn]")
//     describing what's not enforced. Cases:
//
//   - libproxychains.so missing → non-HTTP traffic from
//     dynamically-linked binaries bypasses the host allowlist
//
//   - Landlock TCP unsupported (kernel <6.7) → static binaries can
//     bypass the host allowlist via raw connect()
//
//   - systemd-run missing → manifest resource limits not enforced
//
//   - launcher extraction failed → exec block (seccomp) disabled
//
// Pass [WithLogger] to observe degraded-mode warnings. Treating any
// warning as fatal is the caller's choice; bento doesn't presume a
// security posture for you.
package bento
