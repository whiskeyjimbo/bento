# [ADR-0003] Host-Side HTTP CONNECT Proxy for Network Egress

* **Status:** Accepted
* **Date:** 2026-07-14

## Context and Problem Statement

Allowing fine-grained per-host:port egress from inside an unprivileged sandbox is challenging. Statically linked binaries (Go, Rust) ignore `LD_PRELOAD` hooks (like `proxychains`), and raw IP routing without root or custom nftables rules cannot reliably map outbound sockets to hostnames.

## Decision Drivers

* Strict default-deny network boundary (`--unshare-net`).
* Per-host/domain allowlisting without root privileges.
* Protection against domain fronting, SNI spoofing, and metadata endpoint probing (e.g. `169.254.169.254`).

## Decision Outcome

Chosen Option: **Host-Side HTTP CONNECT Proxy over an Isolated Unix Domain Socket**.

1. The sandbox runs inside an empty network namespace (`--unshare-net`) with zero IP routes out.
2. An egress proxy (`internal/proxy`) runs host-side, listening on a Unix domain socket bind-mounted into the sandbox.
3. The sandboxed process routes outbound HTTP/HTTPS traffic through the proxy via `HTTP_PROXY`/`HTTPS_PROXY`.
4. Hostname validation is enforced via the HTTP `CONNECT` target. The proxy resolves hostnames host-side and re-verifies resolved IP addresses before connecting, flatly refusing loopback, RFC1918 (unless explicitly allowed by literal IP rule), link-local, and cloud metadata addresses.

### Positive Consequences

* No root required; works entirely via unprivileged user namespaces and Unix domain sockets.
* Prevents SNI spoofing and domain fronting because the requested hostname is bound to the CONNECT request.
* Statically linked binaries that respect proxy environment variables route safely; programs that ignore the proxy fail closed with `ENETUNREACH`.

### Negative Consequences / Trade-offs

* Cooperative proxying: applications that do not support HTTP/HTTPS proxy environment variables cannot reach the network until transparent proxying (TPROXY) is implemented.
