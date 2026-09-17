# Failure modes: internal/proxy

- Scope: `internal/proxy` (`proxy.go`, `nat64.go`) plus the one production embedder, `internal/linux/linux.go` `startProxy`/`startProxyWith`/`egressCollector`.
- Date: 2026-09-17. Live pass: yes. It ran through the package's own dial and callback hooks, using a temporary in-package test file that was deleted afterwards. No real network, no processes started outside `go test`, no tracked file changed.
- Grades: 4 rows `observed`, 26 `read (test)` (read, and backed by an existing named test in the package), 11 `read`. 41 rows total, 7 dropped.

Both halves turned out thin, in different ways. There are no startup preconditions: the package reads no env vars, config files or binaries. The dependency half is real, but the code has been worked over hard (94 commits, 61 of them fixes). Nearly every behavior verdict is `HANDLED`, and almost every refusal already reaches the run report as its own decision or counter. The findings below are what is left.

## Findings

### 1. The NAT64 site-prefix screen goes inert if the host joins a DNS64 network after the proxy starts

- **What fails:** NAT64 discovery runs once, when `Serve` starts. If the host is not on DNS64 at that moment (the conclusive "no DNS64" answer), and the network changes mid-run (a laptop joins a DNS64/NAT64 Wi-Fi, or a VPN comes up), the proxy never learns the new site prefix. Meanwhile the Go resolver re-reads resolv.conf, so resolution follows the new network.
- **Effect:** an allowlisted hostname that resolves to a site-prefix synthesis wrapping RFC1918 is dialed. The run can reach the LAN through a permitted public name. That is the SSRF shape `nat64.go` exists to close, and nothing reports it.
- **Mechanism:** `proxy.go:709-711` runs discovery once. `nat64.go:131` and `nat64.go:134-149` leave `nat64` empty and `nat64Inconclusive=false` on NXDOMAIN. So in `nat64.go:266` and `nat64.go:269`, neither the `mayWrapUnroutableV4` guess nor the inconclusive fail-closed applies, and `classifyNAT64` returns `ipPublic`.
- **Evidence (observed):** discovery answered `IsNotFound`. Then `guardUpstream(ctx, "tcp", "[2001:db8:64::a00:5]:443", nil)` returned `err=<nil>` with `inconclusive=false prefixes=0`. The same address after a discovery that did see the prefix returned `refusing egress to non-public address 2001:db8:64::a00:5`.
- **Detection:** SILENT. The dial succeeds and is reported `Allowed`.
- **Caveat:** this takes a network change during a run plus a resolver that synthesizes toward RFC1918, so it only matters for long runs on mobile hosts. The one-shot discovery is documented (`nat64.go:17-29`, `proxy.go:692-694`), but a network change after start is not listed as a limit anywhere, including `docs/threat-model.md`.

### 2. An embedder gatekeeper that ignores ctx hangs run teardown with no bound and no report

- **What fails:** an embedder's gate that blocks without selecting on `ctx.Done()`.
- **Effect:** `stop()` never returns, so the run never finishes and there is no report explaining why.
- **Mechanism:** the contract is documented at `proxy.go:228-230`, but nothing enforces it. `callGate` (`proxy.go:1039`) calls the gate with no deadline. Serve's shutdown (`proxy.go:763`) waits for every handler to finish, and `startProxyWith`'s stop waits for Serve to return (`linux.go:1217`).
- **Evidence (observed):** a gate blocking on a channel, one pending CONNECT, then `stop()`: `teardown still blocked after 3.002178091s`. It returned only after the gate was released by hand.
- **Detection:** SILENT, and it's a HANG. Both in-repo embedders honor ctx (`examples/embed/main.go:578`, `examples/supervise/main.go:915`), so this is unreached in the tree. `enforce.Options.NetworkGate` is public API, though, and nothing turns a violation into anything louder than a hang.

### 3. A NAT64 lookup that ignores ctx means the proxy never accepts (unreached in production)

- **What fails:** a `WithNAT64Discovery` lookup that ignores its ctx.
- **Effect:** Serve never reaches `Accept`, so every CONNECT from the sandbox hangs until the client gives up.
- **Mechanism:** `proxy.go:709-711` bounds the lookup only through ctx.
- **Evidence (observed):** with a lookup that blocks without watching ctx, the CONNECT read hit `i/o timeout after 5.000331487s` with no answer from the proxy.
- **Detection:** SILENT, and it's a HANG. It is unreached in production because the only production lookup, `DefaultNAT64Lookup` (`nat64.go:101-103`), passes ctx to `net.Resolver.LookupIP`, which honors it. Recorded because the option is exported and the 3s bound is a promise made by the caller, not by the proxy.

### 4. NAT64 discovery failing inconclusively is only visible once it costs a connection

- **What fails:** discovery returns an error or a non-deriving AAAA.
- **Effect:** for the rest of the run, IPv6-only allowlisted hosts are refused (`nat64.go:204-206`). This is counted, but only per lost connection. A run that never dialed an IPv6-only host carries no trace that its guard was in fail-closed mode.
- **Mechanism:** `nat64Inconclusive` is set at `nat64.go:131` and `nat64.go:142`, but there is no accessor for it. Only `NAT64Blackouts` is exported (`proxy.go:194`), and it goes to `linux.go:1223`.
- **Detection:** LOGGED-ONLY at best (as a blackout count), and SILENT until a connection is lost. The design comment at `nat64.go:218-222` makes this choice on purpose. It fits the "decided correctly, then declined to tell anyone" shape, but its cost is low: nothing was lost that went unreported.

## Full matrix

Behavior: HANDLED / HANG / SILENT-WRONG / CRASH / UNREACHED. Detection is what the run report carries (via `egressCollector` or `proxyOutcome`).

| id | behavior | effect | detection | grade | evidence |
|---|---|---|---|---|---|
| upstream-tcp/connection-refused | HANDLED, 502 | script sees "could not reach" | DETECTED as `Unreachable` (counted, unnamed: `linux.go:1098`) | read (test) | `proxy.go:975-979`; `TestAFailedDialIsReportedApartFromAnEstablishedTunnel` |
| upstream-tcp/connection-hang (SYN blackhole) | HANDLED, 15s | slot held 15s | DETECTED `Unreachable` | read | `proxy.go:291-297` |
| upstream-tcp/accepts-then-silent | HANDLED, 30s first-byte | slot held 30s | none specific; tunnel closes | read (test) | `proxy.go:1324`; `TestTunnelBoundsASilentUpstreamThroughTheClientsTraffic` |
| upstream-tcp/stalls-mid-stream | HANDLED, 5m idle | slot held up to 5m per tunnel | none | read (test) | `proxy.go:1305-1315`; `TestTunnelOneWayTransferNotIdleTimedOut` |
| upstream-tcp/stops-reading (write blocks) | HANDLED, first-byte or idle deadline bounds writes | slot held up to 5m | none | read | `proxy.go:1297`, `proxy.go:1313`, `proxy.go:1324` |
| upstream-tcp/reset-mid-stream | HANDLED, copy ends, halfClose | tunnel truncated, script sees reset | none (correctly, since it's the peer's doing) | read | `proxy.go:1373-1379`, `proxy.go:1336-1352` |
| upstream-tcp/half-close | HANDLED | return path stays open | n/a | read (test) | `TestTunnelHalfCloseKeepsTheReturnDirectionOpen` |
| upstream-tcp/multi-address one refused by guard | HANDLED | refusal on a non-first address is not lost | DETECTED `GuardBlocked` | read (test) | `proxy.go:950`; `TestGuardBlockSurvivesAnotherAddressesError` |
| upstream-tcp/panicking conn (dial hook) | HANDLED | process survives | DETECTED `HandlerFaults` | read (test) | `proxy.go:1336-1361`; `TestPanicInACopyGoroutineDoesNotKillTheProcess` |
| system-resolver/unresolvable | HANDLED, 502 | same as refused | DETECTED `Unreachable` | read | `proxy.go:943-979` |
| system-resolver/hang | HANDLED, the 15s dial timeout covers resolution | slot held 15s | DETECTED `Unreachable` | read | `proxy.go:297` (net.Dialer.Timeout includes resolve) |
| system-resolver/answers-non-public (rebind) | HANDLED | refused, same text as a dial failure | DETECTED `GuardBlocked`, named | read (test) | `proxy.go:395-419`; `TestBlocksPermittedHostResolvingToNonPublic`; `guard_concurrency_test.go` |
| system-resolver/changes-network-mid-run | SILENT-WRONG | site-prefix NAT64 screen inert, LAN reachable via allowlisted name | SILENT | observed | Finding 1 |
| nat64-discovery/nxdomain | HANDLED (conclusive "no DNS64") | none | n/a | read (test) | `nat64.go:131`; `nat64_test.go` |
| nat64-discovery/hang | HANDLED, 3s then inconclusive | run start delayed 3s; IPv6-only hosts refused | DETECTED `NAT64Blackouts` only when a connection is lost | read (test) | `proxy.go:709`; `nat64.go:131`; `TestNAT64BlackoutsCountTheConnectionsTheRunActuallyLost` |
| nat64-discovery/servfail or refused | HANDLED, inconclusive | as above | as above | read | `nat64.go:131` |
| nat64-discovery/garbage AAAA (captive portal) | HANDLED, inconclusive | as above | as above | read (test) | `nat64.go:137-143`; `nat64_fuzz_test.go` |
| nat64-discovery/lookup ignores ctx | HANG | proxy never accepts | SILENT | observed | Finding 3; unreached via `nat64.go:101-103` |
| nat64-discovery/inconclusive-no-loss | HANDLED | fail-closed mode invisible | SILENT | read | Finding 4 |
| gatekeeper/panic | HANDLED, 403 | refused | DETECTED `GateFaulted` + `gateFaults` | read (test) | `proxy.go:1030-1040`; `TestGatekeeperPanicIsDeny` |
| gatekeeper/slow (honors ctx) | HANDLED | slot pinned while prompting; flood leads to at-capacity | DETECTED `RefusedAtCapacity` | read (test) | `proxy.go:250-253`; `TestGatekeeperUnblockedByCancel` |
| gatekeeper/hang ignoring ctx | HANG | teardown never returns | SILENT | observed | Finding 2 |
| gatekeeper/cancelled mid-prompt | HANDLED | no tunnel opens | n/a | read (test) | `TestConcurrentGatesBlockedAtCancelOpenNoTunnels` |
| observer/panic | HANDLED | decision lost | DETECTED `ObserverFaults` | read (test) | `proxy.go:1008-1018`; `TestAPanickingObserverCountsTheDecisionItLost` |
| observer/panic on accept path | HANDLED | Serve survives | DETECTED `ObserverFaults` | read (test) | `TestObserverPanicOnRefusedDoesNotKillServe` |
| observer/slow | UNREACHED | would stall the accept loop at capacity | n/a | read | only embedder takes a short mutex: `linux.go:1053-1055` |
| listener/transient (EMFILE, ENFILE, ENOMEM, ENOBUFS, ECONNABORTED) | HANDLED, backoff 5ms to 1s | socket unanswered during backoff | DETECTED `AcceptRetries` degrades layer | read (test) | `proxy.go:718-750`; `TestServeCountsTheAcceptRetriesItRodeOut`; `linux.go:474` |
| listener/permanent error | HANDLED, returns err after drain | egress dead for rest of run | DETECTED `serveErr` | read (test) | `proxy.go:757-766`; `TestServeReturnsTerminalAcceptError` |
| listener/closed during retry backoff | HANDLED | exits promptly | n/a | read (test) | `proxy.go:743-747`; `TestServeStopsOnAClosedListener` |
| listener/Serve called twice | HANDLED, error | none | loud error | read (test) | `proxy.go:696`; `TestSecondServeIsRefusedBeforeItRewritesDiscovery` |
| client/connects, sends nothing | HANDLED, 30s | slot held 30s | DETECTED `Refused` | read (test) | `proxy.go:851`; `TestServeCancelUnblocksPendingConnect` |
| client/never reads status | HANDLED, 5s write deadline | slot held up to 5s | status-path decision already reported | read (test) | `proxy.go:1262-1265`; `TestStatusWriteDoesNotPinAHandlerOnAClientThatNeverReads` |
| client/oversized request | HANDLED, 64KiB cap | 400 | DETECTED `Refused` | read (test) | `proxy.go:1048`; `TestOversizedRequestRejected` |
| client/dies mid-headers | HANDLED | 400 | DETECTED `Refused` with host | read | `proxy.go:1131-1136` |
| client/not CONNECT | HANDLED | 400 naming the remedy | DETECTED `Untunneled` | read (test) | `TestUntunneledRequestReportsItsDestination` |
| client/cancel mid-tunnel | HANDLED | tunnel torn down | n/a | read (test) | `proxy.go:848`, `proxy.go:986`; `TestServeCancelTearsDownTunnel` |
| resource/concurrency cap reached | HANDLED, 503 | declared egress refused by load | DETECTED `RefusedAtCapacity` degrades layer | read (test) | `proxy.go:767-784`; `linux.go:495`; `TestConcurrencyIsCapped` |
| resource/cap + non-reading flood on accept path | HANDLED | accept loop not stalled | DETECTED | observed | 512 slots pinned by pending gates, 50 never-reading flood conns, 51st answered `503` in 743us, atCapacity=51. `proxy.go:777` write fits the fresh socket buffer |
| resource/fd exhaustion (host-wide) | HANDLED via accept retry | as listener/transient | DETECTED | read | `proxy.go:651-659`, `proxy.go:678-687` |
| resource/handler panic before decision | HANDLED, 502 | connection dropped | DETECTED `Faulted` | read (test) | `proxy.go:819-840`; `TestPanicBeforeTheTunnelAnswersWithAStatus` |
| resource/memory per tunnel | HANDLED | 32KiB×2 buffer, times 512 slots, is about 33MiB max | none | read | `proxy.go:1368`, `proxy.go:659` |

## Not injected

- **Everything that needs a real resolver or kernel TCP behavior** (SYN blackhole, resolver hang, mid-stream reset): `WithDialer` replaces the whole default dialer including the guard hook, so a fake there can't exercise the real `net.Dialer` timeout path. Left at `read`.
- **Host-wide fd and memory exhaustion:** not safe to cause on a shared host. Left at `read`, backed by the fake-listener retry tests.

## Dropped rows

- **TLS rows** (bad cert, handshake timeout, protocol mismatch): the proxy is a byte tunnel and never touches TLS.
- **env-\*, config-\*, credential-\*, path-\*, binary-\*:** the package reads none. The socket path is created by the embedder (`linux.go:1204`), whose failure is loud (`linux: starting egress proxy`).
- **pool-exhausted:** no connection pool. Every tunnel dials fresh.
- **port-already-bound:** unix socket from the embedder, not a port. It fails at `net.Listen` loudly.
- **retry-storm on upstream:** the proxy never retries a dial.
- **stale-cache:** there is no DNS cache beyond Go's resolver, which re-reads config. The one-time cache that does exist (NAT64 discovery) is covered by finding 1.

## Phase 5: outside the grid

The code was reread for comments that contradict the code, recovers that swallow errors silently, signals that are built but never read, one outcome covering several causes, and limits nobody watches. Only one thing turned up that the grid didn't cover: `nat64Inconclusive` is set but never exported (finding 4). All four fault counters and every decision are read by `startProxyWith` and `egressCollector` (`linux.go:1219-1225`, `linux.go:1061-1110`). All three `recover()` sites count or report what they catch. `Unreachable` and `Allowed` share an unnamed tally on purpose (`linux.go:1098-1103`), and the comment there says why. No comment/code contradictions were found in the files read.

## Teardown

The temporary probe file `internal/proxy/zz_failmode_probe_test.go` was deleted after the run, and `git status` shows `internal/proxy` clean. No processes, ports or sockets outlived `go test` (sockets were in `t.TempDir()`).
