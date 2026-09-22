# Perf grid - egress proxy, per connection and per read

Base commit: **bca2d24** (`perf/shield-rule-cost`), confirmed with `git rev-parse HEAD` in the
measurer's worktree before any number below was taken. Counts only - allocations
(`testing.AllocsPerRun`, `runtime.MemStats`, `pprof -memprofilerate=1`), syscalls
(`strace -f -c` on the test binary), and deadline calls on the conns (a counting `net.Conn`
wrapper). Other measurers shared the machine; the two ns/op figures below are labelled
**contaminated by concurrent load** and are order-of-magnitude only.

Instrumentation: one throwaway test file in `internal/proxy` (in-memory `memConn`, counting
`countConn`, a loopback-TCP `tunnel` driver, a `Serve` driver over a unix socket with a real
TCP upstream behind `WithDialer`), plus one throwaway edit to `tunnel` for a no-extend control.
Both deleted after measuring; `proxy.go` is back to the base SHA.

## Invariant

Each stage's cost is bounded by a known function of its input - O(1) per connection, O(R)
where it iterates the rules, O(1) per read in the copy loop - and the per-unit constant is
what the design needs and no more. Symbols: **R** network rules, **N** reads per tunnel,
**H** request header lines.

## Scales measured

| axis | minimal | typical | pathological |
|---|---|---|---|
| bytes per tunnel | 1 KiB | 1 MiB | 1 GiB (32 KiB reads only) |
| read size | 1 B | - | 32 KiB |
| connections, sequential | 1 | 100 | 10,000 |
| network rules R | 1 | 20 | 2,000 |
| rule host length | <= 32 B (`h12.example.org`) | - | 41-44 B (`svc-0001.eu-central-1.compute.amazonaws.com`) |

Rules were ordered with the matching rule **last** (worst case for a hit); the miss case scans
all R by construction.

## Stages and how often each runs

| stage | file:line | runs |
|---|---|---|
| S1 accept + dispatch | `proxy.go:868-923` | 1 / conn |
| S2 handle setup (recover, `AfterFunc`, CONNECT deadline) | `proxy.go:953-1002` | 1 / conn |
| S3 CONNECT parse | `proxy.go:1210` | 1 / conn; header loop 1 / header line |
| S4 allowlist `policy.Allows` | `proxy.go:1043`, `policy/match.go:27` | 1 / conn, iterates R |
| S5 gate `callGate` | `proxy.go:1182` | 1 / conn, only on allowlist miss |
| S6 literal grant + ctx wrap | `proxy.go:1087-1093`, `:573` | 1 / conn, iterates R when the target is an IP literal |
| S7 dial guard `guardUpstream` + classify | `proxy.go:492`, `:629`, `nat64.go:223` | 1 / resolved address |
| S8 tunnel setup | `proxy.go:1134-1150`, `:1444-1508` | 1 / conn |
| S9 copy loop | `proxy.go:1519` (`extend` at `:1457`) | **1 / read, both directions** |
| S10 teardown | `proxy.go:1540`, handle's defers | 1 / conn |

## Grid

Instructions column: **not measurable** on every row - `perf_event_paranoid=4` refuses
`perf stat` to this user, and neither valgrind nor qemu is installed.

| stage | allocs | syscalls (proxy side) | timer ops / deadline calls | complexity | verdict |
|---|---|---|---|---|---|
| S1 | 2 / conn in `Serve` (`wg.Go` closure) + 7 in stdlib `UnixListener.Accept` | accept4 1 (+1 EAGAIN), getsockname 1, epoll_ctl 1 | 0 | O(1) | ok |
| S2 | ~4 `context.AfterFunc` (both AfterFuncs, S2+S8) + 3 in `handle` (closures) | 0 | 2 `SetReadDeadline` (arm `:1002`, clear `:1030`) | O(1) | ok |
| S3 | **9** at H=1, **18** at H=10: `LimitedReader`, `bufio` 4 KiB (2), `strings.Fields`, one `ReadString` alloc per line | read 1 (45-byte request in one read) | 0 | O(H), H capped by `maxRequestBytes` | ok |
| S4, rule host <= 32 B | **0** at R=1/20/2000, hit or miss | 0 | 0 | O(R) | ok |
| S4, rule host >= 33 B | **2 per rule**: hit-last 4 / 42 / 4,002, **miss 2 / 40 / 4,000** at R=1/20/2000; boundary measured 31 B=0, 32 B=0, 33 B=2 | 0 | 0 | O(R) work, **O(R) allocs** | **constant - finding 2** |
| S5 | 0 (`callGate`), nil gate O(1); denied conn total 16 allocs incl. 403 body | 0 (status write 1) | 1 `SetWriteDeadline` on a refusal | O(1) | ok |
| S6, hostname target | 2 (`net.ParseIP` error on the hostname, `:579`) + 1 `WithValue` + 1 escaped `dialRefusals`; `withDialRefusals`+`withLiteralGrant` alone = 4 | 0 | 0 | O(1) | ok |
| S6, IP target, IP-only rules | 1 at R=1/20/2000 | 0 | 0 | O(R) parse | ok (allocs), re-parses R rules per conn |
| S6, IP target, hostname rules | **1 per hostname rule**: 1 / 20 / 2,000 | 0 | 0 | O(R) work, **O(R) allocs** | **constant - finding 3** |
| S7 `guardUpstream` direct | 0 for public v4, public v6, private-with-grant; **1** for a NAT64 `64:ff9b::/96` address (`net.IPv4` in `embeddedIPv4`, `:761`) | 0 | 0 | O(1) per address (O(prefixes) over `p.nat64`) | ok |
| S7 production dial | stdlib `net.Dialer.DialContext` ~27 allocs / conn (measured on the test dialer, which is the same `net.Dialer` path minus ControlContext) | socket, connect (EINPROGRESS), epoll_ctl, getsockopt, getpeername, getsockname, setsockopt x5 (NODELAY + 4 keepalive) = 11 | 0 | O(1) | ok - stdlib; guard itself not reachable hermetically, see below |
| S8 | tunnel 7 (closures, `upstreamSpoke`, `panics`, wg) + `JoinHostPort` 1 + `io.WriteString` 1 (200 line) | write 1 (200 line) | client `SetDeadline` 1, upstream `SetDeadline` 1 (first-byte bound) | O(1) | ok |
| S9 per read | **0** (mallocs over a whole tunnel flat at 14-36, 1 KiB through 1 GiB) | read 1 + write 1 per read (+ EAGAIN/epoll when drained); **SetDeadline adds 0** | **2 `SetDeadline` per read after upstream's first byte, 1 before** | O(1) per read, O(N) per tunnel | **constant on the hottest path - finding 1** |
| S9 buffers | 2 x 32 KiB `copyIdle` buffers per conn | - | - | O(1) | constant - finding 4 |
| S10 | 0 | shutdown 2, epoll_ctl DEL 2, close 2 | `halfClose` `SetDeadline` only on a conn with no `CloseWrite` (0 in production) | O(1) | ok |

### Whole connection

| cell | K=1 | K=100 | K=10,000 | verdict |
|---|---|---|---|---|
| allocs / conn, in-memory `handle`, 1 rule | 36.0 | 33.1 | 33.0 | ok, flat |
| bytes / conn | 71,896 | 70,864 | 70,827 | constant - 64 KiB is the two copy buffers |
| goroutines retained after | 0 | 0 | 0 | ok |
| heap-in-use delta after GC | -48 KiB | 0 | +24 KiB | ok, no retention |
| syscalls / conn through `Serve` (strace, both test ends included) | - | 73.4 non-futex | 73.1 non-futex (+10.5 futex) | ok, flat |

The in-memory `handle` count is the same (33) whether the parent ctx is `Background` or a
`WithCancel` as `Serve` passes; the cancelCtx children-map insert/delete under its mutex per
connection allocates nothing measurable here, and its **contention** across up to 512
concurrent handlers is not measurable without wall time.

Proxy-side syscall breakdown for one connection (strace without `-c`, attributed by fd): S1 4,
S3 1, S7 11, S8 1, S9 2 per read (+ EOF/EAGAIN reads), S10 6 - about 25 + 2N. The other ~48 of
the 73 are the test's own client and upstream-server ends plus runtime.

### S7 not reachable hermetically

`WithDialer` replaces the whole `net.Dialer`, so `guardUpstream` (its `ControlContext`) never
runs on the measured connections, and the production dialer's only hermetic target - loopback -
is refused by the guard itself. The guard was measured by calling it directly (row S7).

### S9 per-read detail (loopback TCP, `tunnel` driven directly)

The harness finishes the upload before the download starts, so upload reads happen before
upstream has spoken (1 `SetDeadline` each, client only) and download reads after (2 each).

| bytes | read size | reads up->client | client `SetDeadline` | upstream `SetDeadline` | mallocs (whole tunnel) |
|---|---|---|---|---|---|
| 1 KiB | 1 B | 1,024 | 2,049 | 1,025 | 18 |
| 1 MiB | 1 B | 1,048,576 | 2,097,153 | 1,048,577 | 32 |
| 1 KiB | 32 KiB | 1 | 3 | 2 | 20 |
| 1 MiB | 32 KiB | 33 | 66 | 34 | 15 |
| 1 GiB | 32 KiB | 32,801 | 65,570 | 32,802 | 14 |
| 1 GiB | 1 B | not measured - ~3 G syscalls; linearity is shown by the 1 KiB and 1 MiB rows | | | |

So **SetDeadline calls = 1 per pre-first-byte read + 2 per post-first-byte read + 2 at setup**,
exactly, in every cell.

What one `SetDeadline` costs (read from source, go1.27): `internal/poll.setDeadlineImpl`
(`fd_poll_runtime.go:146`) does `time.Until` (a clock read) and `incref`/`decref`, then
`runtime.poll_runtime_pollSetDeadline` (`netpoll.go:372`) takes `pd.lock`, reads `nanotime`,
and does **one** `timer.modify` (rd == wd, so the combined timer - the write timer stays
stopped). With `extend`'s own `time.Now`, one post-first-byte read costs **5 clock reads,
2 pd locks, 4 atomic ref ops, 2 runtime timer modifications**. None is a syscall: in the 1 MiB
/ 1 B strace, `write` = 3,145,841 against 3,145,728 payload writes (proxy both directions +
the test server), so 3.1 M `SetDeadline` calls produced at most 113 extra writes (netpoll
breaks included). `BenchmarkGridExtend` (time.Now + 2 SetDeadline on TCP conns): 309-331 ns/op,
0 allocs - **contaminated by concurrent load**.

A no-extend control run was attempted and discarded: with `extend` stubbed out, the upstream
stayed on its first-byte deadline, which expired under strace's slowdown and cut the tunnel at
191,312 of 1,048,576 bytes - itself a demonstration that the re-arm is load-bearing.

## Findings, ranked

No cell violates **scaling**: every stage is O(1) per connection or per read, or O(R) where it
iterates the rules, and allocations, goroutines and heap are flat from 1 to 10,000 sequential
connections. All findings are **constant**, ranked by how often the constant is paid.

**1. The copy loop re-arms two runtime timers on every read.** (constant, hottest path)
`copyIdle` (`proxy.go:1524`) calls `extend` on every read that returns data; `extend`
(`proxy.go:1457-1467`) does `time.Now` plus `client.SetDeadline` and, once upstream has spoken,
`upstream.SetDeadline`. Measured: **2 SetDeadline per read** after the first upstream byte
(1 before), in both directions - 98,372 calls for a 1 GiB tunnel at 32 KiB reads, 3,145,730 for
1 MiB each way at 1-byte reads. Each is 2-3 clock reads, a pd lock and a runtime timer modify;
0 allocs, 0 syscalls. The deadline only needs to move when it is close to firing; it is moved
on every 1-byte read.
*Fix must preserve (see the comment at `:1445`):* both conns re-armed by traffic in either
direction; upstream held at `firstByte` until it speaks; `extendUp`'s **first** call always
arms (a rate limiter that swallows it leaves a live upstream on the first-byte bound); no
teardown earlier than `idle` after the last activity; and no reintroduction of the `:1460`
race (a client read clamping upstream back after the byte that lifted the bound). Shape: arm
to `now + idle + slack` and skip the re-arm while less than `slack` has passed since the last
arm (monotonic clock, per-tunnel atomic), so the tunnel dies within `[idle, idle + slack]` of
the last byte; the `upstreamSpoke` transition forces an arm.
*Red-first test:* drive `tunnel` over `countConn`-wrapped loopback conns with N = 10,000 1-byte
reads inside one slack window; assert total `SetDeadline` calls <= a small constant (base:
~2N = 20,000). Keep `TestTunnelOneWayTransferNotIdleTimedOut` and the first-byte tests green as
the semantics guard, and add one that a tunnel idle for `idle` is still torn down.

**2. `policy.Allows` allocates two strings per rule for any rule host over 32 bytes.**
(constant, per connection x R) `matchHost` (`policy/match.go:92`) calls
`normalizeHost(pattern)` for every rule on every call; `asciiLower` (`policy/match.go:64-71`)
does `[]byte(host)` then `string(b)`, which stay on the stack only up to 32 bytes. Measured
boundary: 31 B = 0, 32 B = 0, **33 B = 2** allocs per rule. Realistic cloud hostnames exceed
32 B. **A denied CONNECT scans all R**, and the sandbox can repeat it at will: 2 / 40 / **4,000**
allocs at R = 1 / 20 / 2,000 for `Allows` alone; a whole denied connection goes from 16 allocs
(R=1) to **4,016** (R=2,000). An allowed connection matching the last rule costs 4,002.
`BenchmarkGridAllowsLong2000` (Allows + literalGrantFor, IP target, 2,000 long hostname rules):
5,998 allocs, 288 KB per connection, ~0.5 ms - ns **contaminated by concurrent load**. Rule
patterns never change after load, so the fold can be done once (at `New`, or by `asciiLower`
returning its input unchanged when it holds no A-Z). `Allows` is shared with any other caller
in the tree, so the fix lands for them too.
*Red-first test:* `testing.AllocsPerRun(policy.Allows(rules, "denied.example", "443")) == 0`
with R = 2,000 lowercase rule hosts of 40+ bytes (base: 4,000).

**3. `literalGrantFor` re-parses every rule per connection and allocates on each hostname rule.**
(constant, per IP-literal connection x R) `proxy.go:584` calls `net.ParseIP(r.Host)` for every
rule; on a hostname rule the parse fails and `netip.ParseAddr` allocates its error. Measured with
an IP-literal CONNECT and hostname rules ahead of the matching IP rule: **1 / 20 / 2,000**
allocs at R = 1 / 20 / 2,000; whole connection 33 / 90 / **6,030** (findings 2 and 3 together).
Also 2 allocs on every hostname CONNECT for the failed `ParseIP(host)` at `:579`.
*Fix shape:* parse the IP-literal rules once in `New` into a slice of `(net.IP, port)`.
*Red-first test:* `AllocsPerRun(p.literalGrantFor("10.0.0.5", "443")) <= 1` with 1,999
hostname rules then `10.0.0.5` (base: 2,000).

**4. 64 KiB of copy buffers per tunnel.** (constant, per connection) `copyIdle`
(`proxy.go:1520`) allocates a fresh 32 KiB buffer per direction: 70.8 KB/conn of the total, up to
~32 MiB at `maxConcurrent` = 512. Within the design (bounded by the concurrency cap) and the
cheapest to leave; a `sync.Pool` would remove the per-connection allocation. The hand-rolled
loop also forgoes `io.Copy`'s splice path for TCP -> unix, but only because the per-read hook
exists; finding 1's fix does not remove the hook, so this stays a note, not a finding.
*Red-first test:* bytes/conn over 1,000 sequential in-memory connections < 8 KiB (base 70,827).

## Cells not measured, and why

- **Instructions**, every row: `perf_event_paranoid=4`, no valgrind or qemu.
- **Production `guardUpstream` on a real dial**: `WithDialer` bypasses ControlContext, and the
  production dialer's only hermetic target (loopback) is refused by the guard. Measured directly.
- **1 GiB at 1-byte reads**: ~3 G syscalls; the 1 KiB and 1 MiB rows show the per-read count is
  exact and linear.
- **cancelCtx mutex contention** from each connection's `AfterFunc` and dial-timeout ctx
  registering under Serve's single cancelCtx: allocation-free (33 either way), contention is a
  wall-time property and wall time is contaminated here.
- **futex / nanosleep / epoll_pwait** per read: scheduling- and strace-dependent, not
  attributable; only `write` and `accept4`/`read`/`shutdown`/`close` counts are cited.
- **Wall time / throughput**: contaminated by concurrent load; the two ns/op figures above are
  labelled as such and are not evidence.

## Benchmark audit

No benchmark in the tree reaches this path (confirmed: `grep -n Benchmark internal/proxy`
finds none). Every fix above needs its count assertion written from scratch; the `countConn`
wrapper and an in-memory `memConn` with a `CloseWrite` are the two fakes that make the counts
deterministic.
