# perf-hunt round 2 - merged findings across three grids

Measured at `bca2d24` (level with `main`, every round-1 fix in). Three measurers, one per
path picked from `perf-hunt-candidates-2.md`; each grid is its own file.

- `perf-grid-launch.md` - one launch end to end, `validate` and `run`, including the bwrap
  argv compile and Landlock rule build round 1 never reached
- `perf-grid-observe.md` - the ptrace tracer behind `bento profile`
- `perf-grid-proxy.md` - the egress proxy, per connection and per read

Counts only. The measurers shared one machine, so no wall time is evidence here; every fix
still needs a serial before/after. `perf_event_paranoid=4` on the measuring host, so no
instruction counts either.

Provenance: the numbers below are the measurers', relayed. The orchestrator re-read the
code behind the two scaling findings (`autoexec.go:161`, `observe_linux_amd64.go:270`) and
confirms the cause as stated; nothing else was independently reproduced.

## The cross-cutting result

Round 1's shape repeats, one level up: **a fix landed on `run` and was not carried to
`validate`.** `af0664c` stopped `run` probing limits it never reads; `validate` still does
(finding 5). `dced93f` memoized the shield set per filesystem view; `validate` builds two
views and assembles twice (finding 4). `803ff2c` put the cheap reachability test before the
stat in `internal/linux`; the gate's copy of `ShieldCarveProblems` still stats first
(finding 10). Each round-1 fix holds where it was applied - the launch grid checks all of
them - and none reached its sibling caller.

The other shape is new: the two scaling findings both sit in code no perf commit has ever
touched (`internal/linux/autoexec.go`, `internal/observe`), which is what the round-2 sweep
predicted from the commit census.

## Findings, merged and ranked

Scaling on a hot path first, then constant on a hot path by frequency x magnitude.

| # | Finding | Class | file:line | Measured |
|---|---------|-------|-----------|----------|
| 1 | Hook-runner resolution re-resolves every write grant inside a per-grant loop, execs `git` per grant, and runs twice per launch | scaling O(W^2), every `run` | `internal/linux/autoexec.go:161-162` inside `hookRunnerDir:124`, called per grant at `:300`; passes at `linux.go:152`, `autoexec.go:217` | B240 (240 write grants, one checkout): 14,520 `EvalSymlinks` per pass, 239,040 of 250,905 stats (95%), 1.24M of 1.36M allocs (91%), 240 `git rev-parse` for one checkout |
| 2 | The tracer stops on every tracee syscall, file-related or not | scaling in total syscalls, per profiled syscall | `internal/observe/observe_linux_amd64.go:270`, resumes `:356`, `:449`, `:533` | 1e6 getpids: 6,000,096 ptrace + 2,000,081 wait4; identical stop count at 10% file syscalls |
| 3 | Every exit stop formats keys and heap-allocates with nothing held | constant, per profiled syscall | `stopKey` `:835` via `releaseDrop` `:1023`, `releaseHeldExec` `:1836`, `recordHeldExistence` `:1325`; `regs` escapes `:997` | 18.0 mallocs per ignored syscall |
| 4 | `validate` assembles the shield set twice and recomputes the grant refusals | constant, every `validate` | `gate/gate.go:174` -> `:567` unmemoized vs `cmd/bento/validate.go:984` / `render.go:403`; refusals `validate.go:985-996` vs `gate.go:362` | 1,281 resolve misses for 644 paths; ~29k allocs, 3.6k stats, 2k readlinks per extra assembly |
| 5 | `validate` runs the full `Probe` for a manifest with no limits | constant, every `validate` | `cmd/bento/validate.go:475`; only `RequiredLayers` read at `:414-416` | 9 execs, 7 avoidable (two `systemd-run` with D-Bus round trips) |
| 6 | `readString` goes through `os.Open`, so every path read registers with the netpoller | constant, per profiled file syscall | `observe_linux_amd64.go:1718`; `openHow:1703` opens it a second time | 8 tracer syscalls per pathname, 16 for openat2; `process_vm_readv` would be 1 |
| 7 | `exists`/`isDir`/`writable` have no run-wide memo; `denyArgs`, `createdShields` and the shield checks each run twice from identical inputs | constant, every `run` | `alias.go:52-72`, `:171-190`; `linux.go:172`, `:159`, `:775`; `shields.go:46`, `:585`, `:703`, `:821` | A240: 14,605 exists checks for 2,413 paths, 29,091 goroutines |
| 8 | The tunnel re-arms two runtime timers on every read | constant, per tunnel read | `internal/proxy/proxy.go:1524` -> `extend` `:1457-1467` | 2 `SetDeadline` per read; 3,145,730 for 1 MiB each way at 1-byte reads. 0 allocs, 0 syscalls |
| 9 | `policy.Allows` allocates twice per rule whose host is over 32 bytes | constant, per connection, scales with rules | `policy/match.go:92`, `:64-71` | 0 allocs at 32 bytes, 2 at 33; a denied CONNECT 16 -> 4,016 allocs at R=2,000 |
| 10 | Gate `ShieldCarveProblems` stats every rule before the cheap reachability test | constant, every `validate` | `gate/gate.go:733` | ~545 follow-stats per call, two calls |
| 11 | GETREGS repeats what `PTRACE_GET_SYSCALL_INFO` already returned | constant, per profiled syscall | `syscallInfo:698`, `inspect:998` | 1 of 3 ptrace ops per stop |
| 12 | `literalGrantFor` re-parses every rule per connection | constant, per connection | `internal/proxy/proxy.go:584` | 1 alloc per hostname rule on an IP-literal target |
| 13 | The bwrap argv-count refusal comes after the whole preflight | constant, refusal path only | `internal/linux/args.go:514` | A240 refused at 9,326 args after 120 git execs and 64,200 stats |
| 14 | 64 KiB of copy buffers per tunnel | constant, bounded by `maxConcurrent` | `proxy.go:1520` | ~32 MiB at 512 tunnels |
| 15 | `add` builds its dedup key before checking `seen` | constant, per profiled file syscall | `observe_linux_amd64.go:312` | 1 alloc per file syscall on a dedup hit |

## Constraints a fix must keep

- **1:** resolving the write grants once per pass is safe. Deduplicating the `git` exec by
  checkout root is not obviously safe: the key has to agree with git's own discovery (`.git`
  files, nested checkouts, `core.worktree`), and a wrong key reports another checkout's hook
  directory.
- **2:** a `SECCOMP_RET_TRACE` filter must still deliver foreign-arch and x32 calls, keep
  `lastOp`'s stop-parity inference sound, deliver exit stops for held entries, and cope with
  the tracee's own filters outranking TRACE. The observe grid lists these in full.
- **7:** bento creates directories between these stages, so an exists/isDir memo has to be
  keyed or invalidated the way the `resolve` memo is.
- **8:** the idle re-arm is load-bearing (`proxy.go:1445`; a stubbed `extend` cut a tunnel at
  191,312 of 1,048,576 bytes under strace). Rate-limit it by a slack window instead: the
  tunnel then dies within [idle, idle+slack] of the last byte, both directions still re-arm
  both conns, and `extendUp`'s first call still always arms.

## Round-1 reconciliation

Every round-1 fix holds at HEAD (detail in `perf-grid-launch.md`). `validate` at 24 write
grants: 13,141 + 4,935 stat/readlink at `aa5e915`, 10,391 + 4,031 now. Round 1's "5 execs"
ledger for a launch was incomplete: it omitted two `git rev-parse` per write grant, which
predate round 1 and are finding 1.

## Not findings

- Landlock re-stat on the full tier: W+4 stats in the sandbox's own mount namespace, which it
  needs. The degraded tier's duplicate is real but small, read from code only.
- `resolveBwrap`'s trust walk twice per run: round 1 ruled out caching a security check.
- Shield-reclaim `EvalSymlinks`: the symlink-swap guard, linear.
- Nested-checkout and project-config axes: linear throughout.
- Proxy accept, CONNECT parse, gate, `guardUpstream`, teardown: flat per connection from 1 to
  10,000 connections.

## Left unmeasured

- Wall time and instructions retired, everywhere.
- The launch half (bwrap, launcher, Landlock) at A240, which is refused on arg count; B240
  covers those stages at 240 grants.
- Degraded tier and limits-bearing manifests, read from code only.
- The real proxy dial with `guardUpstream` in the control hook: the fake dialer bypasses it
  and loopback is refused by the guard, so the guard was measured by direct call.
- Multi-threaded tracee fan-in under observe.

## Measurement hazard

Unfiltered `strace -f` on `bento run` deadlocked twice inside the launcher's Landlock
`restrict_self` (TSYNC waiting on a traced thread). `strace -f --seccomp-bpf` avoided it on
every run. Use it for any future launch measurement.

## Filed

One bead per finding, labelled `perf-hunt-2026-09-22`. The git-exec dedup under finding 1
is its own bead because its risk is different; it is linked `discovered-from` the resolve
fix so neither closes the other.

| finding | bead | pri |
|---|---|---|
| 1 resolve write grants once per hook pass | bv2-dj2tp | P1 |
| 1 (follow-on) one hook-dir git exec per checkout | bv2-yqn9r | P3 |
| 2 stop only on decoded syscalls (RET_TRACE) | bv2-6rdnk | P2 |
| 3 no key formatting on an empty exit stop | bv2-jibyv | P2 |
| 4 validate: shield set and refusals once | bv2-0otom | P2 |
| 5 validate: probe only the manifest's layers | bv2-65vx4 | P2 |
| 6 read tracee paths without the netpoller | bv2-b7aq6 | P2 |
| 7 memoize host checks and repeated derivations | bv2-cxgn0 | P2 |
| 8 re-arm tunnel deadlines once per slack window | bv2-itrte | P2 |
| 9 normalize rule hosts once | bv2-eywkz | P2 |
| 10 gate carve: reachability before stat | bv2-ched5 | P3 |
| 11 drop GETREGS where syscall info suffices | bv2-7ocw0 | P3 |
| 12 parse IP-literal rules once | bv2-2ns5e | P3 |
| 13 refuse an over-long argv before preflight | bv2-7xznp | P4 |
| 14 pool tunnel copy buffers | bv2-eq9k5 | P4 |
| 15 check seen before building the dedup key | bv2-nd0y5 | P4 |
