# Perf grid - ptrace profiler tracer (internal/observe)

Base commit: **bca2d24** (`perf/shield-rule-cost`), confirmed with `git rev-parse HEAD` in the
measuring worktree before any number below was taken. Counts only: tracer-thread syscalls
(strace), ptrace ops, wait4 returns, and heap mallocs. No wall time: other measurers shared the
machine.

## Instruments (throwaway, deleted after measuring)

- **Tracee:** a static C program (`gcc -O2 -static`), `tracee MODE N PCT DIR`. It runs N loop
  iterations; the first PCT% issue one file syscall of MODE, the rest issue a raw
  `syscall(SYS_getpid)`. Static, so there is no loader, and the only syscalls are the ones
  the loop issues plus about 15 of startup. Modes: `statabs` (`newfstatat(AT_FDCWD, "/abs")`),
  `statrel` (`newfstatat(AT_FDCWD, "sub/f")`), `statdirfd` (`newfstatat(dfd, "f")`), `openabs`
  (openat + close), `openat2abs` (openat2 + close), `opendistinct` (openat of N distinct absent
  paths, so N distinct accesses), `execstatic` / `execdyn` (fork + execve of a static binary or
  of dynamic `/bin/true`, then waitpid).
- **Driver:** a `main` package importing `internal/observe` that pins `main` to the main
  thread in `init` (`runtime.LockOSThread`) and calls `observe.Trace`. Because `Trace` locks
  its own OS thread and the goroutine is already on the main thread, `strace -c` **without
  `-f`** records exactly the tracer thread's syscalls and does not collide with the ptrace
  attach of the tracee. It reports `runtime.MemStats.Mallocs` across the `Trace` call.
- **Alloc sites:** the same driver with `MemProfileRate=1` and an `allocs` pprof profile.
  pprof undercounts tiny-allocator objects (two 8-byte `convT64` boxings share one 16-byte
  tiny block and are sampled once), so the **MemStats number is the malloc count** and pprof
  is used only to attribute sites. At 1e4 ignored syscalls pprof shows 140,371 against
  MemStats 180,447; the 40,076 gap equals the `stopKey` boxing count exactly.

Per-unit costs below are **scale deltas**, (count at N=1e4 - count at N=1e2) / 9,900, which
cancel the Go runtime's and the tracee's startup noise.

## Invariant

Each stage's cost is bounded by a known function of its input, and the per-unit constant is
what the design needs. Here: **tracer cost should scale with the syscalls the decoder needs to
see, not with every syscall the tracee makes.** Symbols: **S** tracee syscalls, **F** file
syscalls among them (F <= S), **A** distinct accesses recorded, **I** images in one exec's
chain (bounded by `execChainDepth`).

## Scales measured

| axis | minimal | typical | pathological |
|---|---|---|---|
| loop iterations N | 1e2 | 1e4 | 1e6 |
| file-syscall mix | 0% | 10% | 100% |
| distinct accesses A | 3-4 | 1,003 | 1e6 (`opendistinct`, 100%) |
| exec count (exec rows) | 10 | 100 | not run - see unmeasured |

## Stages and how often each runs

| # | stage | file:line | runs per traced syscall |
|---|---|---|---|
| 1 | wait + dispatch + resume | `observe_linux_amd64.go:361`, `:449`, options `:270` | **2 stops per syscall, every syscall** (1 `wait4` + 1 `PTRACE_SYSCALL` each) |
| 2 | syscall-info read (`nativeSyscall` -> `syscallInfo`) | `:446`, `:564`, `:688` | 1 per stop, every stop |
| 3 | regs read (`PtraceGetRegs`) | `inspect` `:998` | 1 per stop, every stop (before the number is examined) |
| 4 | per-stop bookkeeping (`dropOnce` keys, `releaseDrop`, `releaseHeldExec`, `recordHeldExistence`, all via `stopKey`) | `:445`, `:809-828`, `:834`, `:1023`, `:1070-1071`, `:1325`, `:1836` | entry: `regs` escape; **exit: 4 `stopKey` + 2 slot keys, every exit stop** |
| 5 | path decode (`readString`, `openHow`) | `:1717`, `:1702` | 1 per decoded pathname at an entry stop (2 for openat2) |
| 6 | dirfd resolution (`resolveAt` / `fdPath` / `fdIsDir`) | `:1647-1685` | 1 per relative pathname; `fdIsDir` only for a real dirfd |
| 7 | held / record / dedup maps (`add`, `held`, `seen`, `resolved`, `missed`) | `:305-340`, `:1299`, `:1311`, `:1324` | 1 per file syscall |
| 8 | exec-image resolution (`execImageChain`) | `execimage_linux_amd64.go:63`, called `:348`, `:1792` | 1 per execve/execveat entry (+1 for root) |
| 9 | synthesis at root exit (sort + Absent/Probed) | `:425-434` | once per trace, over A |

## Raw counts (tracer thread, strace -c; mallocs from MemStats)

`fs` = openat + fcntl + epoll_ctl + pread64 + close + readlinkat + newfstatat + openat2 + fstat + read.

| mode | N | pct | wait4 | ptrace | openat | fcntl | epoll_ctl | pread64 | close | readlinkat | newfstatat | mallocs | accesses |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| getpid only | 1e2 | 0 | 233 | 696 | 11 | 30 | 7 | 5 | 15 | 1 | 0 | 2,205 | 3 |
| getpid only | 1e4 | 0 | 20,034 | 60,096 | 11 | 30 | 7 | 5 | 15 | 1 | 0 | 180,430 | 3 |
| getpid only | 1e6 | 0 | 2,000,081 | 6,000,096 | 11 | 30 | 7 | 5 | 15 | 1 | 0 | 18,002,686 | 3 |
| statabs | 1e2 | 10 | 233 | 696 | 21 | 70 | 17 | 15 | 25 | 1 | 0 | 2,355 | 4 |
| statabs | 1e4 | 10 | 20,033 | 60,096 | 1,011 | 4,030 | 1,007 | 1,005 | 1,015 | 1 | 0 | 195,427 | 4 |
| statabs | 1e6 | 10 | 2,000,065 | 6,000,096 | 100,011 | 400,030 | 100,007 | 100,005 | 100,015 | 1 | 0 | 19,502,825 | 4 |
| statabs | 1e2 | 100 | 233 | 696 | 111 | 430 | 107 | 105 | 115 | 1 | 0 | 3,705 | 4 |
| statabs | 1e4 | 100 | 20,033 | 60,096 | 10,011 | 40,030 | 10,007 | 10,005 | 10,015 | 1 | 0 | 330,457 | 4 |
| statrel | 1e2 | 100 | 233 | 696 | 111 | 430 | 107 | 105 | 115 | 101 | 0 | 4,309 | 4 |
| statrel | 1e4 | 100 | 20,035 | 60,096 | 10,011 | 40,030 | 10,007 | 10,005 | 10,015 | 10,001 | 0 | 390,458 | 4 |
| statrel | 1e6 | 100 | 2,000,063 | 6,000,096 | 1,000,011 | 4,000,030 | 1,000,007 | 1,000,005 | 1,000,015 | 1,000,001 | 0 | 39,004,332 | 4 |
| statdirfd | 1e2 | 100 | 233 | 696 | 111 | 430 | 107 | 105 | 115 | 101 | 100 | 4,805 | 4 |
| statdirfd | 1e4 | 100 | 20,033 | 60,096 | 10,011 | 40,030 | 10,007 | 10,005 | 10,015 | 10,001 | 10,000 | 440,464 | 4 |
| statdirfd | 1e6 | 100 | 2,000,038 | 6,000,096 | 1,000,011 | 4,000,030 | 1,000,007 | 1,000,005 | 1,000,015 | 1,000,001 | 1,000,000 | 44,004,525 | 4 |
| openabs (+close) | 1e2 | 100 | 433 | 1,296 | 111 | 430 | 107 | 105 | 115 | 1 | 0 | 5,509 | 4 |
| openabs (+close) | 1e4 | 100 | 40,035 | 120,096 | 10,011 | 40,030 | 10,007 | 10,005 | 10,015 | 1 | 0 | 510,452 | 4 |
| openat2abs (+close) | 1e2 | 100 | 433 | 1,296 | 211 | 830 | 207 | 205 | 215 | 1 | 0 | 6,005 | 4 |
| openat2abs (+close) | 1e4 | 100 | 40,037 | 120,096 | 20,011 | 80,030 | 20,007 | 20,005 | 20,015 | 1 | 0 | 560,488 | 4 |
| opendistinct | 1e2 | 100 | 233 | 696 | 111 | 430 | 107 | 105 | 115 | 1 | 0 | 3,737 | 103 |
| opendistinct | 1e4 | 100 | 20,033 | 60,096 | 10,011 | 40,030 | 10,007 | 10,005 | 10,015 | 1 | 0 | 330,722 | 10,003 |
| opendistinct | 1e6 | 100 | 2,000,036 | 6,000,096 | 1,000,011 | 4,000,030 | 1,000,007 | 1,000,005 | 1,000,015 | 1 | 0 | 33,025,402 | 1,000,003 |
| execstatic | 10 | - | 493 | 1,346 | 71 | 230 | 57 | 65 | 85 | 11 | 0 | 4,775 | 4 |
| execstatic | 100 | - | 4,783 | 13,046 | 611 | 2,030 | 507 | 605 | 715 | 101 | 0 | 45,465 | 4 |
| execdyn | 10 | - | 755 | 2,132 | 91 | 270 | 67 | 75 | 115 | 1 | 0 | 7,196 | 7 |
| execdyn | 100 | - | 7,393 | 20,876 | 811 | 2,430 | 607 | 705 | 1,015 | 1 | 0 | 69,555 | 7 |

exec rows also: `openat2` 11 -> 101 (static, 1 per exec), 21 -> 201 (dynamic, 2 per exec);
`fstat` and `read` track `openat2` one for one.

## Per-unit costs (scale deltas)

| unit | wait4 | ptrace | tracer fs syscalls | mallocs |
|---|---|---|---|---|
| one ignored syscall (getpid) | **2.0** | **6.0** | 0 | **18.0** |
| one absolute `newfstatat` | 2.0 | 6.0 | **8** (openat, 4 fcntl, epoll_ctl, pread64, close) | 33.0 |
| one AT_FDCWD-relative `newfstatat` | 2.0 | 6.0 | 9 (+ readlinkat `/proc/pid/cwd`) | 39.0 |
| one dirfd-relative `newfstatat` | 2.0 | 6.0 | 10 (+ readlinkat `/proc/pid/fd/N`, + newfstatat of it) | 44.0 |
| one absolute `openat` | 2.0 | 6.0 | 8 | 33.0 (51.0 with its close) |
| one absolute `openat2` | 2.0 | 6.0 | **16** (`openHow` and `readString` each open `/proc/pid/mem`) | 38.0 (56.0 with its close) |
| one distinct-path `openat` | 2.0 | 6.0 | 8 | 33.0 (A grows by 1) |
| one static exec cycle (fork + execve + waitpid + child's run) | 47.7 | 130 | ~10 per image (`openat` of `/proc/pid/root`, `openat2`, `fstat`, `openat` of `/proc/self/fd/N`, `read`, 3 `close`) plus the exec path's `readString` | 452 |
| one dynamic exec cycle (2 images) | 73.8 | 208 | 2 images' worth | 692 |

Where an ignored syscall's 18 mallocs come from (pprof sites, MemStats total): the entry stop
pays 1 (`var regs` escapes, `:997`); the exit stop pays 17 - `releaseDrop` (deferred at
`:1023`) builds `key(regs, slot)` for both `dropSlots` via `fmt.Sprintf` over `stopKey`'s own
`fmt.Sprintf` (5 allocs per slot: the two strings plus boxing pid, rip and the key string),
`releaseHeldExec` (`:1836`) and `recordHeldExistence` (`:1325`) each build a `stopKey` (3
allocs) just to find `held` empty, plus the `regs` escape. **6 `fmt.Sprintf` per exit stop,
whether or not anything was ever held or dropped.**

## Grid

Cells are totals at N = 1e2 / 1e4 / 1e6 on the 0%-file workload unless the row says
otherwise, so a stage that should cost nothing on ignored syscalls shows it directly.

### 1. Wait + dispatch + resume

| cost | 1e2 | 1e4 | 1e6 | complexity | verdict |
|---|---|---|---|---|---|
| stops (`wait4`), 0% file | 233 | 20,034 | 2,000,081 | **O(S)**, 2 per syscall | **scaling** - `:270` sets `PTRACE_O_TRACESYSGOOD` and every resume is `PtraceSyscall` (`:356`, `:449`, `:533`), so every syscall of every kind takes an entry and an exit stop |
| stops, 10% file | 233 | 20,033 | 2,000,065 | O(S), not O(F) | **scaling** - 10x fewer file syscalls, identical stop count |
| `PTRACE_SYSCALL` resumes | 1 per stop | | | O(S) | same finding |
| allocs | 0 | 0 | 0 | - | ok |
| fs ops | 0 | 0 | 0 | - | ok |

### 2. Syscall-info read

| cost | 1e2 | 1e4 | 1e6 | complexity | verdict |
|---|---|---|---|---|---|
| `PTRACE_GET_SYSCALL_INFO`, 0% file | ~233 | ~20,032 | ~2,000,032 | O(S), 1 per stop | **scaling** (rides on finding 1); per stop it is needed - it is the only foreign-ABI check (`:564`) |
| allocs | 0 | 0 | 0 | 88-byte buffer stays on the stack | ok |

ptrace total 696 / 60,096 / 6,000,096 = **3 per stop**: GET_SYSCALL_INFO, GETREGS, SYSCALL.

### 3. Regs read

| cost | 1e2 | 1e4 | 1e6 | complexity | verdict |
|---|---|---|---|---|---|
| `PTRACE_GETREGS`, 0% file | ~233 | ~20,032 | ~2,000,032 | O(S), 1 per stop | **constant** - `syscallInfo` (`:688`) already reads the 88-byte `ptrace_syscall_info`, whose entry arm carries `nr`, `args[6]` and `instruction_pointer`; the code keeps only `op` and `arch` from it and then pays a second ptrace op for the same facts. At an exit stop the struct has `rval` but no `nr`, so the exit key would need the entry's nr parked per tid (a thread has one syscall in flight) |
| allocs | 1 per stop (`var regs` escapes, `:997`) | | | O(S) | **constant** |

### 4. Per-stop bookkeeping

| cost | 1e2 | 1e4 | 1e6 | complexity | verdict |
|---|---|---|---|---|---|
| mallocs, 0% file (whole trace, MemStats) | 2,205 | 180,430 | 18,002,686 | **18.0 per ignored syscall**, O(S) | **constant, on every stop** - 17 of the 18 are at the exit stop |
| `fmt.Sprintf` per exit stop | 6 | | | O(S) | **constant** - `releaseDrop` builds both slot keys (`:822-824`, 2 x (`key` + `stopKey`) = 4), `releaseHeldExec` (`:1836`) and `recordHeldExistence` (`:1325`) one `stopKey` each - all run when `held` and `drops` are empty |
| map lookups per exit stop | 2 `delete` on `drops` + 2 lookups on `held` | | | O(1) each | ok (cheap once the keys are cheap) |
| syscalls | 0 | 0 | 0 | - | ok |

### 5. Path decode (`readString`, `openHow`)

| cost | 1e2 | 1e4 | 1e6 | complexity | verdict |
|---|---|---|---|---|---|
| tracer fs syscalls, statabs 10% | 50 extra | 9,000 extra | 900,000 extra (openat 100,011, fcntl 400,030, epoll_ctl 100,007, pread64 100,005, close 100,015) | O(F) | shape ok |
| tracer fs syscalls per pathname | 8 | 8 | 8 | O(1) | **constant** - `os.Open` (`:1718`) goes through `os.newFile`'s netpoller registration: openat + 4 fcntl + epoll_ctl, then pread64 + close. `process_vm_readv` would be 1 |
| per openat2 | 16 | 16 | - | O(1) | **constant** - `openHow` (`:1703`) opens `/proc/pid/mem` a second time for 24 bytes |
| allocs per pathname | ~7 (Sprintf of the `/proc` name, `os.File`, `ByteSliceFromString`, result string, ...) | | | O(1) | constant, minor |

### 6. Dirfd resolution

| cost | 1e2 | 1e4 | 1e6 | complexity | verdict |
|---|---|---|---|---|---|
| readlinkat, statrel 100% | 101 | 10,001 | 1,000,001 | 1 per relative path | ok - the cwd readback is what the design needs |
| newfstatat, statdirfd 100% | 100 | 10,000 | 1,000,000 | 1 per real-dirfd path | ok - `fdIsDir` is the documented ENOTDIR guard (`:1655`) |
| allocs, relative | +6 per path | | | O(1) | ok |
| allocs, dirfd | +11 per path (`fdPath` 3, `fdIsDir` Sprintf + `os.Stat` ~5, readlink buffer) | | | O(1) | ok, minor |

### 7. Held / record / dedup maps

| cost | 1e2 | 1e4 | 1e6 | complexity | verdict |
|---|---|---|---|---|---|
| accesses, opendistinct | 103 | 10,003 | 1,000,003 | O(A) | ok |
| mallocs, opendistinct vs statabs at 100% | 3,737 vs 3,705 | 330,722 vs 330,457 | 33,025,402 vs (33.0/syscall) | O(A); distinct paths add ~0.02 alloc each beyond the dedup-hit case (map growth) | ok |
| `add` key concat (`:312`) | 1 alloc per file syscall, **including dedup hits** | | | O(F) | constant, minor - `path + boolKey(write)` is built before `seen` is consulted |
| entry-stop `stopKey` for `held` (`:1299`, `:1311`) | 3 allocs per file syscall | | | O(F) | constant, minor - same key cost as finding 2 |

### 8. Exec-image resolution

| cost | 10 execs | 100 execs | 1e6 | complexity | verdict |
|---|---|---|---|---|---|
| `openat2` (one per image) static / dynamic | 11 / 21 | 101 / 201 | not run | O(I) per exec, I <= `execChainDepth` | ok |
| fs syscalls per image | ~10 (`/proc/pid/root` O_PATH, `openat2`, `fstat`, `/proc/self/fd/N` reopen, `read`, 3 `close`) | | | O(1) | ok - each step is a documented safety property (`execimage_linux_amd64.go:99-140`); no memo across execs, which is right since the image can change between them |
| share of an exec cycle's tracer cost | dynamic cycle = 208 ptrace + 73.8 wait4 vs ~20 fs syscalls for the chain | | | | ok - the stops the child's own syscalls cause dominate (finding 1) |

### 9. Synthesis at root exit

| cost | 1e2 | 1e4 | 1e6 | complexity | verdict |
|---|---|---|---|---|---|
| allocs, opendistinct | within noise | within noise | ~22k beyond 33 per syscall, map growth | `slices.SortFunc` in place: O(A log A) compares, 0 allocs | ok |
| syscalls | 0 | 0 | 0 | - | ok |

## Findings, ranked

**1. Every tracee syscall costs two stops, file or not (scaling, hot path).** `:270` sets
`PTRACE_O_TRACESYSGOOD` and the loop resumes with `PtraceSyscall` everywhere (`:356`, `:449`,
`:533`), so a stop is taken at entry and exit of every syscall. Each stop is 1 `wait4` + 3
ptrace ops (GET_SYSCALL_INFO, GETREGS, SYSCALL) - **8 tracer syscalls per ignored syscall**,
6,000,096 ptrace + 2,000,081 wait4 for 1e6 getpids at **0% file**. 10% file changes the stop
count by nothing (2,000,065). The invariant says cost should follow F, not S.
*Cause:* `internal/observe/observe_linux_amd64.go:270`, `:449`.
*Fix direction (the orchestrator's call):* a `SECCOMP_RET_TRACE` filter over the decoded set,
`PTRACE_O_TRACESECCOMP`, resume with `PTRACE_CONT` and take a `PtraceSyscall` only after an
event whose pair needs its exit stop (held opens, existence probes, execs). What such a fix has
to preserve - **verify each in ptrace(2) / seccomp(2)**:
- the filter must still RET_TRACE every non-`AUDIT_ARCH_X86_64` arch and every x32-tagged
  number, or the foreign-ABI drop counts (`:564`, `:1049`) go silent;
- `lastOp` / `nextStop` (`:673`) infer parity from seeing every stop; with seccomp stops the
  entry is a `PTRACE_EVENT_SECCOMP` stop and only some pairs have exit stops, so
  `deadThreadLoss`'s ENTRY/EXIT judgement needs re-deriving;
- held entries (`holdOpen`, `inspectExistence`, `holdExecTarget`) still need their exit stop;
- a tracee's own filter returning ERRNO, KILL or USER_NOTIF outranks TRACE, so those calls
  stop being visible - today they are seen at entry;
- the filter must be installed before the target's first decoded syscall, and
  `BlockIoUring`'s pre-fork install is not a slot for it: that filter goes on TSYNC in the
  launcher, which is the tracer, and a RET_TRACE filter there ENOSYSes the tracer's own
  decoded syscalls and the TRACEME'd child's execve (see bv2-6rdnk's design note);
  `undecodedPathSyscalls` and `nullPathnameOK` must be in the traced set;
- `TestTraceCountsEveryLostAccessOnce`, `TestTraceDoesNotCountHandledSignalsAsLostAccesses`
  and the exec / retired-tid tests stay green.

**2. Every exit stop does 6 `fmt.Sprintf` and 17 mallocs, with nothing held (constant, every
stop).** 18.0 mallocs per ignored syscall, 18,002,686 for 1e6 getpids. `releaseDrop`
(deferred at `:1023`, keys built at `:811-824`) formats both `dropSlots` keys over
`stopKey`, and `releaseHeldExec` (`:1836`) and `recordHeldExistence` (`:1325`) each format a
`stopKey` just to find `held` empty; `var regs` (`:997`) escapes on every stop. Independent of
finding 1 - survives any stop model, and after a seccomp fix it would still be paid per
traced stop. A struct key (`{pid, nr, rip, slot}`) or a `len(held)==0` / `len(drops)==0`
short-circuit removes it.
*Cause:* `internal/observe/observe_linux_amd64.go:811`, `:835`, `:1325`, `:1836`, `:997`.

**3. GETREGS duplicates GET_SYSCALL_INFO on every stop (constant, every stop).** 1 of the 3
ptrace ops per stop (2,000,032 of 6,000,096 at 1e6). `syscallInfo` reads the full 88-byte
struct and discards everything but `op` and `arch` (`:698`); the entry arm already holds `nr`,
`args[0..5]` and `instruction_pointer`, which is everything `inspect` reads from `regs` at an
entry stop. The exit arm has `rval` but no `nr`, so an exit stop would key on the tid (one
syscall in flight per thread) or on an nr parked at entry. At minimum an ignored entry stop
could skip GETREGS once `nr` is known.
*Cause:* `internal/observe/observe_linux_amd64.go:698`, `:998`.

**4. Each pathname read costs 8 tracer syscalls; openat2 costs 16 (constant, per file
syscall).** `readString` (`:1718`) does `os.Open("/proc/pid/mem")`, and `os.newFile`
registers the fd with the netpoller: openat, 4 fcntl, epoll_ctl, then pread64 and close.
Measured 8.0 per pathname at every scale (4,000,030 fcntl at 1e6 statrel). `openHow`
(`:1703`) repeats the whole open for 24 bytes, so openat2 pays 16. One `process_vm_readv`
per read (bounded to the page end, then the next page, so an unmapped following page is not a
failure) would be 1; `unix.Open` + `unix.Pread` without the poller would be 3.
*Cause:* `internal/observe/observe_linux_amd64.go:1718`, `:1703`.

**5. Minor constants on the file path.** `add` builds `path + boolKey(write)` before the
`seen` check (`:312`), 1 alloc per file syscall including dedup hits; the dirfd path pays ~11
allocs for `fdPath` + `fdIsDir` Sprintf and `os.Stat`. Right shape, small constant.

Everything else is ok: the relative-path readlink and the dirfd stat are what the design
needs, exec-image resolution is O(chain) per exec with each step a documented safety
property, and synthesis is an in-place sort over A.

## Red-first count tests (one per finding)

Use the existing seams and scale deltas, so the Go helper's startup noise cancels. A raw
`getpid` mode in `TestObserveTraceeHelper` (`observe_tracee_linux_amd64_test.go:51`) issuing
N `syscall.Syscall(SYS_GETPID)` is the workload for 1-3.

1. **Stops per ignored syscall.** Wrap `waitTracee` (`:726`, already a `var`) with a counter.
   Run the getpid mode at N=100 and N=10,000. Assert (stops(1e4) - stops(1e2)) / 9,900 < 0.1.
   Base: **2.0**. A mode issuing N absolute `newfstatat` must still show >= 1 stop per call
   and record the path - the same test catches an over-narrow filter.
2. **Mallocs per ignored syscall.** Same two runs, `runtime.MemStats.Mallocs` around `Trace`
   (the tracer loop is on the calling goroutine; the helper is another process). Assert delta
   per extra getpid < 1. Base: **18.0**. Keep it apart from test 1: a seccomp fix would pass
   test 2 by removing stops while leaving 17 allocs per traced exit stop, so also assert
   mallocs per extra `newfstatat` < ~20 (base 33) to pin the per-stop cost itself.
3. **ptrace ops per stop.** Wrap the ptrace calls behind a counter (there is no seam today;
   `syscallInfo` and `PtraceGetRegs` would need one var each) and assert, at the getpid
   workload, ptrace ops per stop <= 2. Base: **3**.
4. **Tracer syscalls per pathname.** No seam reaches the file opens; drive it as the grid did,
   with the tracer pinned to one thread and `strace -c` without `-f`, or add a `var
   readMem = ...` seam and count calls x syscalls. Assert per extra absolute `newfstatat`
   <= 2 tracer syscalls outside ptrace/wait4 (base **8**), and per openat2 <= 2 (base **16**).

## Cells not measured, and why

- **Wall time:** not taken - concurrent measurers.
- **rt_sigreturn, futex, sched_yield, epoll_pwait, tgkill:** jitter run to run (rt_sigreturn
  2,701 vs ~200 at the same n=100 cell; 448,617 to 1,059,736 across 1e6 cells). They are the
  Go runtime handling SIGCHLD per stop and preemption signals; not used as evidence. They do
  scale with stops, so a fix to finding 1 should shrink them too.
- **Exec rows at 1e6:** not run - a million fork+exec cycles under strace is hours, and the
  10 -> 100 delta is already exactly linear per exec with a per-image constant bounded by
  `execChainDepth`.
- **Multi-threaded tracee / `Wait4(-1)` fan-in:** out of scope for the scaling question; the
  per-stop cost is per tid and the loop is single-goroutine by design (`traceCalls`).
- **Instructions retired:** `perf_event_paranoid` is 4 on this host; counts above already
  separate the stages.
- **Alloc sites via pprof:** pprof undercounts tiny-allocator objects, so pprof gave only the
  site attribution and MemStats gave every malloc number cited.
