# State grid: Landlock ABI vs degraded-tier disclosure

Worktree base 924e291, which is older than d39a454/3771cee. The metadata row is treated as settled.
Host: kernel 7.0.0-28, raw Landlock ABI 8, effective ABI 8 (checked by spike). Low-ABI arms run through `-tags bentoprobe` SetTierPreset.

## Phase 0 - fit

Good fit. Signals: a mirror pair (the landlock.*Restricted predicates plus BestEffort's downgrade
vs the probe.go clause helpers), an enum x call sites shape (ABI thresholds 2/3/4/5/6/9 x five
clause helpers), and repeated one-at-a-time fixes (truncate, ioctl_dev, resolve_unix, net TCP and
scopes were each disclosed in a separate commit). The invariant is one-sided: Consequences may
over-disclose, but must never claim a fence the effective ABI lacks or leave out an access it
cannot restrict.

## Phase 1 - dimensions (from code)

- Effective ABI (landlock_linux.go:682 detectedABI, :695 flooredABI). Collapsed on the thresholds
  the predicates test: 0 (refuse), 1, 2 (refer, :532), 3 (truncate, :609), 4 (net, :648),
  5 (ioctl_dev, :622), 6 (scopes, :658), 9 (resolve_unix, :633), >9. ABI 7 and 8 change no right.
- Reachability: the default build's floor is 0 (abi_floor_linux.go), so ABI 1..N are reachable.
  The landlocktsync floor is 8 (abi_floor_tsync_linux.go), so only 8, 9 and >9 are reachable and
  1-7 floor to 0. Errata: a raw ABI >=6 without the signal-scope fix becomes 5 (:686), so 6-9
  collapse to 5 on those kernels (and to 0 under tsync).
- Right family: fs rwx/make/remove (v1), refer (v2), truncate (v3), TCP bind/connect (v4),
  ioctl_dev (v5), scope signal (v6), scope abstract unix (v6), resolve_unix (v9), metadata (no
  right, settled), and rights newer than V9 (unknown to this build).
- Owning layer: every disclosure lives in the Filesystem layer's Consequences (probe.go:279-288).
  The Network layer is Unavailable on a degraded host and carries none (probe.go:242).

## Phase 2 - verdicts

| # | ABI | Right | Verdict | Where / why | Stamp |
|---|-----|-------|---------|-------------|-------|
| 1 | 0 (incl. tsync 1-7) | all | HANDLED | RestrictDegraded refuses at landlock_linux.go:406; probe's default arm reports Unavailable. Under landlocktsync the Reason says "this kernel has no Landlock" on an ABI 1-7 kernel: wording only, since no run happens | VERIFIED BY READING |
| 2 | 1+ | fs rwx/make/remove | HANDLED | v1 set, degradedRules; "confines filesystem read/write/exec" | VERIFIED BY READING |
| 3 | 1 | refer | HANDLED | below v2 the kernel denies reparenting implicitly; withRefer gate (:521) avoids the v0 collapse. More restrictive, so nothing to disclose | VERIFIED BY READING |
| 4 | 2+ | refer | HANDLED | granted only on write dir rules | VERIFIED BY READING |
| 5 | 1-2 | truncate, read-granted file | HANDLED | truncateResidual probe.go:308; trunc_readonly=OK at V2 | VERIFIED BY SPIKE |
| 6 | 1-2 | truncate, file OUTSIDE every grant | **WRONG (forbidden direction)** | truncate(2) is not an open, so v1 path rules never see it. With truncate unhandled, any file the uid can write under DAC anywhere on the host can be zeroed. truncateResidual names only "a read-only granted file". Spike: read/f symlinked to outside/victim (outside all grants). Preset V2: victim went from 7 bytes to 0. Preset V3: DENIED, still 7 bytes | VERIFIED BY SPIKE |
| 7 | 3+ | truncate | HANDLED | handled, granted only on RW rules; clause empty; V3 arm DENIED | VERIFIED BY SPIKE |
| 8 | 1-3 | TCP bind/connect | HANDLED | netFenceClause probe.go:342 low arm; TestRestrictDegradedDoesNotFenceTCPConnectBelowABI4 exists | VERIFIED BY READING |
| 9 | 4+ | TCP bind/connect | HANDLED | netTCP RestrictNet :450 | VERIFIED BY READING |
| 10 | 4+ | already-connected passed TCP fd, UDP/raw/packet, MPTCP | UNHANDLED (not ABI-conditioned) | the landlock_linux.go:444-449 comment names all three as residuals. The 4+ Consequences says "Landlock denies TCP connect on a descriptor the filter cannot revoke" and names none of them. At 1-3 the passed-fd case is covered by "stays usable"; MPTCP is silent at every ABI unless seccomp's egress filter kills IPPROTO_MPTCP at socket(2) (not checked) | VERIFIED BY READING |
| 11 | 1-4 | ioctl_dev | HANDLED (over-discloses) | ioctlDevResidual :324 says "the host's whole /dev", but nodes outside the grants cannot be opened under v1 path rules, and seccomp covers the inherited tty. Allowed direction | VERIFIED BY READING |
| 12 | 5+ | ioctl_dev | HANDLED | withIoctlDev on every rule; ioctl_readonly=OK at V2 and V3 in the spike | VERIFIED BY SPIKE |
| 13 | 1-5 (incl. errata) | signal scope | HANDLED | signalClause :387 "see and signal"; the 32-combination string test passes | VERIFIED BY EXECUTION |
| 14 | 6+ | signal scope | HANDLED | scopedIPC.RestrictScoped :429; the "but not signal them" string is asserted | VERIFIED BY EXECUTION (string) / READING (kernel) |
| 15 | 1-5 | abstract unix | HANDLED | unixSocketClause :370 low arm | VERIFIED BY EXECUTION |
| 16 | 6+ | abstract unix | HANDLED | "denied by Landlock's IPC scoping" | VERIFIED BY EXECUTION (string) / READING (kernel) |
| 17 | 1-8 | resolve_unix | HANDLED | resolveUnixResidual :401 plus the unixSocketClause middle arm; this host is natively in this arm | VERIFIED BY EXECUTION |
| 18 | 9+ | resolve_unix | HANDLED | degradedFS=V9, granted on write rules | UNSPIKEABLE HERE (host ABI 8, needs an ABI 9 kernel) |
| 19 | raw 6-9 without errata fix | scopes, resolve_unix | HANDLED | effectiveABI drops to 5, matching go-landlock's downgrade, so all three clauses disclose | VERIFIED BY READING |
| 20 | 7, 8 | any | IMPOSSIBLE | no access right enters at 7 (audit flags) or 8 (tsync); no predicate tests them | VERIFIED BY READING |
| 21 | >9 | rights newer than V9 | UNHANDLED (by design, undisclosed) | handled sets are pinned (handledFS=V8, degradedFS=V9, netTCP=V4, scopedIPC=V6), so a future right is neither handled nor named. Deliberate (landlock_linux.go:37). go-landlock v0.9.0 knows no such right, so the report cannot name one specifically, but it could say rights past V9 are unhandled | UNSPIKEABLE HERE |
| 22 | any | metadata | settled | d39a454, 3771cee | - |
| 23 | <8, cgo build | read_dir /proc/<pid>/task | HANDLED (build-only) | bug39 workaround; the shipped binary has cgo off (:388). Not a runtime disclosure gap | VERIFIED BY READING |

23 cells, all walked. Cell 18 cannot be spiked on this host.

## Phase 2 re-open pass

- bd3acf1 (disclose truncate gap) and a48ea73 (probe the low-ABI truncate column) covered cell 5
  only. The ungranted-file cell (6) was left behind: the probe only checks trunc_readonly on a
  read grant, so the wider gap passes every existing test.
- d39a454 (metadata residual) words its row as "on any host path it can name - including one
  outside every grant". Truncate below ABI 3 is the same shape (a path op v1 cannot see) and was
  not reworded to match.
- 47daa37 (condition the TCP-fence claim on the ABI) covered cells 8/9; cell 10's
  ABI-independent residuals did not make it into the 4+ sentence.
- d6d1e1a / 597e20b (ioctl_dev): cells 11/12 are consistent.
- f001a42, bd3acf1, 1014725 (resolve_unix, scopes): cells 13-19 are consistent.
- a406be6 / da5e682 / 024a857 / b324e13 (floors, errata): cells 1 and 19. The only thing left is
  cell 1's Reason wording under landlocktsync.
- Open bd: bv2-z69p3 (SetTierPreset's hybrid is asserted nowhere) is a test-seam item and changes
  no cell.
