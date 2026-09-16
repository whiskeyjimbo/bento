# State grid: full tier vs degraded tier

Area: `internal/linux` bwrap backend (full tier) vs `internal/launcher/degraded.go`,
`internal/landlock`, `internal/linux/degraded.go` (degraded tier). Reviewed 2026-09-16
at 924e291.

## Phase 0 - fit

Strong mirror pair (two launch paths enforcing one manifest), long repeated-fix history
in `fix(degraded|launcher|landlock)`. One-sided invariant:

> The degraded tier may enforce less than the full tier only where the Report
> (filesystem Consequences, layer states, Setup) or Result.Exposed discloses it. It must
> never silently allow what the full tier denies.

Good fit.

## Phase 1 - dimensions (from code)

| # | Fence | Degraded mechanism | Full-tier mechanism |
|---|-------|-------------------|---------------------|
| F1 | read confinement (content) | Landlock RO rules on sysReads+reads (`landlock.degradedRules`) | mount ns, only bound paths exist |
| F2 | credential/read shields | none; `exposedShields` -> Result.Exposed | deny-list binds |
| F3 | write confinement (content, create/remove) | Landlock RW rules on writes+scratch+/dev/null | rw binds only |
| F4 | write shields (.git/hooks etc.) inside a write grant | none; Exposed; `checkWriteNotAboveWriteShield` refuses the unfenceable case | ro binds over the write grant |
| F5 | metadata ops on host paths outside grants (chmod, chown, utimes, setxattr, stat) | nothing handles them | path absent from the mount ns |
| F6 | egress | seccomp `BlockEgress` + Landlock net TCP; network rules / gate refused (`linux.go:65-88`) | netns + proxy |
| F7 | process reach / signals / abstract IPC | seccomp `BlockProcessReach` + Landlock scoping (ABI 6), disclosed by `signalClause`/`unixSocketClause` | pid ns, netns |
| F8 | terminal injection | seccomp `BlockTerminalInjection` | bwrap --new-session |
| F9 | exec block (none/none-strict) | `installExecFilter` via `execBlockFlags`, reconciled | same filter via launcher |
| F10 | limits | systemd scope when `canCreateScope`, admission refusal otherwise | same, plus post-run `attestScopeLimits`/`noteScopeLimits` |
| F11 | env / HOME / TMPDIR | `sandboxEnv(proc.Env, scratch)`, StripEnv, TMPDIR override | `sandboxEnv(proc.Env, SandboxHome)`, --clearenv |
| F12 | auto-exec/hooks audit | `autoExecBefore.changed(writes)` | same |

Arms: A1 success (target ran, any exit), A2 setup failure (launcher never started, or
refused before the target), A3 cancel.

12 x 3 = 36 cells. Enforcement is installed before the target in both tiers, so the arm
mostly decides what is REPORTED; the arm column is where disclosure can drop.

## Phase 2 - verdicts (forbidden-direction violations first)

| Cell | Verdict | Evidence | Stamp |
|------|---------|----------|-------|
| F5 x A1 | **WRONG (forbidden direction)** | Under `RestrictDegraded` with a read grant elsewhere, a child could not read a host file outside the grants (EACCES) but `chmod 0777`, `utimes`, `setxattr user.*` and `stat` on it all succeeded; the file's mode and mtime changed on the host. Landlock has no rights for these ops at any ABI. The full tier cannot name the path. The filesystem layer's Consequences (`probe.go` `filesystemLayer`) says the tier "confines filesystem read/write/exec, nothing more" and lists truncate/ioctl_dev/resolve_unix residuals, but not metadata. A target can chmod `~/.ssh/id_ed25519` 0644, strip or add exec bits on dotfiles, or forge mtimes, undisclosed. Spike host Landlock ABI 8. | VERIFIED BY SPIKE |
| F5 x A3 | WRONG (same; the ops land before the cancel) | as above | VERIFIED BY READING |
| F5 x A2 | IMPOSSIBLE | every fence install in `RunDegraded` (`internal/launcher/degraded.go`) is fatal before the target runs | VERIFIED BY READING |
| F10 x A1 | **WRONG (forbidden direction, disclosure)** | Full tier reads the scope's cgroup after start (`attestScopeLimits`, `linux.go:233-236`) and `noteScopeLimits` (`scopeattest.go:158`) worsens a limits layer to Unavailable when systemd accepted a property and did not apply it. `runDegraded` calls neither, so the same case reports the limit Enforced while the target ran unbounded. | VERIFIED BY READING |
| F10 x A3 | WRONG (same gap on the cancel arm) | `internal/linux/degraded.go` cancel arm returns unattested limits layers | VERIFIED BY READING |
| F10 x A2 | HANDLED | nothing ran; reconcile on the nil-ProcessState arm | VERIFIED BY READING |
| F1 x A1 | HANDLED (allowed narrowing, disclosed) | Landlock RO rules over `systemReadPaths` + /nix + interpreter prefix + reads; existence/stat leak folded into F5 | VERIFIED BY EXECUTION (spike's read arm: permission denied) |
| F1 x A2 | HANDLED | Landlock failure fatal (`restrictDegraded` seam) | VERIFIED BY READING |
| F1 x A3 | HANDLED | installed before target; reconcile on cancel | VERIFIED BY READING |
| F2 x A1 | HANDLED (disclosed) | `exposedShields` -> Exposed; `checkAliasedCredentials` shared; caller DenyPaths refused (`linux.go:87`) | VERIFIED BY READING |
| F2 x A2 | HANDLED | Exposed omitted only when the launcher never started | VERIFIED BY READING |
| F2 x A3 | HANDLED | Exposed carried on cancel | VERIFIED BY READING |
| F3 x A1/A2/A3 | HANDLED | Landlock RW rules; `prepareWriteDirs` and `checkGrants` shared with full tier | VERIFIED BY READING |
| F4 x A1 | HANDLED (disclosed) | `exposedShields` passes `writes`; the bind-ordering-only case refused by `checkWriteNotAboveWriteShield` | VERIFIED BY READING |
| F4 x A2/A3 | HANDLED | as F2 | VERIFIED BY READING |
| F6 x A1 | HANDLED (disclosed) | `BlockEgress` allowlists AF_UNIX/AF_NETLINK and blocks io_uring; Landlock TCP connect; residuals disclosed in `netFenceClause`/`unixSocketClause`; network rules and gate refused | VERIFIED BY READING |
| F6 x A2/A3 | HANDLED | fatal install; network layer forced Unavailable in `degradedProbe` | VERIFIED BY READING |
| F7 x A1/A2/A3 | HANDLED (disclosed) | `BlockProcessReach` fatal; signal/abstract residual disclosed per ABI | VERIFIED BY READING |
| F8 x A1/A2/A3 | HANDLED | `BlockTerminalInjection` fatal and a prerequisite | VERIFIED BY READING |
| F9 x A1/A2/A3 | HANDLED | same `execBlockFlags` in both tiers; reconcile on all three arms | VERIFIED BY READING |
| F11 x A1 | HANDLED | same `sandboxEnv`; HOME defaults to scratch; StripEnv; TMPDIR/TMP/TEMP overridden | VERIFIED BY READING |
| F11 x A2/A3 | IMPOSSIBLE to matter | env only reaches a started target; on cancel it already reached it, same as A1 | VERIFIED BY READING |
| F12 x A1/A3 | HANDLED | `autoExecBefore.changed(writes)` on success, default and cancel arms | VERIFIED BY READING |
| F12 x A2 | HANDLED | not resolved when the launcher never started | VERIFIED BY READING |

## Phase 2 - re-open pass

- bd37cc3 (`disclose truncate gap`), d6d1e1a (ioctl_dev residual), and the resolve_unix
  residual each covered ONE Landlock-unhandled operation. The rest of that row -
  chmod/chown/utimes/setxattr/stat, none handled by Landlock at any ABI - was not
  carried. That is F5.
- c4111fa (`feat(linux): attest the limits layers against the run's scope`) added the
  post-run attestation to the bwrap path only. The degraded row (F10 x A1, A3) did not
  come along.
- bdc5531 (Exposed on cancel), 6f3d430 (hooks on setup failure), 2837cfc (terminal
  prerequisite), 49bfb26 (seam pins), 41cba67 (HOME): rows checked, carried.
- Open: bv2-76t24 (restriction-sequence grid) overlaps; bv2-dyz92 (orphaned descendants)
  is outside these cells.

## Not walked

- Non-amd64 degraded paths (prerequisites refuse there).
- Exec from write grants: both tiers appear to permit; bwrap mount flags not traced.
- Readdir of a parent outside grants (stat succeeded in the spike; readdir not tested).
