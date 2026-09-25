# State grid: grant-derived shields (checkout hooks, core.hooksPath, nested checkouts, project config)

Written 2026-09-25. Area: `internal/linux/autoexec.go` and the grant-derived half of
`internal/linux/shields.go` (`shieldRules`, `derivedWorkspaceRules`, `findWorkspaceEntries`,
`workspaceShields`, `checkoutRoot`, `gitDirShields`), with `denylist.Workspace` /
`WorkspaceGitfile` / `ProjectConfig` as the rule source.

## Phase 0 - fit

Good fit. Mirror pair with an outside oracle: bento's derivation of "where git runs hooks
from" against git's own answer (`git rev-parse --git-path hooks`). Second signal: a
combinatorial surface (config source x location).

Invariant, corrected from the nomination. The nominated form ("must never leave writable a
path git would run") is false by design: `gitDirShields`' doc (shields.go:436-438) and
`autoExecNames`' doc (autoexec.go:25-29) deliberately leave in-tree hook runners and
auto-exec project files WRITABLE and REPORT them instead. So the invariant is two-armed:

> Every path that git, an editor or an agent would load and execute from, and that a write
> grant reaches, is either DenyWrite-shielded, or stamped by the auto-exec report so a
> change to it is named after the run. Covering a path nothing executes from is allowed;
> a path that is neither shielded nor reported is the forbidden direction.

## Phase 1 - grid (cells only)

### Grid H - hook source x location

| # | source | location |
| --- | --- | --- |
| H1 | default `.git/hooks` | grant = checkout root |
| H2 | default `.git/hooks` | grant = subdir of checkout |
| H3 | default hooks | grant is inside `.git` (no work tree) |
| H4 | relative core.hooksPath, in-tree | grant = checkout root |
| H5 | relative core.hooksPath, dir inside the granted subdir | grant = subdir |
| H6 | relative core.hooksPath, dir outside the granted subdir | grant = subdir |
| H7 | absolute core.hooksPath inside a write grant | any |
| H8 | absolute core.hooksPath outside every write grant | any |
| H9 | relative hooksPath | grant spelled through a symlink |
| H10 | hooksPath dir itself replaced by a symlink during run | grant = root |
| H11 | linked worktree (gitfile), hooksPath in config.worktree | grant = worktree |
| H12 | bare repo | grant = the bare repo |
| H13 | nested checkout below grant, default hooks | nested |
| H14 | nested checkout, relative in-tree core.hooksPath | nested |
| H15 | nested checkout, `.husky` with hooksPath unset | nested |
| H16 | core.hooksPath (or other exec key) set in an in-tree file pulled in by `include.path` | grant = root |
| H17 | core.hooksPath in global config pointing into the grant | grant = root |
| H18 | no enclosing checkout; run `git init`s and sets hooksPath | grant, no repo |
| H19 | degraded tier (no shields) | grant = root |
| H20 | submodule gitdir `.git/modules/<x>` hooks/config | grant = root |
| H21 | grant not a repo, enclosing checkout above | grant below checkout, hooks under grant |

### Grid E - project config (editor / agent / tool) x location

| # | entry | location |
| --- | --- | --- |
| E1 | ProjectConfig entry, present | checkout root |
| E2 | ProjectConfig entry, absent | checkout root |
| E3 | present | plain subdir below grant |
| E4 | absent | plain subdir below grant |
| E5 | editor dir as symlink | below grant |
| E6 | agent dir as symlink | below grant |
| E7 | present, inside an existing dir shield | below grant |
| E8 | nested checkout inside `.claude` | below grant |
| E9 | autoExecNames file (package.json etc.) | grant root |
| E10 | autoExecNames file | subdir below grant / nested checkout |
| E11 | ProjectConfig entry | nested checkout root, absent |

## Phase 2/3 - verdicts

Per-cell test: is every executed path either shielded (S) or reported (R)? Neither = forbidden.

### Grid H

| # | verdict | where / why | stamp |
| --- | --- | --- | --- |
| H1 | HANDLED | S: denylist.go:1882 `.git/hooks` DenyWrite dir via workspaceShields shields.go:374 | VERIFIED BY READING |
| H2 | HANDLED | checkoutRoot shields.go:401 anchors at the checkout; hooks outside a subdir grant are unreachable | VERIFIED BY READING |
| H3 | HANDLED | R: autoexec.go:137-170 (bare/.git branches); existing TestAGrantInsideAGitDirFindsTheHooksGitRuns | VERIFIED BY READING |
| H4 | HANDLED (report arm) | R: hookRunnerDir autoexec.go:139-141 join; S: not shielded by design shields.go:436-438 | VERIFIED BY READING |
| H5 | HANDLED | git answers relative to cwd ("hk" from sub), bento joins onto the grant and agrees | VERIFIED BY SPIKE |
| H6 | HANDLED | dir outside the subdir grant is dropped at autoexec.go:173-179 - and unwritable, so allowed | VERIFIED BY READING |
| H7 | HANDLED | R: absolute answer tested for containment autoexec.go:172-179 | VERIFIED BY READING |
| H8 | HANDLED | dropped: not writable by the run | VERIFIED BY READING |
| H9 | HANDLED | grant resolved before joining (9ee1014); TestASymlinkedGrantResolvesItsHookDir | VERIFIED BY READING |
| H10 | HANDLED | containment on resolved paths autoexec.go:172; answer frozen at baseline | VERIFIED BY READING |
| H11 | HANDLED | S: WorkspaceGitfile shields the gitfile denylist.go:1960; gitdir (config.worktree) outside grant | VERIFIED BY READING |
| H12 | HANDLED | R: bare join autoexec.go:143; gitDirShields not applicable (no `.git`) - **but** a bare repo as a write grant has its `hooks/` and `config` writable and only reported, not shielded; allowed by the report arm | VERIFIED BY READING |
| H13 | HANDLED | S: derivedWorkspaceRules shields.go:277-285 gives the nested checkout Workspace rules | VERIFIED BY READING |
| **H14** | **UNHANDLED** | nested checkout's in-tree core.hooksPath dir: not shielded (shields.go:436 residual) AND not reported - hookRunnerDirs autoexec.go:411 asks git only from each grant, never from nestedCheckouts, so the nested repo's hooks dir is never stamped | **VERIFIED BY SPIKE** |
| **H15** | **UNHANDLED** | nested `.husky/` (autoExecDirs) and nested `package.json` etc. (autoExecNames): snapshotAutoExec autoexec.go:354-361 stamps only at each grant root | **VERIFIED BY SPIKE** |
| **H16** | **UNHANDLED** | in-tree file named by `include.path` in the shielded `.git/config`: neither shielded (denylist.go:1880 lists only fixed names) nor stamped. Spike: run writes `core.fsmonitor` there, git honours it, changed and redirected both empty. A core.hooksPath written there would at least surface as `redirected`; fsmonitor / sshCommand / pager / alias do not | **VERIFIED BY SPIKE** |
| H17 | HANDLED | ~/.gitconfig covered by the Home denylist (autoexec.go:95-96 note); hooks dir it names under a grant is reported like H7 | VERIFIED BY READING |
| H18 | HANDLED | redirectedHooks autoexec.go:464; TestHooksInARunCreatedRepoAreReported | VERIFIED BY READING |
| H19 | HANDLED (report arm) | TestDegradedRunReportsTheAutoExecFilesTheTargetChanged; the degraded tier shields nothing, and redirection is named | VERIFIED BY READING |
| H20 | HANDLED | S: gitDirShields walk shields.go:488-521, fail-closed on unreadable/deep | VERIFIED BY READING |
| H21 | HANDLED | R: git discovers upward; answer kept if under a write grant (autoexec.go:128-130) | VERIFIED BY READING |

### Grid E

| # | verdict | where / why | stamp |
| --- | --- | --- | --- |
| E1 | HANDLED | S: Workspace denylist.go:1905-1907 | VERIFIED BY READING |
| E2 | HANDLED | S: absent entries shielded at the anchor (tmpfs + reclaim) | VERIFIED BY READING |
| E3 | HANDLED | S: findWorkspaceEntries shields.go:317-335 | VERIFIED BY READING |
| **E4** | **UNHANDLED (documented)** | absent `.claude/`, `.mcp.json`, `.vscode/` in a plain subdir below the grant: plantable, and an agent or editor started in that subdir loads it. Documented at denylist.go:1922-1924 ("wherever they already exist"); still the forbidden direction and not reported either | VERIFIED BY READING |
| E5 | UNHANDLED (documented) | symlinked editor dir left unshielded shields.go:326-328, relying on editor workspace trust; forbidden direction by design | VERIFIED BY READING |
| E6 | HANDLED | refused shields.go:324-325 | VERIFIED BY READING |
| E7 | HANDLED | insideDirShield shields.go:252; already read-only | VERIFIED BY READING |
| E8 | HANDLED | checkout inside the read-only `.claude` is unwritable (shields.go:227-229) | VERIFIED BY READING |
| E9 | HANDLED (report arm) | R: autoExecNames stamped at grant root autoexec.go:354-357 | VERIFIED BY READING |
| **E10** | **UNHANDLED (documented for subdirs)** | package.json / conftest.py / build.rs below the grant root are not stamped (autoexec.go:55-58 "a recursive walk ... is what this deliberately is not"). For a NESTED CHECKOUT root this is H15 and not covered by that rationale, since nestedCheckouts is already a list bento walks | VERIFIED BY SPIKE (nested) / READING (subdir) |
| E11 | HANDLED | nested checkout gets full Workspace incl. absent ProjectConfig shields.go:283 | VERIFIED BY READING |

Counts: HANDLED 26, UNHANDLED 6 (H14, H15, H16 undocumented; E4, E5, E10-subdir documented), WRONG 0, IMPOSSIBLE 0.

## Re-open pass

- 14b3ca8 / 30181ff (shield nested checkouts): carried the SHIELD half of the row to nested
  checkouts but not the REPORT half - H14/H15 are the rest of that row.
- 7bfdace / 9ee1014 / 2bb374f (relative join, real grant, no work tree): H5, H6, H9, H3 all hold.

## Rejected candidates

- "hooksPath dir in-tree is writable" (H4): the design's report arm; not a defect.
- Bare repo grant hooks writable (H12): reported; allowed arm.
- Nested `.cargo/config.toml` in a crate subdir: documented at denylist.go:1899-1901, cargo residual, not this area's derivation.

## Suggested fixes (for the filer)

- H14/H15: in hookRunnerDirs / snapshotAutoExec, also treat each `sb.nestedCheckouts` entry
  as a root (ask git there; stamp autoExecNames/autoExecDirs there). The list already exists
  and is bounded by maxNestedCheckouts.
- H16: shield (DenyWrite) or at least stamp every `include.path` / `includeIf.*.path`
  target of the shielded `.git/config` that resolves under a write grant
  (`git config --show-origin --list` names them).

## Regression tests to graduate

Reconstructed from the deleted spike; both fail today. `spikeWrite` is MkdirAll plus WriteFile.

```go
// H14/H15 (bv2-fzujr, bv2-mhiqa)
root := resolved(t.TempDir()); gitIn(t, root, "init", "-q")
inner := filepath.Join(root, "inner"); os.Mkdir(inner, 0o755)
gitIn(t, inner, "init", "-q"); gitIn(t, inner, "config", "core.hooksPath", "hk")
paths := []string{"hk/pre-commit", ".husky/pre-commit", "package.json"}
for _, p := range paths { spikeWrite(t, filepath.Join(inner, p), "a") }
b := baselineAutoExec([]string{root}); time.Sleep(10 * time.Millisecond)
for _, p := range paths { spikeWrite(t, filepath.Join(inner, p), "changed") }
changed, _, _ := b.changed([]string{root})
for _, p := range paths {
	if !slices.Contains(changed, filepath.Join(inner, p)) { t.Errorf("nested %s not reported", p) }
}

// H16 (bv2-w7o5l)
root := resolved(t.TempDir()); gitIn(t, root, "init", "-q")
gitIn(t, root, "config", "include.path", "../.gitconfig.local")
inc := filepath.Join(root, ".gitconfig.local"); spikeWrite(t, inc, "")
b := baselineAutoExec([]string{root})
spikeWrite(t, inc, "[core]\n\tfsmonitor = /tmp/evil\n")
changed, redirected, _ := b.changed([]string{root})
if len(changed)+len(redirected) == 0 { t.Error("core.fsmonitor set via in-tree include, nothing reported") }
```
