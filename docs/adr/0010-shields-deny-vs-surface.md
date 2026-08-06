# [ADR-0010] Shields: Authorization Record, Deny, or Surface

* **Status:** Accepted
* **Date:** 2026-08-06

## Context and Problem Statement

The per-tool shield list reads as if it grows without converging.
`denylist.Workspace` plus `gitDirShields` (`internal/linux/args.go:822-944`) is
hundreds of lines that make exactly one tool - git - safe, and the obvious next
step is to write the same shape again for cargo, npm, pytest, eslint, pre-commit
and direnv. Before doing that, settle whether enumeration is the mechanism at all.

The criterion the existing list actually encodes, once you look at what is in it:
shields protect what **auto-executes on the host without being read**. That is why
`.vscode` and `.idea` sit next to `.git/hooks`. None of them is dangerous during
the run - the box bounds reach with a netns, a proxy allowlist, a mount namespace
and write grants - they run later, on the host, when a developer opens the repo or
commits. The contract is that nothing the agent wrote executes without someone
having had the chance to look at it. Bad code in a file that gets reviewed is a
code-review problem and always was.

That criterion does not tell you what to do about `package.json`, which
auto-executes on the developer's next `npm install` and which an agent doing
ordinary dependency work must be able to edit. Denying it breaks the tool;
allowing it silently is the hole. This is the case enumeration cannot resolve, and
it is why the list feels like it never converges.

## Decision

Every auto-executing surface falls into one of three categories. They are ordered:
take the first that applies.

**1. Deny the authorization record, where the tool has one.**

Some tools already gate host-side execution behind a per-host approval record. Deny
write to the record and every file the tool would have auto-executed is covered, in
one bounded rule, including files in workspaces this run never touched and
workspaces that do not exist yet.

direnv is the worked example, already implemented at `denylist.go:685`:
`~/.local/share/direnv/allow` is write-denied rather than shielding workspace
`.envrc` files. direnv keys approval on the file's content hash, so with the allow
record unwritable, any `.envrc` the agent touches fails its approval check and
prompts the developer. Bento's own approval journal a few lines below is the same
shape: shielded so a sandboxed run cannot author its own baseline and make an added
grant look like old news.

A category-1 shield is only complete if it covers **the record and the config that
can bypass the record.** direnv again: `direnv.toml`'s `[whitelist]` skips the
allow check entirely, and that is covered only because `.config/direnv` is
write-denied at `denylist.go:684`. Without this rule a category-1 shield looks
bounded and is not.

The rule is demanding enough that the worked example does not yet satisfy it:
`DIRENV_CONFIG` relocates the config directory holding that `[whitelist]`, and it
is not in `dirEnvs` (`denylist.go:1444`). `homeLocations` covers the
`XDG_CONFIG_HOME` move; the tool-specific variable is the gap. So a category-1
shield is three things, not two - the record, the config that bypasses it, and
every variable that relocates either. Filed separately.

**2. Deny the surface, where there is no record and the agent never legitimately
edits it.** `.git/hooks`, `.git/config`, `.git/config.worktree`, `.vscode`,
`.idea`. This is what `denylist.Workspace` and `gitDirShields` already are.

**3. Surface it in the run report, where the agent must legitimately edit it.**
`package.json` scripts, `conftest.py`, `build.rs`, `setup.py`,
`.github/workflows`, an in-tree `.husky/`. These cannot be denied without breaking
ordinary work. The run reports which auto-executing files it changed, so review
looks there first.

The cost asymmetry is the point and is what makes category 3 safe to be incomplete
on: a gap in a report is a missed hint, a gap in a fence is a silent hole.

## Audit Result

Running the toolchain list against category 1 first, which was the point of doing
this before writing any new rules:

* **pre-commit** - no approval record. The installed `.git/hooks/pre-commit` is
  shielded by `denylist.Workspace`, but that hook only execs `pre-commit hook-impl`,
  which reads `.pre-commit-config.yaml` **at commit time**. On the ordinary host
  where the developer already installed the hook, an agent adding a `repo: local`
  entry with an arbitrary `entry:` runs on the host at the next commit having
  written no hook at all. `.pre-commit-config.yaml` is the `package.json` shape
  exactly: category 3. (Separate gap beside it: `~/.cache/pre-commit` holds cloned
  hook repos the host executes at the next commit, and is not shielded. Category 2,
  home-anchored, filed separately.)
* **husky** - `core.hooksPath` is read from `.git/config` *and* from per-worktree
  `config.worktree` and submodule gitdir configs, all of which are now shielded
  unconditionally, so a run cannot newly redirect hooks. An already-installed
  `.husky/pre-commit` is a tracked in-tree project file: category 3, and the same
  residual `gitDirShields` already documents.
* **npm/yarn/pnpm** - no approval record, and `ignore-scripts` is beside the point:
  the execution surfaces here are not only lifecycle scripts. `.pnpmfile.cjs` is
  executed by pnpm on every install and `ignore-scripts` does not disable it;
  `yarn-path` (classic `.yarnrc`) and `yarnPath` (`.yarnrc.yml`) name an in-tree
  binary yarn execs on *any* invocation - and `~/.yarnrc` is shielded
  (`denylist.go:607`) while the workspace one is not; a workspace `.npmrc`
  `registry=` redirect routes execution through a dependency's install script.
  `~/.npmrc` is `DenyAll` for its tokens. All category 3 (agents edit these), with
  the workspace `.yarnrc`/`.pnpmfile.cjs` asymmetry filed separately.
* **cargo** - `~/.cargo/config.toml` is already denied (`denylist.go:594`). A
  workspace `.cargo/config.toml` (`runner`, `rustflags`, `[target]` linker) has no
  approval record and is the one plausible new category-2 entry. `build.rs` is
  category 3.
* **pytest** - `conftest.py` is imported on collection and is edited routinely:
  category 3. `.pth` files land in a site dir the policy had to grant write to.
* **eslint/prettier** - flat config and plugin resolution out of `node_modules` by
  design. Category 3, both.
* **direnv** - category 1, already covered.
* **go** - no record. `~/.config/go/env` is not shielded, and `go env -w
  GOFLAGS=-toolexec=...` makes every subsequent host `go build` exec an arbitrary
  binary. Category 2, home-anchored, filed separately.
* **maven/gradle** - no record. `.mvn/extensions.xml`, `.mvn/jvm.config` and the
  wrapper's `distributionUrl` all execute on the next `./mvnw` or `./gradlew` with
  no script involved. Category 3.

Category 1 is small, but "exhausted at two entries" would be too strong. Four are
known: direnv's allow record, bento's own journal, VS Code's workspace trust store
(which gates `.vscode/tasks.json` auto-run and is covered incidentally by the
`.config/Code` write-deny at `denylist.go:705`), and mise's trust record for
in-tree `mise.toml` - the direnv shape exactly, and the one that is *not* covered,
since only `.local/share/mise/shims` is shielded (`denylist.go:860`). The useful
claim is the weaker one: **no tool audited keeps an unshielded
approval record except mise**, and category 1 does not scale with the ecosystem
the way the per-tool surface list would.

That is the direct answer to "this feels like it just adds stuff all the time":
the deny list grows only where no authorization record exists and the agent never
legitimately edits the surface. Category 2 gains a handful of entries (workspace
`.cargo/config.toml`, `~/.cache/pre-commit`, `~/.config/go/env`) and category 1
one (mise). Everything else moves to the report, where being incomplete is cheap.

## Considered and Rejected

**Default-deny on dot-entries under a write grant, with explicit opt-in.** The
structural simplification that would replace most of the enumeration with one rule
that grows with the ecosystem instead of trailing it. It does not survive contact
with real agent workflows: `.gitignore`, `.eslintrc.json`, `.prettierrc`,
`.editorconfig`, `.dockerignore` and `.github/workflows` are all routine, harmless
agent edits, and a `DenyWrite` shield has no opt-out (the read opt-in covers
`DenyAll` only, see `shieldNeeded`). It converts ordinary work into refusals. The
correlation between "dot-entry" and "never legitimately edited" is not strong
enough to hang a fence on.

## Consequences

* The expansion work is not a port of the git pattern: a handful of rules (workspace
  `.cargo/config.toml`, `~/.cache/pre-commit`, `~/.config/go/env`, mise's trust
  record) rather than a per-tool surface list, with the rest routed to the report.
* Applying the criterion to the existing rules found one hole and closed it here:
  `gitDirShields` gated `config.worktree` on the file already existing, while
  emitting `config` and `hooks` unconditionally and while `denylist.Workspace`
  shields the top-level `config.worktree` unconditionally. The reasoning for the
  gate - that an absent `config.worktree` is inert because the run cannot enable
  `extensions.worktreeConfig` - does not hold on a repo that already has it on,
  where a planted `config.worktree` with `core.hooksPath` redirects the next commit
  in that worktree. Now emitted unconditionally, like its siblings.
* The category-3 report is a new mechanism. `internal/observe` is ptrace-based and
  profiler-only, so an enforcing run has no post-run change detection today. Filed
  separately; it does not block the category-1 and category-2 work.
* The residuals `gitDirShields` already documents - independent nested repos under
  the grant, repos created during the run, in-tree hook runners - are category 3 by
  this decision, not gaps in category 2.
