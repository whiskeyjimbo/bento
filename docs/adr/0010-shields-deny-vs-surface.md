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

Running the b28a tool list against category 1 first, which was the point of doing
this before writing any new rules:

* **pre-commit** - the entry point is `.git/hooks/pre-commit`, already shielded by
  `denylist.Workspace`. `.pre-commit-config.yaml` cannot execute without a writable
  hook. No new rule. (One genuine gap found beside it: `~/.cache/pre-commit` holds
  cloned hook repos that the host executes at the next commit, and it is not
  shielded. Category 2, home-anchored, filed separately.)
* **husky** - `core.hooksPath` lives in `.git/config`, shielded, so a run cannot
  newly redirect hooks. An already-installed `.husky/pre-commit` is a tracked
  in-tree project file: category 3, and the same residual `gitDirShields` already
  documents.
* **npm/yarn/pnpm** - `ignore-scripts=false` is the default, so a workspace
  `.npmrc` grants nothing that is not already on. `~/.npmrc` is `DenyAll` for its
  tokens. `package.json` lifecycle scripts are category 3.
* **cargo** - `~/.cargo/config.toml` is already denied (`denylist.go:594`). A
  workspace `.cargo/config.toml` (`runner`, `rustflags`, `[target]` linker) has no
  approval record and is the one plausible new category-2 entry. `build.rs` is
  category 3.
* **pytest** - `conftest.py` is imported on collection and is edited routinely:
  category 3. `.pth` files land in a site dir the policy had to grant write to.
* **eslint/prettier** - flat config and plugin resolution out of `node_modules` by
  design. Category 3, both.
* **direnv** - category 1, already covered.

So category 1 is exhausted at two entries: direnv's allow record and bento's own
journal. No other tool in the list keeps a host-side approval record to shield.
Category 2 gains at most one workspace entry and one home entry. Everything else
is category 3.

That is the direct answer to "this feels like it just adds stuff all the time":
the deny list grows only where no authorization record exists and the agent never
legitimately edits the surface, and both of those are now nearly exhausted. The
growth moves to the report, where being incomplete is cheap.

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

* b28a is not a port of the git pattern and is now small: one workspace
  `.cargo/config.toml` rule, one `~/.cache/pre-commit` rule, and the rest routed to
  the report.
* The category-3 report is a new mechanism. `internal/observe` is ptrace-based and
  profiler-only, so an enforcing run has no post-run change detection today. Filed
  separately; it does not block the category-1 and category-2 work.
* The residuals `gitDirShields` already documents - independent nested repos under
  the grant, repos created during the run, in-tree hook runners - are category 3 by
  this decision, not gaps in category 2.
