# Contributing to Bento

Thanks for your interest in Bento. Contributions of all kinds are welcome -
bug reports, fixes, docs, and features.

Bento is a sandbox, so one thing shapes everything below: a change that weakens
the boundary, or that reports a layer as enforced when it is not, is the failure
this project exists to prevent. Changes near enforcement get more scrutiny than
their size suggests, and that is not a comment on the contributor.

## Licensing of contributions

Bento is licensed under **Apache-2.0** (see [`LICENSE`](LICENSE)).

Contributions are accepted under those same terms (**inbound = outbound**). You
retain copyright in your contributions; the record of authorship is the git
history. There is no CLA - the Apache-2.0 license you contribute under already
includes the patent grant in section 3. Please only submit work you have the
right to license this way.

New dependencies are a real cost here, and the threat model trusts the Bento
binary itself, so anything linked into it widens what a user has to trust. Prefer
the standard library or something already in [`go.mod`](go.mod); a new dependency
needs a genuine reason and a license compatible with Apache-2.0.

## Development setup

You need Go (see the version in [`go.mod`](go.mod)) and, on Linux, `bubblewrap`
with unprivileged user namespaces enabled. `make race` needs a C toolchain for
the race detector.

This checkout is not part of the parent `go.work`, so every `go` command needs
`GOWORK=off`. The Makefile sets it for you - prefer the make targets over bare
`go test`.

```bash
make build   # reproducible static binary
make check   # the full gate: vet, crossbuild, lint, test, race, audit, examples, vuln
```

`make check` is the bar before merging. Get it green before opening a PR. It needs
network access: `make vuln` fetches the vulnerability database at run time, so a
dependency with a known advisory stops the merge that introduces it rather than
being reported the next morning.

Useful targets:

```bash
make test        # unit and integration tests
make vet
make lint        # golangci-lint, pinned
make race        # the proxy's concurrency tests under the race detector
make audit       # denylist parity against the firejail reference definitions
make crossbuild  # the tree still compiles for darwin and linux/arm64
make examples    # each examples/*/verify.sh, which the root go test does not reach
make vuln        # govulncheck over both modules; needs network
make cover       # whole-tree coverage with -coverpkg; see "Coverage" below
```

Two of these are easy to underestimate:

- **`make race` is not extra credit.** Several of the proxy's cross-connection
  properties - a gate or egress-guard verdict never landing on another
  connection - are enforced only by the race detector. A narrower breakage of
  them passes hundreds of plain runs and fails immediately under `-race`.
- **`make test` needs host state to mean anything.** The suite runs real probes
  inside real bubblewrap sandboxes, and the denylist audit diffs against the
  locally installed firejail and AppArmor profiles. Without them those tests
  skip, and a green run proves less than it appears to. Install `bubblewrap` and
  `firejail`; set `BENTO_REQUIRE_TEST_DEPS` to turn a skip into a failure, which
  is what CI does.

CI runs the same gate on every push and pull request - see
[`.github/workflows/gate.yml`](.github/workflows/gate.yml), which is the single
definition of the gate that both CI and the release workflow call.

## Tests

**New functionality ships with tests, and a bug fix ships with a regression test
that fails before the fix.** This is not negotiable for anything that touches
enforcement: if a boundary bug could return without a test noticing, the fix is
not finished.

Tests assert behaviour, not implementation. Where a test needs to stand in for
the outside world, prefer a small real implementation - an in-memory store, a
canned transport - over a mock; it survives refactoring in a way an expectation
script does not.

### Coverage

```bash
make cover   # -coverpkg=./... over the whole tree; ~40s, not part of make check
```

The baseline is **86.0% of statements** (2026-08-04), which includes the re-exec'd
seccomp children's counters merged in. Read it with
`go tool cover -func=coverage.out`, and read the per-function column rather than
the per-package one.

Two things about that number are easy to misread.

**It is not comparable to `go test ./... -cover`.** Per-package coverage credits
a function only to its own package's tests, so a package driven entirely from
its callers reads as untested when it is not - `internal/grantrefusal` has no
test file at all and every one of its functions is exercised. `-coverpkg=./...`
measures the tree instead, which also changes the denominator: every package is
counted against every test binary, so the per-package percentages `make cover`
prints are each one test binary's share of the whole tree, not that package's
own coverage. They are meaningless in isolation. Only the total and the
per-function view mean anything.

**Some real coverage is not counted at all.** The sandbox layers are tested
through sacrificial subprocesses, and a subprocess's counters do not reach the
profile:

- `internal/launcher` and `internal/seccomp` re-exec the test binary behind a
  sentinel environment variable. The child is instrumented, so its counters can in
  principle be merged: the toolchain wants `-test.gocoverdir=$DIR` on the child's
  argv and `go tool covdata textfmt` afterwards. (`GOCOVERDIR` in the
  environment is not enough - that is honoured by `go build -cover` binaries,
  not by test binaries.) The two packages differ, so do not read one as evidence
  about the other: seccomp's counters are recovered this way, launcher's cannot be.

  For `internal/launcher` the blocker is Landlock. A child that applied the
  layers is confined to the run's writable grants, and the coverage directory is
  not one; adding it to `Config.Writable` does recover the counters, but then the
  test no longer runs the configuration it claims to test. So the report child
  deliberately calls `os.Exit(0)` before `testing`'s teardown and discards its
  own counters. Removing that call makes the suite fail outright, which is what
  commit 5e86406 fixed; the low numbers are the price.

  For `internal/seccomp` there is no longer a blocker, and its counters are
  recovered. The exec-block filter does not touch `write` or `openat`, so nothing
  stopped the child writing; all that was in the way was the helpers calling
  `os.Exit` on the way out, which skipped the teardown that emits. Only the
  success path was changed - a helper that passes now falls through and lets
  teardown run, while a failing one still exits non-zero and still emits nothing,
  per the last bullet below. `helperCommand` threads `-test.gocoverdir` when
  `BENTO_TEST_COVERDIR` is set, and `make cover` merges the result. Leave that
  wiring in place: without the merge step the children's counters are dropped
  silently, which reads as a coverage regression rather than as a broken merge.

  `backend.DispatchReexec` is **not** the same shape, despite looking like it, and
  measuring it costs nothing to re-learn: it sits at 42.3% and the rest is not
  recoverable. The seccomp helpers' `os.Exit` was incidental verdict-reporting, but
  `reexecFail`'s exit 125 *is* the contract - a stage must never fall through to
  the embedding program's startup, which is what `TestDispatchReexecFailsSetupWith125`
  pins. Nor can `-test.gocoverdir` be threaded: `TestMain` calls `DispatchReexec`
  before `m.Run`, so a stage child exits before the `testing` package parses flags
  at all. Its launch and degraded stages additionally hit the Landlock wall above.
- `internal/landlock` builds `internal/landlock/internal/probe` as a separate
  binary and runs it under bwrap. That coverage is invisible even to
  `-coverpkg`, and recovering it would need the probe built with `-cover` and
  merged through `covdata` - into the same write-after-the-layers-close wall.
- What skips the emit is `os.Exit`, not a non-zero status: the counters are written
  by `testing`'s teardown, which `os.Exit` never returns to. A child failing through
  `t.Fatal` exits 1 and still emits. It happens that every failure path in these
  helpers is an `os.Exit`, so their failure paths - the ones the subprocesses exist
  to exercise - are the least visible of the lot. Keep the distinction in mind when
  reasoning about what landed: meta-data is written at child startup and counters
  only at teardown, so a directory holding `covmeta.*` with no `covcounters.*` means
  the children started and died, not that they never ran.

So `internal/landlock`, `internal/launcher` and `backend.DispatchReexec` read low
because their coverage is uncounted, not because it is missing. Do not chase those
numbers with tests; check what the subprocess tests already assert first.
`internal/seccomp` no longer belongs on that list - its children are merged, so its
number is real and can be read like any other.

## Architecture & conventions

Read [`docs/architecture.md`](docs/architecture.md) before making structural
changes, and [`docs/threat-model.md`](docs/threat-model.md) before touching
anything that grants, shields, or enforces. A few house rules:

- **Commit messages**: one-line conventional commits (`type(area): description`).
- Run `go fmt ./...` before committing. New code reuses the existing patterns
  rather than introducing new ones; match the file you are editing.
- Keep the vocabulary consistent - a *manifest* declares *grants*, *shields*
  cover what is never exposed, `bento profile` proposes and `bento approve`
  stamps. One term per concept, in code, output, and docs.
- **Fail loudly.** A silent fallback in enforcement code is a security bug, not
  a robustness feature. If a layer cannot be enforced, say so rather than
  degrading quietly.

## Pull requests

1. Fork and branch from `main`.
2. Make your change with tests.
3. Ensure `make check` passes.
4. Open a PR describing the change and its motivation. Link any related issue.

If your change moves the enforcement boundary in either direction, say so
explicitly in the PR - which paths, which layer, and why. See the "Versioning and
the boundary" section of [`SECURITY.md`](SECURITY.md) for how that is versioned.

## Reporting bugs / requesting features

Use [GitHub Issues](../../issues). For anything that looks like a boundary
failure - a shield leaking, a grant exposing more than it names, egress reaching
a host the manifest did not allow, or a layer reporting enforcement it is not
delivering - follow [`SECURITY.md`](SECURITY.md) and report it privately instead
of opening a public issue.

## Code of conduct

Participation is governed by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
