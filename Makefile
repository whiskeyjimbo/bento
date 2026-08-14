# Build & Version variables
# Derived, not written down: a literal here goes stale the moment a tag is cut, and
# a build that misreports its version is worse than one that admits it has none.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")

# The build stamp is derived from the source, never the wall clock: reading the clock
# made two builds of one commit differ, so the binary could not be reproduced or
# compared against a published hash. SOURCE_DATE_EPOCH is the reproducible-builds
# standard hook; it defaults to the commit's own timestamp.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo 0)
DATE ?= $(shell date -u -d @$(SOURCE_DATE_EPOCH) +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
	|| date -u -r $(SOURCE_DATE_EPOCH) +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)

# -trimpath keeps the builder's absolute paths out of the binary: without it the
# toolchain and module directories are embedded, which both breaks reproducibility
# across machines and ships the builder's filesystem layout inside a security tool.
# CGO_ENABLED=0 links statically, so the C toolchain and the host libc leave the
# reproducibility surface and the binary carries no runtime loader dependency.
# -buildvcs=false because the commit is already stamped explicitly below: leaving it on
# adds nothing and makes the binary depend on working-tree cleanliness, so a stray edit
# changes the output of an otherwise identical source build.
GO_BUILD_ENV   := GOWORK=off CGO_ENABLED=0
# osusergo forces the pure-Go passwd resolver even under a cgo build. The credential
# shields anchor on the uid's passwd entry precisely because $HOME is caller-chosen
# (see homeAnchors); routing that lookup through libc NSS would put it back under
# caller control, since LD_PRELOAD can make getpwuid_r fail and drop the anchor.
GO_BUILD_FLAGS := -trimpath -buildvcs=false -tags osusergo
# LDFLAGS is left free for the caller. The stamp is appended to whatever they pass
# rather than living in LDFLAGS itself, because `make build LDFLAGS=-s` would
# otherwise erase the version, commit and date and produce a binary that cannot say
# what it is. No -s -w here on purpose: the developer build keeps its symbol table
# and DWARF so a crash in a sandbox layer is debuggable; only the release build in
# .goreleaser.yaml strips, where the size of a downloaded archive is the concern and
# the source is reproducible from the tag anyway.
LDFLAGS ?=
GO_LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE) $(LDFLAGS)"

# Standard GNU install locations. DESTDIR is the staging prefix a packager sets;
# PREFIX is where the binary will actually live at run time.
PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin

# Pinned so the audit is reproducible: floating @latest would let the scanner drift
# under a build that is otherwise fixed. The vulnerability DB is fetched at run time
# and is expected to move; the tool version is not.
GOVULNCHECK_VERSION ?= v1.6.0

# Per-target fuzzing budget. The default is short enough to run on a laptop over every
# target; the nightly job passes a much larger one, which is the run that is actually
# expected to find anything.
FUZZTIME ?= 30s

# Pinned for the same reason as govulncheck: a linter that drifts turns an
# unchanged tree red on its own schedule.
GOLANGCI_LINT_VERSION ?= v2.12.2

# `override` because cover rebuilds this directory with rm -rf, and a command-line
# assignment beats a plain := - so `make cover COVERDIR=~/notes` would delete it. It is
# scratch space for one target, not a knob. COVERPROFILE is the knob, and is only ever
# truncated by go test.
override COVERDIR := .cover
COVERPROFILE ?= coverage.out

# Colors & Styling
BOLD    := \033[1m
CYAN    := \033[36m
GREEN   := \033[32m
YELLOW  := \033[33m
RESET   := \033[0m

.PHONY: all build test cover race fuzz vet crossbuild lint audit examples vuln repro check install clean help

all: build

## @category Build & Distribution
build: ## Compile the bento binary (reproducible: trimmed paths, static, source-derived stamp)
	@printf "$(CYAN)$(BOLD)==> Building bento ($(VERSION) - $(COMMIT))...$(RESET)\n"
	@$(GO_BUILD_ENV) go build $(GO_BUILD_FLAGS) $(GO_LDFLAGS) -o bento ./cmd/bento
	@printf "$(GREEN)$(BOLD)✓ Binary built successfully: ./bento$(RESET)\n"

# Installs the same binary `make build` produced rather than a second `go install`
# build, so what is verified locally is what lands in BINDIR.
install: build ## Install bento to DESTDIR/PREFIX (default /usr/local/bin)
	@printf "$(CYAN)$(BOLD)==> Installing bento to $(DESTDIR)$(BINDIR)...$(RESET)\n"
	@install -d $(DESTDIR)$(BINDIR)
	@install -m 0755 bento $(DESTDIR)$(BINDIR)/bento
	@printf "$(GREEN)$(BOLD)✓ Installed bento successfully!$(RESET)\n"

clean: ## Remove built binaries
	@printf "$(YELLOW)$(BOLD)==> Cleaning build artifacts...$(RESET)\n"
	@rm -f bento
	@printf "$(GREEN)$(BOLD)✓ Clean complete.$(RESET)\n"

## @category Testing & Quality Gates
# BENTO_REQUIRE_TEST_DEPS turns a missing host dependency from a skip into a failure.
# The behavioral tests run a real bwrap and diff against the locally installed firejail
# and AppArmor profiles; without it, a host lacking bwrap, unprivileged user namespaces,
# or those profiles reports a green run over tests that asserted nothing - which is the
# same output as a run that exercised the shield. A bare `go test ./...` still skips, so
# the knob is on the gate rather than on the tests.
test: ## Run unit and integration tests (requires bwrap, userns, firejail and apparmor profiles)
	@printf "$(CYAN)$(BOLD)==> Running tests...$(RESET)\n"
	@GOWORK=off BENTO_REQUIRE_TEST_DEPS=1 go test ./...
	@printf "$(GREEN)$(BOLD)✓ All tests passed!$(RESET)\n"

# The proxy's concurrency tests hold many connections at the gate and the egress guard
# at once to prove a verdict never crosses connections. Whether a broken one is caught
# without the race detector depends on the window: parking a verdict on the Proxy struct
# fails plainly when the wrong verdict is acted on, but a narrow write-read window can
# pass hundreds of plain runs and fail immediately under -race. That is why the gate runs
# this package with it. CGO_ENABLED=1 because -race needs cgo (so check now wants a C
# toolchain), and the scope stays narrow: the linux tier tests spawn real bwrap and
# systemd scopes, which -race would make slow without telling us anything about them.
# The egress collector is the same class of property one layer up - the proxy calls its
# observe from a goroutine per connection - so it needs the detector too. It is named
# rather than run as a package because the rest of internal/linux is the real-sandbox tier
# above: -race over the whole package is 83s against 1s for these. Widen the pattern when
# another concurrent structure lands here. The -list guard is what makes that safe to
# forget: -run with no match exits 0 and prints "no tests to run", so a rename would turn
# this gate into a green no-op.
race: ## Run the proxy concurrency tests under the race detector
	@printf "$(CYAN)$(BOLD)==> Running proxy tests under -race...$(RESET)\n"
	@GOWORK=off CGO_ENABLED=1 go test -race -count=1 ./internal/proxy/...
	@GOWORK=off go test -list 'TestEgressCollector' ./internal/linux/ | grep -q TestEgressCollector \
		|| { printf "$(BOLD)the egress collector tests were renamed; update the -run pattern below$(RESET)\n" >&2; exit 1; }
	@GOWORK=off CGO_ENABLED=1 go test -race -count=1 -run 'TestEgressCollector' ./internal/linux/
	@printf "$(GREEN)$(BOLD)✓ No data races!$(RESET)\n"

# A plain `go test` only replays each Fuzz target's seed corpus, so the targets read as
# covered while nothing ever varies an input. -fuzz actually mutates, but the flag takes
# one target at a time, hence the loop: the target list is discovered from the tree
# rather than written down, so a new Fuzz function is fuzzed the day it lands. The list
# is captured into a variable rather than piped straight into `for`, because a pipeline
# reports grep's status and a command substitution in a `for` word reports none at all -
# either way a package that failed to build would be skipped and the run would still
# print that it found nothing.
#
# Not in `check`: even the laptop budget costs minutes, and the run is time-boxed rather
# than deterministic, so a PR gate would be both slow and flaky. It runs nightly instead.
#
# Interesting inputs go to the fuzz cache under $GOCACHE, which the nightly job persists;
# only a crasher is written into the package's testdata/fuzz, and that one is meant to be
# committed - it is a failing regression test that every later `go test` replays.
fuzz: ## Fuzz every Fuzz* target for FUZZTIME each (default 30s; not part of check)
	@printf "$(CYAN)$(BOLD)==> Fuzzing every target for $(FUZZTIME)...$(RESET)\n"
	@set -e; pkgs=$$(GOWORK=off go list ./...); \
	for pkg in $$pkgs; do \
		listed=$$(GOWORK=off go test -list='^Fuzz' $$pkg); \
		for target in $$(printf '%s\n' "$$listed" | grep '^Fuzz' || true); do \
			printf "$(CYAN)--> $$target ($$pkg)$(RESET)\n"; \
			GOWORK=off go test -run='^$$' -fuzz="^$$target$$" -fuzztime=$(FUZZTIME) $$pkg; \
		done; \
	done
	@printf "$(GREEN)$(BOLD)✓ Fuzzing found no failures.$(RESET)\n"

# Per-package `go test -cover` credits a function only to its own package's tests, so a
# package exercised entirely from its callers reads 0% and looks untested when it is not
# (internal/grantrefusal is the extreme case: no test file, every function driven from
# the thirteen call sites its package doc names). -coverpkg=./... measures the tree
# instead. The consequence is that the denominator changes - every listed package counts
# against every test binary - so these percentages are NOT comparable to the per-package
# ones, and the per-function view is what a reader should act on.
#
# BENTO_REQUIRE_TEST_DEPS mirrors `make test`: without it a host missing bwrap, userns or
# the firejail and AppArmor profiles skips the behavioural tests and reports a lower
# number, which reads as a regression rather than as a host that could not run them.
#
# The seccomp filters are process-wide and permanent, so their tests assert from a
# re-exec'd child - a separate process, whose counters land nowhere unless it is told
# where to put them. BENTO_TEST_COVERDIR is that channel (a project-specific name, not
# GOCOVERDIR, so nothing else in the tree writes into the merge), and the children's
# profile is concatenated onto the parent's afterwards. Appending rather than merging is
# right even though blocks then repeat: -coverpkg already emits every package once per
# test binary, so the profile is full of repeated blocks by construction and go tool
# cover sums them. The dir is rebuilt each run because stale counters would be merged as
# if they were this run's.
#
# -count=1 for the same reason the dir is rebuilt: a cached package result replays the
# parent's profile but never re-runs the children, so the merge would quietly drop every
# counter they contribute and report the drop as a coverage regression.
#
# The profile is assembled under $(COVERDIR) and only moved to $(COVERPROFILE) once the
# merge has succeeded and been read back. go test writes its profile before any of the
# checks below run, so writing it straight to the blessed name would leave a parent-only
# profile behind whenever a check fails - loud at the time, but indistinguishable from a
# good one to whoever reads the file next. The read-back is `> func.txt` rather than a
# pipe to tail on purpose: /bin/sh reports a pipeline's last exit status, so piping would
# mask a failure in the one step that parses the merged profile.
cover: ## Measure coverage across the whole tree with -coverpkg (slow; not in check)
	@printf "$(CYAN)$(BOLD)==> Measuring coverage across the tree...$(RESET)\n"
	@rm -rf $(COVERDIR) $(COVERPROFILE) && mkdir -p $(COVERDIR)
	@GOWORK=off BENTO_REQUIRE_TEST_DEPS=1 BENTO_TEST_COVERDIR=$(abspath $(COVERDIR)) \
		go test -count=1 -covermode=atomic -coverpkg=./... -coverprofile=$(COVERDIR)/parent.out ./...
	@ls $(COVERDIR)/covcounters.* >/dev/null 2>&1 || { \
		printf "$(YELLOW)no child counters in $(COVERDIR); refusing to report a number that silently omits them.\n"; \
		printf "The re-exec'd tests emit only when helperCommand threads -test.gocoverdir from BENTO_TEST_COVERDIR,\n"; \
		printf "and only when the helper returns rather than calling os.Exit.$(RESET)\n"; \
		exit 1; }
	@GOWORK=off go tool covdata textfmt -i=$(COVERDIR) -o=$(COVERDIR)/children.txt
	@[ "$$(head -1 $(COVERDIR)/parent.out)" = "$$(head -1 $(COVERDIR)/children.txt)" ] \
		|| { printf "$(YELLOW)coverage modes differ; refusing to merge$(RESET)\n"; exit 1; }
	@cp $(COVERDIR)/parent.out $(COVERDIR)/merged.out
	@tail -n +2 $(COVERDIR)/children.txt >> $(COVERDIR)/merged.out
	@GOWORK=off go tool cover -func=$(COVERDIR)/merged.out > $(COVERDIR)/func.txt
	@mv $(COVERDIR)/merged.out $(COVERPROFILE)
	@tail -1 $(COVERDIR)/func.txt
	@printf "$(GREEN)$(BOLD)✓ Profile written to $(COVERPROFILE); per-function view: go tool cover -func=$(COVERPROFILE)$(RESET)\n"

vet: ## Run go vet checks
	@printf "$(CYAN)$(BOLD)==> Running go vet...$(RESET)\n"
	@GOWORK=off go vet ./...
	@printf "$(GREEN)$(BOLD)✓ go vet clean!$(RESET)\n"

# The enforcement backend is linux/amd64, but the CLI and the public API are meant to
# compile on darwin too and refuse at runtime - a build that only ever runs on amd64
# Linux drifts back to raw `undefined: unix.O_PATH` errors the first time a syscall
# constant lands in an untagged file. darwin catches a constant that is Linux-only;
# linux/arm64 catches one that is amd64-only, and compiles the `linux && !amd64` seccomp
# and observe variants that nothing else here builds. These two are the whole target
# set: backend_other.go is tagged darwin, so windows and the BSDs do not build at all -
# the untagged CLI files reach for syscall.Stat_t, SIGSYS, and unix.ENODATA, which they
# have no answer for.
#
# landlocktsync is the third arm and a different kind of build: it is not another
# platform but go-landlock's own tag, which raises the library's minimum ABI to 8. The
# floor bento mirrors for it lives in a file nothing else compiles, so without this arm
# neither the mirror nor the availability gate it feeds is ever executed, and a
# go-landlock bump that moved the threshold would drift silently. Tested rather than
# vetted: compiling proves the file parses, running proves the floor is the one the
# library uses.
crossbuild: ## Check the tree still compiles for darwin and linux/arm64
	@printf "$(CYAN)$(BOLD)==> Cross-compiling for unsupported platforms...$(RESET)\n"
	@GOWORK=off GOOS=darwin GOARCH=arm64 go vet ./...
	@GOWORK=off GOOS=linux GOARCH=arm64 go vet ./...
	@GOWORK=off go test -tags landlocktsync ./internal/landlock/...
	@printf "$(GREEN)$(BOLD)✓ Cross-compile clean!$(RESET)\n"

lint: ## Run golangci-lint (pinned; part of check)
	@printf "$(CYAN)$(BOLD)==> Linting ($(GOLANGCI_LINT_VERSION))...$(RESET)\n"
	@GOWORK=off go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run ./...
	@printf "$(GREEN)$(BOLD)✓ Lint clean!$(RESET)\n"

layering: ## Check the architectural boundaries (kernel enforcement, shield assembly)
	@printf "$(CYAN)$(BOLD)==> Checking layering...$(RESET)\n"
	@./scripts/layering.sh
	@printf "$(GREEN)$(BOLD)✓ Layering clean!$(RESET)\n"

audit: ## Run the denylist completeness audit script
	@printf "$(CYAN)$(BOLD)==> Running denylist audit...$(RESET)\n"
	@./scripts/denylist-audit.sh
	@printf "$(GREEN)$(BOLD)✓ Denylist audit complete!$(RESET)\n"

vuln: ## Scan both modules for known vulnerabilities (needs network)
	@printf "$(CYAN)$(BOLD)==> Scanning dependencies (govulncheck $(GOVULNCHECK_VERSION))...$(RESET)\n"
	@GOWORK=off go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...
	@cd examples/supervise && GOWORK=off go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...
	@printf "$(GREEN)$(BOLD)✓ No known vulnerabilities!$(RESET)\n"

repro: ## Verify the binary builds byte-identically from a different source path
	@GO_BUILD_FLAGS="$(GO_BUILD_FLAGS)" VERSION="$(VERSION)" ./scripts/repro-build.sh

# The examples are separate modules (their go.mod replaces bento with ../..), so the
# root `go test ./...` does not reach them and their tests can sit red indefinitely -
# which is how the embed Result-completeness guard, the thing that keeps a new honesty
# field from going unprinted, stayed failing unnoticed. The gate runs each verify.sh.
examples: ## Build, vet and test every example module against the public API
	@printf "$(CYAN)$(BOLD)==> Verifying example modules...$(RESET)\n"
	@for f in examples/*/verify.sh; do "$$f" || exit 1; done
	@printf "$(GREEN)$(BOLD)✓ Examples verified!$(RESET)\n"

# vuln is in here rather than on a nightly schedule because a known-vulnerable
# dependency should stop the merge that introduces it, not be reported the next
# morning. It is the one gate that needs network: the tool is pinned but the
# vulnerability database is fetched at run time and is expected to move.
check: vet crossbuild lint test race layering audit examples vuln ## Run all quality gates (vet, crossbuild, lint, test, race, layering, audit, examples, vuln)
	@printf "\n$(GREEN)$(BOLD)★ All quality gates passed cleanly!$(RESET)\n"

## @category Utilities
help: ## Display this help menu
	@printf "\n$(BOLD)Bento Developer Makefile$(RESET)\n"
	@printf "$(CYAN)Usage:$(RESET) make $(BOLD)[target]$(RESET)\n"
	@awk 'BEGIN {FS = "(:.*## |## @category )"} \
		/^## @category/ { printf "\n\033[1m%s:\033[0m\n", $$2 } \
		/^[a-zA-Z_-]+:.*## / { printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@printf "\n"
