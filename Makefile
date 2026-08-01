# Build & Version variables
VERSION ?= 0.1.0-dev
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
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

# Pinned so the audit is reproducible: floating @latest would let the scanner drift
# under a build that is otherwise fixed. The vulnerability DB is fetched at run time
# and is expected to move; the tool version is not.
GOVULNCHECK_VERSION ?= v1.6.0

# Pinned for the same reason as govulncheck: a linter that drifts turns an
# unchanged tree red on its own schedule.
GOLANGCI_LINT_VERSION ?= v2.12.2

# Colors & Styling
BOLD    := \033[1m
CYAN    := \033[36m
GREEN   := \033[32m
YELLOW  := \033[33m
RESET   := \033[0m

.PHONY: all build test race vet crossbuild lint audit examples vuln repro check install clean help

all: build

## @category Build & Distribution
build: ## Compile the bento binary (reproducible: trimmed paths, static, source-derived stamp)
	@printf "$(CYAN)$(BOLD)==> Building bento ($(VERSION) - $(COMMIT))...$(RESET)\n"
	@$(GO_BUILD_ENV) go build $(GO_BUILD_FLAGS) $(LDFLAGS) -o bento ./cmd/bento
	@printf "$(GREEN)$(BOLD)✓ Binary built successfully: ./bento$(RESET)\n"

install: ## Install bento to GOPATH/bin
	@printf "$(CYAN)$(BOLD)==> Installing bento to GOPATH/bin...$(RESET)\n"
	@$(GO_BUILD_ENV) go install $(GO_BUILD_FLAGS) $(LDFLAGS) ./cmd/bento
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
race: ## Run the proxy concurrency tests under the race detector
	@printf "$(CYAN)$(BOLD)==> Running proxy tests under -race...$(RESET)\n"
	@GOWORK=off CGO_ENABLED=1 go test -race -count=1 ./internal/proxy/...
	@printf "$(GREEN)$(BOLD)✓ No data races!$(RESET)\n"

vet: ## Run go vet checks
	@printf "$(CYAN)$(BOLD)==> Running go vet...$(RESET)\n"
	@GOWORK=off go vet ./...
	@printf "$(GREEN)$(BOLD)✓ go vet clean!$(RESET)\n"

# The enforcement backend is linux/amd64, but the CLI and the public API are meant to
# compile on any Unix and refuse at runtime - a build that only ever runs on amd64 Linux
# drifts back to raw `undefined: unix.O_PATH` errors the first time a syscall constant
# lands in an untagged file. darwin catches a constant that is Linux-only; linux/arm64
# catches one that is amd64-only, and compiles the `linux && !amd64` seccomp and observe
# variants that nothing else here builds. Windows is not covered: the untagged CLI files
# still reach for syscall.Stat_t and SIGSYS, which it has no answer for.
crossbuild: ## Check the tree still compiles for the other Unix targets
	@printf "$(CYAN)$(BOLD)==> Cross-compiling for unsupported platforms...$(RESET)\n"
	@GOWORK=off GOOS=darwin GOARCH=arm64 go vet ./...
	@GOWORK=off GOOS=linux GOARCH=arm64 go vet ./...
	@printf "$(GREEN)$(BOLD)✓ Cross-compile clean!$(RESET)\n"

lint: ## Run golangci-lint (pinned; part of check)
	@printf "$(CYAN)$(BOLD)==> Linting ($(GOLANGCI_LINT_VERSION))...$(RESET)\n"
	@GOWORK=off go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run ./...
	@printf "$(GREEN)$(BOLD)✓ Lint clean!$(RESET)\n"

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
	@GO_BUILD_FLAGS="$(GO_BUILD_FLAGS)" ./scripts/repro-build.sh

# The examples are separate modules (their go.mod replaces bento with ../..), so the
# root `go test ./...` does not reach them and their tests can sit red indefinitely -
# which is how the embed Result-completeness guard, the thing that keeps a new honesty
# field from going unprinted, stayed failing unnoticed. The gate runs each verify.sh.
examples: ## Build, vet and test every example module against the public API
	@printf "$(CYAN)$(BOLD)==> Verifying example modules...$(RESET)\n"
	@for f in examples/*/verify.sh; do "$$f" || exit 1; done
	@printf "$(GREEN)$(BOLD)✓ Examples verified!$(RESET)\n"

check: vet crossbuild lint test race audit examples ## Run all quality gates (vet, crossbuild, lint, test, race, audit, examples)
	@printf "\n$(GREEN)$(BOLD)★ All quality gates passed cleanly!$(RESET)\n"

## @category Utilities
help: ## Display this help menu
	@printf "\n$(BOLD)Bento Developer Makefile$(RESET)\n"
	@printf "$(CYAN)Usage:$(RESET) make $(BOLD)[target]$(RESET)\n"
	@awk 'BEGIN {FS = "(:.*## |## @category )"} \
		/^## @category/ { printf "\n\033[1m%s:\033[0m\n", $$2 } \
		/^[a-zA-Z_-]+:.*## / { printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@printf "\n"
