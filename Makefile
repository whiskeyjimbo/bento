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
GO_BUILD_FLAGS := -trimpath -buildvcs=false
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

# Pinned so the audit is reproducible: floating @latest would let the scanner drift
# under a build that is otherwise fixed. The vulnerability DB is fetched at run time
# and is expected to move; the tool version is not.
GOVULNCHECK_VERSION ?= v1.6.0

# Colors & Styling
BOLD    := \033[1m
CYAN    := \033[36m
GREEN   := \033[32m
YELLOW  := \033[33m
RESET   := \033[0m

.PHONY: all build test race vet audit vuln repro check install clean help

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
test: ## Run unit and integration tests
	@printf "$(CYAN)$(BOLD)==> Running tests...$(RESET)\n"
	@GOWORK=off go test ./...
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

check: vet test race audit ## Run all quality gates (vet, test, race, audit)
	@printf "\n$(GREEN)$(BOLD)★ All quality gates passed cleanly!$(RESET)\n"

## @category Utilities
help: ## Display this help menu
	@printf "\n$(BOLD)Bento Developer Makefile$(RESET)\n"
	@printf "$(CYAN)Usage:$(RESET) make $(BOLD)[target]$(RESET)\n"
	@awk 'BEGIN {FS = "(:.*## |## @category )"} \
		/^## @category/ { printf "\n\033[1m%s:\033[0m\n", $$2 } \
		/^[a-zA-Z_-]+:.*## / { printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@printf "\n"
