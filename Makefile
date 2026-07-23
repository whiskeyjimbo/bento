# Build & Version variables
VERSION ?= 0.1.0-dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

# Colors & Styling
BOLD    := \033[1m
CYAN    := \033[36m
GREEN   := \033[32m
YELLOW  := \033[33m
RESET   := \033[0m

.PHONY: all build test vet audit check install clean help

all: build

## @category Build & Distribution
build: ## Compile the bento binary with version ldflags
	@printf "$(CYAN)$(BOLD)==> Building bento ($(VERSION) - $(COMMIT))...$(RESET)\n"
	@GOWORK=off go build $(LDFLAGS) -o bento ./cmd/bento
	@printf "$(GREEN)$(BOLD)✓ Binary built successfully: ./bento$(RESET)\n"

install: ## Install bento to GOPATH/bin
	@printf "$(CYAN)$(BOLD)==> Installing bento to GOPATH/bin...$(RESET)\n"
	@GOWORK=off go install $(LDFLAGS) ./cmd/bento
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

vet: ## Run go vet checks
	@printf "$(CYAN)$(BOLD)==> Running go vet...$(RESET)\n"
	@GOWORK=off go vet ./...
	@printf "$(GREEN)$(BOLD)✓ go vet clean!$(RESET)\n"

audit: ## Run the denylist completeness audit script
	@printf "$(CYAN)$(BOLD)==> Running denylist audit...$(RESET)\n"
	@./scripts/denylist-audit.sh
	@printf "$(GREEN)$(BOLD)✓ Denylist audit complete!$(RESET)\n"

check: vet test audit ## Run all quality gates (vet, test, audit)
	@printf "\n$(GREEN)$(BOLD)★ All quality gates passed cleanly!$(RESET)\n"

## @category Utilities
help: ## Display this help menu
	@printf "\n$(BOLD)Bento Developer Makefile$(RESET)\n"
	@printf "$(CYAN)Usage:$(RESET) make $(BOLD)[target]$(RESET)\n"
	@awk 'BEGIN {FS = "(:.*## |## @category )"} \
		/^## @category/ { printf "\n\033[1m%s:\033[0m\n", $$2 } \
		/^[a-zA-Z_-]+:.*## / { printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@printf "\n"
