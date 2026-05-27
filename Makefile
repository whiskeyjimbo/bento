# =============================================================================
# Bento Makefile
# =============================================================================
# Elegant, grouped, and colorful automation commands for the Bento sandbox.

.DEFAULT_GOAL := help

# -----------------------------------------------------------------------------
# Color Codes for Terminal Output
# -----------------------------------------------------------------------------
CYAN   := \033[36m
GREEN  := \033[32m
YELLOW := \033[33m
BLUE   := \033[34m
NC     := \033[0m # No Color

# -----------------------------------------------------------------------------
# Phony Targets
# -----------------------------------------------------------------------------
.PHONY: help build launcher fsshim test test-verbose vet fmt clean

# -----------------------------------------------------------------------------
# Group: Help Manual
# -----------------------------------------------------------------------------
help:
	@printf "\n"
	@printf "$(BLUE)=== Bento Script Sandbox Console ===$(NC)\n\n"
	@printf "Usage: make $(YELLOW)[target]$(NC)\n\n"
	@printf "$(CYAN)Build Targets:$(NC)\n"
	@printf "  $(GREEN)build$(NC)          Statically builds launcher and compiles all packages\n"
	@printf "  $(GREEN)launcher$(NC)       Statically compiles Linux/amd64 embedded launcher shim\n\n"
	@printf "$(CYAN)Quality & Testing:$(NC)\n"
	@printf "  $(GREEN)test$(NC)           Run all unit and integration test suites\n"
	@printf "  $(GREEN)test-verbose$(NC)   Run tests with detailed execution log output\n"
	@printf "  $(GREEN)vet$(NC)            Run go vet static inspection tool\n"
	@printf "  $(GREEN)fmt$(NC)            Reformat all source code in workspace\n\n"
	@printf "$(CYAN)Utility Targets:$(NC)\n"
	@printf "  $(GREEN)clean$(NC)          Delete build directories and clean up bin artifacts\n\n"

# -----------------------------------------------------------------------------
# Group: Build Operations
# -----------------------------------------------------------------------------
build: launcher fsshim
	@printf "$(BLUE)[bento:build]$(NC) Compiling bento CLI to bin/bento...\n"
	@mkdir -p bin
	@go build -o bin/bento ./cmd/bento
	@printf "$(GREEN)[bento:build]$(NC) Built bin/bento (install with: sudo install bin/bento /usr/local/bin/)\n"

launcher:
	@printf "$(BLUE)[bento:build]$(NC) Creating launcher embed container directory...\n"
	@mkdir -p internal/launcherbin
	@printf "$(BLUE)[bento:build]$(NC) Compiling statically-linked Linux/amd64 launcher bin...\n"
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
		-tags netgo,osusergo \
		-ldflags="-s -w -extldflags=-static" \
		-o internal/launcherbin/bento-launcher-linux-amd64 \
		./cmd/bento-launcher
	@printf "$(GREEN)[bento:build]$(NC) Static launcher compiled & embedded successfully!\n"

fsshim:
	@printf "$(BLUE)[bento:build]$(NC) Compiling LD_PRELOAD fsshim (strace fallback)...\n"
	@mkdir -p internal/fsshimbin
	@gcc -shared -fPIC -O2 -Wno-unused-result -Wno-nonnull-compare \
		-o internal/fsshimbin/fsshim-linux-amd64.so \
		internal/fsshim/fsshim.c -ldl
	@printf "$(GREEN)[bento:build]$(NC) fsshim compiled & embedded successfully!\n"

# -----------------------------------------------------------------------------
# Group: Verification & Quality
# -----------------------------------------------------------------------------
test: build
	@printf "$(BLUE)[bento:test]$(NC) Executing test suites...\n"
	@go test ./...
	@printf "$(GREEN)[bento:test]$(NC) All tests executed and passed successfully!\n"

test-verbose: build
	@printf "$(BLUE)[bento:test]$(NC) Executing test suites with verbose logs...\n"
	@go test -v ./...

vet:
	@printf "$(BLUE)[bento:check]$(NC) Running standard static analyzer rules...\n"
	@go vet ./...
	@printf "$(GREEN)[bento:check]$(NC) Standard verification passed!\n"

fmt:
	@printf "$(BLUE)[bento:check]$(NC) Reformatting source files...\n"
	@go fmt ./...
	@printf "$(GREEN)[bento:check]$(NC) Code formatting completed!\n"

# -----------------------------------------------------------------------------
# Group: Utility Operations
# -----------------------------------------------------------------------------
clean:
	@printf "$(YELLOW)[bento:clean]$(NC) Removing built launcher bins and cache targets...\n"
	@rm -rf internal/launcherbin internal/fsshimbin bin
	@printf "$(GREEN)[bento:clean]$(NC) Workspace cleaned successfully!\n"
