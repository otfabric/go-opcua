# Self-documented Makefile (https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html)
# Run 'make' or 'make help' to list targets.

.DEFAULT_GOAL := help

# Core library packages measured by `make coverage` (excludes cmd/, examples/, tests/).
TEST_PKGS := . ./ua/ ./uacp/ ./uasc/ ./uapolicy/ ./server/ ./monitor/ ./errors/ ./id/ ./internal/stats/
COVER_PKGS := github.com/otfabric/go-opcua,github.com/otfabric/go-opcua/ua,github.com/otfabric/go-opcua/uacp,github.com/otfabric/go-opcua/uasc,github.com/otfabric/go-opcua/uapolicy,github.com/otfabric/go-opcua/server,github.com/otfabric/go-opcua/monitor,github.com/otfabric/go-opcua/errors,github.com/otfabric/go-opcua/id,github.com/otfabric/go-opcua/internal/stats
COVER_TEST_PKGS := $(TEST_PKGS) ./conformance/

.PHONY: help all test coverage cover lint lint-ci fmt vet integration selfintegration interop examples test-race install-py-opcua gen check-gen

help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: ## Format, test, integration tests, and build examples
	@echo "Running all: fmt, test, integration, selfintegration, examples"
	@$(MAKE) fmt test integration selfintegration examples

test: ## Run unit tests with race detector
	@echo "Running unit tests (race detector)"
	@go test -count=1 -race ./...

lint: ## Run staticcheck
	@echo "Running staticcheck"
	@staticcheck ./...

lint-ci: ## Run golangci-lint
	@echo "Running golangci-lint"
	@golangci-lint run ./...

fmt: ## Format Go code with go fmt
	@echo "Running go fmt"
	@go fmt ./...

vet: ## Run go vet on project packages
	@echo "Running go vet"
	@go vet ./...

integration: ## Run integration tests (Python client vs Go server)
	@echo "Running integration tests (Python client vs Go server)"
	@go test -count=1 -race -v -tags=integration ./tests/python...

selfintegration: ## Run integration tests (Go client vs in-process server)
	@echo "Running integration tests (Go client vs in-process server)"
	@go test -count=1 -race -v -tags=integration ./tests/go...

interop: ## Run interop tests against opcua-interop adapter images (-tags=interop)
	@echo "Running interop tests (open62541 + Milo adapter images)"
	@go test -tags=interop -v -timeout 600s ./interop/...

examples: ## Build all examples into build/
	@echo "Building examples"
	@go build -o build/ ./examples/...

test-race: ## Run all tests (unit + both integration suites) with race detector
	@echo "Running all tests with race detector (unit + integration)"
	@go test -count=1 -race ./...
	@go test -count=1 -race -v -tags=integration ./tests/python...
	@go test -count=1 -race -v -tags=integration ./tests/go...

coverage: ## Run tests with coverage on core library only (writes coverage.out)
	@echo "Running coverage"
	@go test -count=1 -race -coverprofile=coverage.out -covermode=atomic \
		-coverpkg=$(COVER_PKGS) $(COVER_TEST_PKGS)
	@pct=$$(go tool cover -func=coverage.out | awk '/^total:/ {gsub(/%/,""); print $$3}'); \
	echo "Total coverage: $$pct%"; \
	awk -v p="$$pct" 'BEGIN { if (p+0 < 75) { printf "ERROR: coverage %.1f%% is below 75%% threshold\n", p; exit 1 } }'

cover: coverage ## Open coverage report in browser
	@echo "Opening coverage report"
	@go tool cover -html=coverage.out

install-py-opcua: ## Install Python opcua package (for integration tests)
	@echo "Installing Python opcua package"
	@pip3 install opcua

gen: ## Regenerate code (stringer, go generate)
	@echo "Regenerating code"
	@go generate ./...

check-gen: gen ## Verify generated files are up to date
	@echo "Checking for generation drift"
	@if ! git diff --quiet; then \
		echo "ERROR: Generated files are out of date. Run 'make gen' and commit."; \
		git diff --stat; \
		exit 1; \
	fi

check: fmt lint lint-ci vet test coverage ## Run lint + vet + test
