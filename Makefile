# Self-documented Makefile (https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html)
# Run 'make' or 'make help' to list targets.

.DEFAULT_GOAL := help

# Core library packages measured by `make coverage` (excludes cmd/, examples/, tests/).
TEST_PKGS := . ./ua/ ./uacp/ ./uasc/ ./uapolicy/ ./server/ ./monitor/ ./errors/ ./id/ ./internal/stats/ ./internal/mdns/ ./pubsub/ ./pubsub/uadp/ ./pubsub/jsonmsg/ ./pubsub/transport/ ./pubsub/transport/udp/ ./pubsub/transport/mqtt/ ./pubsub/transport/amqp/ ./pubsub/security/ ./pubsub/sks/ ./pubsub/remote/ ./internal/mqtt/ ./internal/amqp/
COVER_PKGS := github.com/otfabric/go-opcua,github.com/otfabric/go-opcua/ua,github.com/otfabric/go-opcua/uacp,github.com/otfabric/go-opcua/uasc,github.com/otfabric/go-opcua/uapolicy,github.com/otfabric/go-opcua/server,github.com/otfabric/go-opcua/monitor,github.com/otfabric/go-opcua/errors,github.com/otfabric/go-opcua/id,github.com/otfabric/go-opcua/internal/stats,github.com/otfabric/go-opcua/internal/mdns,github.com/otfabric/go-opcua/pubsub,github.com/otfabric/go-opcua/pubsub/message,github.com/otfabric/go-opcua/pubsub/uadp,github.com/otfabric/go-opcua/pubsub/jsonmsg,github.com/otfabric/go-opcua/pubsub/transport,github.com/otfabric/go-opcua/pubsub/transport/udp,github.com/otfabric/go-opcua/pubsub/transport/mqtt,github.com/otfabric/go-opcua/pubsub/transport/amqp,github.com/otfabric/go-opcua/pubsub/security,github.com/otfabric/go-opcua/pubsub/sks,github.com/otfabric/go-opcua/pubsub/remote,github.com/otfabric/go-opcua/internal/mqtt,github.com/otfabric/go-opcua/internal/amqp
COVER_TEST_PKGS := $(TEST_PKGS) ./conformance/

.PHONY: help all test test-norace coverage cover lint lint-ci vuln fmt vet verify integration selfintegration interop interop-shard chaos examples test-race install-py-opcua gen check-gen coverage-ledger coverage-gate

help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: ## Format, test, integration tests, and build examples
	@echo "Running all: fmt, test, integration, selfintegration, examples"
	@$(MAKE) fmt test integration selfintegration examples

test-norace: ## Run unit tests without race detector
	@echo "Running unit tests"
	@go test -count=1 ./...

test: ## Run unit tests with race detector
	@echo "Running unit tests (race detector)"
	@go test -count=1 -race ./...

lint: ## Run staticcheck
	@echo "Running staticcheck"
	@staticcheck ./...

lint-ci: ## Run golangci-lint
	@echo "Running golangci-lint"
	@golangci-lint run ./...

vuln: ## Run govulncheck
	@echo "Running govulncheck"
	@govulncheck ./...

fmt: ## Format Go code with go fmt
	@echo "Running go fmt"
	@go fmt ./...

vet: ## Run go vet on project packages
	@echo "Running go vet"
	@go vet ./...

# Core local/CI gate: unit, race, vet, and interop (requires Docker + pinned images).
verify: vet test-norace test interop ## go vet + unit + race + interop

integration: ## Run integration tests (Go client vs FreeOpcUa Python server)
	@echo "Running integration tests (Go client vs FreeOpcUa Python server)"
	@go test -count=1 -race -v -tags=integration ./tests/python...

selfintegration: ## Run integration tests (Go client vs in-process Go server)
	@echo "Running integration tests (Go client vs in-process Go server)"
	@go test -count=1 -race -v -tags=integration ./tests/go...

interop: ## Run interop tests against opcua-interop adapter images (-tags=interop)
	@echo "Running interop tests (open62541 + Milo adapter images)"
	# Suite is ~10m locally / slower on CI GHA runners; keep headroom under the
	# workflow job timeout-minutes (45). Do not use 600s — it flakes at the edge.
	@go test -count=1 -tags=interop -timeout 45m ./interop/...

# One of SHARDS slices of the interop tests (SHARD = 1..SHARDS), for parallel
# CI jobs: the top-level tests are sorted by name and dealt out round-robin,
# so related (and similarly slow) tests land on different shards.
SHARDS ?= 1
SHARD  ?= 1
interop-shard: ## Run shard SHARD of SHARDS of the interop tests (e.g. SHARD=2 SHARDS=6)
	@tests=$$(go test -tags=interop -list '.*' ./interop/ | grep '^Test' | sort \
		| awk -v n=$(SHARDS) -v i=$(SHARD) '(NR - 1) % n == i - 1' | paste -sd'|' -); \
	if [ -z "$$tests" ]; then echo "interop shard $(SHARD)/$(SHARDS): no tests"; exit 0; fi; \
	echo "interop shard $(SHARD)/$(SHARDS): $$(echo "$$tests" | tr '|' '\n' | wc -l | tr -d ' ') tests"; \
	go test -v -count=1 -tags=interop -timeout 45m -run "^($$tests)$$" ./interop/

# Chaos-monkey and parallelism suites: chaos/ and its sub-packages secure,
# datachange, reverse, discovery and codec (see chaos/doc.go). They also run, with a
# short fault-injection phase, as part of `make test`. Override the knobs on
# the command line, e.g. `make chaos CHAOS_DURATION=10m CHAOS_SEED=42`.
CHAOS_DURATION ?= 30s
chaos: ## Run the chaos-monkey and parallelism suites with the race detector (CHAOS_DURATION, CHAOS_SEED)
	@echo "Running chaos suites (CHAOS_DURATION=$(CHAOS_DURATION))"
	@CHAOS_DURATION=$(CHAOS_DURATION) CHAOS_SEED=$(CHAOS_SEED) go test -race -count=1 -timeout 60m ./chaos/...

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
	awk -v p="$$pct" 'BEGIN { if (p+0 < 90) { printf "ERROR: coverage %.1f%% is below 90%% threshold\n", p; exit 1 } }'

# Every library package must reach COVERAGE_MIN percent on its own, generated
# code excluded (internal/cmd/coverage-gate). The coverage of a package counts
# what any test in the module exercises (conformance and chaos included).
COVERAGE_MIN ?= 90
LIB_PKGS = $(shell go list ./... | grep -Ev '/(cmd|examples|tests|interop|chaos|conformance)(/|$$)|/internal/(testutil|cmd)(/|$$)')
coverage-gate: ## Per-package coverage gate: every library package >= COVERAGE_MIN% (generated code excluded)
	@echo "Running coverage gate (min $(COVERAGE_MIN)% per package)"
	@go test -count=1 -timeout=600s -covermode=atomic -coverprofile=coverage-gate.out \
		-coverpkg=$$(echo $(LIB_PKGS) | tr ' ' ',') $$(go list ./... | grep -Ev '/(cmd|examples)(/|$$)')
	@go run ./internal/cmd/coverage-gate -profile coverage-gate.out -min $(COVERAGE_MIN)

cover: coverage ## Open coverage report in browser
	@echo "Opening coverage report"
	@go tool cover -html=coverage.out

install-py-opcua: ## Install Python opcua package (for integration tests)
	@echo "Installing Python opcua package"
	@pip3 install opcua

gen: ## Regenerate code (stringer, go generate)
	@echo "Regenerating code"
	@go generate ./...

coverage-ledger: ## Validate and regenerate interop/COVERAGE.md from coverage.json
	@echo "Rendering interop coverage ledger"
	@go run ./internal/cmd/render-interop-coverage
	@go test -count=1 ./interop -run TestCoverageManifestValid

check-gen: gen ## Verify generated files are up to date
	@echo "Checking for generation drift"
	@if ! git diff --quiet; then \
		echo "ERROR: Generated files are out of date. Run 'make gen' and commit."; \
		git diff --stat; \
		exit 1; \
	fi

check: fmt lint lint-ci vuln verify coverage ## Run lint + vet + vuln + unit/race/interop + coverage
