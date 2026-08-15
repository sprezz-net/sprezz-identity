# Variables
BINARY_NAME=sprezz-identity
COVERAGE_FILE=coverage.out

# Include the environment file and export its variables to the shell session
-include .env
export

.PHONY: all tidy sqlc-check fmt lint test cover clean run build

# Default target runs code generation and verification to guarantee a pristine repository state
all: tidy sqlc-gen templ-gen mock-gen fmt lint test

## tidy: Run go mod tidy to add missing and prune unused modules
tidy:
	@echo "=> Optimizing go.mod and go.sum..."
	go mod tidy

## sqlc-gen: Compile SQL schema definitions and annotations into type-safe Go source code
SQL_QUERIES=$(wildcard internal/adapters/out/postgres/query/*.sql)
SQL_SCHEMA=$(wildcard internal/adapters/out/postgres/migrations/*.sql)
SQLC_TIMESTAMP=internal/adapters/out/postgres/db/.sqlc.gen.timestamp
SQLC_CONFIG=sqlc.yaml

$(SQLC_TIMESTAMP): $(SQLC_SOURCES)
	@echo "=> Compiling query layer using sqlc code generator..."
	@if command -v sqlc > /dev/null; then \
		sqlc generate; \
	else \
		echo "ERROR: sqlc command not found. Install it via 'brew install sqlc'."; \
		exit 1; \
	fi
	@touch $(SQLC_TIMESTAMP)

sqlc-gen: $(SQLC_TIMESTAMP)

## sqlc-check: Validate that generated database files are perfectly synced with queries on disk
sqlc-check:
	@echo "=> Verifying sqlc generation up-to-date state..."
	@if command -v sqlc > /dev/null; then \
		sqlc diff; \
	else \
		echo "ERROR: sqlc command not found. Run 'brew install sqlc'."; \
		exit 1; \
	fi

## templ-gen: Compile templ templates into Go source code
TEMPL_SOURCES=$(shell find internal/views -name "*.templ")
TEMPL_TIMESTAMP=internal/views/.templ.gen.timestamp

$(TEMPL_TIMESTAMP): $(TEMPL_SOURCES)
	@echo "=> Compiling templ templates..."
	@if command -v templ > /dev/null; then \
		templ generate; \
	else \
		echo "ERROR: templ command not found. Install it via 'go install github.com/a-h/templ/cmd/templ@latest'"; \
		exit 1; \
	fi
	@touch $(TEMPL_TIMESTAMP)

templ-gen: $(TEMPL_TIMESTAMP)

## mock-gen: Generate type-safe mocks for domain ports using minimock
PORT_SOURCES=$(wildcard internal/domain/port/*.go) internal/domain/port/portmock/gen.go
MOCK_TIMESTAMP=internal/domain/port/portmock/.minimock.gen.go.timestamp

$(MOCK_TIMESTAMP): $(PORT_SOURCES)
	@echo "=> Generating port mocks using minimock..."
	go generate -run="go run" ./internal/domain/port/portmock/gen.go
	@touch $(MOCK_TIMESTAMP)

mock-gen: $(MOCK_TIMESTAMP)

## fmt: Automatically format all code files according to standard styles
fmt:
	@echo "=> Formatting source tree code..."
	go fmt ./...

## lint: Execute the golangci-lint engine for architectural validations
lint:
	@echo "=> Running golangci-lint audit tree checks..."
	@if command -v golangci-lint > /dev/null; then \
		golangci-lint run ./...; \
	else \
		echo "WARNING: golangci-lint is not installed. Run 'brew install golangci-lint'."; \
		exit 1; \
	fi

## test: Run the entire unit and integration testing harness suite
test: tidy sqlc-gen templ-gen mock-gen
	@echo "=> Running all package test specifications..."
	go test -v -race ./...

## cover: Generate line-by-line profiling data and launch interactive HTML visual report
cover:
	@echo "=> Capturing cross-package test coverage statistics..."
	go test -coverprofile=$(COVERAGE_FILE) -coverpkg=./... ./...
	@echo "=> Detailed statement summary matrix:"
	go tool cover -func=$(COVERAGE_FILE)
	@echo "=> Opening interactive coverage visualization in your web browser..."
	go tool cover -html=$(COVERAGE_FILE)

## build: Compile the core program binary into a transport target
build: tidy sqlc-gen templ-gen
	@echo "=> Building system production binary..."
	go build -o $(BINARY_NAME) cmd/sprezz-identity/main.go

## run: Build and launch the multi-tenant application container engine immediately
run: build
	@echo "=> Bootstrapping Sprezz server runtime..."
	./$(BINARY_NAME)

## clean: Evict transient profiling outputs and temporary compiled targets
clean:
	@echo "=> Evicting build targets and coverage profiles..."
	rm -f $(BINARY_NAME)
	rm -f $(SQLC_TIMESTAMP) $(TEMPL_TIMESTAMP) $(MOCK_TIMESTAMP)
	rm -f $(COVERAGE_FILE)
