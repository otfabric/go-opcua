# Contributing to otfabric/go-opcua

Thank you for your interest in contributing. This document explains how to get started.

## Development setup

- **Go**: 1.25 or later.
- **Python**: 3.11+ (optional, for integration tests against the Python client).

```sh
git clone https://github.com/otfabric/go-opcua.git
cd opcua
go mod download
```

## Running tests

- **Unit and API tests**: `make test` (runs tests with race detector).
- **Coverage**: `make coverage` to generate `coverage.out`; `make cover` to view the report in the browser.
- **Integration tests** (tag-gated; require a running server or Python client):
  - `make integration` — Python client vs Go server.
  - `make selfintegration` — Go client vs in-process server.

By default, `go test ./...` does not run integration tests; use the targets above.

## Code style and linting

- Format code: `make fmt` (gofmt).
- Lint: `make lint` (staticcheck) and `make lint-ci` (golangci-lint; install with `go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest`).

Please run `make fmt` and `make lint` before submitting a PR.

## Submitting changes

1. Open an issue or pick an existing one to discuss the change.
2. Fork the repo, create a branch, and make your changes.
3. Add or update tests as needed.
4. Run `make test`, `make lint`, and (if applicable) `make integration` / `make selfintegration`.
5. Open a pull request with a clear description and reference to the issue.

## Error handling

Prefer sentinel errors from `errors/sentinel.go` and wrap with `%w` so callers can use `errors.Is` / `errors.As`. Avoid the deprecated `errors.New` in the `errors` package for new code.

## Documentation

When you change **public API signatures** (function parameters, return types, or exported types), update:

- **[API.md](API.md)** — keep function and type signatures in sync.
- **docs/*.md** — update any examples or prose that show the old signature (e.g. [docs/architecture.md](docs/architecture.md) for handler types, [docs/server-guide.md](docs/server-guide.md) and [docs/client-guide.md](docs/client-guide.md) for usage).
- **[README.md](README.md)** — if it references the changed API.

Also keep doc comments on exported symbols in sync with behavior.
