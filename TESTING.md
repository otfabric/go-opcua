# Testing go-opcua

How to run each tier. How to work with the suites: [CONTRIBUTING.md](CONTRIBUTING.md#running-tests). Peers, images and the full interop setup: [INTEROP.md](INTEROP.md).

## Tiers

| Tier | Command | Prerequisites | In CI |
|---|---|---|---|
| Unit, API | `make test` | none | yes, Go 1.26 and 1.27, with `-race` |
| End-to-end | `make e2e` (alias of `make selfintegration`): Go client against the in-process Go server | none | no |
| Integration | `make integration`: Go client against the FreeOpcUa Python server | Python 3.11 or later, `make install-py-opcua` | no |
| Conformance | `./conformance/...`, part of `make coverage` | none | yes |
| Chaos, parallelism | `make chaos` (`CHAOS_DURATION`, default 30s; `CHAOS_SEED`) | none | yes, `chaos` job |
| Fuzz | `make fuzz` (`FUZZTIME`, default 10s; targets discovered) | none | yes, 10s per target, about 16 minutes in all |
| Benchmarks | `make bench` | none | no |
| Interop | `make interop`, `make interop-shard SHARD=n SHARDS=m` | Docker | Interop workflow |
| Cross-compile | `make cross` | none | no |
| Generated code | `make check-gen` | none | yes, `gen-drift` job |

`go test ./...` does not run the tiers behind the `integration` and `interop` build tags.

## Environment variables

| Variable | Effect |
|---|---|
| `CHAOS_DURATION`, `CHAOS_SEED` | Length of the chaos phase; replays a printed seed |
| `OPCUA_INTEROP_REQUIRE_CAPABILITIES=1` | Fails instead of skipping when an image lacks a capability |
| `GO_OPCUA_ETH_REQUIRE=1` | Turns the skips of the real Ethernet tests into failures |

The interop images and PKI variables are listed in [INTEROP.md](INTEROP.md#environment-variables).

## Coverage

Two gates. `make coverage` measures `COVER_PKGS`, conformance tests included, and fails below 90; `.github/workflows/ci.yml` requires 94 with the same `coverpkg`. `make coverage-pkg-check` requires `COVER_PKG_MIN` (90) per library package, generated code excluded. `cmd/`, `examples/`, `tests/`, `interop/`, `chaos/` and `conformance/` are test or tool code and are not library packages.

## Fuzz regressions

A failing input is written to `testdata/fuzz/<target>/` of the package. Commit it with the fix: `go test` replays it from then on.
