# Testing go-opcua

How to run each tier. How to work with the suites: [CONTRIBUTING.md](CONTRIBUTING.md#running-tests). Peers, images and the full interop setup: [INTEROP.md](INTEROP.md).

## Tiers

| Tier | Command | Prerequisites | In CI |
|---|---|---|---|
| Unit, API | `make test` | none | yes, Go 1.26 and 1.27, with `-race`; `server`, `uafx/fxcm` and `uafx/fxserver` in the `server` job |
| Crash | the `TestCrash` tests of `uafx/fxserver` and `uafx/fxcm`, part of `make test`: a subprocess on a FileStore killed at each failure window, then restarted | none | yes |
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

Two gates. `make coverage` measures `COVER_PKGS`, conformance tests included, and fails below 90; the `coverage-merged` job of `.github/workflows/ci.yml` requires `COVERAGE_MIN` (94, `make coverage-merged-check`) on the merged profile of the shared jobs and the `server` job, with the same `coverpkg`. `make coverage-pkg-check` requires `COVER_PKG_MIN` (90) per library package, generated code excluded. `cmd/`, `examples/`, `tests/`, `interop/`, `chaos/` and `conformance/` are test or tool code and are not library packages.

## Fixtures of parallel tests

Register the cleanup of a server, client or Manager with `cleanup.Register(t, f)` (`internal/testutil/cleanup`), not `t.Cleanup(f)`. The testing package keeps a parallel test, and the cleanup functions it registered, until its parent test ends, which for a top-level test is the end of the binary: a cleanup that closes a server keeps the closed server reachable until then. `Register` lets go of `f` once it has run. With `t.Cleanup`, the live heap of `uafx/fxcm` reached 5.8 GB and that of `uafx/fxserver` 5.1 GB; with `Register` it peaks at 330 MB and 470 MB, that of `server` at 194 MB (602 MB) and that of `gds/gdsserver` at 163 MB (856 MB).

## Fuzz regressions

A failing input is written to `testdata/fuzz/<target>/` of the package. Commit it with the fix: `go test` replays it from then on.

## When CI runs

| Event | Workflow | What runs |
|---|---|---|
| Pull request | `pr.yml` | `docs.yml` (docsync, otfabric-policy) always; `ci.yml`, `interop.yml` unless every changed file is documentation; then `OT Fabric Required Checks` |
| Push to a branch | none | nothing; dispatch `ci.yml`, `interop.yml` to test a branch without a pull request |
| Push to `main` | `docs.yml` | the light checks; the merged commit was tested as the pull request's merge commit |
| Schedule | `schema-check.yml` | the scheduled runs, on `main` |
| Release | `release.yml` | the release workflow tests the release commit again |

Documentation means an added or modified `*.md` file outside `.github/`, `testdata/` and `vendor/`, other than `AGENTS.md` and `CLAUDE.md`. A deleted or renamed document, or any other file, runs everything. `OT Fabric Required Checks` fails unless every job that applies succeeded; its summary lists them.
