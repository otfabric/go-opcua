# AGENTS.md — go-opcua

## What this is

Pure Go OPC UA client and server library: secure channels, sessions, subscriptions, history, discovery, alarms, GDS and PubSub (`pubsub/`). Profile: **protocol-library**. Nothing is certified by the OPC Foundation; independently verified capabilities are in the interop ledgers.

## Organisation standards

This repository follows **otfabric/engineering policy 1.1**, profile **protocol-library** (`.otfabric/policy.yaml`, mode `enforce`). Where this file and the organisation standards disagree, this file wins here: say so in your report.

## Where the truth lives

| Question | Source |
|---|---|
| Wire behaviour | OPC UA Parts as cited in the code and docs/; ECC deviations in docs/interop-gaps.md |
| What is verified against independent stacks | INTEROP.md, `interop/coverage.json` and `interop/COVERAGE.md` (`make coverage-ledger`), `interop/GAPS.md` |
| Scope not implemented, peer deviations, workarounds | LIMITATIONS.md, docs/interop-gaps.md |
| Security configuration | docs/security.md |
| Design | docs/architecture.md |
| Errors | ERRORS.md |
| Release history | RELEASE.md (`## vX.Y.Z` … `---`) |

## Hard rules

1. Never lower `COVER_PKG_MIN` (90 per library package, `make coverage-pkg-check`), the 90 % gate of `make coverage`, or `coverage-min` in `.github/workflows/ci.yml`. No new lint suppressions, and do not skip or delete tests to make CI pass.
2. Generated files come from `make gen`; `make check-gen` fails on drift. Do not edit them by hand. `interop/COVERAGE.md` and `interop/GAPS.md` are rendered from the ledger.
3. Never invent protocol semantics: cite the Part and clause.
4. Interop claims only from a test recorded in the ledger, against the pinned opcua-interop release.
5. No incidental breaking changes to exported API; this library stays on v0 or v1.
6. `chaos/` stays out of the shared race job: it starves timing-sensitive tests (see `.github/workflows/ci.yml`).

## Commands

| When you change… | Run |
|---|---|
| anything | `make check` (needs Docker: it runs `make interop`) |
| without Docker | `make vet test coverage-pkg-check` |
| reconnect, subscriptions, concurrency | `make chaos` |
| generated code inputs | `make check-gen` |
| interop-relevant behaviour | `make interop` (Docker), then `make coverage-ledger` |
| PubSub over Ethernet | the `pubsub-eth` CI job (`GO_OPCUA_ETH_REQUIRE=1`, needs root) |

## Definition of Done

Tests for new behaviour, including error paths; a fuzz target for a new decoder of untrusted input; docs updated in the same change; RELEASE.md section for user-visible changes.

## Git and releases

Branches and PRs. Do not push to `main`, tag or run the Release workflow unless the maintainer asks in the session.
