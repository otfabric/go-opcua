# Feature status

What go-opcua implements and how each area is verified. Status: v1.29.1, interop ledger pinned to opcua-interop v0.17.0. The sources of truth are the service matrix in the [README](../README.md#service-support-matrix) and the ledger [interop/COVERAGE.md](../interop/COVERAGE.md); this page summarises them per area. What is out of scope or unverified is in [LIMITATIONS.md](../LIMITATIONS.md).

Nothing here is a conformance claim: no OPC Foundation certification has been attempted.

## Versions and platforms

| Item | Status |
|---|---|
| Go | 1.26 or later; CI runs 1.26 and 1.27 |
| Tested in CI | Linux amd64, with the race detector; real AF_PACKET sockets on a veth pair for the Ethernet PubSub transport |
| Other platforms | `make cross` builds them; no test runs there |
| Real mDNS multicast | Verified on Linux only |

## How to read the table

The columns count ledger capabilities against open62541 and Eclipse Milo, the two peers of `interop/coverage.json`. A capability counts for **Client** when go-opcua's client has a verified direction against either peer, and for **Server** when either peer's client has one against go-opcua's server. **Not verified** counts capabilities with no verified direction there: the peers cannot exercise them, or they are deferred. Go-to-Go tests never count. async-opcua, UA-.NETStandard, node-opcua and asyncua keep ledgers of their own in `interop/testdata/ledger-*.json`; totals per peer are in the [README](../README.md#interop-evidence).

| Area | Capabilities | Client verified | Server verified | Not verified |
|---|---:|---:|---:|---:|
| Alarms and conditions | 11 | 2 | 11 | 0 |
| Attribute services | 15 | 15 | 15 | 0 |
| Browse | 7 | 7 | 7 | 0 |
| Certificate management (GDS) | 16 | 5 | 16 | 0 |
| Custom types | 2 | 0 | 0 | 2 |
| Diagnostics | 2 | 1 | 1 | 1 |
| Discovery | 8 | 6 | 8 | 0 |
| Encoding | 6 | 5 | 6 | 0 |
| Events | 9 | 7 | 5 | 1 |
| History | 12 | 2 | 7 | 5 |
| Information model | 1 | 0 | 0 | 1 |
| Method | 2 | 2 | 2 | 0 |
| Node management | 4 | 4 | 2 | 0 |
| PubSub | 34 | 29 | 28 | 5 |
| Query | 2 | 0 | 0 | 2 |
| Security | 60 | 57 | 57 | 3 |
| Session | 2 | 2 | 2 | 0 |
| Subscriptions | 21 | 17 | 13 | 0 |
| Transport | 8 | 4 | 3 | 4 |
| View | 2 | 2 | 2 | 0 |
| **Total** | **224** | **167** | **185** | **24** |

These counts are a snapshot of `interop/COVERAGE.md`; when they differ, the ledger is right. A row counted as not verified is not necessarily missing: the per-row reason is in the ledger and in [interop/GAPS.md](../interop/GAPS.md), and the other peers may verify it.

## Test evidence

| Level | Where |
|---|---|
| Unit and service | `go test` per package; 90 % per library package, `make coverage-pkg-check` |
| Conformance (Go to Go) | `conformance/` |
| Chaos and parallelism | `chaos/`, CI job `chaos` |
| Fuzz | `make fuzz`, every target in CI |
| Independent stacks | `interop/`: open62541, Milo, async-opcua, UA-.NETStandard, node-opcua, asyncua, all in every interop run ([INTEROP.md](../INTEROP.md)) |
