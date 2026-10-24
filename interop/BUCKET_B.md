# Bucket B decisions (post–gap-closure waves)

Counts from `go run ./internal/cmd/render-interop-coverage -summary`.

## Publication

opcua-interop **v0.8.2** published:
https://github.com/otfabric/opcua-interop/releases/tag/v0.8.2
(release run https://github.com/otfabric/opcua-interop/actions/runs/40055105259)

Pinned digests (multi-arch indexes) in `harness_test.go` / CI:

| Image | Digest |
|---|---|
| open62541 | `sha256:e035d07896a650a820a552e778202bc847c78855ff3d4ae0de1f172606d48866` |
| milo | `sha256:2d84fa47b67d785fe84ebeb3e4d41ec75841e459fd43fd689bf45c1fddc9a15e` |

## Promoted on published v0.5.0

| Item | Directions |
|---|---|
| `discovery.find-servers` | O→S, M→S (C→ already verified) |
| `translate.browse-path` | O→S, M→S (C→ already verified) |
| Event subscription / decode / BaseEvent select | C→O, C→M |
| `event.filter.of-type` | all four |
| `event.filter.severity-threshold` | all four |
| `history.read.raw` | C→O, C→M (O→S/M→S already verified) |
| `history.read.continuation` | O→S, M→S (`--scenario continue`) |

## Completed without new fixture work

| Item | Status |
|---|---|
| Milo EncodingMask (strict BadWriteNotSupported) | `unsupported` C→M |
| Milo Republish / TransferSubscriptions service path | `verified` C→M |
| Stack-neutral TCP reconnect recovery | `verified` C→O and C→M (`recreated`) |
| `event.emission.custom` | `deferred` |
| Broad `event.filter.where-clause` | `deferred` (narrow severity/of-type instead) |
| C→ history continuation | `deferred` (optional; not required this pass) |

## Deferred at that point (outside the core parity claim; see "Still deferred after v0.7.0")

Advanced HA, NodeSet2, custom-type peer fixture, Query, NodeManagement,
IssuedIdentityToken, A&C, LDS, general WhereClause expression surface, custom
event models. See `GAPS.md` — not a backlog for this pass.

## Promoted on published v0.6.0 (open62541 v1.5.9 / Milo 1.1.8)

Uses the v0.6.0 adapter surface: client ops `register-nodes`, `node-management`,
and the global `--channel-lifetime-ms` flag.

| Item | Directions |
|---|---|
| `security.channel.renewal` | all four |
| `history.read.continuation` | C→O, C→M (C→M paging only — Milo SDK does not surface release) |
| `view.register-nodes` (new row) | all four |
| `nodemgmt.add-nodes`, `nodemgmt.delete-nodes` | C→O, O→S, M→S; C→M `unsupported` |
| `subscription.modify`, `monitoreditem.modify` (new rows) | C→O, C→M |
| `subscription.publishing-mode`, `monitoreditem.monitoring-mode` (new rows) | all four |
| `event.filter.where-clause` | C→O, C→M (comparison operators, positive + negative) |
| `event.queue-overflow` | C→O, C→M (EventQueueOverflowEventType ahead of the queued events) |

## Promoted on opcua-interop v0.7.0 (open62541 v1.5.9 / Milo 1.1.8)

Uses the v0.7.0 adapter surface: client ops `codec`, `find-servers-on-network`,
`register-server`; `subscribe --deadband-absolute / --deadband-percent /
--trigger`; `--reverse-listen` / `--reverse-connect`; ECC security profiles and
`--ecc-dir`; `--lds`, `--mdns-name`, `--register-with`; the fixture's
`Analog.Level` / `Analog.Setpoint` AnalogItems. Ledger: 231 → 341 verified,
336 → 516 rows (45 new capabilities).

| Item | Directions |
|---|---|
| `monitoreditem.deadband`, `.trigger`, `.sampling-interval`, `.percent-deadband` (new rows) | all four |
| `security.ecc-nistp256.*`, `security.ecc-nistp384.*` — sign, sign-encrypt, subscription, username.valid / .invalid, renewal (12 new rows) | C→O, O→S; Milo `unsupported` (no ECC policy) |
| `security.ecc-nistp256-aesgcm.*`, `security.ecc-nistp256-chachapoly.*`, `security.ecc-curve25519.*` — sign-encrypt, write, subscription, username.valid / .invalid, renewal (18 new rows) | C→O, O→S; Milo `unsupported` |
| `security.ecc.unimplemented-policy` (new row; brainpoolP256r1, brainpoolP384r1, curve448) | C→O, O→S; Milo `unsupported` |
| `transport.reverse-connect`, `.subscription`, `.secure` (new rows) | C→O, O→S; Milo `unsupported` (no ReverseHello) |
| `encoding.json.variant`, `encoding.xml.variant` (new rows) | all four |
| `encoding.json.datavalue` (new row) | C→O, O→S, M→S; C→M `unsupported` (Milo decodes only its nested form) |
| `encoding.xml.datavalue` (new row) | C→M, M→S; C→O / O→S `unsupported` (open62541 has no XML DataValue) |
| `discovery.lds-registration` (was deferred) | C→O, O→S, M→S; C→M `unsupported` (Milo is no LDS) |
| `discovery.find-servers-on-network` (was deferred) | C→O, O→S, M→S; C→M `unsupported` |
| `discovery.register-server` (new row) | O→S, M→S; C→ `not-applicable` (the go-opcua registrant is `discovery.lds-registration`) |
| `discovery.register-server2.mdns` (new row) | C→O, O→S, M→S; C→M `unsupported` |
| `discovery.multicast` (new row) | C→O, O→S; Milo `unsupported` (no mDNS) |

Tightened: `subscription.publishing-mode` O→S / M→S assert the exact `[3,4,5]`
window again (the adapters now request SamplingInterval 0).

Direction columns for capabilities that are not "a client calls a server"
(codec, registration, mDNS, reverse connect) are explained in the capability
titles in `capabilities.json` / `COVERAGE.md`.

## Still deferred after v0.7.0

Advanced HA, NodeSet2, custom-type peer fixture, Query, IssuedIdentityToken,
A&C, GDS, general WhereClause expression surface, custom event models,
HistoryRead modified / at-time / processed, HistoryUpdate, certificate chains
and CRLs, secured LDS registration against a peer LDS, the ECC policies
go-opcua does not implement (brainpoolP256r1, brainpoolP384r1, curve448).
