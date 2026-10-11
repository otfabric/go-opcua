# Bucket B decisions (post–gap-closure waves)

Counts from `go run ./internal/cmd/render-interop-coverage -summary`.

## Publication

opcua-interop **v0.6.0** published:
https://github.com/otfabric/opcua-interop/releases/tag/v0.6.0

Pinned digests (multi-arch indexes) in `harness_test.go` / CI:

| Image | Digest |
|---|---|
| open62541 | `sha256:d8cdfd67c9dd71713515fdf0e34533d7ff9f6d004bd5c7ceb349db40e325a1f2` |
| milo | `sha256:95ad873ff5ae86a35815a1c6db2b75963675040f3283307e57ac10273194ab3f` |

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

## Deferred (outside current core parity claim)

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
