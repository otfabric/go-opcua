# Bucket B decisions (post–gap-closure waves)

Counts from `go run ./internal/cmd/render-interop-coverage -summary`.

## Publication

opcua-interop **v0.5.0** published:
https://github.com/otfabric/opcua-interop/releases/tag/v0.5.0

Pinned digests (multi-arch indexes) in `harness_test.go` / CI:

| Image | Digest |
|---|---|
| open62541 | `sha256:53c7a184ca9769bab87c6b5335c01322925411894368644913133c0812999283` |
| milo | `sha256:c462f45a5e9b9ce8878788b97c77973832b23861e7ae5d0c6642279f798c15cf` |

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
