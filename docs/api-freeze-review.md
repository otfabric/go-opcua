# Public API freeze review (v1.3.0)

Focused review of the surface added or expanded through v1.3.0.
Goal: freeze the public API before more protocol features; prefer documentation
and small consistency fixes over new services.

## Verdict

The v1.3.0 client surface is largely coherent: subscription mutation APIs return
full `ua.*Response` types, recovery is observe-only, and history is pluggable via
small optional interfaces. Freeze now. Treat the items below as the only API
debt worth clearing before Query / NodeManagement / A&C.

## Consistency matrix

| Area | Pattern | Assessment |
|---|---|---|
| `Subscription.Monitor` / `Unmonitor` / `Modify*` / `Set*` | Full `ua.*Response` + `error` | Idiomatic; keep |
| `Client.Republish` / `TransferSubscriptions` | Full `ua.*Response` + `error` | Idiomatic; keep |
| `Client.Subscribe` | Simplified `*Subscription` | Intentional helper; document that raw CreateSubscription is via `Send` |
| `WithSubscriptionRecoveryHandler` | Sync callback, no return | Matches `WithConnStateHandler`; keep |
| `server.HistoryProvider` + optional interfaces | Minimal capability slices | Good; keep |
| `ua.RegisterExtensionObject` | Global registry | Fine; `TypeRegistry` stays advanced |
| Auth validators | `func(...) error` options | Minimal and clear |

## Findings

### 1. Names — mostly idiomatic

- `Monitor` / `Unmonitor` match common client SDKs; keep.
- Recovery outcomes (`transferred`, `republished`, `recreated`, …) are clear strings; keep as `SubscriptionRecoveryOutcome`.
- Prefer not renaming `Subscribe` to `CreateSubscription` — that would imply a full-response API that does not exist.

**Freeze action:** Document in `API.md` that `Subscribe` is the ergonomic CreateSubscription path; callers needing the raw response use `Client.Send` with `ua.CreateSubscriptionRequest`.

### 2. Full protocol responses — nearly consistent

Full responses today: Monitor, Unmonitor, Modify*, SetMonitoringMode, SetTriggering, SetPublishingMode, Republish, TransferSubscriptions.

Simplified: `Subscribe` → `*Subscription`.

**Freeze action:** Do **not** add a second public CreateSubscription helper unless it returns `*ua.CreateSubscriptionResponse`. One pattern per operation.

### 3. Interfaces — minimal enough

`HistoryProvider` + optional `HistoryDataUpdater` / `*HistoryReader` / `*HistoryDeleter` interfaces are the right shape (capability detection by type assert).

`EventEmitter` is thin and unused outside `Server` — acceptable freeze debt; do not expand.

### 4. Context and errors — consistent

Subscription and recovery entry points take `context.Context` and return `error` for transport/session failures; per-item StatusCodes live in the response. Keep that split.

### 5. Recovery callbacks — documented but easy to misuse

`WithSubscriptionRecoveryHandler` is called **synchronously from the reconnect goroutine** and **must not block**. That is correct for observability, but a slow handler stalls recovery for all subscriptions.

**Freeze actions:**

1. Keep the sync contract (do not switch to async without a version bump).
2. Stress-test that a blocking handler delays subsequent `notifyRecovery` calls (see `subscription_lifecycle_stress_test.go`).
3. Docs already warn; reinforce in examples that handlers should only enqueue work.

Manual `Republish` / `TransferSubscriptions` correctly do **not** emit recovery events (only automatic reconnect does). Keep that distinction.

### 6. Exported implementation details

| Export | Recommendation |
|---|---|
| `server.EventMonitoredItem` | Freeze as-is for now; prefer unexporting in a future major if no external users |
| `ua.TypeRegistry` | Keep; advanced but legitimate |
| Unexported `Subscription` fields (`nextSeq`, item maps) | Correct — do not export |

### 7. Explicit non-goals until freeze lifts

- Query / NodeManagement / IssuedIdentityToken / A&C public APIs
- Changing `Subscribe` return type
- Making recovery handlers async
- Expanding `HistoryProvider` with event-history methods

## Freeze checklist

- [x] Review completed (`docs/api-freeze-review.md`)
- [ ] No new exported APIs without updating this doc
- [x] Reliability stress coverage for recovery/lifecycle (`subscription_lifecycle_stress_test.go`, `client_reconnect_recovery_test.go`, `server/historian_ext_test.go`, `uasc/sequence_rollover_test.go`)
- [x] Parser fuzz coverage expanded (`ua/fuzz_test.go`, `uasc/fuzz_test.go`, `uacp/fuzz_test.go`)
- [x] README interop claim points at `interop/COVERAGE.md` without certification language
