# Plan: Remove underscore names from generated code

**Target release:** v0.2.0 (breaking change — pre-1.0, acceptable)
**Tracking issue:** TBD

## Problem

The `.golangci.yml` has one remaining exclusion: `ST1003` (Go naming convention:
no underscores) is suppressed for `_gen.go` and `schema/` files. This hides
~13,500 exported constants and a handful of struct fields/status codes that use
underscores inherited verbatim from the OPC UA spec CSVs.

## Root cause

The code generators (`cmd/id`, `cmd/status`, `cmd/service`) run names through
`goname.Format()` which fixes Go abbreviations (`Id`→`ID`, `Xml`→`XML`) but
**does not convert underscores to CamelCase**. The OPC Foundation spec files use
underscores as hierarchical separators:

```
ServerType_ServerArray,2005,Variable          → const ServerType_ServerArray = 2005
GoodEdited_DependentValueChanged,0x01160000   → StatusGoodEdited_DependentValueChanged
PriorityValue_PCP (in Opc.Ua.Types.bsd)      → struct field PriorityValue_PCP
```

## Scope

### Generated files affected

| Generator | Output file(s) | Underscore names |
|-----------|----------------|-----------------|
| `cmd/id` | `id/id_Variable_gen.go` | ~10,500 |
| `cmd/id` | `id/id_Object_gen.go` | ~1,500 |
| `cmd/id` | `id/id_Method_gen.go` | ~1,500 |
| `cmd/id` | `id/id_ObjectType_gen.go` | ~4 |
| `cmd/id` | `id/id_names_gen.go` | (map values, derived) |
| `cmd/status` | `ua/status_gen.go` | 9 |
| `cmd/service` | `ua/extobjs_gen.go` | 2 (struct fields) |

### Callers in hand-written code

~120 references to underscore `id.*` constants across 11 non-generated files:

- `aggregate.go` — 19 refs (`id.AggregateFunction_*`)
- `client.go` — 10 refs (`id.*_Encoding_DefaultBinary`, `id.Server_*`)
- `subscription.go` — 1 ref (`id.Server_ServerDiagnostics_*`)
- `server/service_handlers.go` — 35 refs (`id.*Request_Encoding_DefaultBinary`)
- `server/server_nodes.go` — 25 refs (`id.Server_ServerStatus_*`, `id.Server_ServerCapabilities_*`)
- `ua/well_known_role.go` — 12 refs (`id.WellKnownRole_*`)
- `ua/extension_object.go` — 5 refs (`id.*_Encoding_DefaultBinary`)
- `ua/event_filter_builder.go` — 2 refs
- `uasc/secure_channel_instance.go` — 4 refs
- `examples/trigger/trigger.go` — 1 ref
- `examples/subscribe/subscribe.go` — 3 refs
- Plus ~20 refs in test files

## Implementation plan

### Phase 1: Update generators

1. **`cmd/service/goname/format.go`** — Add underscore-to-CamelCase conversion:

   ```go
   func Format(s string) string {
       parts := strings.Split(s, "_")
       for i, p := range parts {
           if len(p) > 0 {
               parts[i] = strings.ToUpper(p[:1]) + p[1:]
           }
       }
       s = strings.Join(parts, "")
       return fixes.Replace(idents.Replace(s))
   }
   ```

2. **`cmd/id/main.go`** — Replace the local `goName()` function with a call to
   `goname.Format()` so all generators share the same logic.

3. **`cmd/status/main.go`** — Already uses `goname.Format()`, no change needed.

### Phase 2: Regenerate

Run `make gen` to regenerate all `_gen.go` files with the new CamelCase names.

### Phase 3: Update callers

Update all ~120 references in hand-written code. These are mechanical
find-and-replace operations within each file:

- `id.ServerType_ServerArray` → `id.ServerTypeServerArray`
- `id.AggregateFunction_Average` → `id.AggregateFunctionAverage`
- `id.WellKnownRole_Anonymous` → `id.WellKnownRoleAnonymous`
- `id.Server_ServerStatus_CurrentTime` → `id.ServerServerStatusCurrentTime`
- `StatusGoodEdited_DependentValueChanged` → `StatusGoodEditedDependentValueChanged`
- `PriorityValue_PCP` → `PriorityValuePCP`

### Phase 4: Remove the exclusion

Delete the ST1003 exclusion from `.golangci.yml`:

```yaml
  exclusions:
    rules:
      - linters: [staticcheck]
        text: "ST1003"
        path: "(_gen\\.go$|^schema/)"
```

Remove the `staticcheck.checks` setting entirely (defaults include all checks).

### Phase 5: Verify

- `make check` passes with 0 issues
- `make gen` is idempotent (regenerating produces identical output)

## Risks and considerations

- **Breaking change** — All exported `id.*` constants with underscores change
  names. Any downstream users referencing these constants will get compile
  errors. Acceptable at v0.1.x → v0.2.0.

- **`schema/uaNodeSet.go`** — Contains Go struct types that mirror the XML
  schema. Field names like `UAType` don't have underscores. No changes needed.

- **Reverse lookup maps** — `id/id_names_gen.go` stores names as map values
  (strings). These are currently the Go constant names. After renaming, the map
  values will also be CamelCase. If any tooling relies on the underscore form
  for display, consider keeping the original spec name as the map value instead.

- **`id.Name()` output** — The `Name()` function returns the Go constant name.
  After this change, `id.Name(2005)` will return `"ServerTypeServerArray"`
  instead of `"ServerType_ServerArray"`. If human-readable spec names are
  needed, consider storing the original CSV name alongside the Go name.

## Not in scope

- Renaming non-generated hand-written code (already done in v0.1.15).
- Changing the OPC UA spec files themselves.
- Adding deprecated aliases (not worth the complexity at pre-1.0).
